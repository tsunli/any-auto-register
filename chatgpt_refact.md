# ChatGPT 注册链路改进方案

> 目标：把成功率从 4/18 的 **0.2%** 拉回到 **≥ 50%**，并消除"连续全军覆没"型事故。

## 1. 数据基线（最近 3 天 task_logs）

```
broken_pipe   855  ← 压倒性大头
add_phone     535  ← 已修（B2）
other          87
http_409       57
oauth_consent  16
cf_block       12
tls_curl        8
otp_timeout     1
```

按日成功率：
```
2026-04-15  520/1172 = 44%
2026-04-16  189/715  = 26%
2026-04-17  252/943  = 27%
2026-04-18    1/407  = 0.2%   ← 灾难性
```

## 2. 根因诊断

| 现象 | 根因 | 依据 |
|---|---|---|
| Broken pipe 爆发 | curl_cffi `Session` 连接池一旦腐烂，后续所有请求永久 `[Errno 32]`。只有 `passwordless/send-otp` 分支被 B1 熔断，其他 HTTP 点继续用坏 session | 日志里裸 `[Errno 32] Broken pipe` 不带 `passwordless OTP 异常` 前缀的占 ≥ 40% |
| add_phone 循环 | OpenAI 对邮箱/IP 风控后永久 add_phone，旧代码反复触发 | 已在 B2 修复 |
| 4/18 全崩 | 单账号失败不重建 session → 整个线程持续坏连接 + 代理/UA 指纹命中拦截 | 同任务 15-20 条连续 Broken pipe |
| 409 未退避 | 指纹+IP 限流时立即重试 | 57 次 409 但没 IP 冷却日志 |
| 成功率无先兆告警 | 连续全失败不熔断 | 4/18 连跑 406 个 failed 才看到 |

核心结论：**Session 生命周期管理缺失是主要杀手，其它都是次生问题。**

## 3. 改进方案（按 ROI）

### P0-1：全链路 HTTP wrapper + 熔断重建

**范围**：`platforms/chatgpt/oauth_client.py`

**问题**：B1 只覆盖一个 except 分支；session 里 `self.session.get/post` 散布在 30+ 处，任何一处 Broken pipe 都不会重建。

**方案**：
1. 新增 `_http(method, url, **kwargs)` wrapper：
   - 调用 `self.session.request(method, url, ...)`
   - `except` 内调用 `_is_connection_broken(e)` → 若命中 → `_recreate_session()` → 重试一次
   - 二次 Broken pipe → `raise SkipCurrentAttemptRequested`
2. 用 `ast-grep` / grep 替换：`self.session.get(` → `self._http('GET', `，`self.session.post(` → `self._http('POST', `。
3. 保留原签名兼容：kwargs 透传。

**伪码**：
```python
def _http(self, method: str, url: str, *, _retry: bool = False, **kwargs):
    try:
        return self.session.request(method, url, **kwargs)
    except TaskInterruption:
        raise
    except Exception as e:
        if self._is_connection_broken(e) and not _retry:
            self._log(f"连接中断({type(e).__name__})，重建 session 后单次重试: {url}")
            self._recreate_session()
            return self._http(method, url, _retry=True, **kwargs)
        if self._is_connection_broken(e):
            raise SkipCurrentAttemptRequested(f"session 重建后仍失败: {type(e).__name__}")
        raise
```

**验证**：
- `grep "self.session\.\(get\|post\|request\)" oauth_client.py` 应为 0
- 跑一轮 20 账号，task_logs 里 `exception=BrokenPipeError` 条数 < 之前的 10%

**风险**：改动点多（~30 处），需一次性整体替换。估算 30 分钟 + 20 分钟回归。

---

### P0-2：Session 主动回收（不等 Broken pipe 出现）

**范围**：`platforms/chatgpt/oauth_client.py`

**问题**：curl_cffi impersonate session 的 keep-alive 很激进，连续用 5+ 分钟或 100+ 次后连接池大概率部分失效。

**方案**：
1. `__init__` 加计数器：`self._session_req_count = 0`、`self._session_born_at = time.time()`
2. `_http` 入口检查：
   ```python
   MAX_REQ = 80
   MAX_AGE = 240  # 4 分钟
   if self._session_req_count >= MAX_REQ or time.time() - self._session_born_at > MAX_AGE:
       self._log(f"session 到期回收: reqs={self._session_req_count}")
       self._recreate_session()
   self._session_req_count += 1
   ```
3. `_recreate_session` 重置计数器。

**风险**：回收期间正在执行的 OAuth state 不丢失（state 存在 `self` 属性里，session 本身无状态）。已验证 `_recreate_session` 目前只换 `self.session` 对象。

---

### P0-3：任务级连续失败熔断器

**范围**：`core/task_runtime.py` + `api/tasks.py`

**问题**：4/18 连跑 406 failed，如果在第 20 个就停，能救 386 个邮箱+代理额度。

**方案**：
1. `TaskControl` 加字段：
   ```python
   consecutive_fail_threshold: int = 15
   consecutive_fail_count: int = 0
   ```
2. `api/tasks.py` _do_one 成功 → 清零；`failed` 或非白名单 `skipped` → +1；到达阈值 → `control.request_stop()` + 告警日志。
3. 白名单 skipped：`add_phone 黑名单`（预期现象，不计数）。

**对外**：`RegisterTaskRequest` 新增 `consecutive_fail_threshold` 字段，默认 15，0 表示禁用。

**验证**：构造连续 15 次 Broken pipe 任务，第 16 次应自动 stop 且 task_logs 写入 `[ABORT] consecutive fail`。

---

### P1-1：409 / CF 限流 IP 冷却

**范围**：`core/proxy_pool.py` + `oauth_client.py` 409 处理

**问题**：57 次 409 同 IP 连撞不退避。

**方案**：
1. `proxy_pool` 加 `cool_down(proxy, seconds=300)`：冷却期内 `get_next` 不返回该代理。
2. `oauth_client` 任何 HTTP 返回 409/429/403+CF 时：
   ```python
   if r.status_code in (409, 429) or (r.status_code == 403 and "cloudflare" in r.text.lower()):
       try:
           from core.proxy_pool import proxy_pool as _pp
           if self.proxy: _pp.cool_down(self.proxy, 600)
       except Exception: pass
       raise SkipCurrentAttemptRequested(f"IP 限流 {r.status_code}，冷却代理")
   ```
3. 现在 `proxy_pool` 为空 → 直接 raise（给用户信号补池子）。

**风险**：小规模无代理池时会立刻 skip 全量。加开关 `ip_cooldown_enabled`（默认 True）。

---

### P1-2：Rescue 脚本先跑一轮验证 B1/B2/B4 效果

**操作**：
```bash
# 小量试跑 20 个，间隔 90s 控制指纹暴露
python scripts/rescue_stuck_accounts.py --limit 20 --delay 90
```

**观察指标**：
- task_logs 里 `source=rescue_script` 且 `status=success` 比例
- `has_access_token / has_session_token` 双真比例
- `elapsed_ms` 分布（期望 P50 < 60s）

若成功率 > 40% → 可把 limit 加大跑 505 全量；若 < 10% → 停下看具体 error 再定位。

---

### P1-3：task_logs stage 粒度落库

**范围**：`oauth_client.py`  `_enter_stage`

**问题**：当前 detail_json 只有总 stage（success/failed），看不出死在哪步。

**方案**：
1. `_enter_stage(name, note="")` 内调用回调 → platform → task 层，把 stage 写入 `task_logs.detail_json.stages`（list append）。
2. 失败时 detail_json 形如：
   ```json
   {
     "stage": "failed",
     "stages_trace": ["authorize_init", "signup_email", "email_otp_send", "authorize_continue"],
     "last_stage": "authorize_continue",
     ...
   }
   ```

**价值**：后续 SQL 可直接统计 `last_stage` TOP N 找改进方向。

---

### P2-1：executor_type=headless 真跑通

**范围**：`AccessTokenOnlyRegistrationEngine.__init__` 只接受 `browser_mode`；需要检查 `headless` 是否被消费。

**操作**：
1. `grep "browser_mode" platforms/chatgpt/` 跑一遍看 headless 分支是否完整
2. 若缺，补充 Playwright headless 发起 `chat.openai.com` 会话获取 sentinel token
3. 目前 `sentinel_browser.get_sentinel_token_via_browser` 已有实现，确认 engine 会调用

---

### P2-2：指纹多样化

**范围**：`oauth_client.py` `_recreate_session`

**方案**：每次重建时随机 `impersonate`：
```python
import random
IMPERSONATE_POOL = ["chrome120", "chrome123", "chrome124", "safari17_0"]
# curl_cffi Session(impersonate=random.choice(IMPERSONATE_POOL))
```
搭配 UA 同步变化。`user_agent` 工具目前从 `utils.py` 读；加配套映射表。

**风险**：impersonate 名字必须是 curl_cffi 支持列表；先 `python -c "import curl_cffi; print(curl_cffi.requests.BrowserType._member_names_)"` 取真实列表。

---

### P2-3：配置化超时 + 前端暴露

把 P0-2 的 `MAX_REQ / MAX_AGE` 进 `configs` 表 + `api/config.py` 白名单，前端 Settings 页可调。

---

## 4. 实施顺序与时间估算

| 阶段 | 项 | 预计工时 | 验证方式 |
|---|---|---|---|
| Day 1 | P0-1 全链路 wrapper | 45 分钟 | grep=0 + 20 账号回归 |
| Day 1 | P0-2 session 回收 | 15 分钟 | 单元测：调 100 次后断言重建次数 ≥ 1 |
| Day 1 | 跑 rescue 20 账号冒烟 | 30 分钟 | 成功率 > 40% |
| Day 2 | P0-3 连续失败熔断 | 30 分钟 | 构造 15 连失败 mock |
| Day 2 | P1-1 IP 冷却 | 30 分钟 | 手造 409 看 cool_down 日志 |
| Day 2 | P1-3 stage 追踪 | 20 分钟 | detail_json 出现 stages_trace |
| Day 3 | 跑 rescue 100 账号 | - | 成功率复盘 |
| Day 3+ | P2-1/2/3 | 按需 | |

## 5. 回滚/安全

- 每项独立 commit，挂 `B6-P0-1` 这样的前缀
- 所有熔断/skip 路径都带日志，可从 task_logs 追溯
- P0-1 是改动最大的一项，先在分支 `refactor/chatgpt-http-wrapper` 上做，回归通过再合 main
- P0-2 `MAX_REQ/MAX_AGE` 起始保守（80/240s），跑通后再调

## 6. 验收指标

跑 100 账号批次，期望：
- `status=success` 比例 ≥ **50%**（当前 ~25%）
- `exception=BrokenPipeError` 出现次数 **< 5**（当前 ~400/天）
- 无单任务连续 20 失败（熔断生效）
- task_logs `detail_json.last_stage` 可用于后续定位
