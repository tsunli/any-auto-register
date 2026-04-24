# ChatGPT Log-Driven Refactor Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 基于 `account_manager.db` 的真实运行数据，把 ChatGPT 注册链路的下一轮重构聚焦到 **可观测性、当前残余失败点、以及两段注册链路的运行时一致性**，避免重复重做已经落地的 `OAuthClient` 修复。

**Architecture:** 当前 ChatGPT 注册实际分为两段：前半段由 `ChatGPTClient.register_complete_flow()` 推进注册状态机，后半段由 `OAuthClient.login_and_get_tokens()` 或 `ChatGPTClient.reuse_session_and_get_tokens()` 完成 token / session 落地（`platforms/chatgpt/refresh_token_registration_engine.py:471-585`, `platforms/chatgpt/access_token_only_registration_engine.py:152-209`, `platforms/chatgpt/chatgpt_client.py:495-560`）。本次重构先统一日志与阶段追踪，再修复 `access_token_only / rescue` 的 session-token 落地失败，最后把 `ChatGPTClient` 的 HTTP 运行时与 `OAuthClient` 收敛到同一语义。

**Tech Stack:** Python, SQLModel/SQLite, unittest, existing FastAPI task API, existing frontend settings/register pages

---

## Evidence Baseline (from `account_manager.db`)

- `task_logs` 中 ChatGPT 日志共有 **4098** 条，时间跨度为 **2026-04-09 02:22:53** 到 **2026-04-19 04:21:33**。其中 `success=1569`、`failed=2529`。  
  Source of truth: `core/db.py:40-49`, live DB query against `task_logs`.
- 日成功率在 **2026-04-18** 跌到 **1/407 = 0.2%**，但在 **2026-04-19** 已恢复到 **13/15 = 86.7%**。这说明系统不是持续全局崩坏，而是已从历史灾难态恢复，下一轮应优先解决**当前残余失败点**与**结构性债务**。  
  Evidence source: live DB query against `task_logs.created_at/status`.
- **4083 / 4098** 条 ChatGPT `task_logs.detail_json` 为空，说明历史日志几乎无法按 `mode / executor / source / stage / task_id` 精确切片。当前 `TaskLog` 表结构也没有 `task_id / run_id / source` 字段（`core/db.py:40-49`），而 API task 与 rescue script 仍各自写日志（`api/tasks.py:131-145`, `scripts/rescue_stuck_accounts.py:85-97`）。
- 最新仍在发生的失败样本，集中为 rescue/access-token-only 链路上的：  
  `注册成功，但复用会话获取 AccessToken 失败: 缺少 ChatGPT session-token，注册回调可能未完全落地`。  
  该错误可直接映射到 `platforms/chatgpt/chatgpt_client.py:516-552`。
- `OAuthClient` 已具备 `_http()`、session recreate、session age/request-count 回收、以及 409/429/CF 代理冷却（`platforms/chatgpt/oauth_client.py:1780-1900`）；但 `ChatGPTClient` 仍存在多处直接 `self.session.get/post(...)` 业务调用（例如 `platforms/chatgpt/chatgpt_client.py:339,419,475,537,605,625,673,718,799,827,887,957`）。
- `accounts` 不是成功率真相源，因为 `save_account()` 会对同平台同邮箱做 upsert（`core/db.py:78-113`）。因此后续所有成功率/失败率判断必须基于统一后的运行日志，而不是 `accounts.updated_at`。

---

## Decision Summary

1. **先重构日志与观测层**，否则后续所有优化都继续靠猜。
2. **优先修复 access_token_only / rescue 的 session-token 落地失败**，因为这是当前最新、仍在真实发生的失败点。
3. **下一轮稳定性收敛重点放在 `ChatGPTClient`**，不要重复大规模重做已经具备 wrapper 的 `OAuthClient`。
4. **补任务级连续失败熔断**，防止未来再次出现长时间连续失败空转。
5. **统一配置口径**，避免 `default_executor` / `default_executor_type` 双轨继续扩散（`api/config.py:8-16,37-40`, `api/tasks.py:246-253`, `frontend/src/pages/RegisterTaskPage.tsx:44-50`）。

---

## Acceptance Criteria

- 新写入的 ChatGPT 运行日志中，`detail_json` 非空率达到 **100%**，并至少包含 `source / registration_mode / executor_type / elapsed_ms / last_stage`。
- 同一个 ChatGPT 任务能够在日志中用 `task_id` 或等价 `run_id` 重建失败序列，不再需要从全局时序猜测连续失败区间。
- `access_token_only / rescue` 链路的失败原因能够区分为：`callback_not_landed`、`session_cookie_missing`、`auth_session_missing_access_token` 等具体类别，而不是统一落成“缺少 ChatGPT session-token”。
- `ChatGPTClient` 业务代码中不再散落直接 `self.session.get/post` 调用；HTTP 入口统一走共享 wrapper。
- `consecutive_fail_threshold` 真正生效：达到阈值时任务自动停止并写出明确 `[ABORT]` 日志。
- 前端设置与后端配置只保留一个默认执行器主键，且注册任务请求会明确传递连续失败阈值。

---

## Task 1: 统一 ChatGPT 运行日志 schema 与写入入口

**Files:**
- Update: `core/db.py`
- Update: `api/tasks.py`
- Update: `scripts/rescue_stuck_accounts.py`
- Update: `platforms/chatgpt/chatgpt_registration_mode_adapter.py`
- Create: `tests/test_chatgpt_task_logging.py`

- [ ] **Step 1: 定义统一的 ChatGPT task log detail schema，并决定最小可落地字段集**

将新日志 detail 规范统一为至少包含以下字段：

```json
{
  "task_id": "task_...",
  "run_id": "chatgpt-register-...",
  "source": "manual|rescue_script|cleanup|other",
  "registration_mode": "refresh_token|access_token_only",
  "executor_type": "protocol|headless|headed",
  "proxy": "",
  "elapsed_ms": 12345,
  "last_stage": "token_exchange",
  "stages_trace": ["authorize_continue", "otp", "about_you", "token_exchange"],
  "has_access_token": true,
  "has_refresh_token": true,
  "has_session_token": false,
  "error_code": "session_cookie_missing"
}
```

设计时保持向后兼容：旧日志允许为空，但**新写入**一律使用该 schema。  
Relevant files: `core/db.py:40-49`, `api/tasks.py:131-145`, `scripts/rescue_stuck_accounts.py:85-97`.

- [ ] **Step 2: 抽一个统一的 TaskLog 写入 helper，禁止 API task / rescue script 各写一套**

将 `api/tasks.py` 中 `_save_task_log()`（`api/tasks.py:131-145`）提升为可复用 helper，或者抽到 `core/db.py` / 新模块中，要求：

- API 注册任务使用统一 helper
- `scripts/rescue_stuck_accounts.py:85-97` 改为使用同一 helper
- 统一注入 `task_id / source / detail schema`

**不要**继续让 rescue script 只写 `source=rescue_script` 到 `detail_json`，而 API task 只写一套零散字段。

- [ ] **Step 3: 在 adapter/account extra 中透传调试元数据，供日志层直接消费**

当前 `build_account()` / `_build_account_extra()` 只透传 token/source/mode（`platforms/chatgpt/chatgpt_registration_mode_adapter.py:82-110`）。  
需要补充把 engine/result metadata 中的以下内容带进 `Account.extra`：

- `last_stage`
- `stages_trace`
- `registration_flow`
- `token_flow`
- `error_code`

这样 `api/tasks.py` 在 success / failed / skipped 落库时无需再猜测。

- [ ] **Step 4: 为统一日志写入补测试，并验证数据库样本符合新 schema**

新增 `tests/test_chatgpt_task_logging.py`，覆盖：

- API 注册成功日志 detail 非空
- API 注册失败日志 detail 含 `last_stage`
- rescue script 日志与 API task 共用同一 schema
- `source` / `registration_mode` / `executor_type` 均可回读

**Verification:**

```bash
python -m unittest tests.test_chatgpt_task_logging -v
python - <<'PY'
import sqlite3, json
conn = sqlite3.connect('account_manager.db')
rows = conn.execute("SELECT detail_json FROM task_logs WHERE platform='chatgpt' ORDER BY id DESC LIMIT 20").fetchall()
for (raw,) in rows:
    d = json.loads(raw or '{}')
    assert d, raw
    assert 'source' in d and 'executor_type' in d and 'last_stage' in d
print('detail_json schema smoke passed')
PY
```

---

## Task 2: 把 stage trace 从打印日志升级为结构化状态

**Files:**
- Update: `platforms/chatgpt/chatgpt_client.py`
- Update: `platforms/chatgpt/oauth_client.py`
- Update: `platforms/chatgpt/refresh_token_registration_engine.py`
- Update: `platforms/chatgpt/access_token_only_registration_engine.py`
- Update: `tests/test_chatgpt_register.py`

- [ ] **Step 1: 为 `ChatGPTClient` / `OAuthClient` 增加 `stage_trace` 容器**

当前 `_enter_stage()` 只更新 `last_stage` 并打印（`platforms/chatgpt/chatgpt_client.py:180-186`, `platforms/chatgpt/oauth_client.py:240-255`）。  
改为：

- 初始化 `self.stage_trace: list[str]`
- `_enter_stage()` append 标准化阶段名
- 重复阶段允许保留，或在日志层保留原始 trace + 去重 trace 两份

- [ ] **Step 2: engine 在返回 `RegistrationResult` 时，把阶段信息带到 metadata**

在：

- `platforms/chatgpt/refresh_token_registration_engine.py:330-365`
- `platforms/chatgpt/access_token_only_registration_engine.py:174-204`

补充：

- `last_stage`
- `stages_trace`
- `registration_flow`
- `token_flow`

使 adapter/日志层无需从字符串错误里反向解析阶段。

- [ ] **Step 3: 对失败返回路径补稳定的 `error_code` / `error_stage`**

特别是以下高频失败：

- add_phone 未获得 workspace/callback
- callback 未落地
- session cookie 未落地
- `/api/auth/session` 未返回 access token

这些错误当前多以字符串拼接形式出现，如 `platforms/chatgpt/chatgpt_client.py:551-552`。  
重构后要求保留用户可读 message，但同时给出程序可分析的 `error_code`。

- [ ] **Step 4: 为阶段追踪补测试**

在 `tests/test_chatgpt_register.py` 中新增断言：

- `register_complete_flow()` 到 `about_you` interrupt 时有 trace
- `reuse_session_and_get_tokens()` 失败时能返回 `last_stage` / `error_code`
- adapter.build_account() 后 `Account.extra` 含 `stages_trace`

**Verification:**

```bash
python -m unittest tests.test_chatgpt_register tests.test_chatgpt_registration_mode_adapter -v
```

---

## Task 3: 优先修复 access_token_only / rescue 的 session-token 落地失败

**Files:**
- Update: `platforms/chatgpt/chatgpt_client.py`
- Update: `scripts/rescue_stuck_accounts.py`
- Update: `tests/test_chatgpt_register.py`

- [ ] **Step 1: 将 `reuse_session_and_get_tokens()` 拆成三个具名步骤**

当前函数把这三件事耦合在一起（`platforms/chatgpt/chatgpt_client.py:495-560`）：

1. `land_registration_callback`
2. `ensure_chatgpt_session_cookie`
3. `fetch_chatgpt_auth_session`

先拆分成 3 个私有 helper，并让每个 helper 返回 `(ok, value_or_error_code)`。

- [ ] **Step 2: 把“补触达首页等 cookie”逻辑从匿名循环改成可诊断路径**

当前 session cookie 补落地逻辑写在 `platforms/chatgpt/chatgpt_client.py:527-550`，失败后统一落成：

```python
return False, "缺少 ChatGPT session-token，注册回调可能未完全落地"
```

重构后要求明确区分：

- callback 没真正落地到 ChatGPT
- callback 落地了但 next-auth cookie 没出现
- cookie 有了但 `/api/auth/session` 未返 token

这些都要体现在 `error_code` 和日志 detail 中。

- [ ] **Step 3: rescue script 把失败 detail 记录为结构化信息，不再只存字符串**

当前 rescue 失败 detail 只有 `elapsed` 和 `[rescue] {err}`（`scripts/rescue_stuck_accounts.py:117-145`, `192-200`）。  
改为把：

- `source=rescue_script`
- `run_id`
- `registration_mode=access_token_only`
- `last_stage`
- `error_code`
- `has_access_token/has_session_token`

一起落库。

- [ ] **Step 4: 用单元测试锁住 rescue 当前真实失败样本**

在 `tests/test_chatgpt_register.py` 中增加：

- callback 未落地 -> `callback_not_landed`
- cookie 缺失 -> `session_cookie_missing`
- `/api/auth/session` 无 access token -> `auth_session_missing_access_token`
- 首页补触达一次后成功拿到 cookie/token 的 happy path

**Verification:**

```bash
python -m unittest tests.test_chatgpt_register -v
python scripts/rescue_stuck_accounts.py --limit 5 --delay 30
```

期望：

- 不再出现模糊的单一句子失败
- 每次失败都能落到具体 `error_code`

---

## Task 4: 把 `ChatGPTClient` 的 HTTP 运行时与 `OAuthClient` 对齐

**Files:**
- Update: `platforms/chatgpt/chatgpt_client.py`
- Update: `platforms/chatgpt/oauth_client.py` (only if extracting shared helper)
- Optionally Create: `platforms/chatgpt/http_runtime.py`
- Update: `tests/test_chatgpt_register.py`

- [ ] **Step 1: 选择轻量共享方案，避免引入过度抽象**

推荐方案：

- 提取窄共享 helper（例如 `platforms/chatgpt/http_runtime.py`）
- 只封装：
  - broken connection 判定
  - session recreate
  - request-count / age 回收
  - 409/429/403+CF 判定
  - 单次重试

**不要**把 `ChatGPTClient` / `OAuthClient` 的业务状态机抽成统一超类。

- [ ] **Step 2: 为 `ChatGPTClient` 增加 `_http()` / session lifecycle / cooldown 语义**

参考 `OAuthClient` 现有实现：

- `_recreate_session()`：`platforms/chatgpt/oauth_client.py:1780-1817`
- `_maybe_rotate_session()`：`platforms/chatgpt/oauth_client.py:1818-1826`
- `_http()`：`platforms/chatgpt/oauth_client.py:1861-1885`
- `_is_connection_broken()`：`platforms/chatgpt/oauth_client.py:1888-1900`

把同等语义引入 `ChatGPTClient`，同时保留其现有 `_reset_session()` 用于**指纹重置**（`platforms/chatgpt/chatgpt_client.py:225-260`），不要和连接池重建混用。

- [ ] **Step 3: 替换 `ChatGPTClient` 内部所有直接 `self.session.get/post` 业务调用**

至少覆盖当前已知位置：

- `platforms/chatgpt/chatgpt_client.py:339`
- `platforms/chatgpt/chatgpt_client.py:419`
- `platforms/chatgpt/chatgpt_client.py:475`
- `platforms/chatgpt/chatgpt_client.py:537`
- `platforms/chatgpt/chatgpt_client.py:605`
- `platforms/chatgpt/chatgpt_client.py:625`
- `platforms/chatgpt/chatgpt_client.py:673`
- `platforms/chatgpt/chatgpt_client.py:718`
- `platforms/chatgpt/chatgpt_client.py:799`
- `platforms/chatgpt/chatgpt_client.py:827`
- `platforms/chatgpt/chatgpt_client.py:887`
- `platforms/chatgpt/chatgpt_client.py:957`

- [ ] **Step 4: 为 shared runtime 补单元测试**

覆盖：

- broken pipe -> recreate -> retry success
- broken pipe twice -> `SkipCurrentAttemptRequested`
- req_count / age 达阈值后自动回收
- 409/429/403+CF -> 冷却代理 / 或在无代理池时返回稳定 skip

**Verification:**

```bash
python -m unittest tests.test_chatgpt_register -v
python - <<'PY'
from pathlib import Path
import re
text = Path('platforms/chatgpt/chatgpt_client.py').read_text()
hits = re.findall(r'self\\.session\\.(get|post)\\(', text)
assert not hits, hits
print('no direct session get/post in ChatGPTClient business flow')
PY
```

---

## Task 5: 真正落地任务级连续失败熔断

**Files:**
- Update: `api/tasks.py`
- Update: `core/task_runtime.py` (only if snapshot needs to expose the counter)
- Update: `frontend/src/pages/RegisterTaskPage.tsx`
- Update: `frontend/src/pages/Accounts.tsx`
- Update: `tests/test_register_task_controls.py`
- Update: `tests/test_task_runtime.py`

- [ ] **Step 1: 在 `_run_register()` 中实现连续失败计数**

当前 `RegisterTaskRequest` 已有 `consecutive_fail_threshold` 字段（`api/tasks.py:28-39`），但运行逻辑尚未消费。  
在 `api/tasks.py:381-411` 的 future 聚合处增加：

- `failed` -> `+1`
- `success` -> reset
- `skipped` -> 默认 `+1`，但为白名单 skip 预留豁免机制

- [ ] **Step 2: 到达阈值后自动 stop，并写出明确 `[ABORT]` 日志**

达到阈值时执行：

- `_log(task_id, "[ABORT] consecutive fail threshold reached ...")`
- `control.request_stop()`
- cancel 仍在排队的 future

并把熔断原因写入新日志 schema。

- [ ] **Step 3: 前端表单显式传递阈值，而不是只靠默认值**

当前两个入口都未把 `consecutive_fail_threshold` 传到 `/tasks/register`：

- `frontend/src/pages/RegisterTaskPage.tsx:185-198`
- `frontend/src/pages/Accounts.tsx:801-813`

补上表单项与 payload 传递，默认值取 15。

- [ ] **Step 4: 补测试锁住熔断行为**

覆盖：

- 连续 15 次 failed -> 自动 stopped
- 中间一次 success -> 计数清零
- 白名单 skip 不触发熔断

**Verification:**

```bash
python -m unittest tests.test_register_task_controls tests.test_task_runtime -v
```

---

## Task 6: 清理配置口径漂移，并把稳定性参数暴露到设置页

**Files:**
- Update: `api/config.py`
- Update: `frontend/src/pages/Settings.tsx`
- Update: `frontend/src/pages/RegisterTaskPage.tsx`
- Update: `frontend/src/pages/Accounts.tsx`
- Update: `frontend/src/lib/configValueParsers.ts`

- [ ] **Step 1: 统一默认执行器主键，只保留一个 canonical key**

当前存在：

- `default_executor`（前端读取）：`frontend/src/pages/RegisterTaskPage.tsx:44-50`
- `default_executor_type`（后端运行时读取）：`api/tasks.py:246-253`

数据库当前也体现了漂移：`default_executor=''`，`default_executor_type='headless'`。  
统一保留 `default_executor_type`，并在兼容窗口内允许从旧 key 回填。

- [ ] **Step 2: 把 HTTP 稳定性参数暴露到配置 API**

为以下 key 增加 API 白名单与 UI：

- `chatgpt_oauth_session_max_requests`
- `chatgpt_oauth_session_max_age_seconds`
- `chatgpt_ip_cooldown_enabled`
- `chatgpt_ip_cooldown_seconds`
- `consecutive_fail_threshold`（若决定做全局默认值）

目前这些 key 不在 `api/config.py:8-110` 的配置白名单中。

- [ ] **Step 3: Settings 页增加 ChatGPT 稳定性小节**

在 `frontend/src/pages/Settings.tsx` 的 ChatGPT section（`272-335`）中新增：

- session 请求数阈值
- session 生命周期阈值
- IP 冷却开关 / 秒数
- 连续失败阈值默认值（可选）

- [ ] **Step 4: 验证 UI/后端配置一致**

**Verification:**

```bash
python - <<'PY'
import sqlite3
conn = sqlite3.connect('account_manager.db')
for key in ['default_executor_type','chatgpt_oauth_session_max_requests','chatgpt_oauth_session_max_age_seconds']:
    print(key, conn.execute('SELECT value FROM configs WHERE key=?', (key,)).fetchone())
PY
```

并在浏览器 Network 面板确认 `/config` 与 `/tasks/register` payload 一致。

---

## Risks and Mitigations

- **风险：日志 schema 改动后，新旧日志混杂，查询脚本需要兼容两种格式。**  
  **Mitigation:** 查询脚本先做向后兼容；验收只要求“新写入日志 100% 非空且符合新 schema”。

- **风险：`ChatGPTClient` HTTP runtime 改动较大，容易把当前已恢复的 happy path 打坏。**  
  **Mitigation:** 先锁测试，再按 helper -> callsite 替换的顺序推进；每替换一批就跑 `tests.test_chatgpt_register`。

- **风险：rescue/session-token 落地修复依然可能受服务端时序波动影响。**  
  **Mitigation:** 把失败原因显式拆分成 callback/cookie/auth-session 三段，先提升可诊断性，再谈进一步优化策略。

- **风险：熔断过于激进，会误停含大量预期 skip 的任务。**  
  **Mitigation:** 给白名单 skip 保留豁免机制；先把阈值默认定为 15，再根据新日志调优。

---

## Verification Sequence

按依赖顺序执行，不要跳步：

1. `tests.test_chatgpt_task_logging`
2. `tests.test_chatgpt_register`
3. `tests.test_chatgpt_registration_mode_adapter`
4. `tests.test_register_task_controls`
5. `tests.test_task_runtime`
6. 前端检查：Settings / RegisterTaskPage / Accounts payload
7. `python scripts/rescue_stuck_accounts.py --limit 5 --delay 30`
8. 小批量真实注册任务（建议 5-10 个）验证新日志与熔断行为

推荐命令：

```bash
python -m unittest \
  tests.test_chatgpt_task_logging \
  tests.test_chatgpt_register \
  tests.test_chatgpt_registration_mode_adapter \
  tests.test_register_task_controls \
  tests.test_task_runtime -v
```

---

## Definition of Done

- 最新 20 条 ChatGPT 日志中，`detail_json` 全部非空且包含统一字段集。
- rescue/access-token-only 链路的失败可以明确区分 callback / cookie / auth-session 三段原因。
- `ChatGPTClient` 与 `OAuthClient` 的 HTTP runtime 语义一致。
- 连续失败熔断经测试可复现，并在真实小批量任务中可观测。
- 配置/UI 不再存在 `default_executor` / `default_executor_type` 双轨歧义。

