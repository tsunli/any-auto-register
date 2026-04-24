#!/usr/bin/env python3
"""
批量注册 ChatGPT 账号脚本（参考 rescue_stuck_accounts.py）。

示例：
  python scripts/register_chatgpt_accounts.py --count 5 --delay 90 --mode access_token_only
  python scripts/register_chatgpt_accounts.py --count 3 --mail-provider luckmail --proxy http://user:pass@ip:port
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlmodel import Session, select

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.base_mailbox import create_mailbox
from core.base_platform import RegisterConfig
from core.config_store import config_store
from core.db import AccountModel, engine, save_account, write_task_log
from core.registry import get, load_all
from platforms.chatgpt.chatgpt_registration_mode_adapter import (
    normalize_chatgpt_registration_mode,
)
from platforms.chatgpt.token_rescue import try_rescue_refresh_token


_STOP = False
SUCCESSFUL_CHATGPT_ACCOUNT_STATUSES = ("registered", "trial", "subscribed")


def _handle_sigint(_signum, _frame):
    global _STOP
    _STOP = True
    print("\n[register] 收到中断信号，执行完当前账号后停止")


signal.signal(signal.SIGINT, _handle_sigint)


def _normalize_email(email: str | None) -> str:
    return str(email or "").strip().lower()


def load_successfully_registered_emails() -> set[str]:
    with Session(engine) as session:
        rows = session.exec(
            select(AccountModel.email)
            .where(AccountModel.platform == "chatgpt")
            .where(AccountModel.status.in_(SUCCESSFUL_CHATGPT_ACCOUNT_STATUSES))
        ).all()
    return {_normalize_email(email) for email in rows if _normalize_email(email)}


def _parse_extra_value(raw: str) -> Any:
    text = str(raw or "").strip()
    if not text:
        return ""
    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if low == "null":
        return None
    try:
        return json.loads(text)
    except Exception:
        return text


def _parse_extra_pairs(pairs: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for item in pairs:
        raw = str(item or "").strip()
        if not raw:
            continue
        if "=" not in raw:
            raise ValueError(f"--extra 参数格式错误（需 KEY=VALUE）: {raw}")
        key, value = raw.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"--extra 参数 key 不能为空: {raw}")
        result[key] = _parse_extra_value(value)
    return result


def _is_sensitive_key(key: str) -> bool:
    text = str(key or "").lower()
    markers = (
        "token",
        "key",
        "pass",
        "password",
        "secret",
        "auth",
        "cookie",
        "bearer",
        "smtp",
        "proxy",
    )
    return any(m in text for m in markers)


def _mask_value(value: Any) -> Any:
    text = str(value or "")
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:2]}{'*' * (len(text) - 6)}{text[-4:]}"


def _mask_proxy(proxy: str) -> str:
    try:
        parts = urlsplit(proxy)
        if not parts.netloc or "@" not in parts.netloc:
            return proxy
        userinfo, host = parts.netloc.rsplit("@", 1)
        if ":" in userinfo:
            user, _pwd = userinfo.split(":", 1)
            safe_netloc = f"{user}:***@{host}"
        else:
            safe_netloc = f"***@{host}"
        return urlunsplit((parts.scheme, safe_netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        return "***"


def _safe_extra_snapshot(extra: dict[str, Any], include_keys: list[str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in include_keys:
        if key not in extra:
            continue
        value = extra.get(key)
        result[key] = _mask_value(value) if _is_sensitive_key(key) else value
    return result


def _log_task(platform: str, email: str, status: str, error: str, detail: dict) -> None:
    payload = dict(detail or {})
    write_task_log(
        platform,
        email or "",
        status,
        error=error or "",
        detail=payload,
        source=str(payload.get("source") or "").strip(),
        run_id=str(payload.get("run_id") or "").strip(),
    )


def _build_platform(
    platform_cls,
    *,
    extra: dict[str, Any],
    proxy: str | None,
    executor_type: str,
    captcha_solver: str,
    successful_emails: set[str] | None = None,
    allow_reregister: bool = False,
):
    successful_email_set = successful_emails if successful_emails is not None else set()
    config = RegisterConfig(
        executor_type=executor_type,
        captcha_solver=captcha_solver,
        proxy=proxy,
        extra=extra,
    )
    mailbox = create_mailbox(
        provider=extra.get("mail_provider", "tempmail_lol"),
        extra=extra,
        proxy=proxy,
    )
    if successful_email_set and not allow_reregister:
        mailbox = _RegisteredEmailSkippingMailbox(
            mailbox=mailbox,
            successful_emails=successful_email_set,
        )
    return platform_cls(config=config, mailbox=mailbox)


class _RegisteredEmailSkippingMailbox:
    def __init__(
        self,
        *,
        mailbox,
        successful_emails: set[str],
        max_attempts: int = 5000,
    ):
        self._mailbox = mailbox
        self._successful_emails = successful_emails
        self._max_attempts = max(1, int(max_attempts or 1))

    def __getattr__(self, item):
        return getattr(self._mailbox, item)

    def get_email(self):
        attempts = 0
        seen_emails_in_cycle: set[str] = set()
        while attempts < self._max_attempts:
            account = self._mailbox.get_email()
            email = _normalize_email(getattr(account, "email", ""))
            if not email or email not in self._successful_emails:
                return account
            if email in seen_emails_in_cycle:
                break
            seen_emails_in_cycle.add(email)
            attempts += 1
            log_fn = getattr(self, "_log_fn", None)
            if callable(log_fn):
                log_fn(f"邮箱 {email} 已成功注册，跳过并重新取号 ({attempts}/{self._max_attempts})")
        raise RuntimeError(f"连续获取到已成功注册邮箱，已重试 {self._max_attempts} 次，疑似邮箱池已耗尽")

    def get_current_ids(self, account):
        return self._mailbox.get_current_ids(account)

    def wait_for_code(self, *args, **kwargs):
        return self._mailbox.wait_for_code(*args, **kwargs)


def _sync_saved_account_to_cliproxyapi(
    account_id: int | None,
    *,
    api_url: str | None = None,
    api_key: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    if not account_id:
        return {
            "ok": False,
            "uploaded": False,
            "skipped": False,
            "message": "账号未落库，无法同步到 CLIProxyAPI",
            "remote_state": "",
            "results": [],
        }

    from services.chatgpt_sync import (
        backfill_chatgpt_account_to_cpa,
        get_cliproxy_sync_state,
    )

    try:
        with Session(engine) as session:
            row = session.get(AccountModel, int(account_id))
            if row is None:
                return {
                    "ok": False,
                    "uploaded": False,
                    "skipped": False,
                    "message": f"未找到账号记录: {account_id}",
                    "remote_state": "",
                    "results": [],
                }

            outcome = backfill_chatgpt_account_to_cpa(
                row,
                session=session,
                api_url=api_url,
                api_key=api_key,
                commit=True,
                force=force,
            )
            sync_state = get_cliproxy_sync_state(row)
            return {
                "ok": bool(outcome.get("ok")),
                "uploaded": bool(outcome.get("uploaded")),
                "skipped": bool(outcome.get("skipped")),
                "message": str(outcome.get("message") or ""),
                "remote_state": str(sync_state.get("remote_state") or ""),
                "results": list(outcome.get("results") or []),
            }
    except Exception as exc:
        return {
            "ok": False,
            "uploaded": False,
            "skipped": False,
            "message": f"CLIProxyAPI 同步异常: {exc}",
            "remote_state": "",
            "results": [],
        }


def _register_one(
    platform_cls,
    *,
    email: str | None,
    password: str | None,
    extra: dict[str, Any],
    proxy: str | None,
    executor_type: str,
    captcha_solver: str,
    cliproxyapi_sync: bool,
    cliproxyapi_api_url: str | None = None,
    cliproxyapi_api_key: str | None = None,
    successful_emails: set[str] | None = None,
    allow_reregister: bool = False,
    try_upgrade_refresh_token: bool = True,
    otp_timeout: int = 300,
    browser_mode: str = "protocol",
) -> tuple[bool, Any, dict]:
    started = time.time()
    successful_email_set = successful_emails if successful_emails is not None else set()
    normalized_email = _normalize_email(email)
    if normalized_email and normalized_email in successful_email_set and not allow_reregister:
        return (
            False,
            "skipped",
            {
                "elapsed": 0.0,
                "email": email or "",
                "executor_type": executor_type,
                "skip_reason": "already_successfully_registered",
                "skip_message": "邮箱已成功注册，跳过",
            },
        )
    platform = _build_platform(
        platform_cls,
        extra=extra,
        proxy=proxy,
        executor_type=executor_type,
        captcha_solver=captcha_solver,
        successful_emails=successful_email_set,
        allow_reregister=allow_reregister,
    )
    platform._log_fn = lambda msg: print(f"  [log] {msg}")
    mailbox = getattr(platform, "mailbox", None)
    if mailbox is not None:
        mailbox._log_fn = platform._log_fn
    try:
        account = platform.register(email=email, password=password)
    except Exception as e:
        metadata = dict(getattr(platform, "last_error_metadata", {}) or {})
        return (
            False,
            f"{type(e).__name__}: {e}",
            {
                "elapsed": round(time.time() - started, 1),
                "email": email or "",
                "executor_type": executor_type,
                **metadata,
            },
        )

    try:
        saved_account = save_account(account)
        normalized_saved_email = _normalize_email(getattr(account, "email", ""))
        if normalized_saved_email:
            successful_email_set.add(normalized_saved_email)
    except Exception as e:
        return (
            False,
            f"save_account 失败: {e}",
            {
                "elapsed": round(time.time() - started, 1),
                "email": getattr(account, "email", "") or email or "",
                "executor_type": executor_type,
            },
        )

    # --- refresh_token 升级（仅 access_token_only 模式）---
    rescue_ok = False
    rescue_err = ""
    rescue_detail: dict[str, Any] = {}
    registration_mode = (getattr(account, "extra", {}) or {}).get("chatgpt_registration_mode", "")
    if try_upgrade_refresh_token and registration_mode == "access_token_only":
        print("  [rescue] access_token_only 模式，尝试补齐 refresh_token...")
        rescue_ok, rescue_err, rescue_detail = try_rescue_refresh_token(
            saved_account,
            global_config=extra,
            proxy=proxy,
            browser_mode=browser_mode,
            otp_timeout=otp_timeout,
            logger=lambda msg: print(f"  [rescue] {msg}"),
        )
        if rescue_ok:
            print("  [rescue] ✅ refresh_token 补齐成功")
        else:
            print(f"  [rescue] ⚠️ refresh_token 补齐失败: {rescue_err}")

    cliproxyapi_result: dict[str, Any] = {
        "ok": False,
        "uploaded": False,
        "skipped": False,
        "message": "",
        "remote_state": "",
        "results": [],
    }
    if cliproxyapi_sync:
        cliproxyapi_result = _sync_saved_account_to_cliproxyapi(
            getattr(saved_account, "id", None),
            api_url=cliproxyapi_api_url,
            api_key=cliproxyapi_api_key,
            force=rescue_ok,
        )

    acc_extra = getattr(account, "extra", {}) or {}
    detail = {
        "elapsed": round(time.time() - started, 1),
        "email": getattr(account, "email", "") or email or "",
        "executor_type": executor_type,
        "has_access_token": bool((getattr(account, "token", "") or "").strip()),
        "has_refresh_token": bool(rescue_detail.get("has_refresh_token") or acc_extra.get("refresh_token", "")),
        "has_session_token": bool(rescue_detail.get("has_session_token") or acc_extra.get("session_token", "")),
        "registration_mode": rescue_detail.get("registration_mode") or registration_mode,
        "last_stage": rescue_detail.get("last_stage") or acc_extra.get("last_stage", ""),
        "stages_trace": rescue_detail.get("stages_trace") or acc_extra.get("stages_trace", []),
        "error_code": acc_extra.get("error_code", ""),
        "skip_reason": "",
        "rescue_attempted": try_upgrade_refresh_token and registration_mode == "access_token_only",
        "rescue_ok": rescue_ok,
        "rescue_err": rescue_err,
        "cliproxyapi_auto_sync": bool(cliproxyapi_sync),
        "cliproxyapi_sync_ok": bool(cliproxyapi_result.get("ok")),
        "cliproxyapi_uploaded": bool(cliproxyapi_result.get("uploaded")),
        "cliproxyapi_skipped": bool(cliproxyapi_result.get("skipped")),
        "cliproxyapi_remote_state": str(cliproxyapi_result.get("remote_state") or ""),
        "cliproxyapi_message": str(cliproxyapi_result.get("message") or ""),
    }
    return True, account, detail


def main():
    parser = argparse.ArgumentParser(description="批量注册 ChatGPT 账号并写入 accounts 表")
    parser.add_argument("--count", type=int, default=200, help="注册数量（默认 200）")
    parser.add_argument("--delay", type=int, default=60, help="每个账号间隔秒数（默认 60）")
    parser.add_argument(
        "--mode",
        type=str,
        default="access_token_only",
        help="注册模式：refresh_token | access_token_only（默认 access_token_only）",
    )
    parser.add_argument("--mail-provider", type=str, default="", help="邮箱提供商（不传则沿用配置）")
    parser.add_argument(
        "--executor",
        type=str,
        default="protocol",
        choices=["protocol", "headless", "headed"],
        help="执行器类型（默认 protocol）",
    )
    parser.add_argument("--captcha-solver", type=str, default="yescaptcha", help="验证码服务（默认 yescaptcha）")
    parser.add_argument("--proxy", type=str, default="", help="代理 URL")
    parser.add_argument("--email", type=str, default="", help="固定邮箱（仅支持 count=1）")
    parser.add_argument("--password", type=str, default="", help="固定密码（不传则自动随机）")
    parser.add_argument("--register-max-retries", type=int, default=None, help="单账号最大重试次数")
    parser.add_argument("--extra", action="append", default=[], help="额外配置，格式 KEY=VALUE，可重复")
    parser.add_argument("--dry-run", action="store_true", help="仅打印生效配置，不执行注册")
    parser.add_argument("--no-task-log", action="store_true", help="不写 task_logs 记录")
    parser.add_argument("--allow-reregister", action="store_true", help="允许重复注册已成功状态的邮箱，不做成功账号跳过过滤")
    parser.add_argument("--no-cliproxyapi-sync", action="store_true", help="注册成功后不自动同步到 CLIProxyAPI")
    parser.add_argument("--cliproxyapi-api-url", type=str, default="", help="覆盖 CLIProxyAPI Base URL")
    parser.add_argument("--cliproxyapi-api-key", type=str, default="", help="覆盖 CLIProxyAPI 管理 Key")
    parser.add_argument("--no-upgrade-refresh-token", action="store_true", help="access_token_only 注册后不自动补 refresh_token")
    parser.add_argument("--otp-timeout", type=int, default=300, help="补 refresh_token 时 OTP 等待超时秒数（默认 300）")
    parser.add_argument("--browser-mode", type=str, default="protocol", help="浏览器模式（默认 protocol）")
    parser.add_argument("--source", type=str, default="register_script", help="写入 task_logs.detail.source")
    args = parser.parse_args()

    if args.count <= 0:
        raise SystemExit("--count 必须大于 0")
    if args.email and args.count > 1:
        raise SystemExit("固定 --email 时仅支持 --count 1，避免重复覆盖同邮箱账号")

    extra = config_store.get_all().copy()
    if args.mail_provider:
        extra["mail_provider"] = args.mail_provider.strip()
    elif not extra.get("mail_provider"):
        extra["mail_provider"] = "tempmail_lol"
    if args.mode:
        extra["chatgpt_registration_mode"] = normalize_chatgpt_registration_mode(args.mode)
    if args.register_max_retries is not None:
        extra["register_max_retries"] = int(args.register_max_retries)
    parsed_extra = _parse_extra_pairs(args.extra)
    extra.update(parsed_extra)

    proxy = args.proxy.strip() or None
    password = args.password.strip() or None
    fixed_email = args.email.strip() or None
    mode = normalize_chatgpt_registration_mode(extra.get("chatgpt_registration_mode"))
    cliproxyapi_sync = not args.no_cliproxyapi_sync
    cliproxyapi_api_url = args.cliproxyapi_api_url.strip() or None
    cliproxyapi_api_key = args.cliproxyapi_api_key.strip() or None

    print(
        f"[register] count={args.count} delay={args.delay}s executor={args.executor} "
        f"mail_provider={extra.get('mail_provider')} mode={mode} "
        f"cliproxyapi_sync={'on' if cliproxyapi_sync else 'off'} "
        f"allow_reregister={'on' if args.allow_reregister else 'off'}"
    )
    if proxy:
        print(f"[register] proxy={_mask_proxy(proxy)}")
    if args.dry_run:
        print("[register] dry-run 模式，生效 extra 配置如下：")
        include_keys = [
            "mail_provider",
            "chatgpt_registration_mode",
            "register_max_retries",
            "default_captcha_solver",
            "default_executor_type",
            "mailbox_otp_timeout_seconds",
        ]
        include_keys.extend(list(parsed_extra.keys()))
        safe_view = _safe_extra_snapshot(extra, include_keys)
        print(json.dumps(safe_view, ensure_ascii=False, indent=2))
        return

    load_all()
    platform_cls = get("chatgpt")
    successful_emails = set()
    if not args.allow_reregister:
        successful_emails = load_successfully_registered_emails()

    stats = {"ok": 0, "skip": 0, "fail": 0}
    created_emails: list[str] = []
    run_id = f"{args.source}-{int(time.time())}"
    for i in range(args.count):
        if _STOP:
            print("[register] 已中断")
            break
        print(f"\n[register] ({i + 1}/{args.count}) 开始")
        ok, payload, detail = _register_one(
            platform_cls,
            email=fixed_email,
            password=password,
            extra=extra,
            proxy=proxy,
            executor_type=args.executor,
            captcha_solver=args.captcha_solver,
            cliproxyapi_sync=cliproxyapi_sync,
            cliproxyapi_api_url=cliproxyapi_api_url,
            cliproxyapi_api_key=cliproxyapi_api_key,
            successful_emails=successful_emails,
            allow_reregister=args.allow_reregister,
            try_upgrade_refresh_token=not args.no_upgrade_refresh_token,
            otp_timeout=args.otp_timeout,
            browser_mode=args.browser_mode,
        )

        email = (detail.get("email") or fixed_email or "").strip()
        detail = {
            **detail,
            "source": args.source,
            "run_id": run_id,
            "executor_type": detail.get("executor_type") or args.executor,
            "proxy": proxy or "",
            "mail_provider": extra.get("mail_provider", ""),
            "registration_mode": detail.get("registration_mode") or mode,
        }

        if ok:
            stats["ok"] += 1
            created_emails.append(email)
            print(f"  ✅ 成功: {email} (elapsed={detail.get('elapsed')}s)")
            if detail.get("cliproxyapi_auto_sync"):
                sync_state = detail.get("cliproxyapi_remote_state") or "unknown"
                sync_msg = detail.get("cliproxyapi_message") or "no message"
                prefix = "  [cliproxyapi] ✅" if detail.get("cliproxyapi_sync_ok") else "  [cliproxyapi] ⚠️"
                print(f"{prefix} remote_state={sync_state} message={sync_msg}")
            if not args.no_task_log:
                _log_task("chatgpt", email, "success", "", detail)
        elif str(payload or "") == "skipped" or detail.get("skip_reason"):
            stats["skip"] += 1
            skip_message = str(detail.get("skip_message") or "邮箱已成功注册，跳过")
            print(f"  ⏭️ 跳过: {skip_message}")
            if not args.no_task_log:
                _log_task("chatgpt", email, "skipped", skip_message, detail)
        else:
            stats["fail"] += 1
            err = str(payload or "unknown error")
            print(f"  ❌ 失败: {err}")
            if not args.no_task_log:
                _log_task("chatgpt", email, "failed", f"[register_script] {err}", detail)

        if i < args.count - 1 and not _STOP:
            time.sleep(max(0, int(args.delay)))

    print(f"\n[register] 完成: {stats}")
    if created_emails:
        print(f"[register] 新增/更新邮箱: {created_emails}")


if __name__ == "__main__":
    main()
