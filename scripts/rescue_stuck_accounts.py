#!/usr/bin/env python3
"""
对卡在 add_phone 或未入库的 forwardmail 邮箱进行补救：
以 access_token_only 模式走 chatgpt.com 站内 email-OTP 登录，
拿到 accessToken + session_token 后写入 accounts 表。

Usage:
    python scripts/rescue_stuck_accounts.py [--limit 5] [--delay 60] [--dry-run]

- limit:   本次最多处理多少个邮箱（默认 10）
- delay:   每个邮箱之间的间隔秒数（默认 60）
- dry-run: 只列出候选邮箱，不真正发起登录
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.base_mailbox import create_mailbox
from core.base_platform import RegisterConfig
from core.config_store import config_store
from core.db import AccountModel, engine, save_account, write_task_log
from core.registry import get, load_all
from platforms.chatgpt.oauth_client import is_email_add_phone_blacklisted
from scripts.register_chatgpt_accounts import (
    _sync_saved_account_to_cliproxyapi,
    load_successfully_registered_emails,
)


_STOP = False


def _handle_sigint(_signum, _frame):
    global _STOP
    _STOP = True
    print("\n[rescue] 收到中断信号，执行完当前邮箱后停止")


signal.signal(signal.SIGINT, _handle_sigint)


def load_pool_emails(pool_path: Path) -> list[str]:
    if not pool_path.exists():
        raise FileNotFoundError(f"forwardmail 池文件不存在: {pool_path}")
    data = json.loads(pool_path.read_text(encoding="utf-8"))
    emails: list[str] = []
    for item in data:
        if isinstance(item, dict):
            email = (item.get("email") or "").strip()
        else:
            email = str(item or "").strip()
        if email and email not in emails:
            emails.append(email)
    return emails


def load_registered_emails() -> set[str]:
    return load_successfully_registered_emails()


def resolve_pool_path() -> Path:
    pool_file = (config_store.get("forwardmail_pool_file") or "").strip()
    pool_dir = (config_store.get("forwardmail_pool_dir") or "mail").strip()
    base = ROOT / pool_dir
    if pool_file:
        return base / pool_file
    candidates = sorted(base.glob("forwardmail_*.json"))
    if not candidates:
        raise FileNotFoundError(f"{base} 下未找到 forwardmail_*.json")
    return candidates[-1]


def log_task(
    platform: str,
    email: str,
    status: str,
    error: str,
    detail: dict,
    *,
    run_id: str = "",
) -> None:
    write_task_log(
        platform,
        email,
        status,
        error=error or "",
        detail=detail,
        source="rescue_script",
        run_id=run_id,
    )


def build_platform(extra: dict):
    load_all()
    PlatformCls = get("chatgpt")
    config = RegisterConfig(
        executor_type="protocol",
        captcha_solver=extra.get("default_captcha_solver") or "yescaptcha",
        proxy=None,
        extra=extra,
    )
    mailbox = create_mailbox(
        provider=extra.get("mail_provider", "forwardmail"),
        extra=extra,
        proxy=None,
    )
    return PlatformCls(config=config, mailbox=mailbox)


def rescue_one(
    email: str,
    extra: dict,
    *,
    cliproxyapi_sync: bool,
    cliproxyapi_api_url: str | None = None,
    cliproxyapi_api_key: str | None = None,
) -> tuple[bool, str, dict]:
    platform = build_platform(extra)
    platform._log_fn = lambda msg: print(f"  [log] {msg}")
    started = time.time()
    try:
        account = platform.register(email=email, password=None)
    except Exception as e:
        metadata = dict(getattr(platform, "last_error_metadata", {}) or {})
        return False, f"{type(e).__name__}: {e}", {
            "elapsed": round(time.time() - started, 1),
            "email": email or "",
            "executor_type": "protocol",
            **metadata,
        }

    token = (account.token or "").strip() if account else ""
    session_token = ""
    if account and isinstance(account.extra, dict):
        session_token = (account.extra.get("session_token") or "").strip()

    if not token and not session_token:
        return False, "register 返回空 token", {"elapsed": round(time.time() - started, 1)}

    try:
        saved_account = save_account(account)
    except Exception as e:
        return False, f"save_account 失败: {e}", {"elapsed": round(time.time() - started, 1)}

    cliproxyapi_result = {
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
            force=True,
        )

    detail = {
        "elapsed": round(time.time() - started, 1),
        "email": getattr(account, "email", "") or email or "",
        "executor_type": "protocol",
        "has_access_token": bool(token),
        "has_refresh_token": bool((account.extra or {}).get("refresh_token", "")),
        "has_session_token": bool(session_token),
        "registration_mode": (account.extra or {}).get("chatgpt_registration_mode", ""),
        "last_stage": (account.extra or {}).get("last_stage", ""),
        "stages_trace": (account.extra or {}).get("stages_trace", []),
        "error_code": (account.extra or {}).get("error_code", ""),
        "cliproxyapi_auto_sync": bool(cliproxyapi_sync),
        "cliproxyapi_sync_ok": bool(cliproxyapi_result.get("ok")),
        "cliproxyapi_uploaded": bool(cliproxyapi_result.get("uploaded")),
        "cliproxyapi_skipped": bool(cliproxyapi_result.get("skipped")),
        "cliproxyapi_remote_state": str(cliproxyapi_result.get("remote_state") or ""),
        "cliproxyapi_message": str(cliproxyapi_result.get("message") or ""),
    }
    return True, "", detail


def main():
    parser = argparse.ArgumentParser(description="批量补救 ChatGPT 卡 add_phone / 未入库邮箱")
    parser.add_argument("--limit", type=int, default=10, help="最多处理邮箱数（默认 10）")
    parser.add_argument("--delay", type=int, default=60, help="邮箱间隔秒数（默认 60）")
    parser.add_argument("--dry-run", action="store_true", help="只打印候选不执行")
    parser.add_argument("--pool", type=str, default="", help="指定 forwardmail 池文件路径")
    parser.add_argument("--no-cliproxyapi-sync", action="store_true", help="补救成功后不自动同步到 CLIProxyAPI")
    parser.add_argument("--cliproxyapi-api-url", type=str, default="", help="覆盖 CLIProxyAPI Base URL")
    parser.add_argument("--cliproxyapi-api-key", type=str, default="", help="覆盖 CLIProxyAPI 管理 Key")
    args = parser.parse_args()

    extra = config_store.get_all().copy()
    extra["chatgpt_registration_mode"] = "access_token_only"
    extra.setdefault("mail_provider", "forwardmail")
    cliproxyapi_sync = not args.no_cliproxyapi_sync
    cliproxyapi_api_url = args.cliproxyapi_api_url.strip() or None
    cliproxyapi_api_key = args.cliproxyapi_api_key.strip() or None

    pool_path = Path(args.pool) if args.pool else resolve_pool_path()
    print(f"[rescue] 使用 forwardmail 池: {pool_path}")

    pool_emails = load_pool_emails(pool_path)
    registered = load_registered_emails()
    pre_filter = [e for e in pool_emails if e.lower() not in registered]
    candidates = [e for e in pre_filter if not is_email_add_phone_blacklisted(e)]
    blacklisted_count = len(pre_filter) - len(candidates)

    print(
        f"[rescue] 池内邮箱: {len(pool_emails)} | 已入库: {len(pool_emails) - len(pre_filter)} "
        f"| 黑名单: {blacklisted_count} | 待补救: {len(candidates)}"
    )

    if args.dry_run:
        for e in candidates[: args.limit]:
            print(f"  - {e}")
        return

    if not candidates:
        print("[rescue] 无待补救邮箱，退出")
        return

    to_process = candidates[: args.limit]
    run_id = f"rescue-{int(time.time())}"
    print(
        f"[rescue] 本次处理 {len(to_process)} 个，间隔 {args.delay}s "
        f"cliproxyapi_sync={'on' if cliproxyapi_sync else 'off'}"
    )

    stats = {"ok": 0, "fail": 0}
    for idx, email in enumerate(to_process, 1):
        if _STOP:
            print("[rescue] 已中断")
            break
        print(f"\n[rescue] ({idx}/{len(to_process)}) {email}")
        ok, err, detail = rescue_one(
            email,
            extra,
            cliproxyapi_sync=cliproxyapi_sync,
            cliproxyapi_api_url=cliproxyapi_api_url,
            cliproxyapi_api_key=cliproxyapi_api_key,
        )
        if ok:
            stats["ok"] += 1
            print(f"  ✅ 成功 (elapsed={detail.get('elapsed')}s)")
            if detail.get("cliproxyapi_auto_sync"):
                sync_state = detail.get("cliproxyapi_remote_state") or "unknown"
                sync_msg = detail.get("cliproxyapi_message") or "no message"
                prefix = "  [cliproxyapi] ✅" if detail.get("cliproxyapi_sync_ok") else "  [cliproxyapi] ⚠️"
                print(f"{prefix} remote_state={sync_state} message={sync_msg}")
            log_task(
                "chatgpt",
                email,
                "success",
                "",
                {
                    **detail,
                    "registration_mode": detail.get("registration_mode", ""),
                },
                run_id=run_id,
            )
        else:
            stats["fail"] += 1
            print(f"  ❌ 失败: {err}")
            log_task(
                "chatgpt",
                email,
                "failed",
                f"[rescue] {err}",
                {
                    **detail,
                    "registration_mode": detail.get("registration_mode", ""),
                },
                run_id=run_id,
            )

        if idx < len(to_process) and not _STOP:
            time.sleep(args.delay)

    print(f"\n[rescue] 完成: {stats}")


if __name__ == "__main__":
    main()
