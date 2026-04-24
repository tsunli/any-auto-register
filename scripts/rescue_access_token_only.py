#!/usr/bin/env python3
"""
补齐 access_token_only 模式 ChatGPT 账号的 refresh_token。

背景：
    AccessTokenOnlyRegistrationEngine 通过复用注册会话调 /api/auth/session
    获取的 accessToken 走的是 ChatGPT Web 端 NextAuth Session（client_id=app_X8zY6vW2pQ9tR3dE7nK1jL5gH），
    没有 offline_access scope，因此协议层面不会下发 refresh_token。
    要为这类账号补齐 refresh_token，只能重新走一次 Codex OAuth 授权码流程（client_id=app_EMoamEEZ73f0CkXaXp7hrann）：
        /oauth/authorize (scope=openid profile email offline_access) → email OTP 登录 → POST /oauth/token

本脚本对 accounts 表中 platform=chatgpt 且 refresh_token 为空的账号批量执行：
    1. 读邮箱 + 现有 extra
    2. 构造邮箱收件器 + EmailServiceAdapter
    3. 调 OAuthClient.login_and_get_tokens(passwordless=True, allow_phone_verification=False)
    4. 把 access_token / refresh_token / id_token / session_token / workspace_id / client_id 写回 extra_json
    5. 重新同步到 CLIProxyAPI

Usage:
    python scripts/rescue_access_token_only.py [--limit N] [--delay 60] [--dry-run]
                                               [--id 30] [--email xxx@icloud.com]
                                               [--no-cliproxyapi-sync]
                                               [--proxy http://user:pass@host:port]
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
import time
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlmodel import Session, select

from core.config_store import config_store
from core.db import AccountModel, engine, write_task_log
from platforms.chatgpt.token_rescue import try_rescue_refresh_token
from scripts.register_chatgpt_accounts import _sync_saved_account_to_cliproxyapi


_STOP = False


def _handle_sigint(_signum, _frame):
    global _STOP
    _STOP = True
    print("\n[rescue-at] 收到中断信号，完成当前账号后退出")


signal.signal(signal.SIGINT, _handle_sigint)


# ─────────────────────────────── Core Rescue ────────────────────────────── #

def _parse_extra(extra_json: str) -> dict:
    try:
        value = json.loads(extra_json or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _needs_rescue(extra: dict) -> bool:
    access = str(extra.get("access_token") or "").strip()
    refresh = str(extra.get("refresh_token") or "").strip()
    return bool(access) and not refresh


def _query_candidates(
    *,
    only_id: int | None,
    only_email: str | None,
) -> list[AccountModel]:
    with Session(engine) as session:
        stmt = select(AccountModel).where(AccountModel.platform == "chatgpt")
        if only_id:
            stmt = stmt.where(AccountModel.id == only_id)
        if only_email:
            stmt = stmt.where(AccountModel.email == only_email)
        rows = list(session.exec(stmt.order_by(AccountModel.id)))
    return [r for r in rows if _needs_rescue(_parse_extra(r.extra_json))]


def rescue_one(
    row: AccountModel,
    *,
    global_config: dict,
    proxy: str | None,
    browser_mode: str,
    otp_timeout: int,
    logger,
) -> tuple[bool, str, dict]:
    if not _needs_rescue(_parse_extra(row.extra_json)):
        return False, "已有 refresh_token，跳过", {
            "elapsed": 0.0,
            "skip_reason": "already_has_refresh_token",
        }
    return try_rescue_refresh_token(
        row,
        global_config=global_config,
        proxy=proxy,
        browser_mode=browser_mode,
        otp_timeout=otp_timeout,
        logger=logger,
    )


# ─────────────────────────────── CLI Entry ─────────────────────────────── #

def _resolve_proxy(cli_proxy: str | None, global_config: dict) -> str | None:
    if cli_proxy:
        return cli_proxy.strip() or None
    value = str(global_config.get("proxy") or "").strip()
    return value or None


def main() -> int:
    parser = argparse.ArgumentParser(description="补齐 access_token_only 账号的 refresh_token")
    parser.add_argument("--limit", type=int, default=0, help="最多处理账号数（0 表示全部）")
    parser.add_argument("--delay", type=int, default=60, help="账号之间间隔秒数（默认 60）")
    parser.add_argument("--dry-run", action="store_true", help="只列候选账号，不执行")
    parser.add_argument("--id", dest="only_id", type=int, default=0, help="只处理指定账号 id")
    parser.add_argument("--email", dest="only_email", type=str, default="", help="只处理指定邮箱")
    parser.add_argument("--proxy", type=str, default="", help="覆盖代理 URL（默认读 config_store.proxy）")
    parser.add_argument("--browser-mode", type=str, default="protocol", help="浏览器模式，默认 protocol")
    parser.add_argument("--otp-timeout", type=int, default=300, help="OTP 等待超时秒数（默认 300）")
    parser.add_argument("--no-cliproxyapi-sync", action="store_true", help="成功后不同步到 CLIProxyAPI")
    parser.add_argument("--cliproxyapi-api-url", type=str, default="", help="覆盖 CLIProxyAPI Base URL")
    parser.add_argument("--cliproxyapi-api-key", type=str, default="", help="覆盖 CLIProxyAPI 管理 Key")
    args = parser.parse_args()

    global_config = dict(config_store.get_all() or {})
    proxy = _resolve_proxy(args.proxy or None, global_config)
    cliproxyapi_sync = not args.no_cliproxyapi_sync
    cliproxyapi_api_url = args.cliproxyapi_api_url.strip() or None
    cliproxyapi_api_key = args.cliproxyapi_api_key.strip() or None

    candidates = _query_candidates(
        only_id=int(args.only_id) if args.only_id else None,
        only_email=args.only_email.strip() or None,
    )
    print(f"[rescue-at] 候选账号数: {len(candidates)}")
    for row in candidates:
        print(f"  - id={row.id} email={row.email} created={row.created_at}")

    if args.dry_run or not candidates:
        return 0

    to_process = candidates if args.limit <= 0 else candidates[: args.limit]
    run_id = f"rescue-at-{uuid.uuid4().hex[:8]}-{int(time.time())}"
    print(
        f"[rescue-at] 本次处理 {len(to_process)} 个，间隔 {args.delay}s "
        f"browser_mode={args.browser_mode} proxy={'on' if proxy else 'off'} "
        f"cliproxyapi_sync={'on' if cliproxyapi_sync else 'off'} run_id={run_id}"
    )

    stats = {"ok": 0, "fail": 0, "skipped": 0}
    for idx, row in enumerate(to_process, 1):
        if _STOP:
            print("[rescue-at] 已中断，停止处理剩余账号")
            break

        header = f"({idx}/{len(to_process)}) id={row.id} email={row.email}"
        print(f"\n[rescue-at] {header}")

        def _log(msg: str):
            print(f"  [log] {msg}")

        ok, err, detail = rescue_one(
            row,
            global_config=global_config,
            proxy=proxy,
            browser_mode=args.browser_mode,
            otp_timeout=args.otp_timeout,
            logger=_log,
        )

        if ok:
            stats["ok"] += 1
            print(
                f"  ✅ 补齐成功 elapsed={detail.get('elapsed')}s "
                f"workspace={detail.get('workspace_id') or '-'}"
            )
            if cliproxyapi_sync and detail.get("account_id"):
                sync_result = _sync_saved_account_to_cliproxyapi(
                    int(detail["account_id"]),
                    api_url=cliproxyapi_api_url,
                    api_key=cliproxyapi_api_key,
                    force=True,
                )
                detail["cliproxyapi_sync_ok"] = bool(sync_result.get("ok"))
                detail["cliproxyapi_uploaded"] = bool(sync_result.get("uploaded"))
                detail["cliproxyapi_skipped"] = bool(sync_result.get("skipped"))
                detail["cliproxyapi_remote_state"] = str(sync_result.get("remote_state") or "")
                detail["cliproxyapi_message"] = str(sync_result.get("message") or "")
                prefix = "  [cliproxyapi] ✅" if sync_result.get("ok") else "  [cliproxyapi] ⚠️"
                print(
                    f"{prefix} remote_state={detail['cliproxyapi_remote_state'] or 'unknown'} "
                    f"message={detail['cliproxyapi_message'] or 'no message'}"
                )

            write_task_log(
                "chatgpt",
                row.email,
                "success",
                error="",
                detail=detail,
                source="rescue_access_token_only",
                run_id=run_id,
            )
        else:
            if detail.get("skip_reason") == "already_has_refresh_token":
                stats["skipped"] += 1
                print(f"  ⏭️  跳过: {err}")
            else:
                stats["fail"] += 1
                print(f"  ❌ 失败: {err}")
            write_task_log(
                "chatgpt",
                row.email,
                "failed" if detail.get("skip_reason") != "already_has_refresh_token" else "skipped",
                error=f"[rescue-at] {err}",
                detail=detail,
                source="rescue_access_token_only",
                run_id=run_id,
            )

        if idx < len(to_process) and not _STOP:
            time.sleep(args.delay)

    print(f"\n[rescue-at] 完成统计: {stats}")
    return 0 if stats["fail"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
