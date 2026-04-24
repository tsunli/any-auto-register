#!/usr/bin/env python3
"""
批量同步已注册的 ChatGPT 账号到 CLIProxyAPI 远端状态。

默认行为：
- 只处理 platform=chatgpt
- 只同步 status in (registered, trial, subscribed)
- 默认会把同步结果写回 accounts.extra_json.sync_statuses.cliproxyapi

示例：
  python scripts/sync_chatgpt_cliproxyapi_accounts.py
  python scripts/sync_chatgpt_cliproxyapi_accounts.py --limit 50
  python scripts/sync_chatgpt_cliproxyapi_accounts.py --status registered --status invalid
  python scripts/sync_chatgpt_cliproxyapi_accounts.py --email demo@example.com --no-write-db
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable

from sqlmodel import Session, select

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.db import AccountModel, engine
from services.chatgpt_sync import (
    build_chatgpt_sync_account,
    update_account_model_cliproxy_sync,
)
from services.cliproxyapi_sync import sync_chatgpt_cliproxyapi_status_batch

DEFAULT_STATUSES = ["registered", "trial", "subscribed"]


def normalize_statuses(statuses: Iterable[str] | None, *, all_statuses: bool = False) -> list[str]:
    if all_statuses:
        return []
    seen: list[str] = []
    for item in list(statuses or []) or DEFAULT_STATUSES:
        text = str(item or "").strip().lower()
        if text and text not in seen:
            seen.append(text)
    return seen


def select_accounts(
    session: Session,
    *,
    statuses: list[str] | None = None,
    email_contains: str = "",
    limit: int = 0,
    all_statuses: bool = False,
) -> list[AccountModel]:
    q = select(AccountModel).where(AccountModel.platform == "chatgpt")
    normalized_statuses = normalize_statuses(statuses, all_statuses=all_statuses)
    if normalized_statuses:
        q = q.where(AccountModel.status.in_(normalized_statuses))
    if email_contains:
        q = q.where(AccountModel.email.contains(str(email_contains).strip()))
    q = q.order_by(AccountModel.id.asc())
    if limit and int(limit) > 0:
        q = q.limit(int(limit))
    return list(session.exec(q).all())


def sync_accounts(
    session: Session,
    accounts: list[AccountModel],
    *,
    write_db: bool = True,
    api_url: str | None = None,
    api_key: str | None = None,
) -> dict[str, object]:
    sync_accounts_payload = []
    id_to_account: dict[int, AccountModel] = {}
    for account in accounts:
        sync_obj = build_chatgpt_sync_account(account)
        sync_obj.id = account.id
        sync_accounts_payload.append(sync_obj)
        if account.id is not None:
            id_to_account[int(account.id)] = account

    result_map = sync_chatgpt_cliproxyapi_status_batch(
        sync_accounts_payload,
        api_url=api_url,
        api_key=api_key,
    )

    summary = {
        "total": len(accounts),
        "usable": 0,
        "not_found": 0,
        "unreachable": 0,
        "other": 0,
        "results": result_map,
    }

    for account_id, sync_result in result_map.items():
        remote_state = str(sync_result.get("remote_state") or "").strip().lower()
        if remote_state == "usable":
            summary["usable"] += 1
        elif remote_state == "not_found":
            summary["not_found"] += 1
        elif remote_state == "unreachable":
            summary["unreachable"] += 1
        else:
            summary["other"] += 1

        if write_db:
            account = id_to_account.get(int(account_id))
            if account is not None:
                update_account_model_cliproxy_sync(
                    account,
                    sync_result,
                    session=session,
                    commit=False,
                )

    if write_db:
        session.commit()

    return summary


def _print_summary(accounts: list[AccountModel], summary: dict[str, object]) -> None:
    print(
        "[cliproxy-sync] 完成: "
        f"total={summary['total']} usable={summary['usable']} "
        f"not_found={summary['not_found']} unreachable={summary['unreachable']} "
        f"other={summary['other']}"
    )
    result_map = summary.get("results", {})
    if not isinstance(result_map, dict):
        return
    for account in accounts:
        if account.id is None:
            continue
        sync_result = result_map.get(int(account.id), {})
        if not isinstance(sync_result, dict):
            sync_result = {}
        print(
            "[cliproxy-sync]",
            account.email,
            "status=" + str(account.status or ""),
            "remote_state=" + str(sync_result.get("remote_state") or "unknown"),
            "message=" + str(sync_result.get("message") or ""),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="批量同步 ChatGPT 账号到 CLIProxyAPI 状态")
    parser.add_argument("--status", action="append", default=[], help="要同步的账号状态，可重复；默认 registered/trial/subscribed")
    parser.add_argument("--all-statuses", action="store_true", help="忽略默认状态过滤，处理所有 chatgpt 账号")
    parser.add_argument("--email", type=str, default="", help="按邮箱模糊过滤")
    parser.add_argument("--limit", type=int, default=0, help="最多处理多少个账号（0=不限制）")
    parser.add_argument("--api-url", type=str, default="", help="覆盖 CLIProxyAPI Base URL")
    parser.add_argument("--api-key", type=str, default="", help="覆盖 CLIProxyAPI 管理 Key")
    parser.add_argument("--no-write-db", action="store_true", help="只做远端同步探测，不写回本地 accounts.extra_json")
    args = parser.parse_args()

    with Session(engine) as session:
        accounts = select_accounts(
            session,
            statuses=args.status,
            email_contains=args.email,
            limit=args.limit,
            all_statuses=args.all_statuses,
        )
        print(f"[cliproxy-sync] 命中账号数: {len(accounts)}")
        if not accounts:
            print("[cliproxy-sync] 无匹配账号，退出")
            return

        summary = sync_accounts(
            session,
            accounts,
            write_db=not args.no_write_db,
            api_url=args.api_url or None,
            api_key=args.api_key or None,
        )
        _print_summary(accounts, summary)


if __name__ == "__main__":
    main()
