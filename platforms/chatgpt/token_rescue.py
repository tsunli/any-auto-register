"""ChatGPT refresh_token 补救工具（供 register 和 rescue 脚本复用）。"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from sqlmodel import Session

from core.base_mailbox import MailboxAccount, create_mailbox
from core.db import AccountModel, engine
from platforms.chatgpt.constants import OAUTH_CLIENT_ID
from platforms.chatgpt.oauth_client import OAuthClient
from platforms.chatgpt.refresh_token_registration_engine import EmailServiceAdapter


class ExistingEmailService:
    """针对既有邮箱的轻量邮箱服务 —— 不创建新邮箱，只接收指定邮箱的 OTP。"""

    def __init__(self, mailbox, email: str, provider: str, log_fn):
        self._mailbox = mailbox
        self._email = email
        self._provider = provider
        self._log = log_fn
        self._account = MailboxAccount(
            email=email,
            account_id=email,
            extra={"provider": provider, "rescue": True},
        )
        self._before_ids: set = set()
        try:
            getter = getattr(mailbox, "get_current_ids", None)
            if callable(getter):
                self._before_ids = set(getter(self._account) or [])
        except Exception as exc:
            self._log(f"[mailbox] 获取基线邮件 ID 失败（可忽略）: {exc}")
        self.service_type = type("ST", (), {"value": provider})()

    def create_email(self, config=None):
        return {"email": self._email, "service_id": self._email, "token": ""}

    def get_verification_code(
        self,
        email: str | None = None,
        email_id=None,
        timeout: int = 120,
        pattern=None,
        otp_sent_at=None,
        exclude_codes=None,
    ):
        target = str(email or self._email).strip()
        if target and target.lower() != self._email.lower():
            self._log(f"[mailbox] 告警：OTP 目标邮箱与预期不一致 ({target} ≠ {self._email})")
        return self._mailbox.wait_for_code(
            self._account,
            keyword="",
            timeout=int(timeout or 120),
            before_ids=set(self._before_ids),
            otp_sent_at=otp_sent_at,
            exclude_codes=exclude_codes,
        )

    def update_status(self, success, error=None):
        pass


def try_rescue_refresh_token(
    row: AccountModel,
    *,
    global_config: dict,
    proxy: str | None,
    browser_mode: str,
    otp_timeout: int,
    logger,
) -> tuple[bool, str, dict[str, Any]]:
    """对已入库账号走 Codex OAuth 登录链路，补写 refresh_token 并更新 DB。

    Returns:
        (ok, error_message, detail_dict)
    """
    started = time.time()

    extra_before: dict = {}
    try:
        value = json.loads(row.extra_json or "{}")
        extra_before = value if isinstance(value, dict) else {}
    except Exception:
        pass

    email = (row.email or "").strip()
    password = (row.password or "").strip() or "AAb1234567890!"
    provider = str(
        extra_before.get("mail_provider") or global_config.get("mail_provider") or "forwardmail"
    ).strip()
    merged_config = {**global_config, **extra_before, "mailbox_otp_timeout_seconds": otp_timeout}

    logger(f"构造邮箱收件器: provider={provider}")
    try:
        mailbox = create_mailbox(provider=provider, extra=merged_config, proxy=proxy)
        mailbox._log_fn = lambda msg: logger(f"[mailbox] {msg}")
    except Exception as exc:
        return False, f"create_mailbox 失败: {exc}", {"elapsed": round(time.time() - started, 1)}

    email_service = ExistingEmailService(mailbox, email, provider, logger)
    email_adapter = EmailServiceAdapter(email_service, email, logger)

    logger("启动 OAuth 登录链路（passwordless OTP, 不走 add_phone）...")
    oauth_client = OAuthClient(merged_config, proxy=proxy, verbose=False, browser_mode=browser_mode)
    oauth_client._log = lambda msg: logger(f"[oauth] {msg}")

    try:
        tokens = oauth_client.login_and_get_tokens(
            email,
            password,
            device_id="",
            skymail_client=email_adapter,
            prefer_passwordless_login=True,
            allow_phone_verification=False,
            force_new_browser=True,
            force_chatgpt_entry=False,
            screen_hint="login",
            force_password_login=False,
            complete_about_you_if_needed=False,
            login_source="token_rescue",
        )
    except Exception as exc:
        return False, f"login_and_get_tokens 异常: {type(exc).__name__}: {exc}", {
            "elapsed": round(time.time() - started, 1),
            "last_stage": getattr(oauth_client, "last_stage", ""),
            "stages_trace": list(getattr(oauth_client, "stage_trace", []) or []),
        }

    if not tokens:
        return False, oauth_client.last_error or "OAuth 登录失败（未拿到 tokens）", {
            "elapsed": round(time.time() - started, 1),
            "last_stage": getattr(oauth_client, "last_stage", ""),
            "stages_trace": list(getattr(oauth_client, "stage_trace", []) or []),
            "error_code": str(getattr(oauth_client, "last_error_code", "") or "").strip(),
        }

    access_token = str(tokens.get("access_token") or "").strip()
    refresh_token = str(tokens.get("refresh_token") or "").strip()
    id_token = str(tokens.get("id_token") or "").strip()

    if not refresh_token:
        return False, "OAuth 返回结果中仍无 refresh_token（scope 可能被服务端降级）", {
            "elapsed": round(time.time() - started, 1),
            "has_access_token": bool(access_token),
            "has_id_token": bool(id_token),
            "last_stage": getattr(oauth_client, "last_stage", ""),
            "stages_trace": list(getattr(oauth_client, "stage_trace", []) or []),
        }

    session_token = _extract_session_token(oauth_client)
    workspace_id = _extract_workspace_id(oauth_client)

    now_iso = datetime.now(timezone.utc).isoformat()
    updated_extra = {
        **extra_before,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "id_token": id_token or extra_before.get("id_token", ""),
        "session_token": session_token or extra_before.get("session_token", ""),
        "workspace_id": workspace_id or extra_before.get("workspace_id", ""),
        "client_id": OAUTH_CLIENT_ID,
        "chatgpt_registration_mode": "refresh_token",
        "chatgpt_has_refresh_token_solution": True,
        "chatgpt_token_source": "access_token_only_rescue",
        "mail_provider": provider,
        "rescue_access_token_only": {
            "rescued_at": now_iso,
            "previous_registration_mode": extra_before.get("chatgpt_registration_mode", ""),
            "previous_client_id": extra_before.get("client_id", ""),
            "last_stage": getattr(oauth_client, "last_stage", ""),
            "stages_trace": list(getattr(oauth_client, "stage_trace", []) or []),
        },
    }

    saved_account_id: int | None = None
    try:
        with Session(engine) as session:
            db_row = session.get(AccountModel, row.id)
            if db_row is None:
                return False, f"账号落库记录已消失: id={row.id}", {
                    "elapsed": round(time.time() - started, 1)
                }
            db_row.extra_json = json.dumps(updated_extra, ensure_ascii=False)
            db_row.token = access_token
            db_row.updated_at = datetime.now(timezone.utc)
            session.add(db_row)
            session.commit()
            session.refresh(db_row)
            saved_account_id = db_row.id
    except Exception as exc:
        return False, f"写回 DB 失败: {exc}", {"elapsed": round(time.time() - started, 1)}

    return True, "", {
        "elapsed": round(time.time() - started, 1),
        "account_id": saved_account_id,
        "email": email,
        "has_access_token": True,
        "has_refresh_token": True,
        "has_session_token": bool(session_token),
        "workspace_id": workspace_id,
        "client_id": OAUTH_CLIENT_ID,
        "last_stage": getattr(oauth_client, "last_stage", ""),
        "stages_trace": list(getattr(oauth_client, "stage_trace", []) or []),
        "registration_mode": "refresh_token",
        "token_flow": "oauth_client.login_and_get_tokens",
    }


def _extract_session_token(oauth_client: OAuthClient) -> str:
    getter = getattr(oauth_client, "_get_cookie_value", None)
    if not callable(getter):
        return ""
    return str(
        getter("__Secure-next-auth.session-token", "chatgpt.com")
        or getter("__Secure-authjs.session-token", "chatgpt.com")
        or ""
    ).strip()


def _extract_workspace_id(oauth_client: OAuthClient) -> str:
    wid = str(getattr(oauth_client, "last_workspace_id", "") or "").strip()
    if wid:
        return wid
    try:
        data = oauth_client._decode_oauth_session_cookie() or {}
    except Exception:
        data = {}
    workspaces = data.get("workspaces") or []
    if not workspaces:
        return ""
    return str((workspaces[0] or {}).get("id") or "").strip()
