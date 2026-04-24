"""数据库模型 - SQLite via SQLModel"""
from datetime import datetime, timezone
import os
import re
from typing import Optional
from sqlmodel import Field, SQLModel, create_engine, Session, select
import json


def _utcnow():
    return datetime.now(timezone.utc)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///account_manager.db")
engine = create_engine(DATABASE_URL)


class AccountModel(SQLModel, table=True):
    __tablename__ = "accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    platform: str = Field(index=True)
    email: str = Field(index=True)
    password: str
    user_id: str = ""
    region: str = ""
    token: str = ""
    status: str = "registered"
    trial_end_time: int = 0
    cashier_url: str = ""
    extra_json: str = "{}"   # JSON 存储平台自定义字段
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    def get_extra(self) -> dict:
        return json.loads(self.extra_json or "{}")

    def set_extra(self, d: dict):
        self.extra_json = json.dumps(d, ensure_ascii=False)


class TaskLog(SQLModel, table=True):
    __tablename__ = "task_logs"

    id: Optional[int] = Field(default=None, primary_key=True)
    platform: str
    email: str
    status: str        # success | failed
    error: str = ""
    detail_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow)


class OutlookAccountModel(SQLModel, table=True):
    __tablename__ = "outlook_accounts"

    id: Optional[int] = Field(default=None, primary_key=True)
    email: str = Field(index=True, sa_column_kwargs={"unique": True})
    password: str
    client_id: str = ""
    refresh_token: str = ""
    enabled: bool = True
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    last_used: Optional[datetime] = None


class ProxyModel(SQLModel, table=True):
    __tablename__ = "proxies"

    id: Optional[int] = Field(default=None, primary_key=True)
    url: str = Field(unique=True)
    region: str = ""
    success_count: int = 0
    fail_count: int = 0
    is_active: bool = True
    last_checked: Optional[datetime] = None


def _extract_stage_from_error(error: str) -> str:
    text = str(error or "").strip()
    if not text:
        return ""
    match = re.search(r"\[stage=([^\]]+)\]", text)
    if not match:
        return ""
    return str(match.group(1) or "").strip()


def build_task_log_detail(
    detail: dict | None = None,
    *,
    task_id: str = "",
    run_id: str = "",
    source: str = "",
    error: str = "",
) -> dict:
    payload = dict(detail or {})
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        for key in (
            "last_stage",
            "stages_trace",
            "registration_flow",
            "token_flow",
            "error_code",
            "run_id",
        ):
            if key not in payload and key in metadata:
                payload[key] = metadata[key]

    registration_mode = str(
        payload.get("registration_mode") or payload.get("mode") or ""
    ).strip()
    payload["registration_mode"] = registration_mode
    payload["mode"] = registration_mode

    payload["task_id"] = str(task_id or payload.get("task_id") or "").strip()
    payload["run_id"] = str(
        run_id or payload.get("run_id") or payload["task_id"] or ""
    ).strip()
    payload["source"] = str(source or payload.get("source") or "").strip()
    payload["executor_type"] = str(payload.get("executor_type") or "").strip()
    payload["proxy"] = str(payload.get("proxy") or "").strip()
    payload["error_code"] = str(payload.get("error_code") or "").strip()

    if "elapsed_ms" not in payload:
        elapsed_seconds = payload.get("elapsed")
        try:
            payload["elapsed_ms"] = int(float(elapsed_seconds) * 1000)
        except (TypeError, ValueError):
            payload["elapsed_ms"] = 0
    else:
        try:
            payload["elapsed_ms"] = int(payload.get("elapsed_ms") or 0)
        except (TypeError, ValueError):
            payload["elapsed_ms"] = 0

    stages_trace = payload.get("stages_trace") or []
    if isinstance(stages_trace, str):
        stages_trace = [stages_trace] if stages_trace.strip() else []
    elif not isinstance(stages_trace, list):
        stages_trace = list(stages_trace) if stages_trace else []
    stages_trace = [str(item).strip() for item in stages_trace if str(item).strip()]

    last_stage = str(payload.get("last_stage") or "").strip()
    if not last_stage:
        last_stage = _extract_stage_from_error(error)
    if not last_stage and stages_trace:
        last_stage = stages_trace[-1]
    if last_stage and not stages_trace:
        stages_trace = [last_stage]
    payload["last_stage"] = last_stage
    payload["stages_trace"] = stages_trace

    for token_field in (
        "has_access_token",
        "has_refresh_token",
        "has_session_token",
    ):
        payload[token_field] = bool(payload.get(token_field, False))

    return payload


def write_task_log(
    platform: str,
    email: str,
    status: str,
    *,
    error: str = "",
    detail: dict | None = None,
    task_id: str = "",
    run_id: str = "",
    source: str = "",
    created_at: datetime | None = None,
) -> TaskLog:
    normalized_detail = build_task_log_detail(
        detail,
        task_id=task_id,
        run_id=run_id,
        source=source,
        error=error,
    )
    if not normalized_detail.get("stage"):
        normalized_detail["stage"] = str(status or "").strip()

    with Session(engine) as session:
        log = TaskLog(
            platform=platform,
            email=email or "",
            status=status,
            error=error or "",
            detail_json=json.dumps(normalized_detail, ensure_ascii=False),
            created_at=created_at or _utcnow(),
        )
        session.add(log)
        session.commit()
        session.refresh(log)
        return log


def save_account(account) -> 'AccountModel':
    """从 base_platform.Account 存入数据库（同平台同邮箱则更新）"""
    with Session(engine) as session:
        existing = session.exec(
            select(AccountModel)
            .where(AccountModel.platform == account.platform)
            .where(AccountModel.email == account.email)
        ).first()
        if existing:
            existing.password = account.password
            existing.user_id = account.user_id or ""
            existing.region = account.region or ""
            existing.token = account.token or ""
            existing.status = account.status.value
            existing.extra_json = json.dumps(account.extra or {}, ensure_ascii=False)
            existing.cashier_url = (account.extra or {}).get("cashier_url", "")
            existing.updated_at = _utcnow()
            session.add(existing)
            session.commit()
            session.refresh(existing)
            return existing
        m = AccountModel(
            platform=account.platform,
            email=account.email,
            password=account.password,
            user_id=account.user_id or "",
            region=account.region or "",
            token=account.token or "",
            status=account.status.value,
            extra_json=json.dumps(account.extra or {}, ensure_ascii=False),
            cashier_url=(account.extra or {}).get("cashier_url", ""),
        )
        session.add(m)
        session.commit()
        session.refresh(m)
        return m


def init_db():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
