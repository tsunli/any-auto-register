"""ChatGPT 注册模式适配器。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, replace
import time
from typing import Callable, Optional

from core.base_platform import Account, AccountStatus
from core.task_runtime import SkipCurrentAttemptRequested, TaskInterruption

CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN = "refresh_token"
CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY = "access_token_only"
DEFAULT_CHATGPT_REGISTRATION_MODE = CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN


def normalize_chatgpt_registration_mode(value) -> str:
    normalized = str(value or "").strip().lower().replace("-", "_")
    if normalized in {
        CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
        "access_token",
        "at_only",
        "without_rt",
        "without_refresh_token",
        "no_rt",
        "0",
        "false",
    }:
        return CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY
    if normalized in {
        CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
        "rt",
        "with_rt",
        "has_rt",
        "1",
        "true",
    }:
        return CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN
    return DEFAULT_CHATGPT_REGISTRATION_MODE


def resolve_chatgpt_registration_mode(extra: Optional[dict]) -> str:
    extra = extra or {}
    if "chatgpt_registration_mode" in extra:
        return normalize_chatgpt_registration_mode(extra.get("chatgpt_registration_mode"))
    if "chatgpt_has_refresh_token_solution" in extra:
        return (
            CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN
            if bool(extra.get("chatgpt_has_refresh_token_solution"))
            else CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY
        )
    return DEFAULT_CHATGPT_REGISTRATION_MODE


@dataclass(frozen=True)
class ChatGPTRegistrationContext:
    email_service: object
    proxy_url: Optional[str]
    callback_logger: Callable[[str], None]
    email: Optional[str]
    password: Optional[str]
    browser_mode: str
    max_retries: int
    extra_config: dict


class BaseChatGPTRegistrationModeAdapter(ABC):
    mode: str

    @abstractmethod
    def _create_engine(self, context: ChatGPTRegistrationContext):
        """按模式构造底层注册引擎。"""

    def run(self, context: ChatGPTRegistrationContext):
        engine = self._create_engine(context)
        if context.email is not None:
            engine.email = context.email
        if context.password is not None:
            engine.password = context.password
        try:
            return engine.run()
        except TaskInterruption:
            self.last_error_metadata = dict(
                getattr(engine, "last_error_metadata", {}) or {}
            )
            raise

    def build_account(self, result, fallback_password: str) -> Account:
        return Account(
            platform="chatgpt",
            email=getattr(result, "email", ""),
            password=getattr(result, "password", "") or fallback_password,
            user_id=getattr(result, "account_id", ""),
            token=getattr(result, "access_token", ""),
            status=AccountStatus.REGISTERED,
            extra=self._build_account_extra(result),
        )

    def _build_account_extra(self, result) -> dict:
        resolved_mode = normalize_chatgpt_registration_mode(
            getattr(
                result,
                "registration_mode",
                getattr(result, "chatgpt_registration_mode", self.mode),
            )
        )
        payload = {
            "access_token": getattr(result, "access_token", ""),
            "refresh_token": getattr(result, "refresh_token", ""),
            "id_token": getattr(result, "id_token", ""),
            "session_token": getattr(result, "session_token", ""),
            "workspace_id": getattr(result, "workspace_id", ""),
            "chatgpt_registration_mode": resolved_mode,
            "chatgpt_has_refresh_token_solution": resolved_mode == CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
            "chatgpt_token_source": getattr(result, "source", "register"),
        }
        metadata = getattr(result, "metadata", None)
        if isinstance(metadata, dict):
            for key in (
                "last_stage",
                "stages_trace",
                "registration_flow",
                "token_flow",
                "error_code",
                "run_id",
            ):
                if key in metadata:
                    payload[key] = metadata.get(key)
        return payload


class RefreshTokenChatGPTRegistrationAdapter(BaseChatGPTRegistrationModeAdapter):
    mode = CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN
    _ADD_PHONE_ERROR_CODES = {
        "add_phone_workspace_or_callback_missing",
        "add_phone_verification_failed",
        "add_phone_send_failed",
        "add_phone_state_unexpected",
        "add_phone_config_code_invalid",
        "add_phone_config_code_missing",
        "add_phone_capability_missing",
    }
    _ADD_PHONE_MARKERS = (
        "add_phone",
        "add-phone",
        "passwordless 登录后仍停留在 add_phone",
    )

    def _create_engine(self, context: ChatGPTRegistrationContext):
        from platforms.chatgpt.refresh_token_registration_engine import RefreshTokenRegistrationEngine

        extra_config = dict(context.extra_config or {})
        extra_config.setdefault(
            "chatgpt_defer_add_phone_blacklist_for_at_fallback",
            True,
        )
        return RefreshTokenRegistrationEngine(
            email_service=context.email_service,
            proxy_url=context.proxy_url,
            callback_logger=context.callback_logger,
            browser_mode=context.browser_mode,
            max_retries=context.max_retries,
            extra_config=extra_config,
        )

    @staticmethod
    def _result_failed(result) -> bool:
        return not bool(result) or not bool(getattr(result, "success", False))

    @staticmethod
    def _result_error_message(result) -> str:
        return str(getattr(result, "error_message", "") or "").strip()

    @staticmethod
    def _mark_result_mode(result, mode: str):
        if result is not None:
            setattr(result, "registration_mode", mode)
        return result

    @staticmethod
    def _result_metadata(result) -> dict:
        metadata = getattr(result, "metadata", None)
        return metadata if isinstance(metadata, dict) else {}

    @classmethod
    def _result_error_code(cls, result) -> str:
        metadata = cls._result_metadata(result)
        return str(metadata.get("error_code") or "").strip()

    @classmethod
    def _is_add_phone_failure(cls, result, error_message: str) -> bool:
        error_code = cls._result_error_code(result).lower()
        if error_code in cls._ADD_PHONE_ERROR_CODES:
            return True
        text = " ".join(
            filter(
                None,
                [
                    str(error_message or "").strip(),
                    cls._result_error_message(result),
                    error_code,
                ],
            )
        ).lower()
        return any(marker in text for marker in cls._ADD_PHONE_MARKERS)

    @staticmethod
    def _read_bool_config(extra: Optional[dict], key: str, *, default: bool) -> bool:
        if not isinstance(extra, dict) or key not in extra:
            return default
        value = extra.get(key)
        if isinstance(value, bool):
            return value
        text = str(value or "").strip().lower()
        if text in {"1", "true", "yes", "on"}:
            return True
        if text in {"0", "false", "no", "off"}:
            return False
        return default

    @staticmethod
    def _read_int_config(
        extra: Optional[dict],
        key: str,
        *,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        if isinstance(extra, dict) and key in extra:
            try:
                parsed = int(extra.get(key))
                return max(minimum, min(parsed, maximum))
            except Exception:
                pass
        return max(minimum, min(default, maximum))

    @staticmethod
    def _fallback_email_from_result(primary_result, context: ChatGPTRegistrationContext) -> str:
        return str(
            getattr(primary_result, "email", "")
            or context.email
            or ""
        ).strip()

    @staticmethod
    def _fallback_password_from_result(primary_result, context: ChatGPTRegistrationContext) -> str:
        return str(
            getattr(primary_result, "password", "")
            or context.password
            or ""
        ).strip()

    def _build_access_token_only_context(
        self,
        context: ChatGPTRegistrationContext,
        primary_result,
    ) -> ChatGPTRegistrationContext:
        fallback_extra = dict(context.extra_config or {})
        fallback_extra["chatgpt_reuse_generated_email"] = True
        fallback_extra["chatgpt_defer_add_phone_blacklist_for_at_fallback"] = False
        return replace(
            context,
            email=self._fallback_email_from_result(primary_result, context) or None,
            password=self._fallback_password_from_result(primary_result, context) or None,
            extra_config=fallback_extra,
        )

    @staticmethod
    def _compose_add_phone_reason(*messages: str) -> str:
        seen: list[str] = []
        for message in messages:
            text = str(message or "").strip()
            if text and text not in seen:
                seen.append(text)
        return " ; ".join(seen)

    def run(self, context: ChatGPTRegistrationContext):
        primary_result = None
        primary_error = ""
        try:
            primary_result = super().run(context)
        except TaskInterruption:
            raise
        except Exception as exc:
            primary_error = f"{type(exc).__name__}: {exc}"

        if not self._result_failed(primary_result):
            return self._mark_result_mode(
                primary_result,
                CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
            )

        if not primary_error:
            primary_error = self._result_error_message(primary_result)

        should_add_phone_fallback = self._is_add_phone_failure(
            primary_result,
            primary_error,
        ) and self._read_bool_config(
            context.extra_config,
            "chatgpt_add_phone_at_fallback_enabled",
            default=True,
        )

        if context.callback_logger:
            reason = primary_error or "未知错误"
            if should_add_phone_fallback:
                context.callback_logger(
                    f"codex auth 命中 add_phone 风控，准备延迟后回退 access_token_only: {reason}"
                )
            else:
                context.callback_logger(
                    f"codex auth 注册失败，回退 access_token_only 模式: {reason}"
                )

        fallback_context = context
        if should_add_phone_fallback:
            fallback_delay_seconds = self._read_int_config(
                context.extra_config,
                "chatgpt_add_phone_at_fallback_delay_seconds",
                default=30,
                minimum=0,
                maximum=600,
            )
            if context.callback_logger and fallback_delay_seconds > 0:
                context.callback_logger(
                    f"add_phone 风控延迟 {fallback_delay_seconds}s 后尝试 access_token_only"
                )
            if fallback_delay_seconds > 0:
                time.sleep(fallback_delay_seconds)
            fallback_context = self._build_access_token_only_context(context, primary_result)
            if context.callback_logger:
                fallback_email = (
                    self._fallback_email_from_result(primary_result, fallback_context)
                    or "-"
                )
                context.callback_logger(
                    f"开始 access_token_only 兜底: email={fallback_email}"
                )

        fallback_result = None
        fallback_error = ""
        try:
            fallback_adapter = AccessTokenOnlyChatGPTRegistrationAdapter()
            fallback_result = fallback_adapter.run(fallback_context)
        except TaskInterruption:
            raise
        except Exception as exc:
            fallback_error = f"{type(exc).__name__}: {exc}"

        if not self._result_failed(fallback_result):
            if context.callback_logger:
                fallback_email = (
                    self._fallback_email_from_result(fallback_result, fallback_context)
                    or "-"
                )
                context.callback_logger(
                    f"access_token_only 兜底成功: email={fallback_email}"
                )
            return self._mark_result_mode(
                fallback_result,
                CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
            )

        if not fallback_error:
            fallback_error = self._result_error_message(fallback_result)

        if should_add_phone_fallback and self._is_add_phone_failure(
            fallback_result,
            fallback_error,
        ):
            email = self._fallback_email_from_result(primary_result, fallback_context)
            reason = self._compose_add_phone_reason(primary_error, fallback_error)
            if email:
                from platforms.chatgpt.oauth_client import _append_add_phone_blacklist

                _append_add_phone_blacklist(email, reason=reason)
            self.last_error_metadata = dict(self._result_metadata(fallback_result) or self._result_metadata(primary_result))
            if reason:
                self.last_error_metadata["error_code"] = self._result_error_code(fallback_result) or self._result_error_code(primary_result)
            if context.callback_logger:
                context.callback_logger(
                    f"access_token_only 兜底后仍命中 add_phone 风控，邮箱 {email or '-'} 已加入黑名单: {reason}"
                )
            raise SkipCurrentAttemptRequested(f"add_phone 风控: {reason}")

        if should_add_phone_fallback and context.callback_logger:
            fallback_email = (
                self._fallback_email_from_result(primary_result, fallback_context)
                or "-"
            )
            reason = fallback_error or "未知错误"
            context.callback_logger(
                f"access_token_only 兜底失败（非 add_phone 终态）: email={fallback_email} reason={reason}"
            )

        final_result = fallback_result if fallback_result is not None else primary_result
        if final_result is not None:
            combined = " ; ".join(
                text for text in (primary_error, fallback_error) if text
            ).strip()
            if combined and not self._result_error_message(final_result):
                setattr(final_result, "error_message", combined)
            return self._mark_result_mode(
                final_result,
                CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
            )

        raise RuntimeError(
            "codex auth 与 access_token_only 均失败"
            + (f": {primary_error}" if primary_error else "")
        )


class AccessTokenOnlyChatGPTRegistrationAdapter(BaseChatGPTRegistrationModeAdapter):
    mode = CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY

    def _create_engine(self, context: ChatGPTRegistrationContext):
        from platforms.chatgpt.access_token_only_registration_engine import AccessTokenOnlyRegistrationEngine

        return AccessTokenOnlyRegistrationEngine(
            email_service=context.email_service,
            proxy_url=context.proxy_url,
            browser_mode=context.browser_mode,
            callback_logger=context.callback_logger,
            max_retries=context.max_retries,
            extra_config=context.extra_config,
        )


def build_chatgpt_registration_mode_adapter(
    extra: Optional[dict],
) -> BaseChatGPTRegistrationModeAdapter:
    mode = resolve_chatgpt_registration_mode(extra)
    if mode == CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY:
        return AccessTokenOnlyChatGPTRegistrationAdapter()
    return RefreshTokenChatGPTRegistrationAdapter()
