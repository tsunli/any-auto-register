import unittest
from unittest import mock

from platforms.chatgpt.chatgpt_registration_mode_adapter import (
    CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
    CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
    ChatGPTRegistrationContext,
    build_chatgpt_registration_mode_adapter,
    resolve_chatgpt_registration_mode,
)


class ChatGPTRegistrationModeAdapterTests(unittest.TestCase):
    def test_resolve_defaults_to_refresh_token_mode(self):
        self.assertEqual(
            resolve_chatgpt_registration_mode({}),
            CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
        )

    def test_resolve_supports_boolean_no_rt_flag(self):
        self.assertEqual(
            resolve_chatgpt_registration_mode(
                {"chatgpt_has_refresh_token_solution": False}
            ),
            CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
        )

    def test_build_account_marks_selected_mode(self):
        adapter = build_chatgpt_registration_mode_adapter(
            {"chatgpt_registration_mode": "access_token_only"}
        )
        result = type(
            "Result",
            (),
            {
                "email": "demo@example.com",
                "password": "pw",
                "account_id": "acct-demo",
                "access_token": "at-demo",
                "refresh_token": "",
                "id_token": "id-demo",
                "session_token": "session-demo",
                "workspace_id": "ws-demo",
                "source": "register",
                "metadata": {
                    "last_stage": "token_exchange",
                    "stages_trace": ["authorize_continue", "token_exchange"],
                    "registration_flow": "register_complete_flow",
                    "token_flow": "reuse_session_and_get_tokens",
                    "error_code": "",
                },
            },
        )()

        account = adapter.build_account(result, fallback_password="fallback")

        self.assertEqual(account.email, "demo@example.com")
        self.assertEqual(account.password, "pw")
        self.assertEqual(
            account.extra["chatgpt_registration_mode"],
            CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
        )
        self.assertFalse(account.extra["chatgpt_has_refresh_token_solution"])
        self.assertEqual(account.extra["last_stage"], "token_exchange")
        self.assertEqual(
            account.extra["stages_trace"],
            ["authorize_continue", "token_exchange"],
        )
        self.assertEqual(
            account.extra["registration_flow"], "register_complete_flow"
        )
        self.assertEqual(
            account.extra["token_flow"], "reuse_session_and_get_tokens"
        )

    def test_access_token_only_adapter_passes_runtime_context_to_engine(self):
        created = {}

        class FakeEngine:
            def __init__(self, **kwargs):
                created["kwargs"] = kwargs
                self.email = None
                self.password = None

            def run(self):
                created["email"] = self.email
                created["password"] = self.password
                return type("Result", (), {"success": True})()

        adapter = build_chatgpt_registration_mode_adapter(
            {"chatgpt_registration_mode": "access_token_only"}
        )
        context = ChatGPTRegistrationContext(
            email_service=object(),
            proxy_url="http://127.0.0.1:7890",
            callback_logger=lambda _msg: None,
            email="demo@example.com",
            password="pw-demo",
            browser_mode="headed",
            max_retries=5,
            extra_config={"register_max_retries": 5},
        )

        with mock.patch(
            "platforms.chatgpt.access_token_only_registration_engine.AccessTokenOnlyRegistrationEngine",
            FakeEngine,
        ):
            adapter.run(context)

        self.assertEqual(created["email"], "demo@example.com")
        self.assertEqual(created["password"], "pw-demo")
        self.assertEqual(created["kwargs"]["browser_mode"], "headed")
        self.assertEqual(created["kwargs"]["max_retries"], 5)

    def test_refresh_mode_fallbacks_to_access_token_when_codex_auth_failed(self):
        class RefreshFailEngine:
            def __init__(self, **kwargs):
                self.email = None
                self.password = None

            def run(self):
                return type(
                    "Result",
                    (),
                    {
                        "success": False,
                        "error_message": "codex auth failed",
                    },
                )()

        class AccessSuccessEngine:
            def __init__(self, **kwargs):
                self.email = None
                self.password = None

            def run(self):
                return type(
                    "Result",
                    (),
                    {
                        "success": True,
                        "email": "fallback@example.com",
                        "password": "pw",
                        "account_id": "acct-fallback",
                        "access_token": "at-fallback",
                        "refresh_token": "",
                        "id_token": "",
                        "session_token": "sess-fallback",
                        "workspace_id": "ws-fallback",
                        "source": "register",
                    },
                )()

        adapter = build_chatgpt_registration_mode_adapter(
            {"chatgpt_registration_mode": "refresh_token"}
        )
        context = ChatGPTRegistrationContext(
            email_service=object(),
            proxy_url=None,
            callback_logger=lambda _msg: None,
            email="fallback@example.com",
            password="pw",
            browser_mode="protocol",
            max_retries=2,
            extra_config={},
        )

        with mock.patch(
            "platforms.chatgpt.refresh_token_registration_engine.RefreshTokenRegistrationEngine",
            RefreshFailEngine,
        ), mock.patch(
            "platforms.chatgpt.access_token_only_registration_engine.AccessTokenOnlyRegistrationEngine",
            AccessSuccessEngine,
        ):
            result = adapter.run(context)

        self.assertTrue(result.success)
        self.assertEqual(
            result.registration_mode,
            CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
        )
        account = adapter.build_account(result, fallback_password="fallback")
        self.assertEqual(
            account.extra["chatgpt_registration_mode"],
            CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
        )
        self.assertFalse(account.extra["chatgpt_has_refresh_token_solution"])

    def test_refresh_mode_keeps_codex_auth_result_when_primary_success(self):
        class RefreshSuccessEngine:
            def __init__(self, **kwargs):
                self.email = None
                self.password = None

            def run(self):
                return type(
                    "Result",
                    (),
                    {
                        "success": True,
                        "email": "primary@example.com",
                        "password": "pw",
                        "account_id": "acct-primary",
                        "access_token": "at-primary",
                        "refresh_token": "rt-primary",
                        "id_token": "id-primary",
                        "session_token": "sess-primary",
                        "workspace_id": "ws-primary",
                        "source": "register",
                    },
                )()

        class AccessShouldNotRunEngine:
            def __init__(self, **kwargs):
                raise AssertionError("primary success 时不应触发 fallback")

        adapter = build_chatgpt_registration_mode_adapter(
            {"chatgpt_registration_mode": "refresh_token"}
        )
        context = ChatGPTRegistrationContext(
            email_service=object(),
            proxy_url=None,
            callback_logger=lambda _msg: None,
            email="primary@example.com",
            password="pw",
            browser_mode="protocol",
            max_retries=2,
            extra_config={},
        )

        with mock.patch(
            "platforms.chatgpt.refresh_token_registration_engine.RefreshTokenRegistrationEngine",
            RefreshSuccessEngine,
        ), mock.patch(
            "platforms.chatgpt.access_token_only_registration_engine.AccessTokenOnlyRegistrationEngine",
            AccessShouldNotRunEngine,
        ):
            result = adapter.run(context)

        self.assertTrue(result.success)
        self.assertEqual(
            result.registration_mode,
            CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
        )
        account = adapter.build_account(result, fallback_password="fallback")
        self.assertEqual(
            account.extra["chatgpt_registration_mode"],
            CHATGPT_REGISTRATION_MODE_REFRESH_TOKEN,
        )
        self.assertTrue(account.extra["chatgpt_has_refresh_token_solution"])

    def test_refresh_mode_add_phone_failure_delays_then_falls_back_to_access_token_only(self):
        created = {}

        class RefreshAddPhoneFailEngine:
            def __init__(self, **kwargs):
                self.email = None
                self.password = None

            def run(self):
                return type(
                    "Result",
                    (),
                    {
                        "success": False,
                        "email": "same@example.com",
                        "password": "pw-same",
                        "error_message": "passwordless 登录后仍停留在 add_phone",
                        "metadata": {
                            "error_code": "add_phone_workspace_or_callback_missing",
                            "last_stage": "workspace_select",
                            "stages_trace": ["otp", "workspace_select"],
                        },
                    },
                )()

        class AccessSuccessEngine:
            def __init__(self, **kwargs):
                self.email = None
                self.password = None
                created["kwargs"] = kwargs

            def run(self):
                created["email"] = self.email
                created["password"] = self.password
                return type(
                    "Result",
                    (),
                    {
                        "success": True,
                        "email": "same@example.com",
                        "password": "pw-same",
                        "account_id": "acct-at",
                        "access_token": "at",
                        "refresh_token": "",
                        "id_token": "",
                        "session_token": "sess",
                        "workspace_id": "ws",
                        "source": "register",
                    },
                )()

        logs: list[str] = []
        adapter = build_chatgpt_registration_mode_adapter(
            {"chatgpt_registration_mode": "refresh_token"}
        )
        context = ChatGPTRegistrationContext(
            email_service=object(),
            proxy_url=None,
            callback_logger=logs.append,
            email=None,
            password=None,
            browser_mode="protocol",
            max_retries=2,
            extra_config={"chatgpt_add_phone_at_fallback_delay_seconds": 12},
        )

        with mock.patch(
            "platforms.chatgpt.refresh_token_registration_engine.RefreshTokenRegistrationEngine",
            RefreshAddPhoneFailEngine,
        ), mock.patch(
            "platforms.chatgpt.access_token_only_registration_engine.AccessTokenOnlyRegistrationEngine",
            AccessSuccessEngine,
        ), mock.patch(
            "platforms.chatgpt.chatgpt_registration_mode_adapter.time.sleep"
        ) as sleep_mock:
            result = adapter.run(context)

        self.assertTrue(result.success)
        self.assertEqual(
            result.registration_mode,
            CHATGPT_REGISTRATION_MODE_ACCESS_TOKEN_ONLY,
        )
        sleep_mock.assert_called_once_with(12)
        self.assertEqual(created["email"], "same@example.com")
        self.assertEqual(created["password"], "pw-same")
        self.assertTrue(created["kwargs"]["extra_config"]["chatgpt_reuse_generated_email"])
        self.assertTrue(
            any("add_phone 风控" in entry and "access_token_only" in entry for entry in logs)
        )
        self.assertTrue(
            any("开始 access_token_only 兜底" in entry for entry in logs)
        )
        self.assertTrue(
            any("access_token_only 兜底成功" in entry for entry in logs)
        )

    def test_refresh_mode_blacklists_and_skips_when_access_token_only_also_hits_add_phone(self):
        class RefreshAddPhoneFailEngine:
            def __init__(self, **kwargs):
                self.email = None
                self.password = None

            def run(self):
                return type(
                    "Result",
                    (),
                    {
                        "success": False,
                        "email": "same@example.com",
                        "password": "pw-same",
                        "error_message": "passwordless 登录后仍停留在 add_phone",
                        "metadata": {
                            "error_code": "add_phone_workspace_or_callback_missing",
                            "last_stage": "workspace_select",
                            "stages_trace": ["otp", "workspace_select"],
                        },
                    },
                )()

        class AccessAddPhoneFailEngine:
            def __init__(self, **kwargs):
                self.email = None
                self.password = None

            def run(self):
                return type(
                    "Result",
                    (),
                    {
                        "success": False,
                        "email": "same@example.com",
                        "password": "pw-same",
                        "error_message": "未支持的注册状态: page=add_phone method=GET next=https://auth.openai.com/add-phone...",
                        "metadata": {
                            "last_stage": "otp",
                            "stages_trace": ["otp", "add_phone"],
                        },
                    },
                )()

        logs: list[str] = []
        adapter = build_chatgpt_registration_mode_adapter(
            {"chatgpt_registration_mode": "refresh_token"}
        )
        context = ChatGPTRegistrationContext(
            email_service=object(),
            proxy_url=None,
            callback_logger=logs.append,
            email=None,
            password=None,
            browser_mode="protocol",
            max_retries=2,
            extra_config={"chatgpt_add_phone_at_fallback_delay_seconds": 0},
        )

        with mock.patch(
            "platforms.chatgpt.refresh_token_registration_engine.RefreshTokenRegistrationEngine",
            RefreshAddPhoneFailEngine,
        ), mock.patch(
            "platforms.chatgpt.access_token_only_registration_engine.AccessTokenOnlyRegistrationEngine",
            AccessAddPhoneFailEngine,
        ), mock.patch(
            "platforms.chatgpt.chatgpt_registration_mode_adapter.time.sleep"
        ) as sleep_mock, mock.patch(
            "platforms.chatgpt.oauth_client._append_add_phone_blacklist"
        ) as blacklist_mock:
            from core.task_runtime import SkipCurrentAttemptRequested

            with self.assertRaises(SkipCurrentAttemptRequested) as exc:
                adapter.run(context)

        sleep_mock.assert_not_called()
        blacklist_mock.assert_called_once()
        self.assertEqual(blacklist_mock.call_args.args[0], "same@example.com")
        self.assertIn("add_phone", blacklist_mock.call_args.kwargs["reason"])
        self.assertIn("add_phone", str(exc.exception))
        self.assertTrue(
            any("已加入黑名单" in entry for entry in logs)
        )


if __name__ == "__main__":
    unittest.main()
