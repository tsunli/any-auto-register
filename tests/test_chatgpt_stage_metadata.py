import unittest
from unittest import mock

from platforms.chatgpt.access_token_only_registration_engine import (
    AccessTokenOnlyRegistrationEngine,
)
from platforms.chatgpt.chatgpt_client import ChatGPTClient
from platforms.chatgpt.oauth_client import OAuthClient
from platforms.chatgpt.refresh_token_registration_engine import (
    RefreshTokenRegistrationEngine,
    RegistrationResult,
)


class _DummyEmailService:
    service_type = type("ST", (), {"value": "dummy"})()

    def create_email(self):
        return {"email": "user@example.com", "service_id": "svc-1"}

    def get_verification_code(self, **kwargs):
        return "123456"


class _FakeAccessChatGPTClient:
    def __init__(self, *args, **kwargs):
        self.device_id = "device-fixed"
        self.stage_trace = ["authorize_continue", "otp", "token_exchange"]
        self.last_stage = "token_exchange"
        self.last_token_exchange_error_code = "session_cookie_missing"

    def register_complete_flow(self, *args, **kwargs):
        return True, "注册成功"

    def reuse_session_and_get_tokens(self):
        return False, "缺少 ChatGPT session-token，注册回调可能未完全落地"


class ChatGPTStageMetadataTests(unittest.TestCase):
    def test_chatgpt_client_enter_stage_appends_trace(self):
        client = ChatGPTClient.__new__(ChatGPTClient)
        client.stage_trace = []
        client.last_stage = ""
        client._log = lambda _msg: None

        client._enter_stage("authorize_continue")
        client._enter_stage("otp")

        self.assertEqual(client.stage_trace, ["authorize_continue", "otp"])
        self.assertEqual(client.last_stage, "otp")

    def test_oauth_client_enter_stage_appends_trace(self):
        client = OAuthClient.__new__(OAuthClient)
        client.stage_trace = []
        client.last_stage = ""
        client._log = lambda _msg: None

        client._enter_stage("authorize_continue")
        client._enter_stage("workspace_select")

        self.assertEqual(
            client.stage_trace, ["authorize_continue", "workspace_select"]
        )
        self.assertEqual(client.last_stage, "workspace_select")

    def test_access_token_only_engine_failure_metadata_includes_stage_trace(self):
        engine = AccessTokenOnlyRegistrationEngine(
            email_service=_DummyEmailService(),
            proxy_url=None,
            callback_logger=lambda _msg: None,
            max_retries=1,
        )

        with mock.patch(
            "platforms.chatgpt.access_token_only_registration_engine.ChatGPTClient",
            _FakeAccessChatGPTClient,
        ):
            result = engine.run()

        self.assertFalse(result.success)
        self.assertEqual(result.metadata["last_stage"], "token_exchange")
        self.assertEqual(
            result.metadata["stages_trace"],
            ["authorize_continue", "otp", "token_exchange"],
        )
        self.assertEqual(result.metadata["error_code"], "session_cookie_missing")

    def test_refresh_engine_populate_result_merges_stage_trace(self):
        engine = RefreshTokenRegistrationEngine(
            email_service=_DummyEmailService(),
            proxy_url=None,
            callback_logger=lambda _msg: None,
            max_retries=1,
        )
        engine.email = "user@example.com"
        engine.password = "pw"

        register_client = type(
            "RegisterClient",
            (),
            {
                "stage_trace": ["authorize_continue", "otp", "about_you"],
                "last_stage": "about_you",
                "device_id": "device-fixed",
                "impersonate": "chrome136",
                "ua": "UA",
            },
        )()
        oauth_client = type(
            "OAuthClientLike",
            (),
            {
                "last_workspace_id": "ws-1",
                "last_stage": "token_exchange",
                "stage_trace": ["workspace_select", "token_exchange"],
                "_decode_oauth_session_cookie": lambda self: {"workspaces": [{"id": "ws-1"}]},
                "_get_cookie_value": lambda self, name, domain=None: "session-1",
            },
        )()

        result = RegistrationResult(success=False)
        engine._populate_result_from_tokens(
            result=result,
            tokens={
                "access_token": "at",
                "refresh_token": "rt",
                "id_token": "id",
                "account_id": "acct-1",
            },
            oauth_client=oauth_client,
            registration_message="pending_about_you_submission",
            source="register",
            register_client=register_client,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.metadata["last_stage"], "token_exchange")
        self.assertEqual(
            result.metadata["stages_trace"],
            [
                "authorize_continue",
                "otp",
                "about_you",
                "workspace_select",
                "token_exchange",
            ],
        )
        self.assertEqual(
            result.metadata["register_stages_trace"],
            ["authorize_continue", "otp", "about_you"],
        )
        self.assertEqual(
            result.metadata["oauth_stages_trace"],
            ["workspace_select", "token_exchange"],
        )


if __name__ == "__main__":
    unittest.main()
