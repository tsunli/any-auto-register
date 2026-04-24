import sys
import types
import unittest
from unittest import mock

smstome_tool_stub = types.ModuleType("smstome_tool")
smstome_tool_stub.PhoneEntry = type("PhoneEntry", (), {})
smstome_tool_stub.get_unused_phone = lambda *args, **kwargs: None
smstome_tool_stub.mark_phone_blacklisted = lambda *args, **kwargs: None
smstome_tool_stub.parse_country_slugs = lambda value: []
smstome_tool_stub.update_global_phone_list = lambda *args, **kwargs: 0
smstome_tool_stub.wait_for_otp = lambda *args, **kwargs: None
sys.modules.setdefault("smstome_tool", smstome_tool_stub)

from platforms.chatgpt.oauth_client import OAuthClient
from platforms.chatgpt.chatgpt_client import ChatGPTClient
from platforms.chatgpt.refresh_token_registration_engine import (
    RefreshTokenRegistrationEngine,
)
from platforms.chatgpt.utils import FlowState


class DummyEmailService:
    service_type = type("ST", (), {"value": "dummy"})()

    def create_email(self):
        return {"email": "user@example.com", "service_id": "svc-1"}

    def get_verification_code(self, **kwargs):
        return "123456"


class RefreshTokenRegistrationEngineTests(unittest.TestCase):
    def _make_engine(self, **kwargs):
        return RefreshTokenRegistrationEngine(
            email_service=DummyEmailService(),
            proxy_url="http://127.0.0.1:7890",
            callback_logger=lambda msg: None,
            max_retries=1,
            **kwargs,
        )

    @mock.patch("platforms.chatgpt.refresh_token_registration_engine.OAuthManager")
    @mock.patch("platforms.chatgpt.refresh_token_registration_engine.OAuthClient")
    def test_run_uses_oauth_single_chain_signup_main_chain(
        self,
        mock_oauth_client_cls,
        mock_oauth_manager_cls,
    ):
        oauth_client = mock.Mock()
        oauth_client.device_id = "device-fixed"
        oauth_client.ua = "UA"
        oauth_client.sec_ch_ua = '"Chromium";v="136"'
        oauth_client.impersonate = "chrome136"
        oauth_client.signup_and_get_tokens.return_value = {
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": "id-token",
            "account_id": "acct-1",
        }
        oauth_client.last_error = ""
        oauth_client.last_workspace_id = "ws-1"
        oauth_client._decode_oauth_session_cookie.return_value = {
            "workspaces": [{"id": "ws-1"}]
        }
        oauth_client._get_cookie_value.return_value = "session-1"
        mock_oauth_client_cls.return_value = oauth_client

        oauth_manager = mock.Mock()
        oauth_manager.extract_account_info.return_value = {
            "email": "user@example.com",
            "account_id": "acct-1",
        }
        mock_oauth_manager_cls.return_value = oauth_manager

        engine = self._make_engine(extra_config={"register_max_retries": 1})
        result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.email, "user@example.com")
        self.assertEqual(result.account_id, "acct-1")
        self.assertEqual(result.workspace_id, "ws-1")
        self.assertEqual(result.refresh_token, "rt")
        self.assertEqual(result.session_token, "session-1")
        self.assertEqual(result.source, "register")

        oauth_client.signup_and_get_tokens.assert_called_once()
        oauth_client.login_and_get_tokens.assert_not_called()
        signup_args = oauth_client.signup_and_get_tokens.call_args.args
        self.assertEqual(signup_args[0], "user@example.com")
        self.assertEqual(signup_args[1], result.password)
        signup_kwargs = oauth_client.signup_and_get_tokens.call_args.kwargs
        self.assertFalse(signup_kwargs["allow_phone_verification"])
        self.assertEqual(signup_kwargs["signup_source"], "refresh_token_engine")

    @mock.patch("platforms.chatgpt.refresh_token_registration_engine.OAuthManager")
    @mock.patch("platforms.chatgpt.refresh_token_registration_engine.OAuthClient")
    def test_run_switches_to_login_when_signup_reports_existing_account(
        self,
        mock_oauth_client_cls,
        mock_oauth_manager_cls,
    ):
        oauth_client = mock.Mock()
        oauth_client.device_id = "device-fixed"
        oauth_client.ua = "UA"
        oauth_client.sec_ch_ua = '"Chromium";v="136"'
        oauth_client.impersonate = "chrome136"
        oauth_client.signup_and_get_tokens.return_value = None
        oauth_client.last_error = "注册失败: 400 - user_already_exists"
        oauth_client.login_and_get_tokens.return_value = {
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": "id-token",
        }
        oauth_client.last_workspace_id = "ws-1"
        oauth_client._decode_oauth_session_cookie.return_value = {
            "workspaces": [{"id": "ws-1"}]
        }
        oauth_client._get_cookie_value.return_value = ""
        mock_oauth_client_cls.return_value = oauth_client

        oauth_manager = mock.Mock()
        oauth_manager.extract_account_info.return_value = {
            "email": "user@example.com",
            "account_id": "acct-existing",
        }
        mock_oauth_manager_cls.return_value = oauth_manager

        engine = self._make_engine()
        result = engine.run()

        self.assertTrue(result.success)
        self.assertEqual(result.source, "login")
        self.assertEqual(result.account_id, "acct-existing")
        oauth_client.signup_and_get_tokens.assert_called_once()
        login_kwargs = oauth_client.login_and_get_tokens.call_args.kwargs
        self.assertEqual(login_kwargs["login_source"], "existing_account_continue")
        self.assertTrue(login_kwargs["force_new_browser"])
        self.assertEqual(login_kwargs["user_agent"], "UA")

    @mock.patch("platforms.chatgpt.refresh_token_registration_engine.OAuthManager")
    @mock.patch("platforms.chatgpt.refresh_token_registration_engine.OAuthClient")
    def test_run_retry_uses_newly_created_email_in_next_attempt(
        self,
        mock_oauth_client_cls,
        mock_oauth_manager_cls,
    ):
        class RotatingEmailService:
            service_type = type("ST", (), {"value": "dummy"})()

            def __init__(self):
                self.index = 0

            def create_email(self):
                self.index += 1
                return {
                    "email": f"user{self.index}@example.com",
                    "service_id": f"svc-{self.index}",
                }

            def get_verification_code(self, **kwargs):
                return "123456"

        oauth_client = mock.Mock()
        oauth_client.device_id = "device-fixed"
        oauth_client.ua = "UA"
        oauth_client.sec_ch_ua = '"Chromium";v="136"'
        oauth_client.impersonate = "chrome136"
        oauth_client.last_error = ""
        signup_results = iter(
            [
                (None, "network timeout"),
                (
                    {
                        "access_token": "at",
                        "refresh_token": "rt",
                        "id_token": "id-token",
                        "account_id": "acct-1",
                    },
                    "",
                ),
            ]
        )

        def _signup_side_effect(*args, **kwargs):
            result_value, error_value = next(signup_results)
            oauth_client.last_error = error_value
            return result_value

        oauth_client.signup_and_get_tokens.side_effect = _signup_side_effect
        oauth_client.login_and_get_tokens.return_value = {
            "access_token": "at",
            "refresh_token": "rt",
            "id_token": "id-token",
            "account_id": "acct-1",
        }
        oauth_client.last_workspace_id = "ws-1"
        oauth_client._decode_oauth_session_cookie.return_value = {
            "workspaces": [{"id": "ws-1"}]
        }
        oauth_client._get_cookie_value.return_value = "session-1"
        mock_oauth_client_cls.return_value = oauth_client

        oauth_manager = mock.Mock()
        oauth_manager.extract_account_info.return_value = {
            "email": "user2@example.com",
            "account_id": "acct-1",
        }
        mock_oauth_manager_cls.return_value = oauth_manager

        engine = RefreshTokenRegistrationEngine(
            email_service=RotatingEmailService(),
            proxy_url="http://127.0.0.1:7890",
            callback_logger=lambda msg: None,
            max_retries=2,
        )
        result = engine.run()

        self.assertTrue(result.success)
        call_args = oauth_client.signup_and_get_tokens.call_args_list
        self.assertEqual(call_args[0].args[0], "user1@example.com")
        self.assertEqual(call_args[1].args[0], "user2@example.com")


class OAuthClientPasswordlessTests(unittest.TestCase):
    def _make_client(self):
        return OAuthClient({}, proxy="http://127.0.0.1:7890", verbose=False)

    def test_oauth_get_cookie_value_supports_chunked_session_cookie(self):
        client = OAuthClient.__new__(OAuthClient)
        client.session = types.SimpleNamespace(
            cookies=[
                types.SimpleNamespace(
                    name="__Secure-next-auth.session-token.1",
                    domain=".chatgpt.com",
                    value="part-b",
                ),
                types.SimpleNamespace(
                    name="__Secure-next-auth.session-token.0",
                    domain=".chatgpt.com",
                    value="part-a",
                ),
            ]
        )

        value = client._get_cookie_value(
            "__Secure-next-auth.session-token",
            "chatgpt.com",
        )
        self.assertEqual(value, "part-apart-b")

    def test_submit_signup_register_uses_minimal_headers_strategy(self):
        client = self._make_client()
        client.session.post = mock.Mock(
            return_value=mock.Mock(status_code=200, url="https://auth.openai.com/api/accounts/user/register")
        )

        with mock.patch(
            "platforms.chatgpt.oauth_client.get_sentinel_token_via_browser",
            return_value="sentinel-demo",
        ), mock.patch(
            "platforms.chatgpt.oauth_client.build_sentinel_token",
            return_value="",
        ):
            ok = client._submit_signup_register(
                "user@example.com",
                "Secret123!",
                "device-fixed",
                user_agent="UA",
                sec_ch_ua='"Chromium";v="136"',
                impersonate="chrome136",
                referer="https://auth.openai.com/create-account/password",
            )

        self.assertTrue(ok)
        kwargs = client.session.post.call_args.kwargs
        self.assertIn("data", kwargs)
        self.assertNotIn("json", kwargs)
        headers = kwargs["headers"]
        self.assertEqual(headers["Referer"], "https://auth.openai.com/create-account/password")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(headers["Accept"], "application/json")
        self.assertEqual(headers["openai-sentinel-token"], "sentinel-demo")
        self.assertNotIn("Origin", headers)
        self.assertNotIn("oai-device-id", headers)

    def test_login_and_get_tokens_prefers_passwordless_over_password_verify(self):
        client = self._make_client()
        login_password_state = FlowState(
            page_type="login_password",
            continue_url="https://auth.openai.com/log-in/password",
            current_url="https://auth.openai.com/log-in/password",
        )
        email_otp_state = FlowState(
            page_type="email_otp_verification",
            continue_url="https://auth.openai.com/email-verification",
            current_url="https://auth.openai.com/email-verification",
        )
        consent_state = FlowState(
            page_type="consent",
            continue_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            current_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        )

        with mock.patch.object(client, "_bootstrap_oauth_session", return_value="https://auth.openai.com/log-in"), \
            mock.patch.object(client, "_submit_authorize_continue", return_value=login_password_state) as submit_continue, \
            mock.patch.object(client, "_send_passwordless_login_otp", return_value=email_otp_state) as send_passwordless, \
            mock.patch.object(client, "_handle_otp_verification", return_value=consent_state), \
            mock.patch.object(client, "_oauth_submit_workspace_and_org", return_value=("auth-code", None)), \
            mock.patch.object(client, "_exchange_code_for_tokens", return_value={"access_token": "at"}), \
            mock.patch.object(client, "_submit_password_verify") as submit_password:
            tokens = client.login_and_get_tokens(
                "user@example.com",
                "Secret123!",
                "device-fixed",
                user_agent="UA",
                sec_ch_ua='"Chromium";v="136"',
                impersonate="chrome136",
                skymail_client=mock.Mock(),
                prefer_passwordless_login=True,
                allow_phone_verification=False,
            )

        self.assertEqual(tokens["access_token"], "at")
        submit_continue.assert_called_once()
        self.assertEqual(submit_continue.call_args.kwargs["screen_hint"], "login")
        send_passwordless.assert_called_once()
        submit_password.assert_not_called()

    def test_login_and_get_tokens_visits_add_phone_continue_url_before_phone_branch(self):
        client = self._make_client()
        add_phone_state = FlowState(
            page_type="add_phone",
            continue_url="https://auth.openai.com/add-phone",
            current_url="https://auth.openai.com/api/accounts/email-otp/validate",
            source="api",
        )
        consent_state = FlowState(
            page_type="consent",
            continue_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            current_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        )

        with mock.patch.object(client, "_bootstrap_oauth_session", return_value="https://auth.openai.com/log-in"), \
            mock.patch.object(client, "_submit_authorize_continue", return_value=add_phone_state), \
            mock.patch.object(client, "_follow_flow_state", return_value=(None, consent_state)) as follow_state, \
            mock.patch.object(client, "_oauth_submit_workspace_and_org", return_value=("auth-code", None)), \
            mock.patch.object(client, "_exchange_code_for_tokens", return_value={"access_token": "at"}), \
            mock.patch.object(client, "_handle_add_phone_verification") as handle_phone:
            tokens = client.login_and_get_tokens(
                "user@example.com",
                "Secret123!",
                "device-fixed",
                prefer_passwordless_login=True,
                allow_phone_verification=False,
            )

        self.assertEqual(tokens["access_token"], "at")
        follow_state.assert_called_once()
        handle_phone.assert_not_called()

    def test_login_and_get_tokens_uses_canonical_consent_url_when_state_is_add_phone(self):
        client = self._make_client()
        add_phone_state = FlowState(
            page_type="add_phone",
            continue_url="https://auth.openai.com/add-phone",
            current_url="https://auth.openai.com/add-phone",
        )

        with mock.patch.object(client, "_bootstrap_oauth_session", return_value="https://auth.openai.com/log-in"), \
            mock.patch.object(client, "_submit_authorize_continue", return_value=add_phone_state), \
            mock.patch.object(client, "_state_supports_workspace_resolution", return_value=True), \
            mock.patch.object(client, "_state_requires_navigation", return_value=False), \
            mock.patch.object(client, "_oauth_submit_workspace_and_org", return_value=("auth-code", None)) as submit_workspace, \
            mock.patch.object(client, "_exchange_code_for_tokens", return_value={"access_token": "at"}):
            tokens = client.login_and_get_tokens(
                "user@example.com",
                "Secret123!",
                "device-fixed",
                prefer_passwordless_login=True,
                allow_phone_verification=False,
                skymail_client=mock.Mock(),
            )

        self.assertEqual(tokens["access_token"], "at")
        self.assertEqual(
            submit_workspace.call_args.args[0],
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        )

    def test_login_and_get_tokens_retries_once_when_add_phone_has_no_workspace(self):
        client = self._make_client()
        add_phone_state = FlowState(
            page_type="add_phone",
            continue_url="https://auth.openai.com/add-phone",
            current_url="https://auth.openai.com/add-phone",
        )

        with mock.patch.object(client, "_bootstrap_oauth_session", return_value="https://auth.openai.com/log-in") as bootstrap, \
            mock.patch.object(client, "_submit_authorize_continue", return_value=add_phone_state) as submit_continue, \
            mock.patch.object(client, "_state_supports_workspace_resolution", return_value=False), \
            mock.patch.object(client, "_state_requires_navigation", return_value=False):
            tokens = client.login_and_get_tokens(
                "user@example.com",
                "Secret123!",
                "device-fixed",
                prefer_passwordless_login=True,
                allow_phone_verification=False,
                skymail_client=mock.Mock(),
            )

        self.assertIsNone(tokens)
        self.assertEqual(bootstrap.call_count, 2)
        self.assertEqual(submit_continue.call_count, 2)
        self.assertIn("未获取到 workspace / callback", client.last_error)

    def test_send_passwordless_login_otp_does_not_send_email_field(self):
        client = self._make_client()
        response = mock.Mock()
        response.status_code = 200
        response.url = "https://auth.openai.com/api/accounts/passwordless/send-otp"
        response.json.return_value = {"page": {"type": "email_otp_verification"}}
        client.session.post = mock.Mock(return_value=response)

        expected_state = FlowState(
            page_type="email_otp_verification",
            continue_url="https://auth.openai.com/email-verification",
            current_url="https://auth.openai.com/email-verification",
        )
        with mock.patch.object(
            client,
            "_state_from_payload",
            return_value=expected_state,
        ):
            state = client._send_passwordless_login_otp(
                "user@example.com",
                "device-fixed",
            )

        self.assertEqual(state, expected_state)
        kwargs = client.session.post.call_args.kwargs
        self.assertNotIn("json", kwargs)
        self.assertNotIn("data", kwargs)

    def test_send_passwordless_login_otp_sets_error_code_on_http_failure(self):
        client = self._make_client()
        response = mock.Mock()
        response.status_code = 403
        response.text = "blocked"
        client.session.post = mock.Mock(return_value=response)

        state = client._send_passwordless_login_otp(
            "user@example.com",
            "device-fixed",
        )

        self.assertIsNone(state)
        self.assertEqual(client.last_error_code, "oauth_passwordless_send_failed")

    def test_login_and_get_tokens_submits_about_you_when_configured(self):
        client = self._make_client()
        about_you_state = FlowState(
            page_type="about_you",
            continue_url="https://auth.openai.com/about-you",
            current_url="https://auth.openai.com/about-you",
        )
        consent_state = FlowState(
            page_type="consent",
            continue_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            current_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
        )

        with mock.patch.object(client, "_bootstrap_oauth_session", return_value="https://auth.openai.com/log-in"), \
            mock.patch.object(client, "_submit_authorize_continue", return_value=about_you_state), \
            mock.patch.object(client, "_submit_about_you_create_account", return_value=consent_state) as submit_about_you, \
            mock.patch.object(client, "_oauth_submit_workspace_and_org", return_value=("auth-code", None)), \
            mock.patch.object(client, "_exchange_code_for_tokens", return_value={"access_token": "at"}):
            tokens = client.login_and_get_tokens(
                "user@example.com",
                "Secret123!",
                "device-fixed",
                prefer_passwordless_login=True,
                allow_phone_verification=False,
                complete_about_you_if_needed=True,
                first_name="Ivy",
                last_name="Stone",
                birthdate="1990-01-02",
                skymail_client=mock.Mock(),
            )

        self.assertEqual(tokens["access_token"], "at")
        submit_about_you.assert_called_once()
        self.assertEqual(submit_about_you.call_args.args[0], "Ivy")
        self.assertEqual(submit_about_you.call_args.args[1], "Stone")
        self.assertEqual(submit_about_you.call_args.args[2], "1990-01-02")

    def test_submit_about_you_sets_error_code_when_profile_incomplete(self):
        client = self._make_client()

        state = client._submit_about_you_create_account(
            "",
            "",
            "",
            "device-fixed",
            user_agent="UA",
            sec_ch_ua='"Chromium";v="136"',
            impersonate="chrome136",
        )

        self.assertIsNone(state)
        self.assertEqual(client.last_error_code, "about_you_profile_incomplete")

    def test_submit_about_you_sets_error_code_on_http_failure(self):
        client = self._make_client()
        response = mock.Mock()
        response.status_code = 500
        response.text = "server error"
        response.url = "https://auth.openai.com/api/accounts/create_account"
        client.session.post = mock.Mock(return_value=response)

        with mock.patch(
            "platforms.chatgpt.oauth_client.build_sentinel_token",
            return_value="",
        ):
            state = client._submit_about_you_create_account(
                "Ivy",
                "Stone",
                "1990-01-02",
                "device-fixed",
                user_agent="UA",
                sec_ch_ua='"Chromium";v="136"',
                impersonate="chrome136",
                referer="https://auth.openai.com/about-you",
            )

        self.assertIsNone(state)
        self.assertEqual(client.last_error_code, "about_you_submit_failed")

    def test_workspace_submit_sets_error_code_when_session_data_missing(self):
        client = self._make_client()

        with mock.patch.object(
            client,
            "_load_workspace_session_data",
            return_value=None,
        ):
            code, state = client._oauth_submit_workspace_and_org(
                "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "device-fixed",
                "UA",
                "chrome136",
                max_retries=1,
            )

        self.assertIsNone(code)
        self.assertIsNone(state)
        self.assertEqual(client.last_error_code, "consent_session_missing")

    def test_workspace_submit_sets_error_code_when_workspace_missing(self):
        client = self._make_client()

        with mock.patch.object(
            client,
            "_load_workspace_session_data",
            return_value={"workspaces": []},
        ):
            code, state = client._oauth_submit_workspace_and_org(
                "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "device-fixed",
                "UA",
                "chrome136",
                max_retries=1,
            )

        self.assertIsNone(code)
        self.assertIsNone(state)
        self.assertEqual(client.last_error_code, "workspace_missing")

    def test_login_and_get_tokens_sets_error_code_when_email_otp_client_missing(self):
        client = self._make_client()
        email_otp_state = FlowState(
            page_type="email_otp_verification",
            continue_url="https://auth.openai.com/email-verification",
            current_url="https://auth.openai.com/email-verification",
        )

        with mock.patch.object(client, "_bootstrap_oauth_session", return_value="https://auth.openai.com/log-in"), \
            mock.patch.object(client, "_submit_authorize_continue", return_value=email_otp_state):
            tokens = client.login_and_get_tokens(
                "user@example.com",
                "Secret123!",
                "device-fixed",
                skymail_client=None,
                prefer_passwordless_login=True,
                allow_phone_verification=False,
            )

        self.assertIsNone(tokens)
        self.assertEqual(client.last_error_code, "oauth_otp_client_missing")


class BrowserFallbackTests(unittest.TestCase):
    def _make_reuse_client(self, state: FlowState):
        client = ChatGPTClient.__new__(ChatGPTClient)
        client.session = mock.Mock()
        client.session.cookies = types.SimpleNamespace(jar=[])
        client.last_registration_state = state
        client.last_stage = ""
        client.last_token_exchange_error_code = ""
        client.last_token_exchange_error = ""
        client._log = lambda _msg: None
        client._browser_pause = lambda *_args, **_kwargs: None
        client._headers = lambda *_args, **_kwargs: {}
        return client

    def test_chatgpt_get_cookie_value_supports_chunked_session_cookie(self):
        client = ChatGPTClient.__new__(ChatGPTClient)
        client.session = types.SimpleNamespace(
            cookies=types.SimpleNamespace(
                jar=[
                    types.SimpleNamespace(
                        name="__Secure-next-auth.session-token.1",
                        domain=".chatgpt.com",
                        value="part-b",
                    ),
                    types.SimpleNamespace(
                        name="__Secure-next-auth.session-token.0",
                        domain=".chatgpt.com",
                        value="part-a",
                    ),
                ]
            )
        )

        value = client.get_next_auth_session_token()
        self.assertEqual(value, "part-apart-b")

    def test_chatgpt_create_account_uses_browser_fallback_on_challenge(self):
        client = ChatGPTClient(proxy="http://127.0.0.1:7890", verbose=False, browser_mode="headless")
        client._get_sentinel_token = mock.Mock(return_value="sentinel-token")
        client._browser_submit_create_account = mock.Mock(
            return_value=(
                True,
                FlowState(
                    page_type="consent",
                    continue_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    current_url="https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                ),
            )
        )

        response = mock.Mock()
        response.status_code = 403
        response.text = "<!DOCTYPE html>Just a moment..."
        response.url = "https://auth.openai.com/about-you"
        client.session.post = mock.Mock(return_value=response)

        ok, next_state = client.create_account("Ivy", "Stone", "1990-01-02", return_state=True)

        self.assertTrue(ok)
        self.assertEqual(next_state.page_type, "consent")
        client._browser_submit_create_account.assert_called_once()

    def test_chatgpt_create_account_protocol_mode_skips_browser_fallback(self):
        client = ChatGPTClient(proxy="http://127.0.0.1:7890", verbose=False, browser_mode="protocol")
        client._get_sentinel_token = mock.Mock(return_value="sentinel-token")
        client._browser_submit_create_account = mock.Mock()

        response = mock.Mock()
        response.status_code = 403
        response.text = "<!DOCTYPE html>Just a moment..."
        response.url = "https://auth.openai.com/about-you"
        response.json.side_effect = ValueError("not json")
        client.session.post = mock.Mock(return_value=response)

        ok, detail = client.create_account("Ivy", "Stone", "1990-01-02", return_state=True)

        self.assertFalse(ok)
        self.assertIn("HTTP 403", detail)
        client._browser_submit_create_account.assert_not_called()

    def test_load_workspace_session_data_uses_browser_warm_page_when_needed(self):
        client = OAuthClient({}, proxy="http://127.0.0.1:7890", verbose=False, browser_mode="headless")
        client._decode_oauth_session_cookie = mock.Mock(
            side_effect=[
                None,
                {"workspaces": [{"id": "ws-1"}]},
            ]
        )
        client._fetch_consent_page_html = mock.Mock(return_value="")
        client._browser_warm_page = mock.Mock(
            return_value={
                "url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                "html": "<html></html>",
            }
        )

        session_data = client._load_workspace_session_data(
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            user_agent="UA",
            impersonate="chrome136",
        )

        self.assertEqual(session_data["workspaces"][0]["id"], "ws-1")
        client._browser_warm_page.assert_called_once()

    def test_workspace_submit_falls_back_to_browser_callback_when_api_follow_has_no_code(self):
        client = OAuthClient({}, proxy="http://127.0.0.1:7890", verbose=False, browser_mode="headless")
        client._load_workspace_session_data = mock.Mock(
            return_value={"workspaces": [{"id": "ws-1"}]}
        )
        client._oauth_follow_for_code = mock.Mock(return_value=(None, "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"))
        client._browser_capture_callback = mock.Mock(
            return_value="http://localhost:1455/auth/callback?code=auth-code&state=demo"
        )

        response = mock.Mock()
        response.status_code = 200
        response.url = "https://auth.openai.com/api/accounts/workspace/select"
        response.text = '{"continue_url":"https://auth.openai.com/sign-in-with-chatgpt/codex/consent"}'
        response.json.return_value = {
            "continue_url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "page": {
                "type": "consent",
                "payload": {
                    "url": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent"
                },
            },
            "data": {
                "orgs": [],
            },
        }
        client.session.post = mock.Mock(return_value=response)

        code, state = client._oauth_submit_workspace_and_org(
            "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "device-fixed",
            "UA",
            "chrome136",
        )

        self.assertEqual(code, "auth-code")
        self.assertEqual(state.page_type, "oauth_callback")
        client._browser_capture_callback.assert_called_once()

    def test_reuse_session_and_get_tokens_marks_callback_not_landed(self):
        client = self._make_reuse_client(
            FlowState(
                page_type="external_url",
                continue_url="https://chatgpt.com/",
                current_url="https://auth.openai.com/about-you",
            )
        )

        with mock.patch.object(client, "_follow_flow_state", return_value=(False, "callback missing")):
            ok, detail = client.reuse_session_and_get_tokens()

        self.assertFalse(ok)
        self.assertIn("注册回调落地失败", detail)
        self.assertEqual(client.last_token_exchange_error_code, "callback_not_landed")

    def test_reuse_session_and_get_tokens_marks_session_cookie_missing(self):
        client = self._make_reuse_client(
            FlowState(
                page_type="chatgpt_home",
                current_url="https://chatgpt.com/",
            )
        )
        client.session.get = mock.Mock(return_value=mock.Mock(status_code=200, url="https://chatgpt.com/"))

        with mock.patch.object(client, "get_next_auth_session_token", side_effect=["", "", "", "", ""]):
            with mock.patch("time.sleep", return_value=None):
                ok, detail = client.reuse_session_and_get_tokens()

        self.assertFalse(ok)
        self.assertIn("缺少 ChatGPT session-token", detail)
        self.assertEqual(client.last_token_exchange_error_code, "session_cookie_missing")

    def test_reuse_session_and_get_tokens_marks_auth_session_missing_access_token(self):
        client = self._make_reuse_client(
            FlowState(
                page_type="chatgpt_home",
                current_url="https://chatgpt.com/",
            )
        )

        with mock.patch.object(client, "get_next_auth_session_token", return_value="sess-token"):
            with mock.patch.object(
                client,
                "fetch_chatgpt_session",
                return_value=(False, "/api/auth/session 未返回 accessToken"),
            ):
                ok, detail = client.reuse_session_and_get_tokens()

        self.assertFalse(ok)
        self.assertEqual(detail, "/api/auth/session 未返回 accessToken")
        self.assertEqual(
            client.last_token_exchange_error_code,
            "auth_session_missing_access_token",
        )


if __name__ == "__main__":
    unittest.main()
