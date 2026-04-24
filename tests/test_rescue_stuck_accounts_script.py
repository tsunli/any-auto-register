import importlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from core.base_platform import Account


def _import_rescue_script():
    module_name = "scripts.rescue_stuck_accounts"
    sys.modules.pop(module_name, None)

    fake_oauth_client = types.ModuleType("platforms.chatgpt.oauth_client")
    fake_oauth_client.is_email_add_phone_blacklisted = lambda _email: False

    fake_register_script = types.ModuleType("scripts.register_chatgpt_accounts")
    fake_register_script._sync_saved_account_to_cliproxyapi = lambda *args, **kwargs: {
        "ok": False,
        "uploaded": False,
        "skipped": False,
        "message": "",
        "remote_state": "",
        "results": [],
    }
    fake_register_script.load_successfully_registered_emails = lambda: set()

    fake_config_store_module = types.ModuleType("core.config_store")

    class _FakeConfigStore:
        def get_all(self):
            return {}

        def get(self, _key, default=""):
            return default

    fake_config_store_module.config_store = _FakeConfigStore()

    with mock.patch.dict(
        sys.modules,
        {
            "platforms.chatgpt.oauth_client": fake_oauth_client,
            "scripts.register_chatgpt_accounts": fake_register_script,
            "core.config_store": fake_config_store_module,
        },
    ):
        return importlib.import_module(module_name)


class RescueStuckAccountsScriptTests(unittest.TestCase):
    def test_load_registered_emails_delegates_to_successful_helper(self):
        rescue_stuck_accounts = _import_rescue_script()

        with mock.patch.object(
            rescue_stuck_accounts,
            "load_successfully_registered_emails",
            return_value={"ok@example.com", "trial@example.com"},
        ) as helper_mock:
            emails = rescue_stuck_accounts.load_registered_emails()

        self.assertEqual(emails, {"ok@example.com", "trial@example.com"})
        helper_mock.assert_called_once_with()

    def test_rescue_one_adds_cliproxyapi_detail_when_sync_enabled(self):
        rescue_stuck_accounts = _import_rescue_script()
        platform = SimpleNamespace(
            register=mock.Mock(
                return_value=Account(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    extra={
                        "session_token": "session-token",
                        "chatgpt_registration_mode": "access_token_only",
                        "last_stage": "token_exchange",
                        "stages_trace": ["otp", "token_exchange"],
                    },
                )
            ),
            last_error_metadata={},
        )

        with mock.patch.object(rescue_stuck_accounts, "build_platform", return_value=platform):
            with mock.patch.object(
                rescue_stuck_accounts,
                "save_account",
                return_value=SimpleNamespace(id=321),
            ):
                with mock.patch.object(
                    rescue_stuck_accounts,
                    "_sync_saved_account_to_cliproxyapi",
                    return_value={
                        "ok": True,
                        "uploaded": True,
                        "skipped": False,
                        "message": "补传完成，远端状态=usable",
                        "remote_state": "usable",
                        "results": [],
                    },
                ) as sync_mock:
                    ok, err, detail = rescue_stuck_accounts.rescue_one(
                        "demo@example.com",
                        {"chatgpt_registration_mode": "access_token_only"},
                        cliproxyapi_sync=True,
                        cliproxyapi_api_url="http://127.0.0.1:8317",
                        cliproxyapi_api_key="demo",
                    )

        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.assertTrue(detail["cliproxyapi_auto_sync"])
        self.assertTrue(detail["cliproxyapi_sync_ok"])
        self.assertTrue(detail["cliproxyapi_uploaded"])
        self.assertFalse(detail["cliproxyapi_skipped"])
        self.assertEqual(detail["cliproxyapi_remote_state"], "usable")
        self.assertEqual(detail["cliproxyapi_message"], "补传完成，远端状态=usable")
        sync_mock.assert_called_once_with(
            321,
            api_url="http://127.0.0.1:8317",
            api_key="demo",
        )

    def test_rescue_one_keeps_success_when_cliproxyapi_sync_fails(self):
        rescue_stuck_accounts = _import_rescue_script()
        platform = SimpleNamespace(
            register=mock.Mock(
                return_value=Account(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    extra={"chatgpt_registration_mode": "access_token_only"},
                )
            ),
            last_error_metadata={},
        )

        with mock.patch.object(rescue_stuck_accounts, "build_platform", return_value=platform):
            with mock.patch.object(
                rescue_stuck_accounts,
                "save_account",
                return_value=SimpleNamespace(id=654),
            ):
                with mock.patch.object(
                    rescue_stuck_accounts,
                    "_sync_saved_account_to_cliproxyapi",
                    return_value={
                        "ok": False,
                        "uploaded": False,
                        "skipped": False,
                        "message": "CLIProxyAPI 无法连接",
                        "remote_state": "unreachable",
                        "results": [],
                    },
                ):
                    ok, err, detail = rescue_stuck_accounts.rescue_one(
                        "demo@example.com",
                        {"chatgpt_registration_mode": "access_token_only"},
                        cliproxyapi_sync=True,
                    )

        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.assertTrue(detail["cliproxyapi_auto_sync"])
        self.assertFalse(detail["cliproxyapi_sync_ok"])
        self.assertFalse(detail["cliproxyapi_uploaded"])
        self.assertEqual(detail["cliproxyapi_remote_state"], "unreachable")
        self.assertEqual(detail["cliproxyapi_message"], "CLIProxyAPI 无法连接")

    def test_rescue_one_skips_cliproxyapi_sync_when_disabled(self):
        rescue_stuck_accounts = _import_rescue_script()
        platform = SimpleNamespace(
            register=mock.Mock(
                return_value=Account(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    extra={"chatgpt_registration_mode": "access_token_only"},
                )
            ),
            last_error_metadata={},
        )

        with mock.patch.object(rescue_stuck_accounts, "build_platform", return_value=platform):
            with mock.patch.object(
                rescue_stuck_accounts,
                "save_account",
                return_value=SimpleNamespace(id=987),
            ):
                with mock.patch.object(
                    rescue_stuck_accounts,
                    "_sync_saved_account_to_cliproxyapi",
                ) as sync_mock:
                    ok, err, detail = rescue_stuck_accounts.rescue_one(
                        "demo@example.com",
                        {"chatgpt_registration_mode": "access_token_only"},
                        cliproxyapi_sync=False,
                    )

        self.assertTrue(ok)
        self.assertEqual(err, "")
        self.assertFalse(detail["cliproxyapi_auto_sync"])
        self.assertFalse(detail["cliproxyapi_sync_ok"])
        self.assertFalse(detail["cliproxyapi_uploaded"])
        self.assertEqual(detail["cliproxyapi_message"], "")
        sync_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
