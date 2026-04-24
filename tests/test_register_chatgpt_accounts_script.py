import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from sqlmodel import Session, SQLModel, create_engine

from core.base_platform import Account
from core.db import AccountModel
from scripts import register_chatgpt_accounts


class RegisterChatGPTAccountsScriptTests(unittest.TestCase):
    def test_load_successfully_registered_emails_filters_to_success_statuses(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            engine = create_engine(f"sqlite:///{Path(tmp_dir) / 'accounts.db'}")
            SQLModel.metadata.create_all(engine)
            with Session(engine) as session:
                for email, status in (
                    ("ok1@example.com", "registered"),
                    ("ok2@example.com", "trial"),
                    ("ok3@example.com", "subscribed"),
                    ("skip@example.com", "invalid"),
                ):
                    row = AccountModel(
                        platform="chatgpt",
                        email=email,
                        password="pw",
                        status=status,
                    )
                    session.add(row)
                session.commit()

            with mock.patch.object(register_chatgpt_accounts, "engine", engine):
                emails = register_chatgpt_accounts.load_successfully_registered_emails()

        self.assertEqual(
            emails,
            {"ok1@example.com", "ok2@example.com", "ok3@example.com"},
        )

    def test_registered_email_skipping_mailbox_retries_until_fresh_email(self):
        mailbox = SimpleNamespace(
            get_email=mock.Mock(
                side_effect=[
                    SimpleNamespace(email="used@example.com"),
                    SimpleNamespace(email="fresh@example.com"),
                ]
            ),
            get_current_ids=mock.Mock(return_value=set()),
            wait_for_code=mock.Mock(return_value="123456"),
        )
        wrapper = register_chatgpt_accounts._RegisteredEmailSkippingMailbox(
            mailbox=mailbox,
            successful_emails={"used@example.com"},
            max_attempts=3,
        )
        logs: list[str] = []
        wrapper._log_fn = logs.append

        account = wrapper.get_email()

        self.assertEqual(account.email, "fresh@example.com")
        self.assertEqual(mailbox.get_email.call_count, 2)
        self.assertTrue(any("used@example.com" in entry for entry in logs))

    def test_registered_email_skipping_mailbox_scans_beyond_legacy_50_attempts(self):
        used_accounts = [SimpleNamespace(email=f"used{idx}@example.com") for idx in range(60)]
        mailbox = SimpleNamespace(
            get_email=mock.Mock(side_effect=used_accounts + [SimpleNamespace(email="fresh@example.com")]),
            get_current_ids=mock.Mock(return_value=set()),
            wait_for_code=mock.Mock(return_value="123456"),
        )
        wrapper = register_chatgpt_accounts._RegisteredEmailSkippingMailbox(
            mailbox=mailbox,
            successful_emails={item.email for item in used_accounts},
        )

        account = wrapper.get_email()

        self.assertEqual(account.email, "fresh@example.com")
        self.assertEqual(mailbox.get_email.call_count, 61)

    def test_sync_saved_account_to_cliproxyapi_loads_row_and_delegates(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            engine = create_engine(f"sqlite:///{Path(tmp_dir) / 'accounts.db'}")
            SQLModel.metadata.create_all(engine)
            with Session(engine) as session:
                row = AccountModel(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    status="registered",
                    user_id="acct-1",
                )
                row.set_extra({"access_token": "access-token"})
                session.add(row)
                session.commit()
                session.refresh(row)
                account_id = row.id

            fake_outcome = {
                "ok": True,
                "uploaded": True,
                "skipped": False,
                "message": "补传完成，远端状态=usable",
                "results": [{"name": "CLIProxyAPI 复核", "ok": True, "msg": "usable"}],
            }
            fake_sync_state = {"remote_state": "usable"}

            with mock.patch.object(register_chatgpt_accounts, "engine", engine):
                with mock.patch(
                    "services.chatgpt_sync.backfill_chatgpt_account_to_cpa",
                    return_value=fake_outcome,
                ) as backfill_mock:
                    with mock.patch(
                        "services.chatgpt_sync.get_cliproxy_sync_state",
                        return_value=fake_sync_state,
                    ):
                        result = register_chatgpt_accounts._sync_saved_account_to_cliproxyapi(
                            account_id,
                            api_url="http://127.0.0.1:8317",
                            api_key="demo",
                        )

        self.assertTrue(result["ok"])
        self.assertTrue(result["uploaded"])
        self.assertEqual(result["remote_state"], "usable")
        backfill_mock.assert_called_once()
        row = backfill_mock.call_args.args[0]
        self.assertEqual(row.email, "demo@example.com")
        self.assertEqual(backfill_mock.call_args.kwargs["api_url"], "http://127.0.0.1:8317")
        self.assertEqual(backfill_mock.call_args.kwargs["api_key"], "demo")

    def test_register_one_adds_cliproxyapi_detail_when_sync_enabled(self):
        platform = SimpleNamespace(
            register=mock.Mock(
                return_value=Account(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    extra={
                        "refresh_token": "refresh-token",
                        "chatgpt_registration_mode": "refresh_token",
                        "last_stage": "token_exchange",
                        "stages_trace": ["otp", "token_exchange"],
                    },
                )
            ),
            last_error_metadata={},
        )

        with mock.patch.object(register_chatgpt_accounts, "_build_platform", return_value=platform):
            with mock.patch.object(
                register_chatgpt_accounts,
                "save_account",
                return_value=SimpleNamespace(id=123),
            ):
                with mock.patch.object(
                    register_chatgpt_accounts,
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
                    ok, account, detail = register_chatgpt_accounts._register_one(
                        object,
                        email=None,
                        password=None,
                        extra={},
                        proxy=None,
                        executor_type="protocol",
                        captcha_solver="yescaptcha",
                        cliproxyapi_sync=True,
                        cliproxyapi_api_url="http://127.0.0.1:8317",
                        cliproxyapi_api_key="demo",
                    )

        self.assertTrue(ok)
        self.assertEqual(account.email, "demo@example.com")
        self.assertTrue(detail["cliproxyapi_auto_sync"])
        self.assertTrue(detail["cliproxyapi_sync_ok"])
        self.assertTrue(detail["cliproxyapi_uploaded"])
        self.assertFalse(detail["cliproxyapi_skipped"])
        self.assertEqual(detail["cliproxyapi_remote_state"], "usable")
        self.assertEqual(detail["cliproxyapi_message"], "补传完成，远端状态=usable")
        sync_mock.assert_called_once_with(
            123,
            api_url="http://127.0.0.1:8317",
            api_key="demo",
        )

    def test_register_one_keeps_success_when_cliproxyapi_sync_fails(self):
        platform = SimpleNamespace(
            register=mock.Mock(
                return_value=Account(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    extra={"chatgpt_registration_mode": "refresh_token"},
                )
            ),
            last_error_metadata={},
        )

        with mock.patch.object(register_chatgpt_accounts, "_build_platform", return_value=platform):
            with mock.patch.object(
                register_chatgpt_accounts,
                "save_account",
                return_value=SimpleNamespace(id=456),
            ):
                with mock.patch.object(
                    register_chatgpt_accounts,
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
                    ok, _, detail = register_chatgpt_accounts._register_one(
                        object,
                        email=None,
                        password=None,
                        extra={},
                        proxy=None,
                        executor_type="protocol",
                        captcha_solver="yescaptcha",
                        cliproxyapi_sync=True,
                    )

        self.assertTrue(ok)
        self.assertTrue(detail["cliproxyapi_auto_sync"])
        self.assertFalse(detail["cliproxyapi_sync_ok"])
        self.assertFalse(detail["cliproxyapi_uploaded"])
        self.assertEqual(detail["cliproxyapi_remote_state"], "unreachable")
        self.assertEqual(detail["cliproxyapi_message"], "CLIProxyAPI 无法连接")

    def test_register_one_skips_fixed_email_when_already_successful(self):
        with mock.patch.object(register_chatgpt_accounts, "_build_platform") as build_mock:
            ok, payload, detail = register_chatgpt_accounts._register_one(
                object,
                email="demo@example.com",
                password=None,
                extra={},
                proxy=None,
                executor_type="protocol",
                captcha_solver="yescaptcha",
                cliproxyapi_sync=True,
                successful_emails={"demo@example.com"},
            )

        self.assertFalse(ok)
        self.assertEqual(payload, "skipped")
        self.assertEqual(detail["skip_reason"], "already_successfully_registered")
        self.assertEqual(detail["skip_message"], "邮箱已成功注册，跳过")
        build_mock.assert_not_called()

    def test_register_one_allows_fixed_email_when_allow_reregister_enabled(self):
        platform = SimpleNamespace(
            register=mock.Mock(
                return_value=Account(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    extra={"chatgpt_registration_mode": "refresh_token"},
                )
            ),
            last_error_metadata={},
        )

        with mock.patch.object(register_chatgpt_accounts, "_build_platform", return_value=platform) as build_mock:
            with mock.patch.object(
                register_chatgpt_accounts,
                "save_account",
                return_value=SimpleNamespace(id=159),
            ):
                with mock.patch.object(
                    register_chatgpt_accounts,
                    "_sync_saved_account_to_cliproxyapi",
                    return_value={
                        "ok": True,
                        "uploaded": False,
                        "skipped": True,
                        "message": "远端已存在 (usable)，跳过上传",
                        "remote_state": "usable",
                        "results": [],
                    },
                ):
                    ok, _, detail = register_chatgpt_accounts._register_one(
                        object,
                        email="demo@example.com",
                        password=None,
                        extra={},
                        proxy=None,
                        executor_type="protocol",
                        captcha_solver="yescaptcha",
                        cliproxyapi_sync=True,
                        successful_emails={"demo@example.com"},
                        allow_reregister=True,
                    )

        self.assertTrue(ok)
        self.assertEqual(detail["email"], "demo@example.com")
        self.assertEqual(detail["skip_reason"], "")
        build_mock.assert_called_once()
        self.assertTrue(build_mock.call_args.kwargs["allow_reregister"])

    def test_register_one_skips_cliproxyapi_sync_when_disabled(self):
        platform = SimpleNamespace(
            register=mock.Mock(
                return_value=Account(
                    platform="chatgpt",
                    email="demo@example.com",
                    password="pw",
                    token="access-token",
                    extra={"chatgpt_registration_mode": "refresh_token"},
                )
            ),
            last_error_metadata={},
        )

        with mock.patch.object(register_chatgpt_accounts, "_build_platform", return_value=platform):
            with mock.patch.object(
                register_chatgpt_accounts,
                "save_account",
                return_value=SimpleNamespace(id=789),
            ):
                with mock.patch.object(
                    register_chatgpt_accounts,
                    "_sync_saved_account_to_cliproxyapi",
                ) as sync_mock:
                    ok, _, detail = register_chatgpt_accounts._register_one(
                        object,
                        email=None,
                        password=None,
                        extra={},
                        proxy=None,
                        executor_type="protocol",
                        captcha_solver="yescaptcha",
                        cliproxyapi_sync=False,
                    )

        self.assertTrue(ok)
        self.assertFalse(detail["cliproxyapi_auto_sync"])
        self.assertFalse(detail["cliproxyapi_sync_ok"])
        self.assertFalse(detail["cliproxyapi_uploaded"])
        self.assertEqual(detail["cliproxyapi_message"], "")
        sync_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
