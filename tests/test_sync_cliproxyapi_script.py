import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sqlmodel import Session, SQLModel, create_engine

import core.db as core_db
from core.db import AccountModel
from scripts import sync_chatgpt_cliproxyapi_accounts as sync_script


class SyncCliproxyapiScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.engine = create_engine(f"sqlite:///{Path(self.tmp_dir.name) / 'accounts.db'}")
        SQLModel.metadata.create_all(self.engine)

        with Session(self.engine) as session:
            for idx, status in enumerate(["registered", "trial", "subscribed", "invalid"], start=1):
                acc = AccountModel(
                    platform="chatgpt",
                    email=f"user{idx}@example.com",
                    password="pw",
                    status=status,
                    token=f"token-{idx}",
                    user_id=f"acct-{idx}",
                    extra_json='{"access_token":"token-%s"}' % idx,
                )
                session.add(acc)
            session.commit()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_select_accounts_defaults_to_registered_trial_subscribed(self):
        with Session(self.engine) as session:
            rows = sync_script.select_accounts(session)

        self.assertEqual(
            [row.email for row in rows],
            ["user1@example.com", "user2@example.com", "user3@example.com"],
        )

    def test_select_accounts_supports_email_and_limit(self):
        with Session(self.engine) as session:
            rows = sync_script.select_accounts(
                session,
                email_contains="user",
                statuses=["registered", "trial", "subscribed", "invalid"],
                limit=2,
            )

        self.assertEqual(len(rows), 2)
        self.assertEqual([row.email for row in rows], ["user1@example.com", "user2@example.com"])

    def test_sync_accounts_updates_db_when_enabled(self):
        with Session(self.engine) as session:
            rows = sync_script.select_accounts(session)
            result_map = {
                int(rows[0].id): {"uploaded": True, "remote_state": "usable", "message": "ok"},
                int(rows[1].id): {"uploaded": False, "remote_state": "not_found", "message": "missing"},
                int(rows[2].id): {"uploaded": False, "remote_state": "unreachable", "message": "down"},
            }

            with mock.patch(
                "scripts.sync_chatgpt_cliproxyapi_accounts.sync_chatgpt_cliproxyapi_status_batch",
                return_value=result_map,
            ) as batch_mock:
                with mock.patch(
                    "scripts.sync_chatgpt_cliproxyapi_accounts.update_account_model_cliproxy_sync",
                ) as update_mock:
                    summary = sync_script.sync_accounts(
                        session,
                        rows,
                        write_db=True,
                        api_url="http://127.0.0.1:8317",
                        api_key="demo",
                    )

        batch_mock.assert_called_once()
        self.assertEqual(update_mock.call_count, 3)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["usable"], 1)
        self.assertEqual(summary["not_found"], 1)
        self.assertEqual(summary["unreachable"], 1)

    def test_sync_accounts_skips_db_write_when_disabled(self):
        with Session(self.engine) as session:
            rows = sync_script.select_accounts(session)
            result_map = {
                int(rows[0].id): {"uploaded": True, "remote_state": "usable", "message": "ok"},
                int(rows[1].id): {"uploaded": False, "remote_state": "not_found", "message": "missing"},
                int(rows[2].id): {"uploaded": False, "remote_state": "unreachable", "message": "down"},
            }

            with mock.patch(
                "scripts.sync_chatgpt_cliproxyapi_accounts.sync_chatgpt_cliproxyapi_status_batch",
                return_value=result_map,
            ):
                with mock.patch(
                    "scripts.sync_chatgpt_cliproxyapi_accounts.update_account_model_cliproxy_sync",
                ) as update_mock:
                    summary = sync_script.sync_accounts(session, rows, write_db=False)

        update_mock.assert_not_called()
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["usable"], 1)


if __name__ == "__main__":
    unittest.main()
