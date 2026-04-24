import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sqlmodel import Session, SQLModel, create_engine, select

import core.db as core_db
from core.db import TaskLog
from scripts import register_chatgpt_accounts, rescue_stuck_accounts


class ChatGPTTaskLoggingTests(unittest.TestCase):
    def test_build_task_log_detail_normalizes_schema(self):
        detail = core_db.build_task_log_detail(
            {
                "mode": "refresh_token",
                "stage": "failed",
                "elapsed_ms": 321,
                "has_access_token": True,
            },
            task_id="task-123",
            source="manual",
            error="[stage=authorize_continue] broken pipe",
        )

        self.assertEqual(detail["task_id"], "task-123")
        self.assertEqual(detail["run_id"], "task-123")
        self.assertEqual(detail["source"], "manual")
        self.assertEqual(detail["registration_mode"], "refresh_token")
        self.assertEqual(detail["mode"], "refresh_token")
        self.assertEqual(detail["last_stage"], "authorize_continue")
        self.assertEqual(detail["stages_trace"], ["authorize_continue"])
        self.assertEqual(detail["stage"], "failed")
        self.assertTrue(detail["has_access_token"])
        self.assertFalse(detail["has_refresh_token"])
        self.assertFalse(detail["has_session_token"])

    def test_write_task_log_persists_normalized_detail(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            test_db = Path(tmp_dir) / "task_logs.db"
            engine = create_engine(f"sqlite:///{test_db}")
            SQLModel.metadata.create_all(engine)

            with mock.patch.object(core_db, "engine", engine):
                core_db.write_task_log(
                    "chatgpt",
                    "demo@example.com",
                    "failed",
                    error="[stage=otp] timeout",
                    detail={"mode": "access_token_only"},
                    source="rescue_script",
                    run_id="rescue-run-1",
                )

                with Session(engine) as session:
                    row = session.exec(select(TaskLog)).one()
                    payload = json.loads(row.detail_json)

            self.assertEqual(row.platform, "chatgpt")
            self.assertEqual(row.email, "demo@example.com")
            self.assertEqual(payload["source"], "rescue_script")
            self.assertEqual(payload["run_id"], "rescue-run-1")
            self.assertEqual(payload["registration_mode"], "access_token_only")
            self.assertEqual(payload["last_stage"], "otp")
            self.assertEqual(payload["stages_trace"], ["otp"])

    def test_rescue_log_task_uses_shared_writer(self):
        with mock.patch(
            "scripts.rescue_stuck_accounts.write_task_log",
            create=True,
        ) as mocked:
            rescue_stuck_accounts.log_task(
                "chatgpt",
                "demo@example.com",
                "success",
                "",
                {"elapsed": 1.2},
            )

        mocked.assert_called_once()
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["source"], "rescue_script")
        self.assertEqual(kwargs["detail"]["elapsed"], 1.2)

    def test_register_script_log_task_uses_shared_writer(self):
        with mock.patch(
            "scripts.register_chatgpt_accounts.write_task_log",
            create=True,
        ) as mocked:
            register_chatgpt_accounts._log_task(
                "chatgpt",
                "demo@example.com",
                "failed",
                "[register_script] boom",
                {"source": "register_script", "executor_type": "protocol"},
            )

        mocked.assert_called_once()
        kwargs = mocked.call_args.kwargs
        self.assertEqual(kwargs["source"], "register_script")
        self.assertEqual(kwargs["detail"]["executor_type"], "protocol")


if __name__ == "__main__":
    unittest.main()
