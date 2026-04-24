import unittest
from unittest.mock import patch

from api.tasks import RegisterTaskRequest, _create_task_record, _prepare_register_request, _run_register, _task_store
from core.base_mailbox import BaseMailbox, MailboxAccount
from core.base_platform import Account, BasePlatform


class _FakeMailbox(BaseMailbox):
    def get_email(self) -> MailboxAccount:
        return MailboxAccount(email="demo@example.com")

    def get_current_ids(self, account: MailboxAccount) -> set:
        return set()

    def wait_for_code(
        self,
        account: MailboxAccount,
        keyword: str = "",
        timeout: int = 120,
        before_ids: set = None,
        code_pattern: str = None,
        **kwargs,
    ) -> str:
        def poll_once():
            return None

        return self._run_polling_wait(
            timeout=timeout,
            poll_interval=0.01,
            poll_once=poll_once,
        )


class _FakePlatform(BasePlatform):
    name = "fake"
    display_name = "Fake"

    def __init__(self, config=None, mailbox=None):
        super().__init__(config)
        self.mailbox = mailbox

    def register(self, email: str, password: str = None) -> Account:
        account = self.mailbox.get_email()
        self.mailbox.wait_for_code(account, timeout=1)
        return Account(
            platform="fake",
            email=account.email,
            password=password or "pw",
        )

    def check_valid(self, account: Account) -> bool:
        return True


class _FakeChatGPTWorkspacePlatform(BasePlatform):
    name = "chatgpt"
    display_name = "ChatGPT"

    _counter = 0

    def __init__(self, config=None, mailbox=None):
        super().__init__(config)
        self.mailbox = mailbox

    @classmethod
    def reset_counter(cls):
        cls._counter = 0

    def register(self, email: str, password: str = None) -> Account:
        type(self)._counter += 1
        index = type(self)._counter
        return Account(
            platform="chatgpt",
            email=f"user{index}@example.com",
            password=password or "pw",
            extra={
                "workspace_id": f"ws-{index}",
                "chatgpt_registration_mode": "refresh_token",
                "chatgpt_token_source": "register",
                "last_stage": "token_exchange",
                "stages_trace": [
                    "authorize_continue",
                    "otp",
                    "token_exchange",
                ],
            },
        )

    def check_valid(self, account: Account) -> bool:
        return True


class _FakeChatGPTFailurePlatform(BasePlatform):
    name = "chatgpt"
    display_name = "ChatGPT"

    def __init__(self, config=None, mailbox=None):
        super().__init__(config)
        self.mailbox = mailbox
        self.last_error_metadata = {
            "last_stage": "token_exchange",
            "stages_trace": ["authorize_continue", "otp", "token_exchange"],
            "error_code": "session_cookie_missing",
        }

    def register(self, email: str, password: str = None) -> Account:
        raise RuntimeError("缺少 ChatGPT session-token，注册回调可能未完全落地")

    def check_valid(self, account: Account) -> bool:
        return True


class _AlwaysFailPlatform(BasePlatform):
    name = "fake"
    display_name = "Fake"

    def __init__(self, config=None, mailbox=None):
        super().__init__(config)
        self.mailbox = mailbox

    def register(self, email: str, password: str = None) -> Account:
        raise RuntimeError("simulated failure")

    def check_valid(self, account: Account) -> bool:
        return True


class _FailSuccessFailPlatform(BasePlatform):
    name = "fake"
    display_name = "Fake"
    _index = 0

    def __init__(self, config=None, mailbox=None):
        super().__init__(config)
        self.mailbox = mailbox

    @classmethod
    def reset_counter(cls):
        cls._index = 0

    def register(self, email: str, password: str = None) -> Account:
        type(self)._index += 1
        if type(self)._index in {1, 3}:
            raise RuntimeError(f"simulated failure {type(self)._index}")
        account = self.mailbox.get_email()
        return Account(platform="fake", email=account.email, password=password or "pw")

    def check_valid(self, account: Account) -> bool:
        return True


class _WhitelistSkipPlatform(BasePlatform):
    name = "fake"
    display_name = "Fake"

    def __init__(self, config=None, mailbox=None):
        super().__init__(config)
        self.mailbox = mailbox

    def register(self, email: str, password: str = None) -> Account:
        from core.task_runtime import SkipCurrentAttemptRequested

        raise SkipCurrentAttemptRequested("邮箱 demo@example.com 在 add_phone 黑名单中，跳过注册")

    def check_valid(self, account: Account) -> bool:
        return True


class _SkipWithMetadataPlatform(BasePlatform):
    name = "fake"
    display_name = "Fake"

    def __init__(self, config=None, mailbox=None):
        super().__init__(config)
        self.mailbox = mailbox
        self.last_error_metadata = {
            "last_stage": "workspace_select",
            "stages_trace": ["otp", "workspace_select"],
            "error_code": "add_phone_workspace_or_callback_missing",
        }

    def register(self, email: str, password: str = None) -> Account:
        from core.task_runtime import SkipCurrentAttemptRequested

        raise SkipCurrentAttemptRequested("add_phone 风控: passwordless 登录后仍停留在 add_phone")

    def check_valid(self, account: Account) -> bool:
        return True


class RegisterTaskControlFlowTests(unittest.TestCase):
    def _build_request(self, **overrides):
        payload = {
            "platform": "fake",
            "count": 1,
            "concurrency": 1,
            "proxy": "http://proxy.local:8080",
            "extra": {"mail_provider": "fake"},
        }
        payload.update(overrides)
        return RegisterTaskRequest(**payload)

    def _run_with_control(self, task_id: str, *, stop: bool = False, skip: bool = False):
        req = self._build_request()
        _create_task_record(task_id, req, "manual", None)
        if stop:
            _task_store.request_stop(task_id)
        if skip:
            _task_store.request_skip_current(task_id)

        with (
            patch("core.registry.get", return_value=_FakePlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("core.db.save_account", side_effect=lambda account: account),
            patch("api.tasks._save_task_log"),
        ):
            _run_register(task_id, req)

        return _task_store.snapshot(task_id)

    def test_prepare_register_request_uses_config_default_consecutive_fail_threshold(self):
        req = RegisterTaskRequest(
            platform="fake",
            count=1,
            concurrency=1,
            proxy="http://proxy.local:8080",
            extra={"mail_provider": "fake"},
            consecutive_fail_threshold=None,
        )

        with patch("core.config_store.config_store.get", return_value="9"):
            prepared = _prepare_register_request(req)

        self.assertEqual(prepared.consecutive_fail_threshold, 9)

    def test_skip_current_marks_attempt_as_skipped(self):
        snapshot = self._run_with_control("task-control-skip", skip=True)

        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["success"], 0)
        self.assertEqual(snapshot["skipped"], 1)
        self.assertEqual(snapshot["errors"], [])

    def test_stop_marks_task_as_stopped(self):
        snapshot = self._run_with_control("task-control-stop", stop=True)

        self.assertEqual(snapshot["status"], "stopped")
        self.assertEqual(snapshot["success"], 0)
        self.assertEqual(snapshot["skipped"], 0)
        self.assertEqual(snapshot["errors"], [])

    def test_chatgpt_logs_workspace_progress_after_each_success(self):
        task_id = "task-chatgpt-workspace-progress"
        req = self._build_request(platform="chatgpt", count=2, concurrency=1)
        _create_task_record(task_id, req, "manual", None)
        _FakeChatGPTWorkspacePlatform.reset_counter()

        with (
            patch("core.registry.get", return_value=_FakeChatGPTWorkspacePlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("core.db.save_account", side_effect=lambda account: account),
            patch("api.tasks._save_task_log"),
        ):
            _run_register(task_id, req)

        snapshot = _task_store.snapshot(task_id)
        joined_logs = "\n".join(snapshot["logs"])

        self.assertIn("workspace进度: 1/2", joined_logs)
        self.assertIn("workspace进度: 2/2", joined_logs)

    def test_chatgpt_success_log_includes_task_log_schema_fields(self):
        task_id = "task-chatgpt-log-detail"
        req = self._build_request(platform="chatgpt", count=1, concurrency=1)
        _create_task_record(task_id, req, "manual", None)
        _FakeChatGPTWorkspacePlatform.reset_counter()

        with (
            patch("core.registry.get", return_value=_FakeChatGPTWorkspacePlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("core.db.save_account", side_effect=lambda account: account),
            patch("api.tasks._save_task_log") as mocked_save_log,
        ):
            _run_register(task_id, req)

        mocked_save_log.assert_called_once()
        _, _, status = mocked_save_log.call_args.args[:3]
        detail = mocked_save_log.call_args.kwargs["detail"]

        self.assertEqual(status, "success")
        self.assertEqual(detail["task_id"], task_id)
        self.assertEqual(detail["source"], "manual")
        self.assertEqual(detail["registration_mode"], "refresh_token")
        self.assertEqual(detail["last_stage"], "token_exchange")
        self.assertEqual(
            detail["stages_trace"],
            ["authorize_continue", "otp", "token_exchange"],
        )

    def test_chatgpt_failure_log_includes_platform_error_metadata(self):
        task_id = "task-chatgpt-log-failure-detail"
        req = self._build_request(platform="chatgpt", count=1, concurrency=1)
        _create_task_record(task_id, req, "manual", None)

        with (
            patch("core.registry.get", return_value=_FakeChatGPTFailurePlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("api.tasks._save_task_log") as mocked_save_log,
        ):
            _run_register(task_id, req)

        mocked_save_log.assert_called_once()
        detail = mocked_save_log.call_args.kwargs["detail"]
        self.assertEqual(detail["task_id"], task_id)
        self.assertEqual(detail["source"], "manual")
        self.assertEqual(detail["last_stage"], "token_exchange")
        self.assertEqual(
            detail["stages_trace"],
            ["authorize_continue", "otp", "token_exchange"],
        )
        self.assertEqual(detail["error_code"], "session_cookie_missing")

    def test_consecutive_fail_threshold_stops_task_after_limit(self):
        task_id = "task-consecutive-fail-stop"
        req = self._build_request(count=3, concurrency=1, consecutive_fail_threshold=2)
        _create_task_record(task_id, req, "manual", None)

        with (
            patch("core.registry.get", return_value=_AlwaysFailPlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("api.tasks._save_task_log"),
        ):
            _run_register(task_id, req)

        snapshot = _task_store.snapshot(task_id)
        self.assertEqual(snapshot["status"], "stopped")
        self.assertIn("[ABORT] consecutive fail threshold reached", "\n".join(snapshot["logs"]))

    def test_success_resets_consecutive_fail_counter(self):
        task_id = "task-consecutive-fail-reset"
        req = self._build_request(count=3, concurrency=1, consecutive_fail_threshold=2)
        _create_task_record(task_id, req, "manual", None)
        _FailSuccessFailPlatform.reset_counter()

        with (
            patch("core.registry.get", return_value=_FailSuccessFailPlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("core.db.save_account", side_effect=lambda account: account),
            patch("api.tasks._save_task_log"),
        ):
            _run_register(task_id, req)

        snapshot = _task_store.snapshot(task_id)
        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["success"], 1)
        self.assertEqual(len(snapshot["errors"]), 2)
        self.assertNotIn("[ABORT] consecutive fail threshold reached", "\n".join(snapshot["logs"]))

    def test_add_phone_blacklist_skip_does_not_trigger_consecutive_fail_abort(self):
        task_id = "task-consecutive-fail-whitelist-skip"
        req = self._build_request(count=2, concurrency=1, consecutive_fail_threshold=1)
        _create_task_record(task_id, req, "manual", None)

        with (
            patch("core.registry.get", return_value=_WhitelistSkipPlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("api.tasks._save_task_log"),
        ):
            _run_register(task_id, req)

        snapshot = _task_store.snapshot(task_id)
        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["skipped"], 2)
        self.assertNotIn("[ABORT] consecutive fail threshold reached", "\n".join(snapshot["logs"]))

    def test_skip_log_includes_platform_error_metadata(self):
        task_id = "task-skip-log-error-metadata"
        req = self._build_request(count=1, concurrency=1)
        _create_task_record(task_id, req, "manual", None)

        with (
            patch("core.registry.get", return_value=_SkipWithMetadataPlatform),
            patch("core.base_mailbox.create_mailbox", return_value=_FakeMailbox()),
            patch("api.tasks._save_task_log") as mocked_save_log,
        ):
            _run_register(task_id, req)

        mocked_save_log.assert_called_once()
        detail = mocked_save_log.call_args.kwargs["detail"]
        self.assertEqual(detail["last_stage"], "workspace_select")
        self.assertEqual(
            detail["stages_trace"],
            ["otp", "workspace_select"],
        )
        self.assertEqual(detail["error_code"], "add_phone_workspace_or_callback_missing")


if __name__ == "__main__":
    unittest.main()
