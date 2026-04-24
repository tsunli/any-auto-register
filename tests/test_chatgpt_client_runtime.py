import time
import unittest
from unittest import mock

from core.task_runtime import SkipCurrentAttemptRequested
from platforms.chatgpt.chatgpt_client import ChatGPTClient


class _DummyResponse:
    def __init__(self, status_code=200, text="", url="https://chatgpt.com/"):
        self.status_code = status_code
        self.text = text
        self.url = url


class ChatGPTClientRuntimeTests(unittest.TestCase):
    def _make_client(self):
        client = ChatGPTClient.__new__(ChatGPTClient)
        client.proxy = None
        client._session_req_count = 0
        client._session_born_at = time.time()
        client._session_max_req = 80
        client._session_max_age = 240
        client._ip_cooldown_enabled = True
        client._ip_cooldown_seconds = 600
        client._log = lambda _msg: None
        client.session = mock.Mock()
        return client

    def test_http_recreates_session_and_retries_once_on_broken_pipe(self):
        client = self._make_client()
        first_session = mock.Mock()
        second_session = mock.Mock()
        first_session.get.side_effect = BrokenPipeError("broken pipe")
        second_session.get.return_value = _DummyResponse(status_code=200)
        client.session = first_session

        def _swap_session():
            client.session = second_session
            client._session_req_count = 0
            client._session_born_at = time.time()

        client._recreate_session = mock.Mock(side_effect=_swap_session)

        response = client._http("GET", "https://chatgpt.com/")

        self.assertEqual(response.status_code, 200)
        client._recreate_session.assert_called_once()
        second_session.get.assert_called_once()

    def test_http_raises_skip_when_second_attempt_still_broken(self):
        client = self._make_client()
        first_session = mock.Mock()
        second_session = mock.Mock()
        first_session.get.side_effect = BrokenPipeError("broken pipe")
        second_session.get.side_effect = BrokenPipeError("still broken")
        client.session = first_session

        def _swap_session():
            client.session = second_session
            client._session_req_count = 0
            client._session_born_at = time.time()

        client._recreate_session = mock.Mock(side_effect=_swap_session)

        with self.assertRaises(SkipCurrentAttemptRequested):
            client._http("GET", "https://chatgpt.com/")

    def test_http_rotates_session_when_request_limit_reached(self):
        client = self._make_client()
        client._session_req_count = 5
        client._session_max_req = 5
        client.session.get.return_value = _DummyResponse(status_code=200)

        def _rotate():
            client._session_req_count = 0
            client._session_born_at = time.time()

        client._recreate_session = mock.Mock(side_effect=_rotate)

        client._http("GET", "https://chatgpt.com/")

        client._recreate_session.assert_called_once()

    def test_http_cools_down_proxy_on_rate_limit(self):
        client = self._make_client()
        client.proxy = "http://proxy.local:8080"
        client.session.get.return_value = _DummyResponse(status_code=409)
        client._cool_down_current_proxy = mock.Mock()

        with self.assertRaises(SkipCurrentAttemptRequested):
            client._http("GET", "https://chatgpt.com/")

        client._cool_down_current_proxy.assert_called_once()

    def test_http_cools_down_proxy_on_cloudflare_403(self):
        client = self._make_client()
        client.proxy = "http://proxy.local:8080"
        client.session.get.return_value = _DummyResponse(
            status_code=403, text="<!DOCTYPE html>Just a moment..."
        )
        client._cool_down_current_proxy = mock.Mock()

        with self.assertRaises(SkipCurrentAttemptRequested):
            client._http("GET", "https://chatgpt.com/")

        client._cool_down_current_proxy.assert_called_once()


if __name__ == "__main__":
    unittest.main()
