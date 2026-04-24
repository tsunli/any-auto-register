"""
OAuth 客户端模块 - 处理 Codex OAuth 登录流程
"""

import time
import secrets
import uuid
import json
import random
from urllib.parse import urlparse, parse_qs
from core.proxy_utils import build_requests_proxy_config
from pathlib import Path as _Path
from core.task_runtime import SkipCurrentAttemptRequested, TaskInterruption

_ADD_PHONE_BLACKLIST_FILE = (
    _Path(__file__).resolve().parents[2] / "mail" / "add_phone_blacklist.json"
)


def _append_add_phone_blacklist(email: str, reason: str = "") -> None:
    """把命中 add_phone 风控的邮箱写入持久化黑名单。"""
    email = (email or "").strip().lower()
    if not email:
        return
    try:
        _ADD_PHONE_BLACKLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if _ADD_PHONE_BLACKLIST_FILE.exists():
            try:
                existing = json.loads(_ADD_PHONE_BLACKLIST_FILE.read_text(encoding="utf-8"))
                if not isinstance(existing, dict):
                    existing = {}
            except Exception:
                existing = {}
        if email in existing:
            return
        existing[email] = {
            "blocked_at": int(time.time()),
            "reason": reason or "add_phone",
        }
        _ADD_PHONE_BLACKLIST_FILE.write_text(
            json.dumps(existing, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
    except Exception:
        pass


_ADD_PHONE_BLACKLIST_TTL_SECONDS = 7 * 86400  # 7 天过期


def is_email_add_phone_blacklisted(email: str) -> bool:
    email = (email or "").strip().lower()
    if not email or not _ADD_PHONE_BLACKLIST_FILE.exists():
        return False
    try:
        data = json.loads(_ADD_PHONE_BLACKLIST_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or email not in data:
            return False
        entry = data[email]
        blocked_at = int(entry.get("blocked_at", 0)) if isinstance(entry, dict) else 0
        if blocked_at and (int(time.time()) - blocked_at) > _ADD_PHONE_BLACKLIST_TTL_SECONDS:
            return False
        return True
    except Exception:
        return False

try:
    from curl_cffi import requests as curl_requests
except ImportError:
    import requests as curl_requests

from .phone_service import SMSToMePhoneService
from .utils import (
    FlowState,
    build_browser_headers,
    describe_flow_state,
    extract_flow_state,
    generate_datadog_trace,
    generate_pkce,
    normalize_flow_url,
    random_delay,
    seed_oai_device_cookie,
)
from .sentinel_token import build_sentinel_token
from .sentinel_browser import get_sentinel_token_via_browser


class OAuthClient:
    """OAuth 客户端 - 用于获取 Access Token 和 Refresh Token"""

    def __init__(self, config, proxy=None, verbose=True, browser_mode="protocol"):
        """
        初始化 OAuth 客户端

        Args:
            config: 配置字典
            proxy: 代理地址
            verbose: 是否输出详细日志
            browser_mode: protocol | headless | headed
        """
        self.config = dict(config or {})
        self.oauth_issuer = self.config.get("oauth_issuer", "https://auth.openai.com")
        self.oauth_client_id = self.config.get(
            "oauth_client_id", "app_EMoamEEZ73f0CkXaXp7hrann"
        )
        self.oauth_redirect_uri = self.config.get(
            "oauth_redirect_uri", "http://localhost:1455/auth/callback"
        )
        self.proxy = proxy
        self.verbose = verbose
        self.browser_mode = browser_mode or "protocol"
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_metadata = {}
        self.last_workspace_id = ""
        self.last_state = FlowState()
        self.last_stage = ""
        self.stage_trace = []
        self.device_id = ""
        self.ua = ""
        self.sec_ch_ua = ""
        self.impersonate = ""
        self._session_req_count = 0
        self._session_born_at = time.time()
        self._session_max_req = self._read_int_config(
            (
                "chatgpt_oauth_session_max_requests",
                "chatgpt_session_max_requests",
                "oauth_session_max_requests",
            ),
            default=80,
            minimum=10,
            maximum=1000,
        )
        self._session_max_age = self._read_int_config(
            (
                "chatgpt_oauth_session_max_age_seconds",
                "chatgpt_session_max_age_seconds",
                "oauth_session_max_age_seconds",
            ),
            default=240,
            minimum=30,
            maximum=3600,
        )
        self._ip_cooldown_enabled = self._read_bool_config(
            ("ip_cooldown_enabled", "chatgpt_ip_cooldown_enabled"),
            default=True,
        )
        self._ip_cooldown_seconds = self._read_int_config(
            ("ip_cooldown_seconds", "chatgpt_ip_cooldown_seconds"),
            default=600,
            minimum=60,
            maximum=3600,
        )

        # 创建 session
        self.session = curl_requests.Session()
        if self.proxy:
            self.session.proxies = build_requests_proxy_config(self.proxy)

    def _read_int_config(
        self,
        keys: tuple[str, ...],
        *,
        default: int,
        minimum: int,
        maximum: int,
    ) -> int:
        for key in keys:
            if key not in self.config:
                continue
            value = self.config.get(key)
            try:
                parsed = int(value)
            except Exception:
                continue
            return max(minimum, min(parsed, maximum))
        return max(minimum, min(int(default), maximum))

    def _read_bool_config(self, keys: tuple[str, ...], *, default: bool) -> bool:
        for key in keys:
            if key not in self.config:
                continue
            value = self.config.get(key)
            if isinstance(value, bool):
                return value
            text = str(value or "").strip().lower()
            if text in {"1", "true", "yes", "on"}:
                return True
            if text in {"0", "false", "no", "off"}:
                return False
        return default

    def adopt_browser_context(
        self,
        session,
        *,
        device_id: str = "",
        user_agent: str | None = None,
        sec_ch_ua: str | None = None,
        accept_language: str | None = None,
    ):
        """承接前序浏览器上下文，延续已建立的 cookie / session。"""
        if session is not None:
            self.session = session

        if self.proxy:
            try:
                if not getattr(self.session, "proxies", None):
                    self.session.proxies = build_requests_proxy_config(self.proxy)
            except Exception:
                pass

        header_updates = {}
        if user_agent:
            header_updates["User-Agent"] = user_agent
        if sec_ch_ua:
            header_updates["sec-ch-ua"] = sec_ch_ua
        if accept_language:
            header_updates["Accept-Language"] = accept_language

        if header_updates:
            try:
                self.session.headers.update(header_updates)
            except Exception:
                pass

        if device_id:
            self.device_id = str(device_id or "").strip()
            seed_oai_device_cookie(self.session, device_id)
            self._log(f"已接入前序浏览器上下文: device_id={device_id}")
        if user_agent:
            self.ua = str(user_agent or "").strip()
        if sec_ch_ua:
            self.sec_ch_ua = str(sec_ch_ua or "").strip()

    def _log(self, msg):
        """输出日志"""
        if self.verbose:
            print(f"  [OAuth] {msg}")

    def _enter_stage(self, stage: str, detail: str = ""):
        if not hasattr(self, "stage_trace") or self.stage_trace is None:
            self.stage_trace = []
        self.last_stage = str(stage or "").strip()
        if self.last_stage:
            self.stage_trace.append(self.last_stage)
            message = f"[stage={self.last_stage}]"
            if detail:
                message += f" {detail}"
            self._log(message)

    def _set_error(self, message, *, error_code: str | None = None, extra: dict | None = None):
        raw_message = str(message or "").strip()
        if self.last_stage and raw_message and f"[stage={self.last_stage}]" not in raw_message:
            self.last_error = f"[stage={self.last_stage}] {raw_message}"
        else:
            self.last_error = raw_message
        if error_code is not None:
            self.last_error_code = str(error_code or "").strip()
        metadata = {
            "last_stage": self.last_stage,
            "stages_trace": list(self.stage_trace or []),
            "error_code": self.last_error_code,
        }
        if extra:
            metadata.update(extra)
        self.last_error_metadata = metadata
        if self.last_error:
            self._log(self.last_error)

    def _browser_pause(self, low=0.15, high=0.4):
        """在 headed 模式下注入轻微延迟，模拟真实浏览器操作节奏。"""
        if self.browser_mode == "headed":
            random_delay(low, high)

    @staticmethod
    def _random_chrome_fingerprint():
        profiles = [
            {
                "major": 133,
                "impersonate": "chrome133a",
                "build": 6943,
                "patch_range": (33, 153),
                "sec_ch_ua": '"Not(A:Brand";v="99", "Google Chrome";v="133", "Chromium";v="133"',
            },
            {
                "major": 136,
                "impersonate": "chrome136",
                "build": 7103,
                "patch_range": (48, 175),
                "sec_ch_ua": '"Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
            },
        ]
        platforms = [
            {
                "ua_tpl": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36",
                "platform": '"Windows"',
                "arch": '"x86"',
            },
            {
                "ua_tpl": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36",
                "platform": '"macOS"',
                "arch": '"arm"',
            },
        ]
        profile = random.choice(profiles)
        plat = random.choice(platforms)
        major = profile["major"]
        build = profile["build"]
        patch = random.randint(*profile["patch_range"])
        full_ver = f"{major}.0.{build}.{patch}"
        ua = plat["ua_tpl"].format(ver=full_ver)
        return ua, profile["sec_ch_ua"], profile["impersonate"], plat

    def _ensure_oauth_fingerprint(self, user_agent, sec_ch_ua, impersonate):
        if user_agent and sec_ch_ua and impersonate:
            return user_agent, sec_ch_ua, impersonate

        ua, ch_ua, imp, plat = self._random_chrome_fingerprint()
        user_agent = user_agent or ua
        sec_ch_ua = sec_ch_ua or ch_ua
        impersonate = impersonate or imp
        self.ua = str(user_agent or "").strip()
        self.sec_ch_ua = str(sec_ch_ua or "").strip()
        self.impersonate = str(impersonate or "").strip()

        try:
            self.session.headers.update(
                {
                    "User-Agent": user_agent,
                    "Accept-Language": random.choice(
                        [
                            "en-US,en;q=0.9",
                            "en-US,en;q=0.9,zh-CN;q=0.8",
                            "en,en-US;q=0.9",
                            "en-US,en;q=0.8",
                        ]
                    ),
                    "sec-ch-ua": sec_ch_ua,
                    "sec-ch-ua-mobile": "?0",
                    "sec-ch-ua-platform": plat["platform"],
                    "sec-ch-ua-arch": plat["arch"],
                    "sec-ch-ua-bitness": '"64"',
                }
            )
        except Exception:
            pass

        self._log(
            f"OAuth 指纹: ua={user_agent.split('Chrome/')[-1][:24]}..., sec-ch-ua={sec_ch_ua}, impersonate={impersonate}"
        )
        return user_agent, sec_ch_ua, impersonate


    @staticmethod
    def _iter_text_fragments(value):
        if isinstance(value, str):
            text = value.strip()
            if text:
                yield text
            return
        if isinstance(value, dict):
            for item in value.values():
                yield from OAuthClient._iter_text_fragments(item)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                yield from OAuthClient._iter_text_fragments(item)

    @classmethod
    def _should_blacklist_phone_failure(cls, detail="", state: FlowState | None = None):
        fragments = [str(detail or "").strip()]
        if state is not None:
            fragments.extend(
                cls._iter_text_fragments(
                    {
                        "page_type": state.page_type,
                        "continue_url": state.continue_url,
                        "current_url": state.current_url,
                        "payload": state.payload,
                        "raw": state.raw,
                    }
                )
            )

        combined = " | ".join(fragment for fragment in fragments if fragment).lower()
        if not combined:
            return False

        non_blacklist_markers = (
            "whatsapp",
            "未收到短信验证码",
            "手机号验证码错误",
            "phone-otp/resend",
            "phone-otp/validate 异常",
            "phone-otp/validate 响应不是 json",
            "phone-otp/validate 失败",
            "timeout",
            "timed out",
            "network",
            "connection",
            "proxy",
            "ssl",
            "tls",
            "captcha",
            "too many phone",
            "too many phone numbers",
            "too many verification requests",
            "验证请求过多",
            "接受短信次数过多",
            "session limit",
            "rate limit",
        )
        if any(marker in combined for marker in non_blacklist_markers):
            return False

        blacklist_markers = (
            "phone number is invalid",
            "invalid phone number",
            "invalid phone",
            "phone number invalid",
            "sms verification failed",
            "send sms verification failed",
            "unable to send sms",
            "not a valid mobile number",
            "unsupported phone number",
            "phone number not supported",
            "carrier not supported",
            "电话号码无效",
            "手机号无效",
            "发送短信验证失败",
            "号码无效",
            "号码不支持",
            "手机号不支持",
        )
        return any(marker in combined for marker in blacklist_markers)

    def _blacklist_phone_if_needed(
        self, phone_service, entry, detail="", state: FlowState | None = None
    ):
        if not entry or not self._should_blacklist_phone_failure(detail, state):
            return False
        try:
            phone_service.mark_blacklisted(entry.phone)
            self._log(f"已将手机号加入黑名单: {entry.phone}")
            return True
        except Exception as e:
            self._log(f"写入手机号黑名单失败: {e}")
            return False

    def _headers(
        self,
        url,
        *,
        user_agent=None,
        sec_ch_ua=None,
        accept,
        referer=None,
        origin=None,
        content_type=None,
        navigation=False,
        fetch_mode=None,
        fetch_dest=None,
        fetch_site=None,
        extra_headers=None,
    ):
        accept_language = None
        try:
            accept_language = self.session.headers.get("Accept-Language")
        except Exception:
            accept_language = None

        return build_browser_headers(
            url=url,
            user_agent=user_agent or "Mozilla/5.0",
            sec_ch_ua=sec_ch_ua,
            accept=accept,
            accept_language=accept_language or "en-US,en;q=0.9",
            referer=referer,
            origin=origin,
            content_type=content_type,
            navigation=navigation,
            fetch_mode=fetch_mode,
            fetch_dest=fetch_dest,
            fetch_site=fetch_site,
            headed=self.browser_mode == "headed",
            extra_headers=extra_headers,
        )

    def _state_from_url(self, url, method="GET"):
        state = extract_flow_state(
            current_url=normalize_flow_url(url, auth_base=self.oauth_issuer),
            auth_base=self.oauth_issuer,
            default_method=method,
        )
        if method:
            state.method = str(method).upper()
        return state

    def _state_from_payload(self, data, current_url=""):
        return extract_flow_state(
            data=data,
            current_url=current_url,
            auth_base=self.oauth_issuer,
        )

    def _get_cookie_value(self, name, domain_hint=None):
        """读取当前会话中的 Cookie（兼容 next-auth 分片 cookie）。"""
        try:
            exact_value = ""
            chunk_prefix = f"{name}."
            chunk_parts = {}
            for cookie in self.session.cookies:
                cookie_name = cookie.name if hasattr(cookie, "name") else str(cookie)
                cookie_domain = cookie.domain if hasattr(cookie, "domain") else ""
                if domain_hint and domain_hint not in (cookie_domain or ""):
                    continue
                cookie_value = cookie.value if hasattr(cookie, "value") else ""
                if cookie_name == name:
                    exact_value = cookie_value
                    if exact_value:
                        return exact_value
                    continue
                if not cookie_name.startswith(chunk_prefix):
                    continue
                chunk_idx = cookie_name[len(chunk_prefix):]
                if not chunk_idx.isdigit():
                    continue
                idx = int(chunk_idx)
                if idx not in chunk_parts:
                    chunk_parts[idx] = cookie_value
            if exact_value:
                return exact_value
            if chunk_parts:
                return "".join(value for _, value in sorted(chunk_parts.items()))
        except Exception:
            pass
        return ""

    def _state_signature(self, state: FlowState):
        return (
            state.page_type or "",
            state.method or "",
            state.continue_url or "",
            state.current_url or "",
        )

    def _extract_code_from_state(self, state: FlowState):
        for candidate in (
            state.continue_url,
            state.current_url,
            (state.payload or {}).get("url", ""),
        ):
            code = self._extract_code_from_url(candidate)
            if code:
                return code
        return None

    def _state_is_login_password(self, state: FlowState):
        return state.page_type == "login_password"

    def _state_is_create_account_password(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "create_account_password" or "create-account/password" in target

    def _state_is_email_otp(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return (
            state.page_type == "email_otp_verification"
            or "email-verification" in target
            or "email-otp" in target
        )

    def _state_is_add_phone(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "add_phone" or "add-phone" in target

    def _state_is_about_you(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        return state.page_type == "about_you" or "about-you" in target

    def _state_requires_navigation(self, state: FlowState):
        method = (state.method or "GET").upper()
        if method != "GET":
            return False
        if (
            state.source == "api"
            and state.current_url
            and state.page_type not in {"login_password", "email_otp_verification"}
        ):
            return True
        if state.page_type == "external_url" and state.continue_url:
            return True
        if state.continue_url and state.continue_url != state.current_url:
            return True
        return False

    def _state_supports_workspace_resolution(self, state: FlowState):
        target = f"{state.continue_url} {state.current_url}".lower()
        if state.page_type in {
            "consent",
            "workspace_selection",
            "organization_selection",
        }:
            return True
        if any(
            marker in target
            for marker in (
                "sign-in-with-chatgpt",
                "consent",
                "workspace",
                "organization",
            )
        ):
            return True
        session_data = self._decode_oauth_session_cookie() or {}
        return bool(session_data.get("workspaces"))

    def _follow_flow_state(
        self,
        state: FlowState,
        referer=None,
        user_agent=None,
        impersonate=None,
        max_hops=16,
    ):
        """跟随服务端返回的 continue_url / current_url，返回新的状态或 authorization code。"""
        import re

        current_url = state.continue_url or state.current_url
        last_url = current_url or ""
        referer_url = referer

        if not current_url:
            return None, state

        initial_code = self._extract_code_from_url(current_url)
        if initial_code:
            return initial_code, self._state_from_url(current_url)

        for hop in range(max_hops):
            try:
                headers = self._headers(
                    current_url,
                    user_agent=user_agent,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=referer_url,
                    navigation=True,
                )
                kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
                if impersonate:
                    kwargs["impersonate"] = impersonate

                self._browser_pause(0.12, 0.3)
                r = self._http("GET", current_url, **kwargs)
                last_url = str(r.url)
                self._log(f"follow[{hop + 1}] {r.status_code} {last_url[:120]}")
            except Exception as e:
                maybe_localhost = re.search(r"(https?://localhost[^\s\'\"]+)", str(e))
                if maybe_localhost:
                    location = maybe_localhost.group(1)
                    code = self._extract_code_from_url(location)
                    if code:
                        self._log("从 localhost 异常提取到 authorization code")
                        return code, self._state_from_url(location)
                self._log(f"follow[{hop + 1}] 异常: {str(e)[:160]}")
                return None, self._state_from_url(last_url or current_url)

            code = self._extract_code_from_url(last_url)
            if code:
                return code, self._state_from_url(last_url)

            if r.status_code in (301, 302, 303, 307, 308):
                location = normalize_flow_url(
                    r.headers.get("Location", ""), auth_base=self.oauth_issuer
                )
                if not location:
                    return None, self._state_from_url(last_url or current_url)
                code = self._extract_code_from_url(location)
                if code:
                    return code, self._state_from_url(location)
                referer_url = last_url or referer_url
                current_url = location
                continue

            content_type = (r.headers.get("content-type", "") or "").lower()
            if "application/json" in content_type:
                try:
                    next_state = self._state_from_payload(
                        r.json(), current_url=last_url or current_url
                    )
                except Exception:
                    next_state = self._state_from_url(last_url or current_url)
            else:
                next_state = self._state_from_url(last_url or current_url)

            return None, next_state

        return None, self._state_from_url(last_url or current_url)

    def _bootstrap_oauth_session(
        self,
        authorize_url,
        authorize_params,
        device_id=None,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
    ):
        """启动 OAuth 会话，确保 auth 域上的 login_session 已建立。"""
        if device_id:
            seed_oai_device_cookie(self.session, device_id)

        has_login_session = False
        authorize_final_url = ""

        try:
            headers = self._headers(
                authorize_url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer="https://chatgpt.com/",
                navigation=True,
            )
            kwargs = {
                "params": authorize_params,
                "headers": headers,
                "allow_redirects": True,
                "timeout": 30,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self._http("GET", authorize_url, **kwargs)
            authorize_final_url = str(r.url)
            redirects = len(getattr(r, "history", []) or [])
            self._log(f"/oauth/authorize -> {r.status_code}, redirects={redirects}")

            has_login_session = any(
                (cookie.name if hasattr(cookie, "name") else str(cookie))
                == "login_session"
                for cookie in self.session.cookies
            )
            self._log(f"login_session: {'已获取' if has_login_session else '未获取'}")
        except Exception as e:
            self._log(f"/oauth/authorize 异常: {e}")

        if has_login_session:
            return authorize_final_url

        self._log("未获取到 login_session，尝试 /api/oauth/oauth2/auth...")
        try:
            oauth2_url = f"{self.oauth_issuer}/api/oauth/oauth2/auth"
            kwargs = {
                "params": authorize_params,
                "headers": self._headers(
                    oauth2_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer="https://chatgpt.com/",
                    navigation=True,
                ),
                "allow_redirects": True,
                "timeout": 30,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r2 = self._http("GET", oauth2_url, **kwargs)
            authorize_final_url = str(r2.url)
            redirects2 = len(getattr(r2, "history", []) or [])
            self._log(
                f"/api/oauth/oauth2/auth -> {r2.status_code}, redirects={redirects2}"
            )

            has_login_session = any(
                (cookie.name if hasattr(cookie, "name") else str(cookie))
                == "login_session"
                for cookie in self.session.cookies
            )
            self._log(
                f"login_session(重试): {'已获取' if has_login_session else '未获取'}"
            )
        except Exception as e:
            self._log(f"/api/oauth/oauth2/auth 异常: {e}")

        return authorize_final_url

    def _bootstrap_chatgpt_entry(
        self,
        email: str,
        device_id: str,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
    ) -> str:
        """模拟注册链路一致的 ChatGPT 首页 -> CSRF -> signin/openai。"""
        homepage_url = "https://chatgpt.com/"
        csrf_url = "https://chatgpt.com/api/auth/csrf"
        signin_url = "https://chatgpt.com/api/auth/signin/openai"

        try:
            self._log("force_chatgpt_entry: 访问 ChatGPT 首页...")
            self._browser_pause()
            r_home = self._http("GET", 
                homepage_url,
                headers=self._headers(
                    homepage_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                    navigation=True,
                ),
                allow_redirects=True,
                timeout=30,
            )
            self._log(f"force_chatgpt_entry: 首页状态 {r_home.status_code}")
        except Exception as e:
            self._log(f"force_chatgpt_entry: 首页访问异常: {e}")

        csrf_token = ""
        try:
            self._log("force_chatgpt_entry: 获取 CSRF token...")
            r_csrf = self._http("GET", 
                csrf_url,
                headers=self._headers(
                    csrf_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="application/json",
                    referer=homepage_url,
                    fetch_site="same-origin",
                ),
                timeout=30,
            )
            if r_csrf.status_code == 200:
                csrf_token = (r_csrf.json() or {}).get("csrfToken", "") or ""
                if csrf_token:
                    self._log(f"force_chatgpt_entry: CSRF token={csrf_token[:16]}...")
        except Exception as e:
            self._log(f"force_chatgpt_entry: 获取 CSRF 异常: {e}")

        authorize_url = ""
        try:
            self._log("force_chatgpt_entry: 提交邮箱获取 authorize URL...")
            params = {
                "prompt": "login",
                "ext-oai-did": device_id,
                "auth_session_logging_id": str(uuid.uuid4()),
                "screen_hint": "login_or_signup",
                "login_hint": email,
            }
            form_data = {
                "callbackUrl": "https://chatgpt.com/",
                "csrfToken": csrf_token,
                "json": "true",
            }
            r_signin = self._http("POST", 
                signin_url,
                params=params,
                data=form_data,
                headers=self._headers(
                    signin_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="application/json",
                    referer=homepage_url,
                    origin="https://chatgpt.com",
                    content_type="application/x-www-form-urlencoded",
                    fetch_site="same-origin",
                ),
                timeout=30,
            )
            if r_signin.status_code == 200:
                authorize_url = (r_signin.json() or {}).get("url", "") or ""
                if authorize_url:
                    self._log("force_chatgpt_entry: 已获取 authorize URL")
            else:
                self._log(
                    f"force_chatgpt_entry: authorize URL 获取失败 {r_signin.status_code}"
                )
        except Exception as e:
            self._log(f"force_chatgpt_entry: 提交邮箱异常: {e}")

        if not authorize_url:
            return ""

        try:
            self._log("force_chatgpt_entry: 访问 authorize URL...")
            self._browser_pause()
            kwargs = {
                "headers": self._headers(
                    authorize_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    referer=homepage_url,
                    navigation=True,
                ),
                "allow_redirects": True,
                "timeout": 30,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate
            r_auth = self._http("GET", authorize_url, **kwargs)
            final_url = str(r_auth.url)
            self._log(
                f"force_chatgpt_entry: authorize 最终跳转 {final_url[:160]}"
            )
            return final_url
        except Exception as e:
            self._log(f"force_chatgpt_entry: 访问 authorize 异常: {e}")
            return authorize_url

    def _submit_authorize_continue(
        self,
        email,
        device_id,
        continue_referer,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        authorize_url=None,
        authorize_params=None,
        screen_hint=None,
    ):
        """提交邮箱，获取 OAuth 流程的第一页状态。"""
        self._enter_stage("authorize_continue", f"email={email}")
        self._log("步骤2: POST /api/accounts/authorize/continue")

        self._log(f"authorize_continue: device_id={device_id}")
        sentinel_token = get_sentinel_token_via_browser(
            flow="authorize_continue",
            proxy=self.proxy,
            page_url=continue_referer or f"{self.oauth_issuer}/log-in",
            headless=self.browser_mode != "headed",
            device_id=device_id,
            log_fn=lambda msg: self._log(f"authorize_continue: {msg}"),
        )
        if sentinel_token:
            self._log("authorize_continue: 已通过 Playwright SentinelSDK 获取 token")
        else:
            sentinel_token = build_sentinel_token(
                self.session,
                device_id,
                flow="authorize_continue",
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            if sentinel_token:
                self._log("authorize_continue: 已通过 HTTP PoW 获取 token")
            else:
                self._set_error("无法获取 sentinel token (authorize_continue)")
                return None

        request_url = f"{self.oauth_issuer}/api/accounts/authorize/continue"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=continue_referer,
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
                "openai-sentinel-token": sentinel_token,
            },
        )
        headers.update(generate_datadog_trace())
        payload = {"username": {"kind": "email", "value": email}}
        if screen_hint:
            payload["screen_hint"] = str(screen_hint).strip()

        try:
            kwargs = {
                "json": payload,
                "headers": headers,
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self._http("POST", request_url, **kwargs)
            self._log(f"/authorize/continue -> {r.status_code}")
            self._log(
                "authorize_continue 响应: "
                f"referer={(continue_referer or '')[:100]} "
                f"current_url={str(r.url)[:120]}"
            )

            if (
                r.status_code == 400
                and "invalid_auth_step" in (r.text or "")
                and authorize_url
                and authorize_params
            ):
                self._log("invalid_auth_step，重新 bootstrap...")
                authorize_final_url = self._bootstrap_oauth_session(
                    authorize_url,
                    authorize_params,
                    device_id=device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                continue_referer = (
                    authorize_final_url
                    if authorize_final_url.startswith(self.oauth_issuer)
                    else f"{self.oauth_issuer}/log-in"
                )
                headers["Referer"] = continue_referer
                headers["Sec-Fetch-Site"] = "same-origin"
                headers.update(generate_datadog_trace())
                kwargs = {
                    "json": payload,
                    "headers": headers,
                    "timeout": 30,
                    "allow_redirects": False,
                }
                if impersonate:
                    kwargs["impersonate"] = impersonate
                self._browser_pause()
                r = self._http("POST", request_url, **kwargs)
                self._log(f"/authorize/continue(重试) -> {r.status_code}")

            if r.status_code != 200:
                self._set_error(f"提交邮箱失败: {r.status_code} - {r.text[:180]}")
                return None

            data = r.json()
            flow_state = self._state_from_payload(
                data, current_url=str(r.url) or request_url
            )
            self._log(describe_flow_state(flow_state))
            return flow_state
        except Exception as e:
            self._set_error(f"提交邮箱异常: {e}")
            return None

    def _submit_password_verify(
        self,
        password,
        device_id,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        referer=None,
    ):
        """提交密码，获取下一步状态。"""
        self._log("步骤3: POST /api/accounts/password/verify")

        self._log(f"password_verify: device_id={device_id}")
        sentinel_pwd = get_sentinel_token_via_browser(
            flow="password_verify",
            proxy=self.proxy,
            page_url=referer or f"{self.oauth_issuer}/log-in/password",
            headless=self.browser_mode != "headed",
            device_id=device_id,
            log_fn=lambda msg: self._log(f"password_verify: {msg}"),
        )
        if sentinel_pwd:
            self._log("password_verify: 已通过 Playwright SentinelSDK 获取 token")
        else:
            sentinel_pwd = build_sentinel_token(
                self.session,
                device_id,
                flow="password_verify",
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            if sentinel_pwd:
                self._log("password_verify: 已通过 HTTP PoW 获取 token")
            else:
                self._set_error("无法获取 sentinel token (password_verify)")
                return None

        request_url = f"{self.oauth_issuer}/api/accounts/password/verify"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=referer or f"{self.oauth_issuer}/log-in/password",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
                "openai-sentinel-token": sentinel_pwd,
            },
        )
        headers.update(generate_datadog_trace())

        try:
            kwargs = {
                "json": {"password": password},
                "headers": headers,
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self._http("POST", request_url, **kwargs)
            self._log(f"/password/verify -> {r.status_code}")

            if r.status_code != 200:
                self._set_error(f"密码验证失败: {r.status_code} - {r.text[:180]}")
                return None

            data = r.json()
            flow_state = self._state_from_payload(
                data, current_url=str(r.url) or request_url
            )
            self._log(f"verify {describe_flow_state(flow_state)}")
            return flow_state
        except Exception as e:
            self._set_error(f"密码验证异常: {e}")
            return None

    def _send_passwordless_login_otp(
        self,
        email,
        device_id,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        referer=None,
    ):
        """在 login_password 状态下直接切到 passwordless OTP。"""
        self._log("步骤3: 命中 login_password，按新链路直接触发 passwordless OTP")

        request_url = f"{self.oauth_issuer}/api/accounts/passwordless/send-otp"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=referer or f"{self.oauth_issuer}/log-in/password",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
            },
        )
        headers.update(generate_datadog_trace())

        try:
            kwargs = {
                "headers": headers,
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self._http("POST", request_url, **kwargs)
            self._log(f"/passwordless/send-otp -> {r.status_code}")

            if r.status_code != 200:
                self._set_error(
                    f"触发 passwordless OTP 失败: {r.status_code} - {r.text[:180]}",
                    error_code="oauth_passwordless_send_failed",
                )
                return None

            try:
                data = r.json()
            except Exception:
                data = {}

            flow_state = self._state_from_payload(
                data,
                current_url=str(r.url) or f"{self.oauth_issuer}/email-verification",
            )
            if not self._state_is_email_otp(flow_state):
                flow_state = self._state_from_url(f"{self.oauth_issuer}/email-verification")
            self._log(f"passwordless OTP 已触发 {describe_flow_state(flow_state)}")
            return flow_state
        except TaskInterruption:
            raise
        except Exception as e:
            if self._is_connection_broken(e):
                self._log(f"检测到连接中断({type(e).__name__}): {e}，重建 session 并跳过本邮箱")
                self._recreate_session()
                raise SkipCurrentAttemptRequested(
                    f"连接中断触发 session 重建: {type(e).__name__}"
                )
            self._set_error(
                f"触发 passwordless OTP 异常: {e}",
                error_code="oauth_passwordless_send_failed",
            )
            return None

    def _submit_signup_register(
        self,
        email,
        password,
        device_id,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        referer=None,
    ):
        """在 OAuth signup 流程中提交邮箱+密码。"""
        self._enter_stage("authorize_continue", f"register_user email={email}")
        self._log("步骤3: 命中 create_account_password，提交注册密码")

        request_url = f"{self.oauth_issuer}/api/accounts/user/register"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=referer or f"{self.oauth_issuer}/create-account/password",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={
                "oai-device-id": device_id,
            },
        )
        headers.update(generate_datadog_trace())

        sentinel_token = get_sentinel_token_via_browser(
            flow="username_password_create",
            proxy=self.proxy,
            page_url=referer or f"{self.oauth_issuer}/create-account/password",
            headless=self.browser_mode != "headed",
            device_id=device_id,
            log_fn=lambda msg: self._log(f"username_password_create: {msg}"),
        )
        if sentinel_token:
            self._log("username_password_create: 已通过 Playwright SentinelSDK 获取 token")
        else:
            sentinel_token = build_sentinel_token(
                self.session,
                device_id,
                flow="username_password_create",
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            if sentinel_token:
                self._log("username_password_create: 已通过 HTTP PoW 获取 token")
        if sentinel_token:
            headers["openai-sentinel-token"] = sentinel_token

        payload = {
            "username": email,
            "password": password,
        }

        try:
            kwargs = {
                "json": payload,
                "headers": headers,
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self._http("POST", request_url, **kwargs)
            self._log(f"/user/register -> {r.status_code}")

            if r.status_code != 200:
                self._set_error(f"注册失败: {r.status_code} - {r.text[:180]}")
                return False

            self._log("注册成功")
            self._log(
                f"signup/register 响应: referer={(referer or '')[:100]} current_url={str(r.url)[:120]}"
            )
            return True
        except Exception as e:
            self._set_error(f"注册异常: {e}")
            return False

    def _send_signup_email_otp(
        self,
        device_id,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        referer=None,
    ):
        """在 OAuth signup 流程中触发邮箱验证码。"""
        self._enter_stage("otp", "send signup email otp")
        self._log("步骤4: 触发注册邮箱 OTP")

        request_url = f"{self.oauth_issuer}/api/accounts/email-otp/send"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            referer=referer or f"{self.oauth_issuer}/create-account/password",
            navigation=True,
            fetch_site="same-origin",
        )
        headers.update(generate_datadog_trace())

        try:
            kwargs = {
                "headers": headers,
                "allow_redirects": True,
                "timeout": 30,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self._http("GET", request_url, **kwargs)
            self._log(f"/email-otp/send -> {r.status_code}")
            if r.status_code != 200:
                self._set_error(f"发送注册 OTP 失败: {r.status_code} - {r.text[:180]}")
                return None

            verify_url = f"{self.oauth_issuer}/email-verification"
            verify_headers = self._headers(
                verify_url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer=referer or f"{self.oauth_issuer}/create-account/password",
                navigation=True,
            )
            verify_kwargs = {
                "headers": verify_headers,
                "allow_redirects": True,
                "timeout": 30,
            }
            if impersonate:
                verify_kwargs["impersonate"] = impersonate

            self._browser_pause(0.12, 0.25)
            r_verify = self._http("GET", verify_url, **verify_kwargs)
            self._log(f"/email-verification -> {r_verify.status_code}")

            content_type = (r_verify.headers.get("content-type", "") or "").lower()
            if "application/json" in content_type:
                try:
                    flow_state = self._state_from_payload(
                        r_verify.json(),
                        current_url=str(r_verify.url) or verify_url,
                    )
                except Exception:
                    flow_state = self._state_from_url(str(r_verify.url) or verify_url)
            else:
                flow_state = self._state_from_url(str(r_verify.url) or verify_url)

            if not self._state_is_email_otp(flow_state):
                flow_state = self._state_from_url(verify_url)
            self._log(f"注册 OTP 已触发 {describe_flow_state(flow_state)}")
            return flow_state
        except Exception as e:
            self._set_error(f"发送注册 OTP 异常: {e}")
            return None

    def signup_and_get_tokens(
        self,
        email,
        password,
        first_name,
        last_name,
        birthdate,
        *,
        device_id="",
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        skymail_client=None,
        allow_phone_verification=False,
        signup_source="",
    ):
        """完成 OAuth 单链注册并换取 refresh token。"""
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_metadata = {}
        self.last_workspace_id = ""
        self.last_state = FlowState()
        self._log(
            "开始 OAuth 注册流程..."
            + (f" (source={signup_source})" if signup_source else "")
        )
        self._log(
            "OAuth 注册策略: 单链路 signup -> otp -> about_you -> phone(如需) -> consent/workspace -> token"
        )

        if not skymail_client:
            self._set_error(
                "OAuth 注册流程缺少接码客户端",
                error_code="oauth_signup_otp_client_missing",
            )
            return None

        device_id = str(device_id or "").strip() or str(uuid.uuid4())
        self.device_id = device_id
        user_agent, sec_ch_ua, impersonate = self._ensure_oauth_fingerprint(
            user_agent, sec_ch_ua, impersonate
        )

        code_verifier, code_challenge = generate_pkce()
        oauth_state = secrets.token_urlsafe(32)
        authorize_params = {
            "response_type": "code",
            "client_id": self.oauth_client_id,
            "audience": "https://api.openai.com/v1",
            "redirect_uri": self.oauth_redirect_uri,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": oauth_state,
            "prompt": "login",
            "login_hint": email,
            "screen_hint": "login_or_signup",
            "ext-oai-did": device_id,
            "auth_session_logging_id": str(uuid.uuid4()),
            "ext-passkey-client-capabilities": "1111",
            "codex_cli_simplified_flow": "true",
            "id_token_add_organizations": "true",
        }
        authorize_url = f"{self.oauth_issuer}/oauth/authorize"

        seed_oai_device_cookie(self.session, device_id)

        self._log("步骤1: Bootstrap OAuth session...")
        authorize_final_url = self._bootstrap_oauth_session(
            authorize_url,
            authorize_params,
            device_id=device_id,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
        )
        if not authorize_final_url:
            self._set_error("Bootstrap 失败")
            return None

        continue_referer = f"{self.oauth_issuer}/create-account"
        state = self._submit_authorize_continue(
            email,
            device_id,
            continue_referer,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
            authorize_url=authorize_url,
            authorize_params=authorize_params,
            screen_hint="signup",
        )
        if not state:
            if not self.last_error:
                self._set_error("提交邮箱后未进入有效的 OAuth 注册状态")
            return None

        self._log(f"OAuth 注册状态起点: {describe_flow_state(state)}")
        referer = continue_referer
        seen_states = {}
        register_submitted = False

        for step in range(24):
            self.last_state = state
            self._log(f"注册状态步进[{step + 1}/24]: {describe_flow_state(state)}")
            signature = self._state_signature(state)
            seen_states[signature] = seen_states.get(signature, 0) + 1
            if seen_states[signature] > 2:
                self._set_error(f"OAuth 注册状态卡住: {describe_flow_state(state)}")
                return None

            code = self._extract_code_from_state(state)
            if code:
                self._log(f"获取到 authorization code: {code[:20]}...")
                self._log("步骤7: POST /oauth/token")
                tokens = self._exchange_code_for_tokens(
                    code, code_verifier, user_agent, impersonate
                )
                if tokens:
                    self._log("✅ OAuth 注册成功")
                else:
                    self._log("换取 tokens 失败")
                return tokens

            if self._state_is_create_account_password(state):
                if register_submitted:
                    self._set_error("注册密码阶段重复进入")
                    return None
                ok = self._submit_signup_register(
                    email,
                    password,
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not ok:
                    return None
                register_submitted = True
                state = self._send_signup_email_otp(
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not state:
                    if not self.last_error:
                        self._set_error("注册 OTP 触发后未进入邮箱验证码状态")
                    return None
                referer = state.current_url or referer
                continue

            if self._state_is_email_otp(state):
                next_state = self._handle_otp_verification(
                    email,
                    device_id,
                    user_agent,
                    sec_ch_ua,
                    impersonate,
                    skymail_client,
                    state,
                    prefer_passwordless_login=False,
                    allow_cached_code_retry=False,
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("注册 OTP 验证后未进入下一步状态")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_about_you(state):
                next_state = self._submit_about_you_create_account(
                    first_name,
                    last_name,
                    birthdate,
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("about_you 提交后未进入下一步 OAuth 状态")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_add_phone(state):
                try:
                    raw_dump = json.dumps(state.raw or {}, ensure_ascii=False)
                except Exception:
                    raw_dump = ""
                if raw_dump:
                    self._log(f"add_phone 状态响应体(raw): {raw_dump}")
                if not allow_phone_verification:
                    if not self.last_error:
                        self._set_error("signup 链路命中 add_phone")
                    return None

                next_state = self._handle_add_phone_verification(
                    device_id,
                    user_agent,
                    sec_ch_ua,
                    impersonate,
                    state,
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("手机号验证后未进入下一步 OAuth 状态")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_requires_navigation(state):
                code, next_state = self._follow_flow_state(
                    state,
                    referer=referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if code:
                    self._log(f"获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(
                        code, code_verifier, user_agent, impersonate
                    )
                    if tokens:
                        self._log("✅ OAuth 注册成功")
                    else:
                        self._log("换取 tokens 失败")
                    return tokens
                referer = state.current_url or referer
                state = next_state
                self._log(f"follow state -> {describe_flow_state(state)}")
                continue

            if self._state_supports_workspace_resolution(state):
                self._log("步骤6: 执行 workspace/org 选择")
                consent_entry = (
                    state.continue_url
                    or state.current_url
                    or f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                )
                if self._state_is_add_phone(state):
                    consent_entry = f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                    self._log("步骤6: 当前处于 add_phone，改用 canonical consent URL 继续")
                code, next_state = self._oauth_submit_workspace_and_org(
                    consent_entry,
                    device_id,
                    user_agent,
                    impersonate,
                )
                if code:
                    self._log(f"获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(
                        code, code_verifier, user_agent, impersonate
                    )
                    if tokens:
                        self._log("✅ OAuth 注册成功")
                    else:
                        self._log("换取 tokens 失败")
                    return tokens
                if next_state:
                    referer = state.current_url or referer
                    state = next_state
                    self._log(f"workspace state -> {describe_flow_state(state)}")
                    continue
                if not self.last_error:
                    self._set_error(f"workspace/org 选择失败: {describe_flow_state(state)}")
                return None

            self._set_error(f"未支持的 OAuth 注册状态: {describe_flow_state(state)}")
            return None

        self._set_error("OAuth 注册状态机超出最大步数")
        return None

    def _submit_about_you_create_account(
        self,
        first_name,
        last_name,
        birthdate,
        device_id,
        *,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        referer=None,
    ):
        """在 OAuth 登录态命中 about_you 后提交资料，完成账户创建。"""
        self._enter_stage("about_you", "submit create_account")
        self._log("步骤5: 命中 about_you，提交姓名和生日完成注册")
        self._log(
            "about_you 参数: "
            f"first_name={'已设置' if str(first_name or '').strip() else '缺失'}, "
            f"last_name={'已设置' if str(last_name or '').strip() else '缺失'}, "
            f"birthdate={str(birthdate or '').strip() or '缺失'}"
        )

        full_name = f"{str(first_name or '').strip()} {str(last_name or '').strip()}".strip()
        if not full_name or not str(birthdate or "").strip():
            self._set_error(
                "about_you 资料不完整: 缺少姓名或生日",
                error_code="about_you_profile_incomplete",
            )
            return None

        about_you_url = f"{self.oauth_issuer}/about-you"
        request_url = f"{self.oauth_issuer}/api/accounts/create_account"
        payload = {
            "name": full_name,
            "birthdate": str(birthdate).strip(),
        }
        self._log("about_you 请求体已构建，准备 POST /api/accounts/create_account")

        def _build_create_headers(sentinel_token: str = ""):
            extra_headers = {
                "oai-device-id": device_id,
            }
            if sentinel_token:
                extra_headers["openai-sentinel-token"] = sentinel_token
            headers_local = self._headers(
                request_url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="application/json",
                referer=referer or about_you_url,
                origin=self.oauth_issuer,
                content_type="application/json",
                fetch_site="same-origin",
                extra_headers=extra_headers,
            )
            headers_local.update(generate_datadog_trace())
            return headers_local

        def _post_create(sentinel_token: str = ""):
            kwargs = {
                "json": payload,
                "headers": _build_create_headers(sentinel_token),
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause()
            return self._http("POST", request_url, **kwargs)

        try:
            r = _post_create()
            self._log(f"/create_account -> {r.status_code}")
            self._log(
                "about_you 响应: "
                f"current_url={str(r.url)[:120]} referer={(referer or '')[:100]}"
            )

            if (
                r.status_code in (401, 403)
                or "sentinel" in (r.text or "").lower()
                or "challenge" in (r.text or "").lower()
            ):
                self._log("create_account 首次请求需要额外挑战，补发 sentinel 后重试...")
                sentinel_token = build_sentinel_token(
                    self.session,
                    device_id,
                    flow="oauth_create_account",
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                )
                if not sentinel_token:
                    self._set_error(
                        "无法获取 sentinel token (oauth_create_account)",
                        error_code="about_you_sentinel_missing",
                    )
                    return None

                r = _post_create(sentinel_token)
                self._log(f"/create_account(重试) -> {r.status_code}")
                self._log(
                    "about_you 重试响应: "
                    f"current_url={str(r.url)[:120]} referer={(referer or '')[:100]}"
                )

            if r.status_code == 400 and "already_exists" in (r.text or ""):
                consent_state = self._state_from_url(
                    f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                )
                self._log(f"about_you 命中 already_exists，转入 {describe_flow_state(consent_state)}")
                return consent_state

            if r.status_code != 200:
                self._set_error(
                    f"about_you 提交失败: {r.status_code} - {r.text[:180]}",
                    error_code="about_you_submit_failed",
                )
                return None

            try:
                data = r.json()
            except Exception:
                data = {}

            flow_state = self._state_from_payload(
                data,
                current_url=str(r.url) or request_url,
            )
            if self._state_is_add_phone(flow_state):
                try:
                    raw_text = r.text or ""
                except Exception:
                    raw_text = ""
                try:
                    raw_json = json.dumps(data, ensure_ascii=False)
                except Exception:
                    raw_json = ""
                if raw_text:
                    self._log("add_phone 触发响应体(raw): " + raw_text)
                if raw_json and raw_json != raw_text:
                    self._log("add_phone 触发响应体(json): " + raw_json)
            self._log(f"about_you 提交成功 {describe_flow_state(flow_state)}")
            return flow_state
        except Exception as e:
            self._set_error(
                f"about_you 提交异常: {e}",
                error_code="about_you_submit_failed",
            )
            return None

    def _recreate_session(self):
        """重新创建会话容器，并尽可能保留已有 cookie/headers。"""
        old_session = getattr(self, "session", None)
        old_headers = {}
        old_cookies = None
        if old_session is not None:
            try:
                old_headers = dict(getattr(old_session, "headers", {}) or {})
            except Exception:
                old_headers = {}
            try:
                old_cookies = getattr(old_session, "cookies", None)
            except Exception:
                old_cookies = None

        new_session = curl_requests.Session()
        if self.proxy:
            new_session.proxies = build_requests_proxy_config(self.proxy)
        if old_headers:
            try:
                new_session.headers.update(old_headers)
            except Exception:
                pass
        if old_cookies is not None:
            try:
                new_session.cookies.update(old_cookies)
            except Exception:
                pass

        try:
            if old_session is not None:
                old_session.close()
        except Exception:
            pass
        self.session = new_session
        self._session_req_count = 0
        self._session_born_at = time.time()

    def _maybe_rotate_session(self):
        expired_by_req = self._session_req_count >= self._session_max_req
        expired_by_age = (time.time() - self._session_born_at) >= self._session_max_age
        if expired_by_req or expired_by_age:
            self._log(
                "session 到期回收: "
                f"reqs={self._session_req_count}, age={int(time.time() - self._session_born_at)}s"
            )
            self._recreate_session()

    def _should_cool_down_proxy(self, response) -> bool:
        status_code = int(getattr(response, "status_code", 0) or 0)
        if status_code in (409, 429):
            return True
        if status_code != 403:
            return False
        try:
            text = str(getattr(response, "text", "") or "").lower()
        except Exception:
            text = ""
        cf_markers = (
            "cloudflare",
            "just a moment",
            "cf-ray",
            "attention required",
            "__cf_chl",
            "challenge-platform",
        )
        return any(marker in text for marker in cf_markers)

    def _cool_down_current_proxy(self, status_code: int, url: str):
        if not self._ip_cooldown_enabled or not self.proxy:
            return
        try:
            from core.proxy_pool import proxy_pool as _proxy_pool

            _proxy_pool.cool_down(self.proxy, self._ip_cooldown_seconds)
            self._log(
                f"IP 限流 {status_code}，代理冷却 {self._ip_cooldown_seconds}s: {self.proxy}"
            )
        except Exception as e:
            self._log(f"代理冷却失败(忽略): {e}")

    def _http(self, method: str, url: str, *, _retry: bool = False, **kwargs):
        self._maybe_rotate_session()
        self._session_req_count += 1
        try:
            response = self.session.request(method, url, **kwargs)
        except TaskInterruption:
            raise
        except Exception as e:
            if self._is_connection_broken(e):
                if not _retry:
                    self._log(
                        f"连接中断({type(e).__name__})，重建 session 后单次重试: {url}"
                    )
                    self._recreate_session()
                    return self._http(method, url, _retry=True, **kwargs)
                raise SkipCurrentAttemptRequested(
                    f"session 重建后仍失败: {type(e).__name__}"
                )
            raise

        if self._should_cool_down_proxy(response):
            status_code = int(getattr(response, "status_code", 0) or 0)
            self._cool_down_current_proxy(status_code, url)
            raise SkipCurrentAttemptRequested(f"IP 限流 {status_code}，冷却代理")
        return response

    @staticmethod
    def _is_connection_broken(exc: BaseException) -> bool:
        """识别底层连接已损坏、需要重建 session 的异常。"""
        if exc is None:
            return False
        name = type(exc).__name__
        msg = str(exc).lower()
        if name in {"BrokenPipeError", "ConnectionResetError", "ConnectionAbortedError"}:
            return True
        if "requestserror" in name.lower() or "curlerror" in name.lower():
            return True
        tokens = ("broken pipe", "connection reset", "connection aborted",
                  "connection closed", "epipe", "ssl: bad")
        return any(t in msg for t in tokens)

    def login_and_get_tokens(
        self,
        email,
        password,
        device_id,
        user_agent=None,
        sec_ch_ua=None,
        impersonate=None,
        skymail_client=None,
        prefer_passwordless_login=False,
        allow_phone_verification=True,
        force_new_browser=False,
        force_password_login=False,
        force_chatgpt_entry=False,
        screen_hint="login",
        complete_about_you_if_needed=False,
        first_name="",
        last_name="",
        birthdate="",
        login_source="",
        stop_after_login=False,
        _continue_depth=0,
    ):
        """
        完整的 OAuth 登录流程，获取 tokens

        Args:
            email: 邮箱
            password: 密码
            device_id: 设备 ID
            user_agent: User-Agent
            sec_ch_ua: sec-ch-ua header
            impersonate: curl_cffi impersonate 参数
            skymail_client: Skymail 客户端（用于获取 OTP，如果需要）
            prefer_passwordless_login: 是否强制走 passwordless OTP 链路
            allow_phone_verification: add_phone 后是否允许进入手机号验证码分支
            force_password_login: 即使 prefer_passwordless_login=true，也强制走密码登录
            force_chatgpt_entry: 在 OAuth 前先走 ChatGPT 首页 -> CSRF -> signin/openai
            complete_about_you_if_needed: 命中 about_you 后是否自动提交资料完成注册
            screen_hint: authorize/continue 的 screen_hint（login/signup）
            first_name: about_you 名字
            last_name: about_you 姓氏
            birthdate: about_you 生日，格式 YYYY-MM-DD
            login_source: 当前登录场景，仅用于日志

        Returns:
            dict: tokens 字典，包含 access_token, refresh_token, id_token
        """
        self.last_error = ""
        self.last_error_code = ""
        self.last_error_metadata = {}
        self.last_workspace_id = ""
        self.last_state = FlowState()
        self._log(
            "开始 OAuth 登录流程..."
            + (f" (source={login_source})" if login_source else "")
        )
        self._log(
            "OAuth 策略: "
            f"prefer_passwordless_login={'on' if prefer_passwordless_login else 'off'}, "
            f"allow_phone_verification={'on' if allow_phone_verification else 'off'}, "
            f"complete_about_you_if_needed={'on' if complete_about_you_if_needed else 'off'}, "
            f"force_new_browser={'on' if force_new_browser else 'off'}, "
            f"force_password_login={'on' if force_password_login else 'off'}, "
            f"force_chatgpt_entry={'on' if force_chatgpt_entry else 'off'}, "
            f"screen_hint={screen_hint or 'login'}, "
            f"stop_after_login={'on' if stop_after_login else 'off'}"
        )

        if force_new_browser:
            self._log("force_new_browser: 重新创建 OAuth 会话容器")
            self._recreate_session()
            if skymail_client is not None:
                skymail_client._used_codes = set()
                skymail_client._failed_codes = set()
                self._log("force_new_browser: 已重置 skymail_client OTP 状态")
            device_id = str(uuid.uuid4())
            self._log(f"force_new_browser: 新 device_id={device_id}")
        else:
            if not device_id:
                device_id = str(uuid.uuid4())
                self._log(f"OAuth device_id 缺失，已生成新的 device_id={device_id}")
        self.device_id = str(device_id or "").strip()

        user_agent, sec_ch_ua, impersonate = self._ensure_oauth_fingerprint(
            user_agent, sec_ch_ua, impersonate
        )

        code_verifier, code_challenge = generate_pkce()
        oauth_state = secrets.token_urlsafe(32)
        authorize_params = {
            "response_type": "code",
            "client_id": self.oauth_client_id,
            "redirect_uri": self.oauth_redirect_uri,
            "scope": "openid profile email offline_access",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "state": oauth_state,
        }
        authorize_url = f"{self.oauth_issuer}/oauth/authorize"

        seed_oai_device_cookie(self.session, device_id)

        if force_chatgpt_entry:
            self._log("force_chatgpt_entry: 启动 ChatGPT 首页链路（不影响 OAuth PKCE）")
            _ = self._bootstrap_chatgpt_entry(
                email,
                device_id,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )

        self._log("步骤1: Bootstrap OAuth session...")
        authorize_final_url = self._bootstrap_oauth_session(
            authorize_url,
            authorize_params,
            device_id=device_id,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
        )
        if not authorize_final_url:
            self._set_error("Bootstrap 失败")
            return None

        continue_referer = (
            authorize_final_url
            if authorize_final_url.startswith(self.oauth_issuer)
            else f"{self.oauth_issuer}/log-in"
        )

        state = self._submit_authorize_continue(
            email,
            device_id,
            continue_referer,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
            authorize_url=authorize_url,
            authorize_params=authorize_params,
            screen_hint=str(screen_hint or "login"),
        )
        if not state:
            if not self.last_error:
                self._set_error("提交邮箱后未进入有效的 OAuth 状态")
            return None

        self._log(f"OAuth 状态起点: {describe_flow_state(state)}")
        seen_states = {}
        referer = continue_referer

        def _should_stop_after_login(state_to_check: FlowState):
            if not stop_after_login:
                return False
            if self._state_is_login_password(state_to_check):
                return False
            if self._state_is_email_otp(state_to_check):
                return False
            if self._state_is_create_account_password(state_to_check):
                return False
            return True

        for step in range(20):
            self.last_state = state
            self._log(f"状态步进[{step + 1}/20]: {describe_flow_state(state)}")
            signature = self._state_signature(state)
            seen_states[signature] = seen_states.get(signature, 0) + 1
            if seen_states[signature] > 2:
                self._set_error(f"OAuth 状态卡住: {describe_flow_state(state)}")
                return None

            code = self._extract_code_from_state(state)
            if code:
                self._log(f"获取到 authorization code: {code[:20]}...")
                self._log("步骤7: POST /oauth/token")
                tokens = self._exchange_code_for_tokens(
                    code, code_verifier, user_agent, impersonate
                )
                if tokens:
                    self._log("✅ OAuth 登录成功")
                else:
                    self._log("换取 tokens 失败")
                return tokens

            if prefer_passwordless_login and (not force_password_login) and self._state_is_login_password(state):
                next_state = self._send_passwordless_login_otp(
                    email,
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("passwordless OTP 触发后未进入邮箱验证码状态")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_create_account_password(state) and force_password_login:
                self._log("命中 create_account_password，按强制密码登录路径继续")
                next_state = self._submit_password_verify(
                    password,
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or f"{self.oauth_issuer}/log-in/password",
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("密码验证后未进入下一步 OAuth 状态")
                    return None
                if _should_stop_after_login(next_state):
                    self._log(
                        "登录链路已完成（密码验证后进入下一状态），按要求停止"
                    )
                    self.last_state = next_state
                    self._set_error("登录链路已完成，按要求停止")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_login_password(state):
                next_state = self._submit_password_verify(
                    password,
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("密码验证后未进入下一步 OAuth 状态")
                    return None
                if _should_stop_after_login(next_state):
                    self._log(
                        "登录链路已完成（密码验证后进入下一状态），按要求停止"
                    )
                    self.last_state = next_state
                    self._set_error("登录链路已完成，按要求停止")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if (
                prefer_passwordless_login
                and self._state_is_add_phone(state)
                and self._state_requires_navigation(state)
            ):
                self._log("步骤5: OTP 后命中 add_phone，先实际访问 continue_url 争取重签 workspace Cookie")
                code, next_state = self._follow_flow_state(
                    state,
                    referer=referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if code:
                    self._log(f"获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(
                        code, code_verifier, user_agent, impersonate
                    )
                    if tokens:
                        self._log("✅ OAuth 登录成功")
                    else:
                        self._log("换取 tokens 失败")
                    return tokens
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_email_otp(state):
                if not skymail_client:
                    self._set_error(
                        "当前流程需要邮箱 OTP，但缺少接码客户端",
                        error_code="oauth_otp_client_missing",
                    )
                    return None
                next_state = self._handle_otp_verification(
                    email,
                    device_id,
                    user_agent,
                    sec_ch_ua,
                    impersonate,
                    skymail_client,
                    state,
                    prefer_passwordless_login=prefer_passwordless_login,
                    allow_cached_code_retry=_continue_depth > 0,
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("邮箱 OTP 验证后未进入下一步 OAuth 状态")
                    return None
                if _should_stop_after_login(next_state):
                    self._log(
                        "登录链路已完成（OTP 验证后进入下一状态），按要求停止"
                    )
                    self.last_state = next_state
                    self._set_error("登录链路已完成，按要求停止")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if complete_about_you_if_needed and self._state_is_about_you(state):
                self._log("步骤5: 命中 about_you，执行 interrupt 新链路的资料补全提交")
                next_state = self._submit_about_you_create_account(
                    first_name,
                    last_name,
                    birthdate,
                    device_id,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    impersonate=impersonate,
                    referer=state.current_url or state.continue_url or referer,
                )
                if not next_state:
                    if not self.last_error:
                        self._set_error("about_you 提交后未进入下一步 OAuth 状态")
                    return None
                referer = state.current_url or referer
                state = next_state
                continue

            if self._state_is_add_phone(state):
                try:
                    raw_dump = json.dumps(state.raw or {}, ensure_ascii=False)
                except Exception:
                    raw_dump = ""
                if raw_dump:
                    self._log(f"add_phone 状态响应体(raw): {raw_dump}")
                if not allow_phone_verification:
                    if self._state_supports_workspace_resolution(state):
                        self._log(
                            "步骤5: add_phone 命中，但检测到 workspace 线索，继续尝试 workspace/org 选择"
                        )
                    else:
                        self._log(
                            "步骤5: add_phone 暂无显式 workspace 线索，先尝试 canonical consent URL 抢救"
                        )
                    code, next_state = self._oauth_submit_workspace_and_org(
                        f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
                        device_id,
                        user_agent,
                        impersonate,
                    )
                    if code:
                        self._log(f"获取到 authorization code: {code[:20]}...")
                        self._log("步骤7: POST /oauth/token")
                        tokens = self._exchange_code_for_tokens(
                            code, code_verifier, user_agent, impersonate
                        )
                        if tokens:
                            self._log("✅ OAuth 登录成功")
                        else:
                            self._log("换取 tokens 失败")
                        return tokens
                    if next_state:
                        referer = state.current_url or referer
                        state = next_state
                        self._log(f"add_phone -> workspace state -> {describe_flow_state(state)}")
                        continue

                    workspace_error = str(self.last_error or "").strip()
                    if prefer_passwordless_login and _continue_depth < 1:
                        self._log(
                            "步骤5: canonical consent 仍未拿到 workspace/callback"
                            + (
                                f" ({workspace_error})"
                                if workspace_error
                                else ""
                            )
                            + "，重启一次全新 OAuth session + 新 PKCE"
                        )
                        self._recreate_session()
                        return self.login_and_get_tokens(
                            email,
                            password,
                            device_id,
                            user_agent=user_agent,
                            sec_ch_ua=sec_ch_ua,
                            impersonate=impersonate,
                            skymail_client=skymail_client,
                            prefer_passwordless_login=prefer_passwordless_login,
                            allow_phone_verification=allow_phone_verification,
                            complete_about_you_if_needed=complete_about_you_if_needed,
                            first_name=first_name,
                            last_name=last_name,
                            birthdate=birthdate,
                            login_source=(
                                f"{login_source}:add_phone_continue"
                                if login_source
                                else "add_phone_continue"
                            ),
                            _continue_depth=_continue_depth + 1,
                        )
                    else:
                        reason = (
                            "passwordless 登录后仍停留在 add_phone"
                            + (f" ({workspace_error})" if workspace_error else "")
                        )
                        self._set_error(
                            reason,
                            error_code="add_phone_workspace_or_callback_missing",
                        )
                        defer_add_phone_blacklist = self._read_bool_config(
                            (
                                "chatgpt_defer_add_phone_blacklist_for_at_fallback",
                                "chatgpt_add_phone_at_fallback_enabled",
                            ),
                            default=False,
                        )
                        if defer_add_phone_blacklist:
                            self._log(
                                f"邮箱 {email} 命中 add_phone 风控，暂不立即加入黑名单；交由 access_token_only 兜底"
                            )
                            return None
                        _append_add_phone_blacklist(email, reason=reason)
                        self._log(
                            f"邮箱 {email} 已加入 add_phone 黑名单，跳过本轮以避免 OpenAI 风控加重"
                        )
                        raise SkipCurrentAttemptRequested(f"add_phone 风控: {reason}")
                else:
                    next_state = self._handle_add_phone_verification(
                        device_id,
                        user_agent,
                        sec_ch_ua,
                        impersonate,
                        state,
                    )
                    if not next_state:
                        if not self.last_error:
                            self._set_error("手机号验证后未进入下一步 OAuth 状态")
                        return None
                    referer = state.current_url or referer
                    state = next_state
                    continue

            if self._state_requires_navigation(state):
                code, next_state = self._follow_flow_state(
                    state,
                    referer=referer,
                    user_agent=user_agent,
                    impersonate=impersonate,
                )
                if code:
                    self._log(f"获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(
                        code, code_verifier, user_agent, impersonate
                    )
                    if tokens:
                        self._log("✅ OAuth 登录成功")
                    else:
                        self._log("换取 tokens 失败")
                    return tokens
                referer = state.current_url or referer
                state = next_state
                self._log(f"follow state -> {describe_flow_state(state)}")
                continue

            if self._state_supports_workspace_resolution(state):
                self._log("步骤6: 执行 workspace/org 选择")
                consent_entry = (
                    state.continue_url
                    or state.current_url
                    or f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                )
                if self._state_is_add_phone(state):
                    consent_entry = (
                        f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent"
                    )
                    self._log("步骤6: 当前处于 add_phone，改用 canonical consent URL 继续")
                code, next_state = self._oauth_submit_workspace_and_org(
                    consent_entry,
                    device_id,
                    user_agent,
                    impersonate,
                )
                if code:
                    self._log(f"获取到 authorization code: {code[:20]}...")
                    self._log("步骤7: POST /oauth/token")
                    tokens = self._exchange_code_for_tokens(
                        code, code_verifier, user_agent, impersonate
                    )
                    if tokens:
                        self._log("✅ OAuth 登录成功")
                    else:
                        self._log("换取 tokens 失败")
                    return tokens
                if next_state:
                    referer = state.current_url or referer
                    state = next_state
                    self._log(f"workspace state -> {describe_flow_state(state)}")
                    continue

                if not self.last_error:
                    self._set_error(
                        f"workspace/org 选择失败: {describe_flow_state(state)}"
                    )
                return None

            self._set_error(f"未支持的 OAuth 状态: {describe_flow_state(state)}")
            return None

        self._set_error("OAuth 状态机超出最大步数")
        return None

    def _extract_code_from_url(self, url):
        """从 URL 中提取 code"""
        if not url or "code=" not in url:
            return None
        try:
            return parse_qs(urlparse(url).query).get("code", [None])[0]
        except Exception:
            return None

    def _oauth_follow_for_code(
        self, start_url, referer, user_agent, impersonate, max_hops=16
    ):
        """跟随 URL 获取 authorization code（手动跟随重定向）"""
        code, next_state = self._follow_flow_state(
            self._state_from_url(start_url),
            referer=referer,
            user_agent=user_agent,
            impersonate=impersonate,
            max_hops=max_hops,
        )
        return code, (next_state.current_url or next_state.continue_url or start_url)

    def _acquire_sentinel_token(
        self,
        flow: str,
        page_url: str,
        device_id: str,
        user_agent: str | None = None,
        sec_ch_ua: str | None = None,
        impersonate: str | None = None,
    ) -> str:
        """统一的 sentinel token 获取：优先 Playwright，失败回退 HTTP PoW。"""
        token = get_sentinel_token_via_browser(
            flow=flow,
            proxy=self.proxy,
            page_url=page_url or self.oauth_issuer,
            headless=self.browser_mode != "headed",
            device_id=device_id,
            log_fn=lambda msg: self._log(f"{flow}: {msg}"),
        )
        if token:
            self._log(f"{flow}: 已通过 Playwright SentinelSDK 获取 token")
            return token
        token = build_sentinel_token(
            self.session,
            device_id,
            flow=flow,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            impersonate=impersonate,
        )
        if token:
            self._log(f"{flow}: 已通过 HTTP PoW 获取 token")
        return token or ""

    def _post_workspace_select(
        self,
        workspace_id: str,
        consent_url: str,
        device_id: str,
        user_agent,
        sec_ch_ua,
        impersonate,
        *,
        attempts: int = 3,
    ):
        """POST /workspace/select，带 sentinel + 接口级退避重试。

        返回 tuple(status_code, response_or_none)。上层基于该结果判定是否继续。
        """
        url = f"{self.oauth_issuer}/api/accounts/workspace/select"
        last_exc = None
        for attempt in range(max(1, int(attempts))):
            sentinel = self._acquire_sentinel_token(
                "workspace_select",
                consent_url or self.oauth_issuer,
                device_id,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            headers = self._headers(
                url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="application/json",
                referer=consent_url,
                origin=self.oauth_issuer,
                content_type="application/json",
                fetch_site="same-origin",
                extra_headers={
                    "oai-device-id": device_id,
                    **({"openai-sentinel-token": sentinel} if sentinel else {}),
                },
            )
            headers.update(generate_datadog_trace())

            try:
                kwargs = {
                    "json": {"workspace_id": workspace_id},
                    "headers": headers,
                    "allow_redirects": False,
                    "timeout": 30,
                }
                if impersonate:
                    kwargs["impersonate"] = impersonate

                self._browser_pause()
                r = self._http("POST", url, **kwargs)
                self._log(
                    f"workspace/select -> {r.status_code} "
                    f"(attempt {attempt + 1}/{attempts}, sentinel={'on' if sentinel else 'off'})"
                )
                if r.status_code < 500 and r.status_code != 429:
                    return r.status_code, r
            except Exception as exc:
                last_exc = exc
                self._log(f"workspace/select 异常 (attempt {attempt + 1}): {exc}")

            if attempt < attempts - 1:
                backoff = min(8.0, 1.0 * (2 ** attempt))
                time.sleep(backoff)

        if last_exc is not None:
            self._set_error(
                f"workspace/select 异常: {last_exc}",
                error_code="workspace_select_request_failed",
            )
        return None, None

    def _post_organization_select(
        self,
        org_id: str,
        project_id: str | None,
        referer: str,
        device_id: str,
        user_agent,
        sec_ch_ua,
        impersonate,
        *,
        attempts: int = 3,
    ):
        """POST /organization/select，带 sentinel + 接口级退避重试。"""
        url = f"{self.oauth_issuer}/api/accounts/organization/select"
        body: dict[str, str] = {"org_id": org_id}
        if project_id:
            body["project_id"] = project_id

        last_exc = None
        for attempt in range(max(1, int(attempts))):
            sentinel = self._acquire_sentinel_token(
                "organization_select",
                referer or self.oauth_issuer,
                device_id,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            headers = self._headers(
                url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="application/json",
                referer=referer,
                origin=self.oauth_issuer,
                content_type="application/json",
                fetch_site="same-origin",
                extra_headers={
                    "oai-device-id": device_id,
                    **({"openai-sentinel-token": sentinel} if sentinel else {}),
                },
            )
            headers.update(generate_datadog_trace())

            try:
                kwargs = {
                    "json": body,
                    "headers": headers,
                    "allow_redirects": False,
                    "timeout": 30,
                }
                if impersonate:
                    kwargs["impersonate"] = impersonate

                self._browser_pause()
                r = self._http("POST", url, **kwargs)
                self._log(
                    f"organization/select -> {r.status_code} "
                    f"(attempt {attempt + 1}/{attempts}, sentinel={'on' if sentinel else 'off'})"
                )
                if r.status_code < 500 and r.status_code != 429:
                    return r.status_code, r
            except Exception as exc:
                last_exc = exc
                self._log(f"organization/select 异常 (attempt {attempt + 1}): {exc}")

            if attempt < attempts - 1:
                backoff = min(8.0, 1.0 * (2 ** attempt))
                time.sleep(backoff)

        if last_exc is not None:
            self._set_error(
                f"organization/select 异常: {last_exc}",
                error_code="organization_select_request_failed",
            )
        return None, None

    def _oauth_submit_workspace_and_org(
        self, consent_url, device_id, user_agent, impersonate, max_retries=3
    ):
        """提交 workspace 和 organization 选择。

        核心鲁棒性改进（见失败模式分析）：
          1. POST /workspace/select 与 /organization/select 均带 openai-sentinel-token
             （与 authorize_continue / email_otp_validate 对齐，避免服务端返回降级 HTML）
          2. session_data 获取采用指数退避（0.5s → 2s → 6s），给新账号后端同步时间
          3. 多候选循环：依次尝试全部 workspaces × 全部 orgs，不再固定取 [0]
          4. 接口层重试：非 200 / 429 / 5xx / 网络异常自动退避重试
        """
        self._enter_stage("workspace_select", consent_url[:120] if consent_url else "")
        sec_ch_ua = getattr(self, "sec_ch_ua", None)

        # ─── 阶段 1：获取 consent session_data（指数退避 0.5/2/6s）
        session_data = None
        for attempt in range(max_retries):
            session_data = self._load_workspace_session_data(
                consent_url=consent_url,
                user_agent=user_agent,
                impersonate=impersonate,
            )
            if session_data and session_data.get("workspaces"):
                break
            if attempt < max_retries - 1:
                backoff = min(8.0, 0.5 * (3 ** attempt))
                self._log(
                    f"无法获取 consent session 数据，{backoff:.1f}s 后重试 "
                    f"({attempt + 1}/{max_retries})"
                )
                time.sleep(backoff)

        if not session_data or not session_data.get("workspaces"):
            self._set_error(
                "无法获取 consent session 数据",
                error_code="consent_session_missing",
            )
            return None, None

        workspaces = [ws for ws in (session_data.get("workspaces") or []) if (ws or {}).get("id")]
        if not workspaces:
            self._set_error("session 中没有 workspace 信息", error_code="workspace_missing")
            return None, None

        last_state = None
        # ─── 阶段 2 / 3：多候选循环
        for ws_idx, workspace in enumerate(workspaces):
            workspace_id = str((workspace or {}).get("id") or "").strip()
            if not workspace_id:
                continue
            self.last_workspace_id = workspace_id
            self._log(
                f"选择 workspace [{ws_idx + 1}/{len(workspaces)}]: {workspace_id}"
            )
            self._log(
                f"workspace/select 请求: workspace_id={workspace_id} "
                f"consent_url={(consent_url or '')[:120]}"
            )

            status_code, r = self._post_workspace_select(
                workspace_id,
                consent_url,
                device_id,
                user_agent,
                sec_ch_ua,
                impersonate,
            )
            if r is None:
                continue  # 接口级重试仍失败，尝试下一个 workspace
            if status_code != 200 and status_code not in (301, 302, 303, 307, 308):
                self._log(
                    f"workspace/select 非成功状态 {status_code}，跳过该 workspace 继续尝试"
                )
                continue

            # 2a. 重定向直出 code（罕见但要处理）
            if status_code in (301, 302, 303, 307, 308):
                location = normalize_flow_url(
                    r.headers.get("Location", ""), auth_base=self.oauth_issuer
                )
                if "code=" in location:
                    code = self._extract_code_from_url(location)
                    if code:
                        self._log("从 workspace/select 重定向获取到 code")
                        return code, self._state_from_url(location)
                if location:
                    last_state = self._state_from_url(location)
                continue

            # 2b. 200 → 解析 orgs，多候选循环
            try:
                data = r.json()
            except Exception as exc:
                self._set_error(
                    f"解析 workspace/select 响应异常: {exc}",
                    error_code="workspace_select_response_invalid",
                )
                continue

            workspace_state = self._state_from_payload(data, current_url=str(r.url))
            continue_url = workspace_state.continue_url
            orgs = [o for o in (data.get("data", {}).get("orgs") or []) if (o or {}).get("id")]

            # Fallback：/workspace/select 响应 orgs 为空时，退回到 consent HTML 解析到的 orgs
            if not orgs:
                session_orgs = [
                    o for o in (session_data.get("orgs") or []) if (o or {}).get("id")
                ]
                if session_orgs:
                    self._log(
                        f"/workspace/select 响应 orgs 为空，fallback 到 consent HTML 解析的 "
                        f"{len(session_orgs)} 个 org 候选"
                    )
                    orgs = session_orgs

            if not orgs and continue_url:
                # 无 orgs 直接跟随 continue_url 看能否拿到 code
                code, _ = self._oauth_follow_for_code(
                    continue_url, consent_url, user_agent, impersonate
                )
                if code:
                    return code, self._state_from_url(continue_url)

            for org_idx, org in enumerate(orgs):
                org_id = str((org or {}).get("id") or "").strip()
                if not org_id:
                    continue
                projects = (org or {}).get("projects") or []
                project_id = str((projects[0] or {}).get("id") or "").strip() if projects else ""
                self._log(
                    f"选择 organization [{org_idx + 1}/{len(orgs)}]: {org_id} "
                    f"project={project_id or '-'}"
                )
                org_referer = (
                    continue_url
                    if continue_url and continue_url.startswith("http")
                    else consent_url
                )
                self._log(
                    f"organization/select 请求: org_id={org_id} project_id={project_id or '-'}"
                )
                org_status, r_org = self._post_organization_select(
                    org_id,
                    project_id or None,
                    org_referer,
                    device_id,
                    user_agent,
                    sec_ch_ua,
                    impersonate,
                )
                if r_org is None:
                    continue

                # 3a. 重定向拿 code
                if org_status in (301, 302, 303, 307, 308):
                    location = normalize_flow_url(
                        r_org.headers.get("Location", ""),
                        auth_base=self.oauth_issuer,
                    )
                    if "code=" in location:
                        code = self._extract_code_from_url(location)
                        if code:
                            self._log("从 organization/select 重定向获取到 code")
                            return code, self._state_from_url(location)
                    if location:
                        follow_state = self._state_from_url(location)
                        # 跟随 location 再拿 code
                        code, _ = self._oauth_follow_for_code(
                            location, org_referer, user_agent, impersonate
                        )
                        if code:
                            return code, follow_state
                        last_state = follow_state
                        continue

                # 3b. 200 → state 含 code？
                if org_status == 200:
                    try:
                        org_state = self._state_from_payload(
                            r_org.json(), current_url=str(r_org.url)
                        )
                        self._log(
                            f"organization/select -> {describe_flow_state(org_state)}"
                        )
                        code = self._extract_code_from_state(org_state)
                        if code:
                            return code, org_state

                        # 跟随 continue_url 取 code
                        next_url = org_state.continue_url or continue_url
                        if next_url:
                            code, _ = self._oauth_follow_for_code(
                                next_url, org_referer, user_agent, impersonate
                            )
                            if code:
                                return code, org_state
                        last_state = org_state
                    except Exception as exc:
                        self._set_error(
                            f"解析 organization/select 响应异常: {exc}",
                            error_code="organization_select_response_invalid",
                        )
                    continue

                # 非预期状态
                self._log(
                    f"organization/select 非预期状态 {org_status}，尝试下一个 org 候选"
                )

            # 本 workspace 的 orgs 全部试过都没拿到 code，尝试最终 continue_url
            if continue_url:
                code, _ = self._oauth_follow_for_code(
                    continue_url, consent_url, user_agent, impersonate
                )
                if code:
                    return code, self._state_from_url(continue_url)

            last_state = workspace_state

        self._set_error(
            "workspace/organization 候选全部尝试后仍未拿到 code",
            error_code="workspace_select_exhausted",
        )
        return None, last_state

    def _load_workspace_session_data(self, consent_url, user_agent, impersonate):
        """优先从 cookie 解码 session，失败时回退到 consent HTML 中提取 workspace 数据。"""
        session_data = self._decode_oauth_session_cookie()
        if session_data and session_data.get("workspaces"):
            return session_data

        html = self._fetch_consent_page_html(consent_url, user_agent, impersonate)
        if not html:
            return session_data

        parsed = self._extract_session_data_from_consent_html(html)
        if parsed and parsed.get("workspaces"):
            self._log(
                f"从 consent HTML 提取到 {len(parsed.get('workspaces', []))} 个 workspace"
            )
            return parsed

        return session_data

    def _fetch_consent_page_html(self, consent_url, user_agent, impersonate):
        """获取 consent 页 HTML，用于解析 React Router stream 中的 session 数据。"""
        try:
            headers = self._headers(
                consent_url,
                user_agent=user_agent,
                accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                referer=f"{self.oauth_issuer}/email-verification",
                navigation=True,
            )
            kwargs = {"headers": headers, "allow_redirects": False, "timeout": 30}
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause(0.12, 0.3)
            r = self._http("GET", consent_url, **kwargs)
            if r.status_code == 200 and "text/html" in (
                r.headers.get("content-type", "").lower()
            ):
                return r.text
        except Exception:
            pass
        return ""

    def _extract_session_data_from_consent_html(self, html):
        """从 consent HTML 的 React Router stream 中提取 workspace + orgs session 数据。

        返回结构:
          {
            "session_id": str,
            "openai_client_id": str,
            "workspaces": [{"id": "<uuid>", "kind": ...}, ...],
            "orgs": [{"id": "org-...", "projects": [{"id": "proj_..."}]}, ...]
          }
        其中 orgs 是 /workspace/select 响应 orgs 为空时的 fallback 数据源。
        """
        import json
        import re

        if not html or "workspaces" not in html:
            return None

        def _first_match(patterns, text):
            for pattern in patterns:
                m = re.search(pattern, text, re.S)
                if m:
                    return m.group(1)
            return ""

        def _extract_orgs(normalized: str) -> list[dict]:
            """从 normalized 文本里解出 orgs 列表（id=org-xxx，projects=proj_xxx）。"""
            org_ids = re.findall(r'"(org-[A-Za-z0-9]+)"', normalized)
            if not org_ids:
                return []
            # 保序去重
            unique_orgs: list[str] = []
            seen_org: set[str] = set()
            for oid in org_ids:
                if oid in seen_org:
                    continue
                seen_org.add(oid)
                unique_orgs.append(oid)

            # 为每个 org 贪心地抓紧邻其后的第一个 proj_xxx（typical stream 顺序）
            orgs: list[dict] = []
            cursor = 0
            for oid in unique_orgs:
                pos = normalized.find(oid, cursor)
                if pos < 0:
                    orgs.append({"id": oid, "projects": []})
                    continue
                # 在 org 之后 1200 字符内找第一个 proj_xxx
                window = normalized[pos : pos + 1200]
                proj_match = re.search(r'"(proj_[A-Za-z0-9]+)"', window)
                projects = (
                    [{"id": proj_match.group(1)}] if proj_match else []
                )
                orgs.append({"id": oid, "projects": projects})
                cursor = pos + 1
            return orgs

        def _build_from_text(text):
            if not text or "workspaces" not in text:
                return None

            normalized = text.replace('\\"', '"')

            session_id = _first_match(
                [
                    r'"session_id","([^"]+)"',
                    r'"session_id":"([^"]+)"',
                ],
                normalized,
            )
            client_id = _first_match(
                [
                    r'"openai_client_id","([^"]+)"',
                    r'"openai_client_id":"([^"]+)"',
                ],
                normalized,
            )

            start = normalized.find('"workspaces"')
            if start < 0:
                start = normalized.find("workspaces")
            if start < 0:
                return None

            end = normalized.find('"openai_client_id"', start)
            if end < 0:
                end = normalized.find("openai_client_id", start)
            if end < 0:
                end = min(len(normalized), start + 4000)
            else:
                end = min(len(normalized), end + 600)

            workspace_chunk = normalized[start:end]
            ids = re.findall(r'"id"(?:,|:)"([0-9a-fA-F-]{36})"', workspace_chunk)
            if not ids:
                return None

            kinds = re.findall(r'"kind"(?:,|:)"([^"]+)"', workspace_chunk)
            workspaces = []
            seen = set()
            for idx, wid in enumerate(ids):
                if wid in seen:
                    continue
                seen.add(wid)
                item = {"id": wid}
                if idx < len(kinds):
                    item["kind"] = kinds[idx]
                workspaces.append(item)

            if not workspaces:
                return None

            return {
                "session_id": session_id,
                "openai_client_id": client_id,
                "workspaces": workspaces,
                "orgs": _extract_orgs(normalized),
            }

        candidates = [html]

        for quoted in re.findall(
            r'streamController\.enqueue\(("(?:\\.|[^"\\])*")\)',
            html,
            re.S,
        ):
            try:
                decoded = json.loads(quoted)
            except Exception:
                continue
            if decoded:
                candidates.append(decoded)

        if '\\"' in html:
            candidates.append(html.replace('\\"', '"'))

        best = None
        for candidate in candidates:
            parsed = _build_from_text(candidate)
            if not parsed or not parsed.get("workspaces"):
                continue
            # 优先保留同时带 orgs 的候选；否则返回第一个能解到 workspaces 的
            if parsed.get("orgs"):
                return parsed
            if best is None:
                best = parsed
        return best

    def _decode_oauth_session_cookie(self):
        """解码 oai-client-auth-session cookie"""
        try:
            for cookie in self.session.cookies:
                try:
                    name = cookie.name if hasattr(cookie, "name") else str(cookie)
                    if name == "oai-client-auth-session":
                        value = (
                            cookie.value
                            if hasattr(cookie, "value")
                            else self.session.cookies.get(name)
                        )
                        if value:
                            data = self._decode_cookie_json_value(value)
                            if data:
                                return data
                except Exception:
                    continue
        except Exception:
            pass

        return None

    @staticmethod
    def _decode_cookie_json_value(value):
        import base64
        import json

        raw_value = str(value or "").strip()
        if not raw_value:
            return None

        candidates = [raw_value]
        if "." in raw_value:
            candidates.insert(0, raw_value.split(".", 1)[0])

        for candidate in candidates:
            candidate = candidate.strip()
            if not candidate:
                continue
            padded = candidate + "=" * (-len(candidate) % 4)
            for decoder in (base64.urlsafe_b64decode, base64.b64decode):
                try:
                    decoded = decoder(padded).decode("utf-8")
                    parsed = json.loads(decoded)
                except Exception:
                    continue
                if isinstance(parsed, dict):
                    return parsed

        return None

    def _exchange_code_for_tokens(self, code, code_verifier, user_agent, impersonate):
        """用 authorization code 换取 tokens"""
        self._enter_stage("token_exchange", f"code={str(code or '')[:24]}...")
        url = f"{self.oauth_issuer}/oauth/token"

        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.oauth_redirect_uri,
            "client_id": self.oauth_client_id,
            "code_verifier": code_verifier,
        }

        headers = self._headers(
            url,
            user_agent=user_agent,
            accept="application/json",
            referer=f"{self.oauth_issuer}/sign-in-with-chatgpt/codex/consent",
            origin=self.oauth_issuer,
            content_type="application/x-www-form-urlencoded",
            fetch_site="same-origin",
        )

        try:
            kwargs = {"data": payload, "headers": headers, "timeout": 60}
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause()
            r = self._http("POST", url, **kwargs)

            if r.status_code == 200:
                self._log("token_exchange 成功")
                return r.json()
            else:
                self._set_error(f"换取 tokens 失败: {r.status_code} - {r.text[:200]}")

        except Exception as e:
            self._set_error(f"换取 tokens 异常: {e}")

        return None

    def _send_phone_number(self, phone, device_id, user_agent, sec_ch_ua, impersonate):
        request_url = f"{self.oauth_issuer}/api/accounts/add-phone/send"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=f"{self.oauth_issuer}/add-phone",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={"oai-device-id": device_id},
        )
        headers.update(generate_datadog_trace())

        try:
            kwargs = {
                "json": {"phone_number": phone},
                "headers": headers,
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate

            self._browser_pause(0.12, 0.25)
            resp = self._http("POST", request_url, **kwargs)
        except Exception as e:
            return False, None, f"add-phone/send 异常: {e}"

        self._log(f"/add-phone/send -> {resp.status_code}")
        if resp.status_code != 200:
            return (
                False,
                None,
                f"add-phone/send 失败: {resp.status_code} - {resp.text[:180]}",
            )

        try:
            data = resp.json()
        except Exception:
            return False, None, "add-phone/send 响应不是 JSON"

        next_state = self._state_from_payload(
            data, current_url=str(resp.url) or request_url
        )
        self._log(f"add-phone/send {describe_flow_state(next_state)}")
        return True, next_state, ""

    def _resend_phone_otp(
        self,
        phone_number,
        device_id,
        user_agent,
        sec_ch_ua,
        impersonate,
        state: FlowState,
    ):
        request_url = f"{self.oauth_issuer}/api/accounts/add-phone/send"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=state.current_url
            or state.continue_url
            or f"{self.oauth_issuer}/add-phone",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={"oai-device-id": device_id},
        )
        headers.update(generate_datadog_trace())

        try:
            kwargs = {
                "json": {"phone_number": phone_number},
                "headers": headers,
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause(0.12, 0.25)
            resp = self._http("POST", request_url, **kwargs)
        except Exception as e:
            return False, f"add-phone/send 重发异常: {e}"

        self._log(f"/add-phone/send(resend) -> {resp.status_code}")
        if resp.status_code == 200:
            return True, ""
        return False, f"add-phone/send 重发失败: {resp.status_code} - {resp.text[:180]}"

    def _get_config_value(self, *keys):
        for key in keys:
            value = str(self.config.get(key, "") or "").strip()
            if value:
                return value
        return ""

    def _get_configured_phone_number(self) -> str:
        return self._get_config_value(
            "chatgpt_phone_number",
            "openai_phone_number",
            "phone_number",
        )

    def _get_configured_phone_codes(self) -> list[str]:
        raw = self._get_config_value(
            "chatgpt_phone_otp_codes",
            "chatgpt_phone_otp_code",
            "openai_phone_otp_codes",
            "openai_phone_otp_code",
            "phone_otp_codes",
            "phone_otp_code",
        )
        if not raw:
            return []
        parts = []
        for chunk in raw.replace("\n", ",").replace(";", ",").split(","):
            code = str(chunk or "").strip()
            if code:
                parts.append(code)
        return parts

    def _validate_phone_otp(
        self, code, device_id, user_agent, sec_ch_ua, impersonate, state: FlowState
    ):
        request_url = f"{self.oauth_issuer}/api/accounts/phone-otp/validate"
        headers = self._headers(
            request_url,
            user_agent=user_agent,
            sec_ch_ua=sec_ch_ua,
            accept="application/json",
            referer=state.current_url
            or state.continue_url
            or f"{self.oauth_issuer}/phone-verification",
            origin=self.oauth_issuer,
            content_type="application/json",
            fetch_site="same-origin",
            extra_headers={"oai-device-id": device_id},
        )
        headers.update(generate_datadog_trace())

        try:
            kwargs = {
                "json": {"code": code},
                "headers": headers,
                "timeout": 30,
                "allow_redirects": False,
            }
            if impersonate:
                kwargs["impersonate"] = impersonate
            self._browser_pause(0.12, 0.25)
            resp = self._http("POST", request_url, **kwargs)
        except Exception as e:
            return False, None, f"phone-otp/validate 异常: {e}"

        self._log(f"/phone-otp/validate -> {resp.status_code}")
        if resp.status_code != 200:
            if resp.status_code == 401:
                return False, None, "手机号验证码错误"
            return (
                False,
                None,
                f"phone-otp/validate 失败: {resp.status_code} - {resp.text[:180]}",
            )

        try:
            data = resp.json()
        except Exception:
            return False, None, "phone-otp/validate 响应不是 JSON"

        next_state = self._state_from_payload(
            data, current_url=str(resp.url) or request_url
        )
        self._log(f"手机号 OTP 验证通过 {describe_flow_state(next_state)}")
        return True, next_state, ""

    def _handle_add_phone_verification(
        self, device_id, user_agent, sec_ch_ua, impersonate, state: FlowState
    ):
        configured_phone = self._get_configured_phone_number()
        configured_codes = self._get_configured_phone_codes()

        if configured_phone:
            self._log(f"步骤5: add_phone 使用配置手机号: {configured_phone}")
            sent, next_state, detail = self._send_phone_number(
                configured_phone,
                device_id,
                user_agent,
                sec_ch_ua,
                impersonate,
            )
            if not sent or not next_state:
                self._set_error(
                    detail or "add-phone/send 未返回有效状态",
                    error_code="add_phone_send_failed",
                )
                return None

            if (
                next_state.page_type != "phone_otp_verification"
                and "phone-verification"
                not in f"{next_state.continue_url} {next_state.current_url}".lower()
            ):
                if self._state_supports_workspace_resolution(next_state) or self._state_requires_navigation(next_state):
                    self._log(f"add_phone 提交后已进入后续状态: {describe_flow_state(next_state)}")
                    return next_state
                self._set_error(
                    f"add-phone/send 未进入手机验证码页: {describe_flow_state(next_state)}",
                    error_code="add_phone_state_unexpected",
                )
                return None

            if configured_codes:
                for idx, code in enumerate(configured_codes, start=1):
                    self._log(
                        f"步骤5: 使用配置手机号验证码 {idx}/{len(configured_codes)}: {code}"
                    )
                    valid, validated_state, detail = self._validate_phone_otp(
                        code,
                        device_id,
                        user_agent,
                        sec_ch_ua,
                        impersonate,
                        next_state,
                    )
                    if valid and validated_state:
                        return validated_state
                    self._log(detail or "手机号 OTP 验证失败")

                self._set_error(
                    "配置的手机号验证码未通过验证",
                    error_code="add_phone_config_code_invalid",
                )
                return None

            self._set_error(
                "已提交配置手机号，但未提供 chatgpt_phone_otp_code，当前流程无法继续",
                error_code="add_phone_config_code_missing",
            )
            return None

        phone_service = SMSToMePhoneService(self.config, log_fn=self._log)
        if not phone_service.enabled:
            self._set_error(
                "当前链路需要手机号验证，但未配置可用的手机号能力（SMSToMe 或固定手机号验证码）",
                error_code="add_phone_capability_missing",
            )
            return None

        excluded_prefixes = set()
        last_failure = ""

        for attempt in range(phone_service.max_attempts):
            try:
                entry = phone_service.acquire_phone(exclude_prefixes=excluded_prefixes)
            except Exception as e:
                last_failure = f"获取手机号失败: {e}"
                self._log(last_failure)
                break

            if not entry:
                last_failure = last_failure or "SMSToMe 号码池中无可用手机号"
                break

            prefix = phone_service.prefix_hint(entry.phone)
            self._log(
                f"步骤5: add_phone 选择手机号 {attempt + 1}/{phone_service.max_attempts}: {entry.phone} ({entry.country_slug})"
            )

            sent, next_state, detail = self._send_phone_number(
                entry.phone,
                device_id,
                user_agent,
                sec_ch_ua,
                impersonate,
            )
            if not sent or not next_state:
                last_failure = detail or "add-phone/send 未返回有效状态"
                self._log(last_failure)
                self._blacklist_phone_if_needed(phone_service, entry, last_failure)
                excluded_prefixes.add(prefix)
                continue

            if (
                next_state.page_type != "phone_otp_verification"
                and "phone-verification"
                not in f"{next_state.continue_url} {next_state.current_url}".lower()
            ):
                last_failure = f"add-phone/send 未进入手机验证码页: {describe_flow_state(next_state)}"
                self._log(last_failure)
                self._blacklist_phone_if_needed(
                    phone_service, entry, last_failure, next_state
                )
                excluded_prefixes.add(prefix)
                continue

            session_data = self._decode_oauth_session_cookie() or {}
            verification_channel = (
                str(session_data.get("phone_verification_channel") or "sms")
                .strip()
                .lower()
                or "sms"
            )
            bound_phone = (
                str(session_data.get("phone_number") or entry.phone).strip()
                or entry.phone
            )
            self._log(
                f"add_phone 发码成功: phone={bound_phone}, channel={verification_channel}"
            )

            if verification_channel != "sms":
                last_failure = f"add_phone 已切到 {verification_channel} 通道，当前 SMSToMe 仅支持短信接码"
                self._log(last_failure)
                excluded_prefixes.add(prefix)
                continue

            code = phone_service.wait_for_code(entry)
            if not code:
                self._log("手机号验证码暂未收到，尝试重发一次...")
                resend_ok, resend_detail = self._resend_phone_otp(
                    entry.phone,
                    device_id,
                    user_agent,
                    sec_ch_ua,
                    impersonate,
                    next_state,
                )
                if resend_ok:
                    code = phone_service.wait_for_code(entry)
                if not code:
                    last_failure = (
                        resend_detail or f"手机号 {entry.phone} 未收到短信验证码"
                    )
                    self._log(last_failure)
                    excluded_prefixes.add(prefix)
                    continue

            valid, validated_state, detail = self._validate_phone_otp(
                code,
                device_id,
                user_agent,
                sec_ch_ua,
                impersonate,
                next_state,
            )
            if not valid or not validated_state:
                last_failure = detail or "手机号 OTP 验证失败"
                self._log(last_failure)
                excluded_prefixes.add(prefix)
                continue

            return validated_state

        self._set_error(
            f"add_phone 阶段失败: {last_failure or '未完成手机号验证'}",
            error_code="add_phone_verification_failed",
        )
        return None

    def _handle_otp_verification(
        self,
        email,
        device_id,
        user_agent,
        sec_ch_ua,
        impersonate,
        skymail_client,
        state,
        *,
        prefer_passwordless_login=False,
        allow_cached_code_retry=False,
    ):
        """处理 OAuth 阶段的邮箱 OTP 验证，返回服务端声明的下一步状态。"""
        self._enter_stage("otp", f"email={email}")
        self._log("步骤4: 检测到邮箱 OTP 验证")
        # 记录 OTP 发送时间基线——必须在 sentinel token 等耗时操作之前，
        # 否则邮件 created_at 会早于 otp_cutoff 导致验证码被误判为旧邮件。
        _otp_sent_at_baseline = time.time()

        def _resend_email_otp() -> bool:
            prefer_passwordless = bool(
                prefer_passwordless_login
                or allow_cached_code_retry
                or self.config.get("prefer_passwordless_login")
                or self.config.get("force_passwordless_login")
            )
            resend_ok = False
            if prefer_passwordless:
                request_url = f"{self.oauth_issuer}/api/accounts/passwordless/send-otp"
                headers = self._headers(
                    request_url,
                    user_agent=user_agent,
                    sec_ch_ua=sec_ch_ua,
                    accept="application/json",
                    referer=state.current_url
                    or state.continue_url
                    or f"{self.oauth_issuer}/log-in/password",
                    origin=self.oauth_issuer,
                    content_type="application/json",
                    fetch_site="same-origin",
                    extra_headers={
                        "oai-device-id": device_id,
                    },
                )
                headers.update(generate_datadog_trace())
                try:
                    kwargs = {"headers": headers, "timeout": 30, "allow_redirects": False}
                    if impersonate:
                        kwargs["impersonate"] = impersonate
                    self._browser_pause()
                    resp = self._http("POST", request_url, **kwargs)
                    self._log(f"/passwordless/send-otp -> {resp.status_code}")
                    if resp.status_code == 200:
                        resend_ok = True
                except Exception as e:
                    self._log(f"passwordless resend 异常: {e}")

            if resend_ok:
                self._log("已触发 passwordless OTP 重发")
                return True

            request_url = f"{self.oauth_issuer}/api/accounts/email-otp/send"
            headers = self._headers(
                request_url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="application/json, text/plain, */*",
                referer=state.current_url
                or state.continue_url
                or f"{self.oauth_issuer}/email-verification",
                fetch_site="same-origin",
                extra_headers={
                    "oai-device-id": device_id,
                },
            )
            headers.update(generate_datadog_trace())
            try:
                kwargs = {"headers": headers, "timeout": 30, "allow_redirects": True}
                if impersonate:
                    kwargs["impersonate"] = impersonate
                self._browser_pause()
                resp = self._http("GET", request_url, **kwargs)
                self._log(f"/email-otp/send -> {resp.status_code}")
                if resp.status_code == 200:
                    self._log("已触发 email-otp 重发")
                    return True
                self._log(f"email-otp/send 重发失败: {resp.text[:120]}")
            except Exception as e:
                self._log(f"email-otp/send 重发异常: {e}")
            return False

        request_url = f"{self.oauth_issuer}/api/accounts/email-otp/validate"
        self._log(f"email_otp_validate: device_id={device_id}")
        otp_referer = (
            state.current_url
            or state.continue_url
            or f"{self.oauth_issuer}/email-verification"
        )
        sentinel_otp = get_sentinel_token_via_browser(
            flow="email_otp_validate",
            proxy=self.proxy,
            page_url=otp_referer,
            headless=self.browser_mode != "headed",
            device_id=device_id,
            log_fn=lambda msg: self._log(f"email_otp_validate: {msg}"),
        )
        if sentinel_otp:
            self._log("email_otp_validate: 已通过 Playwright SentinelSDK 获取 token")
        else:
            sentinel_otp = build_sentinel_token(
                self.session,
                device_id,
                flow="email_otp_validate",
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                impersonate=impersonate,
            )
            if sentinel_otp:
                self._log("email_otp_validate: 已通过 HTTP PoW 获取 token")
            else:
                self._log("email_otp_validate: 未生成 sentinel token（继续尝试）")

        def _build_otp_headers():
            extra_headers = {
                "oai-device-id": device_id,
            }
            if sentinel_otp:
                extra_headers["openai-sentinel-token"] = sentinel_otp
            headers_otp = self._headers(
                request_url,
                user_agent=user_agent,
                sec_ch_ua=sec_ch_ua,
                accept="application/json",
                referer=otp_referer,
                origin=self.oauth_issuer,
                content_type="application/json",
                fetch_site="same-origin",
                extra_headers=extra_headers,
            )
            headers_otp.update(generate_datadog_trace())
            return headers_otp

        if not hasattr(skymail_client, "_used_codes"):
            skymail_client._used_codes = set()
        if not hasattr(skymail_client, "_failed_codes"):
            skymail_client._failed_codes = set()

        tried_codes = set(getattr(skymail_client, "_used_codes", set()))
        failed_codes = set(getattr(skymail_client, "_failed_codes", set()))
        try:
            otp_wait_seconds = int(
                self.config.get(
                    "chatgpt_oauth_otp_wait_seconds",
                    self.config.get("chatgpt_otp_wait_seconds", 600),
                )
                or 600
            )
        except Exception:
            otp_wait_seconds = 600
        otp_wait_seconds = max(30, min(otp_wait_seconds, 3600))
        otp_poll_window = min(30, max(10, otp_wait_seconds))
        try:
            default_resend_wait_seconds = 45 if prefer_passwordless_login else 120
            otp_resend_wait_seconds = int(
                self.config.get(
                    "chatgpt_oauth_otp_resend_wait_seconds",
                    self.config.get(
                        "chatgpt_otp_resend_wait_seconds",
                        default_resend_wait_seconds,
                    ),
                )
                or default_resend_wait_seconds
            )
        except Exception:
            otp_resend_wait_seconds = 45 if prefer_passwordless_login else 120
        otp_resend_wait_seconds = max(30, min(otp_resend_wait_seconds, 900))
        otp_deadline = time.time() + otp_wait_seconds
        otp_sent_at = _otp_sent_at_baseline
        next_resend_at = time.time() + otp_resend_wait_seconds
        self._log(
            f"OAuth OTP 等待窗口: total={otp_wait_seconds}s, poll_window={otp_poll_window}s"
        )

        def validate_otp(code):
            tried_codes.add(code)
            self._log(f"尝试 OTP: {code}")

            try:
                kwargs = {
                    "json": {"code": code},
                    "headers": _build_otp_headers(),
                    "timeout": 30,
                    "allow_redirects": False,
                }
                if impersonate:
                    kwargs["impersonate"] = impersonate
                self._browser_pause(0.12, 0.25)
                resp_otp = self._http("POST", request_url, **kwargs)
            except Exception as e:
                self._log(f"email-otp/validate 异常: {e}")
                failed_codes.add(code)
                skymail_client._failed_codes.add(code)
                return None

            self._log(f"/email-otp/validate -> {resp_otp.status_code}")
            if resp_otp.status_code != 200:
                self._log(f"OTP 无效: {resp_otp.text[:160]}")
                failed_codes.add(code)
                skymail_client._failed_codes.add(code)
                return None

            try:
                otp_data = resp_otp.json()
            except Exception:
                self._log("email-otp/validate 响应不是 JSON")
                failed_codes.add(code)
                skymail_client._failed_codes.add(code)
                return None

            next_state = self._state_from_payload(
                otp_data,
                current_url=str(resp_otp.url)
                or (state.current_url or state.continue_url or request_url),
            )
            self._log(f"OTP 验证通过 {describe_flow_state(next_state)}")
            self._log(
                f"otp 响应详情: current_url={str(resp_otp.url)[:120]} tried_codes={len(tried_codes)}"
            )
            remember_successful_code = getattr(
                skymail_client, "remember_successful_code", None
            )
            if callable(remember_successful_code):
                remember_successful_code(code)
            else:
                skymail_client._used_codes.add(code)
                setattr(skymail_client, "_last_success_code", code)
                setattr(skymail_client, "_last_success_code_at", time.time())
            return next_state

        if allow_cached_code_retry:
            cached_code = ""
            cached_age = None
            get_recent_code = getattr(skymail_client, "get_recent_code", None)
            if callable(get_recent_code):
                cached_code = str(
                    get_recent_code(
                        max_age_seconds=min(180, otp_wait_seconds),
                        prefer_successful=True,
                    )
                    or ""
                ).strip()
                cached_age = (
                    time.time() - float(getattr(skymail_client, "_last_success_code_at", 0) or 0)
                    if cached_code
                    else None
                )
            else:
                cached_code = str(
                    getattr(skymail_client, "_last_success_code", "")
                    or getattr(skymail_client, "_last_code", "")
                    or ""
                ).strip()
                cached_ts = float(
                    getattr(skymail_client, "_last_success_code_at", 0)
                    or getattr(skymail_client, "_last_code_at", 0)
                    or 0
                )
                if cached_code and cached_ts:
                    cached_age = time.time() - cached_ts
                    if cached_age > min(180, otp_wait_seconds):
                        cached_code = ""

            if cached_code:
                age_text = (
                    f"{int(max(0, cached_age or 0))}s前"
                    if cached_age is not None
                    else "近期"
                )
                self._log(
                    f"检测到近期缓存 OTP，先直接尝试: {cached_code} ({age_text})"
                )
                next_state = validate_otp(cached_code)
                if next_state:
                    return next_state
                self._log("缓存 OTP 未通过，继续等待新的 OTP...")

        if hasattr(skymail_client, "wait_for_verification_code"):
            self._log("使用 wait_for_verification_code 进行阻塞式获取新验证码...")
            while time.time() < otp_deadline:
                remaining = max(1, int(otp_deadline - time.time()))
                wait_time = min(otp_poll_window, remaining)
                try:
                    code = skymail_client.wait_for_verification_code(
                        email,
                        timeout=wait_time,
                        otp_sent_at=otp_sent_at,
                        exclude_codes=failed_codes,
                    )
                except TaskInterruption:
                    self._set_error("任务已手动停止")
                    return None
                except Exception as e:
                    if "手动停止" in str(e):
                        self._set_error("任务已手动停止")
                        return None
                    self._log(f"等待 OTP 异常: {e}")
                    code = None

                if not code:
                    if time.time() >= next_resend_at and not self.last_error:
                        self._log(
                            f"暂未收到 OTP，触发重发（间隔 {otp_resend_wait_seconds}s）"
                        )
                        if _resend_email_otp():
                            otp_sent_at = time.time()
                            next_resend_at = otp_sent_at + otp_resend_wait_seconds
                        else:
                            next_resend_at = time.time() + otp_resend_wait_seconds
                    self._log("暂未收到新的 OTP，继续等待...")
                    if self.last_error:
                        break
                    continue

                next_state = validate_otp(code)
                if next_state:
                    return next_state
                if self.last_error:
                    break
        else:
            while time.time() < otp_deadline:
                messages = skymail_client.fetch_emails(email) or []
                candidate_codes = []

                for msg in messages[:12]:
                    content = msg.get("content") or msg.get("text") or ""
                    code = skymail_client.extract_verification_code(content)
                    if code and code not in tried_codes:
                        candidate_codes.append(code)

                if not candidate_codes:
                    elapsed = int(otp_wait_seconds - max(0, otp_deadline - time.time()))
                    self._log(f"等待新的 OTP... ({elapsed}s/{otp_wait_seconds}s)")
                    time.sleep(2)
                    continue

                for otp_code in candidate_codes:
                    next_state = validate_otp(otp_code)
                    if next_state:
                        return next_state

                time.sleep(2)
                if self.last_error:
                    break

        if not self.last_error:
            self._set_error(
                f"OAuth 阶段 OTP 验证失败，已尝试 {len(tried_codes)} 个验证码，等待窗口 {otp_wait_seconds}s",
                error_code="oauth_otp_verification_failed",
            )
        return None
