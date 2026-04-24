"""代理池 - 从数据库读取代理，支持轮询和按区域选取"""

from typing import Optional
from sqlmodel import Session, select
from .db import ProxyModel, engine
from .proxy_utils import build_requests_proxy_config
import time, threading, random
from datetime import datetime, timezone


class ProxyPool:
    def __init__(self):
        self._index = 0
        self._lock = threading.Lock()
        self._cooldowns: dict[str, float] = {}

    def cool_down(self, url: str, seconds: int = 300) -> None:
        proxy_url = str(url or "").strip()
        if not proxy_url:
            return
        ttl = max(1, int(seconds or 0))
        expire_at = time.time() + ttl
        with self._lock:
            self._cooldowns[proxy_url] = expire_at

    def _is_cooling_down(self, url: str, now: float) -> bool:
        if not url:
            return False
        until = self._cooldowns.get(url, 0.0)
        return until > now

    def _cleanup_cooldowns(self, now: float) -> None:
        stale = [url for url, until in self._cooldowns.items() if until <= now]
        for url in stale:
            self._cooldowns.pop(url, None)

    def get_next(self, region: str = "") -> Optional[str]:
        """加权轮询取一个可用代理，在高成功率代理间轮换"""
        with Session(engine) as s:
            q = select(ProxyModel).where(ProxyModel.is_active == True)
            if region:
                q = q.where(ProxyModel.region == region)
            proxies = s.exec(q).all()
            if not proxies:
                return None
            now = time.time()
            with self._lock:
                self._cleanup_cooldowns(now)
                proxies = [p for p in proxies if not self._is_cooling_down(p.url, now)]
                if not proxies:
                    return None
            proxies.sort(
                key=lambda p: p.success_count / max(p.success_count + p.fail_count, 1),
                reverse=True,
            )
            with self._lock:
                idx = self._index % len(proxies)
                self._index += 1
            return proxies[idx].url

    def report_success(self, url: str) -> None:
        with Session(engine) as s:
            p = s.exec(select(ProxyModel).where(ProxyModel.url == url)).first()
            if p:
                p.success_count += 1
                p.last_checked = datetime.now(timezone.utc)
                s.add(p)
                s.commit()

    def report_fail(self, url: str) -> None:
        with Session(engine) as s:
            p = s.exec(select(ProxyModel).where(ProxyModel.url == url)).first()
            if p:
                p.fail_count += 1
                p.last_checked = datetime.now(timezone.utc)
                # 连续失败超过10次自动禁用
                if p.fail_count > 0 and p.success_count == 0 and p.fail_count >= 5:
                    p.is_active = False
                s.add(p)
                s.commit()

    def check_all(self) -> dict:
        """检测所有代理可用性"""
        import requests

        with Session(engine) as s:
            proxies = s.exec(select(ProxyModel)).all()
        results = {"ok": 0, "fail": 0}
        for p in proxies:
            try:
                r = requests.get(
                    "https://httpbin.org/ip",
                    proxies=build_requests_proxy_config(p.url),
                    timeout=8,
                )
                if r.status_code == 200:
                    self.report_success(p.url)
                    results["ok"] += 1
                    continue
            except Exception:
                pass
            self.report_fail(p.url)
            results["fail"] += 1
        return results


proxy_pool = ProxyPool()
