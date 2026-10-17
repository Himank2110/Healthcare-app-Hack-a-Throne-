"""Small process-local throttles for the single-instance learning server."""

import hashlib
import hmac
import threading
import time
from collections import defaultdict, deque

from app.config import settings


class SlidingWindowThrottle:
    def __init__(self) -> None:
        self._attempts: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    @staticmethod
    def key(namespace: str, value: str) -> str:
        material = f"{namespace}:{value.strip().lower()}".encode("utf-8")
        return hmac.new(settings.jwt_secret.encode("utf-8"), material, hashlib.sha256).hexdigest()

    def retry_after(self, key: str, limit: int, window_seconds: int) -> int:
        now = time.monotonic()
        with self._lock:
            attempts = self._attempts.get(key)
            if not attempts:
                return 0
            while attempts and now - attempts[0] >= window_seconds:
                attempts.popleft()
            if len(attempts) < limit:
                return 0
            return max(1, int(window_seconds - (now - attempts[0])))

    def record(self, key: str, window_seconds: int) -> None:
        now = time.monotonic()
        with self._lock:
            attempts = self._attempts[key]
            while attempts and now - attempts[0] >= window_seconds:
                attempts.popleft()
            attempts.append(now)
            while len(self._attempts) > 10_000:
                self._attempts.pop(next(iter(self._attempts)))

    def clear(self, key: str) -> None:
        with self._lock:
            self._attempts.pop(key, None)


auth_throttle = SlidingWindowThrottle()
