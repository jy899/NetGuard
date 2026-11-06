"""In-memory login throttling.

After `max_failures` failed logins for the same username from the same client
IP within `window_seconds`, further logins for that pair are refused for
`lockout_seconds` (even with the right password). A successful login clears
the counter. State lives in the server process only, which is enough for the
single-process prototype; it is cleared by a restart (or `reset()` in tests).
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable


class LoginThrottle:
    def __init__(self, max_failures: int = 5, window_seconds: int = 300, lockout_seconds: int = 300,
                 clock: Callable[[], float] = time.monotonic):
        self.max_failures = max_failures
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.clock = clock
        self._failures: dict[tuple[str, str], list[float]] = {}
        self._locked_until: dict[tuple[str, str], float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def key(username: str, client_ip: str | None) -> tuple[str, str]:
        return username.strip().lower(), client_ip or "unknown"

    def locked_for(self, key: tuple[str, str]) -> int:
        """Seconds until this username/IP pair may try again (0 = not locked)."""
        with self._lock:
            until = self._locked_until.get(key)
            if until is None:
                return 0
            remaining = until - self.clock()
            if remaining <= 0:
                del self._locked_until[key]
                return 0
            return int(remaining) + 1

    def record_failure(self, key: tuple[str, str]) -> None:
        with self._lock:
            now = self.clock()
            recent = [t for t in self._failures.get(key, []) if now - t < self.window_seconds]
            recent.append(now)
            if len(recent) >= self.max_failures:
                self._locked_until[key] = now + self.lockout_seconds
                self._failures.pop(key, None)
            else:
                self._failures[key] = recent
            if len(self._failures) > 10_000:  # drop stale entries so memory stays bounded
                self._failures = {k: v for k, v in self._failures.items() if now - v[-1] < self.window_seconds}

    def record_success(self, key: tuple[str, str]) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()
            self._locked_until.clear()


login_throttle = LoginThrottle()
