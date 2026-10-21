"""Brute-force protection for login.

In-memory failure tracking keyed per username AND per client IP: 5 failures
inside 15 minutes locks that key for 15 minutes. In-memory is fine for a
single app process; it resets on restart.
"""

import threading
import time

MAX_FAILURES = 5
WINDOW_SECONDS = 15 * 60
LOCKOUT_SECONDS = 15 * 60


def client_ip(forwarded_for: str | None, peer: str | None) -> str:
    """First X-Forwarded-For hop when behind the proxy, else the socket peer.
    Spoofable on direct hits, but the username key of the limiter doesn't
    depend on it."""
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return peer or "unknown"


class LoginRateLimiter:
    """Track failures per key; too many inside the window locks the key."""

    def __init__(self, max_failures: int = MAX_FAILURES,
                 window: float = WINDOW_SECONDS, lockout: float = LOCKOUT_SECONDS):
        self.max_failures = max_failures
        self.window = window
        self.lockout = lockout
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def locked_for(self, *keys: str) -> float:
        """Seconds until the most-locked of the keys unlocks (0 = open)."""
        now = time.monotonic()
        with self._lock:
            remaining = 0.0
            for key in keys:
                until = self._locked_until.get(key, 0.0)
                if until > now:
                    remaining = max(remaining, until - now)
                elif key in self._locked_until:
                    del self._locked_until[key]
            return remaining

    def record_failure(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                hits = [t for t in self._failures.get(key, []) if now - t < self.window]
                hits.append(now)
                self._failures[key] = hits
                if len(hits) >= self.max_failures:
                    self._locked_until[key] = now + self.lockout
                    self._failures[key] = []

    def record_success(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)
                self._locked_until.pop(key, None)
