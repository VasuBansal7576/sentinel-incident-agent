from __future__ import annotations

import time
from dataclasses import dataclass

from sentinel.errors import ToolErrorKind, ToolExecutionError, redact_sensitive_text


class RateLimitBackend:
    def hit(self, key: str, *, limit: int, window_seconds: int) -> bool:
        raise NotImplementedError

    def close(self) -> None:
        return None


class InMemoryRateLimitBackend(RateLimitBackend):
    def __init__(self) -> None:
        self._buckets: dict[str, tuple[int, float]] = {}

    def hit(self, key: str, *, limit: int, window_seconds: int) -> bool:
        now = time.time()
        count, expires_at = self._buckets.get(key, (0, now + window_seconds))
        if expires_at <= now:
            count, expires_at = 0, now + window_seconds
        count += 1
        self._buckets[key] = (count, expires_at)
        return count <= limit


class RedisRateLimitBackend(RateLimitBackend):
    def __init__(self, redis_url: str, *, socket_timeout_seconds: float = 1.0):
        import redis

        self.client = redis.Redis.from_url(
            redis_url,
            socket_connect_timeout=socket_timeout_seconds,
            socket_timeout=socket_timeout_seconds,
        )

    def ping(self) -> bool:
        return bool(self.client.ping())

    def close(self) -> None:
        self.client.close()

    def hit(self, key: str, *, limit: int, window_seconds: int) -> bool:
        try:
            count = self.client.incr(key)
            if count == 1 or self.client.ttl(key) == -1:
                self.client.expire(key, window_seconds)
            return int(count) <= limit
        except Exception as exc:
            raise ToolExecutionError(
                ToolErrorKind.RETRYABLE,
                f"Rate limit backend unavailable: {redact_sensitive_text(exc, max_length=300)}",
                retryable=True,
                circuit_breaker_failure=False,
            ) from exc


@dataclass
class SharedRateLimiter:
    backend: RateLimitBackend
    limit: int
    window_seconds: int

    def check(self, key: str) -> None:
        if not self.backend.hit(key, limit=self.limit, window_seconds=self.window_seconds):
            raise ToolExecutionError(
                ToolErrorKind.RATE_LIMITED,
                f"Rate limit exceeded for {key}",
                retryable=True,
            )

    def close(self) -> None:
        self.backend.close()
