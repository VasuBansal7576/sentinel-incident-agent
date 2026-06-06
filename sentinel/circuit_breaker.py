from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Callable, TypeVar

from sentinel.errors import SentinelError

T = TypeVar("T")


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(SentinelError):
    pass


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = 3
    recovery_seconds: float = 30.0

    def __post_init__(self) -> None:
        self._state = CircuitState.CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._lock = RLock()

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                elapsed = time.monotonic() - self._opened_at
                if elapsed >= self.recovery_seconds:
                    self._state = CircuitState.HALF_OPEN
            return self._state

    def call(
        self,
        fn: Callable[[], T],
        *,
        should_record_failure: Callable[[Exception], bool] | None = None,
    ) -> T:
        with self._lock:
            if self.state == CircuitState.OPEN:
                raise CircuitOpenError(f"Circuit {self.name} is open")
        try:
            result = fn()
        except Exception as exc:
            if should_record_failure is None or should_record_failure(exc):
                self.record_failure()
            raise
        self.record_success()
        return result

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._state = CircuitState.CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.failure_threshold:
                self._state = CircuitState.OPEN
                self._opened_at = time.monotonic()


_SHARED_BREAKERS: dict[str, CircuitBreaker] = {}
_SHARED_BREAKERS_LOCK = RLock()


def shared_circuit_breaker(name: str) -> CircuitBreaker:
    with _SHARED_BREAKERS_LOCK:
        breaker = _SHARED_BREAKERS.get(name)
        if breaker is None:
            breaker = CircuitBreaker(name=name)
            _SHARED_BREAKERS[name] = breaker
        return breaker


def reset_shared_circuit_breakers() -> None:
    with _SHARED_BREAKERS_LOCK:
        _SHARED_BREAKERS.clear()
