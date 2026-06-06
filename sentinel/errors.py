from __future__ import annotations

import re
from enum import StrEnum
from typing import Any


class ToolErrorKind(StrEnum):
    PERMISSION_DENIED = "permission_denied"
    AUTHORIZATION = "authorization"
    RATE_LIMITED = "rate_limited"
    RETRYABLE = "retryable"
    PERMANENT = "permanent"
    MALFORMED_OUTPUT = "malformed_output"


class SentinelError(Exception):
    """Base error for SENTINEL runtime failures."""


class ToolExecutionError(SentinelError):
    def __init__(
        self,
        kind: ToolErrorKind,
        message: str,
        *,
        retryable: bool = False,
        retry_after_seconds: float | None = None,
        circuit_breaker_failure: bool | None = None,
    ):
        super().__init__(message)
        self.kind = kind
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds
        self.circuit_breaker_failure = circuit_breaker_failure


class ToolAccessDenied(ToolExecutionError):
    def __init__(self, message: str):
        super().__init__(ToolErrorKind.PERMISSION_DENIED, message, retryable=False)


class ModelOutputFailure(SentinelError):
    """Raised when model output does not satisfy a typed contract."""


def redact_sensitive_text(value: Any, *, max_length: int | None = None) -> str:
    """Remove credential-shaped values before errors are persisted or returned."""

    text = str(value)
    for pattern, replacement in _SENSITIVE_TEXT_PATTERNS:
        text = pattern.sub(replacement, text)
    if max_length is not None:
        return text[:max_length]
    return text


_SENSITIVE_TEXT_PATTERNS = (
    (
        re.compile(
            r'(?i)("(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|authorization|secret|token|password)"\s*:\s*")([^"]+)(")'
        ),
        r"\1[redacted]\3",
    ),
    (
        re.compile(
            r"(?i)\b(authorization\s*[:=]\s*)(?:bearer\s+|token\s+token=|token\s+)?([^,;&\s}\]\[]+)"
        ),
        r"\1[redacted]",
    ),
    (
        re.compile(
            r"(?i)\b([A-Za-z0-9_.-]*(?:access[_-]?token|refresh[_-]?token|client[_-]?secret|api[_-]?key|authorization|secret|token|password)[A-Za-z0-9_.-]*\s*[=:]\s*)([^,;&\s}\]\[]+)"
        ),
        r"\1[redacted]",
    ),
    (
        re.compile(r"(?i)\b(bearer|token)\s+([A-Za-z0-9._~+/=-]{8,})"),
        r"\1 [redacted]",
    ),
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^:/\s]+:)([^@\s]+)(@)"),
        r"\1[redacted]\3",
    ),
)
