from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import urlparse

import httpx


READY_ENDPOINT = "/ready/live"
CONNECTIVITY_ENDPOINT = "/live/connectivity"


class ResponseLike(Protocol):
    status_code: int
    text: str

    def json(self) -> Any: ...


class ReceiverClient(Protocol):
    def get(self, url: str, headers: dict[str, str] | None = None) -> ResponseLike: ...


def run_http_receiver_check(
    base_url: str,
    client: ReceiverClient,
    *,
    api_token: str | None = None,
    operator_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    try:
        base_url = normalize_receiver_base_url(base_url)
    except ValueError as exc:
        return {
            "mode": "http",
            "status": "receiver_base_url_invalid",
            "error": str(exc),
        }
    headers = operator_headers if operator_headers is not None else operator_auth_headers(api_token)
    try:
        ready = client.get(f"{base_url}{READY_ENDPOINT}", headers=headers)
        ready_body = response_body(ready)
        if isinstance(ready_body, dict) and ready_body.get("ready") is False:
            return {
                "mode": "http",
                "base_url": base_url,
                "status": "not_ready",
                "endpoint": READY_ENDPOINT,
                **ready_body,
            }
        if ready.status_code >= 400:
            return {
                "mode": "http",
                "base_url": base_url,
                "status": "ready_failed",
                "endpoint": READY_ENDPOINT,
                "code": ready.status_code,
                "body": ready_body,
            }
        if not isinstance(ready_body, dict) or ready_body.get("ready") is not True:
            return {
                "mode": "http",
                "base_url": base_url,
                "status": "ready_malformed",
                "endpoint": READY_ENDPOINT,
                "body": ready_body,
            }

        connectivity = client.get(
            f"{base_url}{CONNECTIVITY_ENDPOINT}",
            headers=headers,
        )
        connectivity_body = response_body(connectivity)
        if isinstance(connectivity_body, dict) and connectivity_body.get("ready") is False:
            return {
                "mode": "http",
                "base_url": base_url,
                "status": "not_ready",
                "endpoint": CONNECTIVITY_ENDPOINT,
                **connectivity_body,
            }
        if connectivity.status_code >= 400:
            return {
                "mode": "http",
                "base_url": base_url,
                "status": "connectivity_failed",
                "endpoint": CONNECTIVITY_ENDPOINT,
                "code": connectivity.status_code,
                "body": connectivity_body,
            }
        if not isinstance(connectivity_body, dict) or connectivity_body.get("ready") is not True:
            return {
                "mode": "http",
                "base_url": base_url,
                "status": "connectivity_malformed",
                "endpoint": CONNECTIVITY_ENDPOINT,
                "body": connectivity_body,
            }

        return {
            "mode": "http",
            "base_url": base_url,
            "status": "ready",
            "ready": ready_body,
            "connectivity": connectivity_body,
        }
    except httpx.HTTPError as exc:
        return {
            "mode": "http",
            "base_url": base_url,
            "status": "receiver_unreachable",
            "error": str(exc),
        }


def normalize_receiver_base_url(base_url: str) -> str:
    if not isinstance(base_url, str):
        raise ValueError("SENTINEL receiver base URL must be a non-empty http(s) URL")
    raw = base_url.strip()
    if not raw:
        raise ValueError("SENTINEL receiver base URL must be a non-empty http(s) URL")
    normalized = raw.rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("SENTINEL receiver base URL must be an http(s) URL with a host")
    if parsed.username or parsed.password:
        raise ValueError("SENTINEL receiver base URL must not include credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("SENTINEL receiver base URL must not include a query string or fragment")
    return normalized


def receiver_preflight_failure(
    summary: dict[str, Any],
    *,
    include_receiver_context: bool = True,
) -> dict[str, Any] | None:
    if summary.get("status") == "ready":
        return None
    if include_receiver_context:
        return dict(summary)
    return {key: value for key, value in summary.items() if key not in {"mode", "base_url"}}


def response_body(response: ResponseLike) -> Any:
    try:
        return response.json()
    except ValueError:
        return response.text


def operator_auth_headers(api_token: str | None) -> dict[str, str]:
    if not api_token:
        return {}
    return {"authorization": f"Bearer {api_token}"}


def receiver_check_exit_code(summary: dict[str, Any]) -> int:
    if summary.get("status") == "ready":
        return 0
    if summary.get("status") in {
        "not_ready",
        "ready_failed",
        "ready_malformed",
        "connectivity_failed",
        "connectivity_malformed",
        "receiver_unreachable",
        "receiver_base_url_invalid",
    }:
        return 2
    return 1
