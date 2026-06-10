from __future__ import annotations

import base64
import json
import math
import os
import re
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import httpx

from sentinel.circuit_breaker import CircuitBreaker, shared_circuit_breaker
from sentinel.config import SentinelSettings
from sentinel.errors import ToolErrorKind, ToolExecutionError, redact_sensitive_text
from sentinel.rate_limiters import (
    InMemoryRateLimitBackend,
    RedisRateLimitBackend,
    SharedRateLimiter,
)


class LiveApiClient:
    def __init__(
        self,
        *,
        base_url: str,
        headers: dict[str, str],
        name: str,
        timeout_seconds: float = 20.0,
        max_pages: int = 25,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.base_url = _normalize_api_base_url(base_url, name)
        self.headers = headers
        self.name = name
        self.client = httpx.Client(timeout=timeout_seconds)
        self.circuit_breaker = circuit_breaker or CircuitBreaker(name=name)
        self.max_pages = _page_limit(max_pages, 25, field="max_pages")
        self.rate_limiter = rate_limiter or SharedRateLimiter(
            InMemoryRateLimitBackend(), limit=120, window_seconds=60
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        url = _resolve_api_url(self.base_url, path, self.name)
        request_headers = {**self.headers, **(extra_headers or {})}

        def _send() -> dict[str, Any]:
            self.rate_limiter.check(self.name)
            try:
                response = self.client.request(
                    method,
                    url,
                    headers=request_headers,
                    params=params,
                    json=json_body,
                )
            except httpx.TimeoutException as exc:
                raise ToolExecutionError(
                    ToolErrorKind.RETRYABLE,
                    f"{self.name} request timed out: {exc}",
                    retryable=True,
                    circuit_breaker_failure=True,
                ) from exc
            except httpx.HTTPError as exc:
                raise ToolExecutionError(
                    ToolErrorKind.RETRYABLE,
                    f"{self.name} transport error: {redact_sensitive_text(exc)}",
                    retryable=True,
                    circuit_breaker_failure=True,
                ) from exc
            if response.status_code == 429:
                raise ToolExecutionError(
                    ToolErrorKind.RATE_LIMITED,
                    f"{self.name} rate limited: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=True,
                    retry_after_seconds=_provider_retry_after_seconds(response.headers),
                    circuit_breaker_failure=False,
                )
            if response.status_code >= 500:
                raise ToolExecutionError(
                    ToolErrorKind.RETRYABLE,
                    f"{self.name} upstream error {response.status_code}: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=True,
                    circuit_breaker_failure=True,
                )
            if _provider_rate_limited_response(self.name, response):
                raise ToolExecutionError(
                    ToolErrorKind.RATE_LIMITED,
                    f"{self.name} rate limited: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=True,
                    retry_after_seconds=_provider_retry_after_seconds(response.headers),
                    circuit_breaker_failure=False,
                )
            if response.status_code in {401, 403}:
                raise ToolExecutionError(
                    ToolErrorKind.AUTHORIZATION,
                    f"{self.name} authorization failed {response.status_code}: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            if response.status_code >= 400:
                raise ToolExecutionError(
                    ToolErrorKind.PERMANENT,
                    f"{self.name} request failed {response.status_code}: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            response_headers = _safe_response_headers(response.headers)
            if not response.content:
                return {"ok": True, "_headers": response_headers}
            try:
                data = response.json()
            except ValueError as exc:
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    f"{self.name} returned non-JSON response: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=False,
                    circuit_breaker_failure=False,
                ) from exc
            if isinstance(data, dict):
                data.setdefault("_headers", response_headers)
                return data
            return {"data": data, "_headers": response_headers}

        return self.circuit_breaker.call(
            _send,
            should_record_failure=_counts_against_live_api_circuit,
        )

    def close(self) -> None:
        self.client.close()

    def paginate_github(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        item_key: str | None = None,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        result = self.paginate_github_result(
            path,
            params=params,
            item_key=item_key,
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        return result["items"]

    def paginate_github_result(
        self,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        item_key: str | None = None,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        url: str | None = path
        page = 0
        page_limit = _page_limit(max_pages, getattr(self, "max_pages", 25))
        while url and page < page_limit:
            page += 1
            data = self.request("GET", url, params=params if page == 1 else None)
            if item_key:
                batch = _require_list(data, item_key, self.name)
            else:
                batch = _require_list(data, "data", self.name)
            items.extend(batch)
            link = _header_value(data.get("_headers", {}), "link")
            url = _extract_next_link(link)
        truncated = bool(url)
        if truncated and not allow_truncated:
            _raise_pagination_truncated(self.name, page_limit, "GitHub Link rel=next")
        return {
            "items": items,
            "page_count": page,
            "page_limit": page_limit,
            "truncated": truncated,
        }

    def paginate_cursor(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        cursor_path: tuple[str, ...] = ("meta", "page", "after"),
        body_cursor_key: tuple[str, ...] = ("page", "cursor"),
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        next_cursor: str | None = None
        page_limit = _page_limit(max_pages, self.max_pages)
        for _ in range(page_limit):
            page_body = json.loads(json.dumps(body or {}))
            if next_cursor:
                _set_nested(page_body, body_cursor_key, next_cursor)
            page_size = _cursor_page_size(page_body, self.name)
            data = self.request(method, path, json_body=page_body)
            batch = _require_list(data, "data", self.name)
            batch = _require_object_items(batch, self.name, "data")
            items.extend(batch)
            next_cursor = _optional_nested_string(data, cursor_path, self.name, ".".join(cursor_path))
            if not next_cursor:
                if page_size is not None and len(batch) >= page_size and not allow_truncated:
                    raise ToolExecutionError(
                        ToolErrorKind.MALFORMED_OUTPUT,
                        f"{self.name} response field '{'.'.join(cursor_path)}' is required when cursor pagination returns a full page; refusing to return unbounded evidence",
                        retryable=False,
                        circuit_breaker_failure=False,
                    )
                break
        if next_cursor and not allow_truncated:
            _raise_pagination_truncated(self.name, page_limit, ".".join(cursor_path))
        return items


class DatadogClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        headers = {"Accept": "application/json"}
        if settings.datadog_oauth_token:
            headers["Authorization"] = f"Bearer {settings.datadog_oauth_token}"
        else:
            headers["DD-API-KEY"] = settings.datadog_api_key or ""
            headers["DD-APPLICATION-KEY"] = settings.datadog_app_key or ""
        self.api = LiveApiClient(
            base_url=settings.datadog_base_url,
            headers=headers,
            name="datadog",
            max_pages=settings.live_max_pages,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
        )

    def search_logs(
        self,
        query: str,
        *,
        start: str = "now-30m",
        end: str = "now",
        limit: int = 25,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> dict[str, Any]:
        body = {"filter": {"query": query, "from": start, "to": end}, "page": {"limit": limit}}
        events = self.api.paginate_cursor(
            "POST",
            "/api/v2/logs/events/search",
            body=body,
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        events = _require_datadog_event_items(events, "logs.events")
        return {"events": events, "query": query}

    def query_metric(self, query: str, *, start_epoch: int | None = None, end_epoch: int | None = None) -> dict[str, Any]:
        now = int(time.time())
        params = {"from": start_epoch or now - 1800, "to": end_epoch or now, "query": query}
        data = self.api.request("GET", "/api/v1/query", params=params)
        _require_datadog_metric_query_confirmation(data)
        return data

    def search_spans(
        self,
        query: str,
        *,
        start: str = "now-30m",
        end: str = "now",
        limit: int = 25,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> dict[str, Any]:
        body = {"filter": {"query": query, "from": start, "to": end}, "page": {"limit": limit}}
        spans = self.api.paginate_cursor(
            "POST",
            "/api/v2/spans/events/search",
            body=body,
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        spans = _require_datadog_event_items(spans, "spans.events")
        return {"spans": spans, "query": query}

    def list_monitors(
        self,
        query: str | None = None,
        *,
        per_page: int = 100,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> dict[str, Any]:
        if query:
            monitors = self._search_monitors(
                query,
                per_page=per_page,
                max_pages=max_pages,
                allow_truncated=allow_truncated,
            )
        else:
            monitors = self._all_monitors(
                per_page=per_page,
                max_pages=max_pages,
                allow_truncated=allow_truncated,
            )
        return {"monitors": monitors, "query": query}

    def _search_monitors(
        self,
        query: str,
        *,
        per_page: int,
        max_pages: int | None,
        allow_truncated: bool,
    ) -> list[dict[str, Any]]:
        monitors: list[dict[str, Any]] = []
        page_limit = _page_limit(max_pages, self.api.max_pages)
        for page in range(page_limit):
            data = self.api.request(
                "GET",
                "/api/v1/monitor/search",
                params={"query": query, "page": page, "per_page": per_page},
            )
            batch = _require_datadog_monitor_items(_require_list(data, "monitors", "datadog"), "monitors")
            monitors.extend(batch)
            metadata = _optional_object(data.get("metadata"), "datadog", "metadata") or {}
            page_count = _optional_int(metadata.get("page_count"), "datadog", "metadata.page_count")
            if page_count is None:
                if not batch:
                    break
                if not allow_truncated:
                    raise ToolExecutionError(
                        ToolErrorKind.MALFORMED_OUTPUT,
                        "datadog response field 'metadata.page_count' is required for monitor search pagination; refusing to return unbounded evidence",
                        retryable=False,
                        circuit_breaker_failure=False,
                    )
                continue
            if page_count is not None and page + 1 >= page_count:
                break
            if page_count is not None and page + 1 >= page_limit and not allow_truncated:
                _raise_pagination_truncated("datadog", page_limit, "metadata.page_count")
            if not batch:
                break
        return monitors

    def _all_monitors(
        self,
        *,
        per_page: int,
        max_pages: int | None,
        allow_truncated: bool,
    ) -> list[dict[str, Any]]:
        monitors: list[dict[str, Any]] = []
        page_limit = _page_limit(max_pages, self.api.max_pages)
        for page in range(page_limit):
            data = self.api.request(
                "GET",
                "/api/v1/monitor",
                params={"page": page, "page_size": per_page},
            )
            batch = _require_datadog_monitor_items(_require_list(data, "data", "datadog"), "data")
            monitors.extend(batch)
            if len(batch) < per_page:
                break
            if page + 1 >= page_limit and not allow_truncated:
                _raise_pagination_truncated("datadog", page_limit, "full monitor page")
        return monitors

    def get_dashboard(self, dashboard_id: str) -> dict[str, Any]:
        return self.api.request("GET", f"/api/v1/dashboard/{dashboard_id}")


class PrometheusClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.api = LiveApiClient(
            base_url=settings.prometheus_url or "http://prometheus:9090",
            headers={"Accept": "application/json"},
            name="prometheus",
            max_pages=settings.live_max_pages,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
        )

    def query_range(
        self,
        query: str,
        *,
        start_epoch: int | None = None,
        end_epoch: int | None = None,
        step: str = "30s",
    ) -> dict[str, Any]:
        now = int(time.time())
        data = self.api.request(
            "GET",
            "/api/v1/query_range",
            params={
                "query": _required_text(query, "Prometheus query_range requires a query"),
                "start": start_epoch or now - 1800,
                "end": end_epoch or now,
                "step": step,
            },
        )
        _require_prometheus_success(data, "query_range")
        return {"query": query, "result": _prometheus_result_items(data), "raw": data}

    def query(self, query: str) -> dict[str, Any]:
        data = self.api.request(
            "GET",
            "/api/v1/query",
            params={"query": _required_text(query, "Prometheus query requires a query")},
        )
        _require_prometheus_success(data, "query")
        return {"query": query, "result": _prometheus_result_items(data), "raw": data}

    def alerting_rules(self) -> dict[str, Any]:
        data = self.api.request("GET", "/api/v1/rules")
        _require_prometheus_success(data, "rules")
        groups = data.get("data", {}).get("groups") if isinstance(data.get("data"), dict) else None
        if not isinstance(groups, list):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                "prometheus rules response field 'data.groups' must be a list",
                retryable=False,
                circuit_breaker_failure=False,
            )
        return {"groups": _require_object_items(groups, "prometheus", "data.groups")}

    def targets(self) -> dict[str, Any]:
        data = self.api.request("GET", "/api/v1/targets")
        _require_prometheus_success(data, "targets")
        active = data.get("data", {}).get("activeTargets") if isinstance(data.get("data"), dict) else None
        if not isinstance(active, list):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                "prometheus targets response field 'data.activeTargets' must be a list",
                retryable=False,
                circuit_breaker_failure=False,
            )
        return {"activeTargets": _require_object_items(active, "prometheus", "data.activeTargets")}


class LokiClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.api = LiveApiClient(
            base_url=settings.loki_url or "http://loki:3100",
            headers={"Accept": "application/json"},
            name="loki",
            max_pages=settings.live_max_pages,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
        )

    def query_range(
        self,
        query: str,
        *,
        start_epoch: int | None = None,
        end_epoch: int | None = None,
        limit: int = 25,
    ) -> dict[str, Any]:
        now = int(time.time())
        data = self.api.request(
            "GET",
            "/loki/api/v1/query_range",
            params={
                "query": _required_text(query, "Loki query_range requires a query"),
                "start": str((start_epoch or now - 1800) * 1_000_000_000),
                "end": str((end_epoch or now) * 1_000_000_000),
                "limit": limit,
                "direction": "backward",
            },
        )
        _require_loki_success(data, "query_range", expected_data_shape="object")
        streams = _loki_result_items(data)
        return {"events": streams, "streams": streams, "query": query}

    def labels(self) -> dict[str, Any]:
        data = self.api.request("GET", "/loki/api/v1/labels")
        _require_loki_success(data, "labels", expected_data_shape="list")
        labels = data.get("data")
        if not isinstance(labels, list) or not all(isinstance(item, str) for item in labels):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                "loki labels response field 'data' must be a list of strings",
                retryable=False,
                circuit_breaker_failure=False,
            )
        return {"labels": labels}


class GitHubClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.owner = settings.github_owner
        self.repo = settings.github_repo
        self.write_enabled = settings.github_write_enabled
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {settings.github_token or ''}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.api = LiveApiClient(
            base_url="https://api.github.com",
            headers=headers,
            name="github",
            max_pages=settings.live_max_pages,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
        )

    @property
    def repo_path(self) -> str:
        if not self.owner or not self.repo:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "GITHUB_OWNER and GITHUB_REPO are required",
                retryable=False,
            )
        return f"/repos/{self.owner}/{self.repo}"

    def commits(
        self,
        *,
        path: str | None = None,
        per_page: int = 30,
        since: str | None = None,
        until: str | None = None,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        params = {"per_page": per_page}
        if path:
            params["path"] = path
        if since:
            params["since"] = since
        if until:
            params["until"] = until
        commits = self.api.paginate_github(
            f"{self.repo_path}/commits",
            params=params,
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        return _require_github_commit_items(commits, expected_owner=self.owner, expected_repo=self.repo)

    def pull_request(self, number: int) -> dict[str, Any]:
        data = self.api.request("GET", f"{self.repo_path}/pulls/{number}")
        _require_github_pull_request_confirmation(
            data,
            number,
            expected_owner=self.owner,
            expected_repo=self.repo,
        )
        return data

    def pull_requests(
        self,
        *,
        state: str = "closed",
        sort: str = "updated",
        direction: str = "desc",
        per_page: int = 10,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        pull_requests = self.api.paginate_github(
            f"{self.repo_path}/pulls",
            params={
                "state": state,
                "sort": sort,
                "direction": direction,
                "per_page": per_page,
            },
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        return _require_github_pull_request_items(
            pull_requests,
            "pull_requests",
            expected_owner=self.owner,
            expected_repo=self.repo,
        )

    def pull_request_files(
        self,
        number: int,
        *,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        files = self.api.paginate_github(
            f"{self.repo_path}/pulls/{number}/files",
            params={"per_page": 100},
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        return _require_github_pull_request_file_items(
            files,
            expected_owner=self.owner,
            expected_repo=self.repo,
        )

    def pull_request_commits(
        self,
        number: int,
        *,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        commits = self.api.paginate_github(
            f"{self.repo_path}/pulls/{number}/commits",
            params={"per_page": 100},
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        return _require_github_commit_items(
            commits,
            expected_owner=self.owner,
            expected_repo=self.repo,
        )

    def deployments(
        self,
        *,
        per_page: int = 30,
        since: str | None = None,
        until: str | None = None,
        max_pages: int | None = None,
        allow_truncated: bool = False,
        include_statuses: bool = True,
        status_limit: int = 5,
    ) -> list[dict[str, Any]]:
        return self.deployment_evidence(
            per_page=per_page,
            since=since,
            until=until,
            max_pages=max_pages,
            allow_truncated=allow_truncated,
            include_statuses=include_statuses,
            status_limit=status_limit,
        )["deployments"]

    def deployment_evidence(
        self,
        *,
        per_page: int = 30,
        since: str | None = None,
        until: str | None = None,
        max_pages: int | None = None,
        allow_truncated: bool = False,
        include_statuses: bool = True,
        status_limit: int = 5,
    ) -> dict[str, Any]:
        page = self.api.paginate_github_result(
            f"{self.repo_path}/deployments",
            params={"per_page": per_page},
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        deployments = _require_github_deployment_items(
            page["items"],
            expected_owner=self.owner,
            expected_repo=self.repo,
        )
        if since or until:
            deployments = [
                deployment
                for deployment in deployments
                if _created_within(deployment, since=since, until=until)
            ]
        if include_statuses:
            deployments = self._with_deployment_statuses(
                deployments,
                status_limit=status_limit,
                allow_truncated=allow_truncated,
            )
        return {
            "deployments": deployments,
            "pagination": {
                "provider": "github",
                "resource": "deployments",
                "page_count": page["page_count"],
                "page_limit": page["page_limit"],
                "truncated": page["truncated"],
            },
        }

    def deployment_statuses(
        self,
        deployment_id: int | str,
        *,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        statuses = self.api.paginate_github(
            f"{self.repo_path}/deployments/{deployment_id}/statuses",
            params={"per_page": 100},
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        return _require_github_deployment_status_items(
            statuses,
            expected_owner=self.owner,
            expected_repo=self.repo,
            expected_deployment_id=deployment_id,
        )

    def _with_deployment_statuses(
        self,
        deployments: list[dict[str, Any]],
        *,
        status_limit: int,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        enriched: list[dict[str, Any]] = []
        for index, deployment in enumerate(deployments):
            item = dict(deployment)
            deployment_id = item.get("id")
            if index < max(0, status_limit):
                if not deployment_id:
                    raise ToolExecutionError(
                        ToolErrorKind.MALFORMED_OUTPUT,
                        "GitHub deployment response missing confirmation field(s): id",
                        retryable=False,
                        circuit_breaker_failure=False,
                    )
                statuses = self.deployment_statuses(deployment_id, allow_truncated=allow_truncated)
                item["statuses"] = statuses
                if statuses:
                    item["latest_status"] = statuses[0]
            enriched.append(item)
        return enriched

    def statuses(self, ref: str) -> dict[str, Any]:
        data = self.api.request("GET", f"{self.repo_path}/commits/{ref}/status")
        _require_github_status_confirmation(data, expected_owner=self.owner, expected_repo=self.repo)
        return data

    def check_runs(
        self,
        ref: str,
        *,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> dict[str, Any]:
        check_runs = self.api.paginate_github(
            f"{self.repo_path}/commits/{ref}/check-runs",
            params={"per_page": 100},
            item_key="check_runs",
            max_pages=max_pages,
            allow_truncated=allow_truncated,
        )
        check_runs = _require_github_check_run_items(
            check_runs,
            expected_owner=self.owner,
            expected_repo=self.repo,
        )
        return {"total_count": len(check_runs), "check_runs": check_runs}

    def contents(self, path: str, ref: str | None = None) -> dict[str, Any]:
        path = _required_text(path, "GitHub contents requires an explicit path")
        params = {"ref": ref} if ref else None
        data = self.api.request("GET", f"{self.repo_path}/contents/{path}", params=params)
        _require_github_content_confirmation(data, expected_path=path)
        return data

    def create_issue(self, title: str, body: str, labels: list[str] | None = None) -> dict[str, Any]:
        title = _required_text(title, "GitHub issue creation requires an explicit title")
        body = _required_text(body, "GitHub issue creation requires an explicit body")
        labels = _optional_github_labels(labels)
        data = self.api.request(
            "POST",
            f"{self.repo_path}/issues",
            json_body={"title": title, "body": body, "labels": labels},
        )
        _require_github_issue_confirmation(
            data,
            expected_owner=self.owner,
            expected_repo=self.repo,
            expected_title=title,
        )
        return data

    def update_file(self, path: str, message: str, content: str, sha: str | None = None) -> dict[str, Any]:
        path = _required_text(path, "GitHub file update requires an explicit path")
        message = _required_text(message, "GitHub file update requires an explicit commit message")
        content = _required_non_empty_string(content, "GitHub file update requires explicit file content")
        body = {"message": message, "content": base64.b64encode(content.encode()).decode()}
        if sha is not None:
            sha = _required_text(sha, "GitHub file update sha must be a non-empty string when provided")
            body["sha"] = sha
        data = self.api.request("PUT", f"{self.repo_path}/contents/{path}", json_body=body)
        _require_github_file_update_confirmation(
            data,
            expected_path=path,
            expected_owner=self.owner,
            expected_repo=self.repo,
            expected_message=message,
        )
        return data


class PagerDutyClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.requester_email = settings.pagerduty_requester_email
        self.enabled = bool(settings.pagerduty_api_key)
        headers = {
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Authorization": f"Token token={settings.pagerduty_api_key or ''}",
        }
        self.api = LiveApiClient(
            base_url="https://api.pagerduty.com",
            headers=headers,
            name="pagerduty",
            max_pages=settings.live_max_pages,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
        )
        self.max_pages = max(1, settings.live_max_pages)

    def get_incident(self, incident_id: str) -> dict[str, Any]:
        data = self.api.request("GET", f"/incidents/{incident_id}")
        _require_pagerduty_incident_read_confirmation(data, incident_id)
        return data

    def list_incidents(
        self,
        query: str | None = None,
        *,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        incidents: list[dict[str, Any]] = []
        offset = 0
        page = 0
        page_limit = _page_limit(max_pages, getattr(self, "max_pages", 25))
        while page < page_limit:
            page += 1
            params: dict[str, Any] = {"limit": 100, "offset": offset, "total": "false"}
            if query:
                params["query"] = query
            data = self.api.request("GET", "/incidents", params=params)
            batch = _require_pagerduty_incident_items(_require_list(data, "incidents", "pagerduty"), "incidents")
            incidents.extend(batch)
            more = _optional_bool(data.get("more"), "pagerduty", "more")
            if more is None:
                if not batch:
                    break
                if not allow_truncated:
                    raise ToolExecutionError(
                        ToolErrorKind.MALFORMED_OUTPUT,
                        "pagerduty response field 'more' is required for incident offset pagination; refusing to return unbounded evidence",
                        retryable=False,
                        circuit_breaker_failure=False,
                    )
                more = True
            if not more:
                break
            if page >= page_limit and not allow_truncated:
                _raise_pagination_truncated("pagerduty", page_limit, "more")
            offset += 100
        return incidents

    def on_calls(
        self,
        *,
        escalation_policy_ids: list[str] | None = None,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        calls: list[dict[str, Any]] = []
        offset = 0
        page = 0
        page_limit = _page_limit(max_pages, getattr(self, "max_pages", 25))
        policy_ids = _optional_non_empty_strings(
            escalation_policy_ids,
            "PagerDuty on-calls escalation_policy_ids",
        )
        while page < page_limit:
            page += 1
            params: dict[str, Any] = {"limit": 100, "offset": offset}
            if policy_ids:
                params["escalation_policy_ids[]"] = policy_ids
            data = self.api.request("GET", "/oncalls", params=params)
            batch = _require_pagerduty_on_call_items(_require_list(data, "oncalls", "pagerduty"))
            calls.extend(batch)
            more = _optional_bool(data.get("more"), "pagerduty", "more")
            if more is None:
                if not batch:
                    break
                if not allow_truncated:
                    raise ToolExecutionError(
                        ToolErrorKind.MALFORMED_OUTPUT,
                        "pagerduty response field 'more' is required for on-call offset pagination; refusing to return unbounded evidence",
                        retryable=False,
                        circuit_breaker_failure=False,
                    )
                more = True
            if not more:
                break
            if page >= page_limit and not allow_truncated:
                _raise_pagination_truncated("pagerduty", page_limit, "more")
            offset += 100
        return calls

    def update_incident_status(self, incident_id: str, status: str, requester_email: str | None = None) -> dict[str, Any]:
        if not isinstance(incident_id, str) or not incident_id.strip():
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "PagerDuty incident updates require an explicit incident_id",
                retryable=False,
            )
        incident_id = incident_id.strip()
        status = _required_pagerduty_incident_status(status)
        requester = requester_email or self.requester_email
        if not requester:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "PagerDuty incident updates require PAGERDUTY_REQUESTER_EMAIL or requester_email",
                retryable=False,
            )
        headers = {"From": requester}
        data = self.api.request(
            "PUT",
            f"/incidents/{incident_id}",
            json_body={"incident": {"type": "incident_reference", "status": status}},
            extra_headers=headers,
        )
        _require_pagerduty_incident_status_confirmation(data, incident_id, status)
        return data


class SlackClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.default_channel = settings.slack_channel_id
        self.enabled = bool(settings.slack_bot_token)
        headers = {"Authorization": f"Bearer {settings.slack_bot_token or ''}", "Content-Type": "application/json"}
        self.api = LiveApiClient(
            base_url="https://slack.com/api",
            headers=headers,
            name="slack",
            max_pages=settings.live_max_pages,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
        )
        self.max_pages = max(1, settings.live_max_pages)

    def api_call(self, method: str, body: dict[str, Any]) -> dict[str, Any]:
        data = self.api.request("POST", f"/{method}", json_body=body)
        if data.get("ok") is False:
            error = _slack_error_text(data)
            kind = _slack_error_kind(error)
            raise ToolExecutionError(
                kind,
                f"Slack {method} failed: {redact_sensitive_text(error, max_length=300)}",
                retryable=kind == ToolErrorKind.RATE_LIMITED,
                retry_after_seconds=_slack_retry_after_seconds(data),
                circuit_breaker_failure=False,
            )
        if data.get("ok") is not True:
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"Slack {method} returned a response without ok=true",
                retryable=False,
            )
        return data

    def oauth_test(self) -> dict[str, Any]:
        return self.api_call("auth.test", {})

    def channel_info(self, channel: str | None = None) -> dict[str, Any]:
        target_channel = _required_text(
            channel or self.default_channel,
            "Slack conversations.info requires a channel",
        )
        data = self.api_call("conversations.info", {"channel": target_channel})
        _require_slack_channel_info_confirmation(data, target_channel)
        return data

    def post_message(self, text: str, channel: str | None = None) -> dict[str, Any]:
        target_channel = _required_text(channel or self.default_channel, "Slack chat.postMessage requires a channel")
        message = _required_text(text, "Slack chat.postMessage requires message text")
        data = self.api_call("chat.postMessage", {"channel": target_channel, "text": message})
        _require_slack_fields(
            "chat.postMessage",
            data,
            ("channel", "ts"),
            expected_channel=target_channel,
            expected_text=message,
        )
        return data

    def create_channel(self, name: str, *, is_private: bool = False) -> dict[str, Any]:
        slug = _slug_channel(name)
        try:
            data = self.api_call("conversations.create", {"name": slug, "is_private": is_private})
            _require_slack_channel_confirmation("conversations.create", data, slug)
            return data
        except ToolExecutionError as exc:
            if "name_taken" not in str(exc):
                raise
            channel = self.find_channel(slug)
            if channel:
                data = {
                    "ok": True,
                    "channel": channel,
                    "created": False,
                    "reused": True,
                }
                _require_slack_channel_confirmation("conversations.create", data, slug)
                return data
            raise

    def find_channel(
        self,
        name: str,
        *,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> dict[str, Any] | None:
        slug = _slug_channel(name)
        for channel in self.list_channels(max_pages=max_pages, allow_truncated=allow_truncated):
            if channel.get("name") == slug:
                return channel
        return None

    def list_channels(
        self,
        *,
        max_pages: int | None = None,
        allow_truncated: bool = False,
    ) -> list[dict[str, Any]]:
        channels: list[dict[str, Any]] = []
        cursor: str | None = None
        page = 0
        page_limit = _page_limit(max_pages, getattr(self, "max_pages", 25))
        page_size = 200
        while page < page_limit:
            page += 1
            body: dict[str, Any] = {"limit": page_size, "types": "public_channel,private_channel"}
            if cursor:
                body["cursor"] = cursor
            data = self.api_call("conversations.list", body)
            batch = _require_slack_channel_items(_require_list(data, "channels", "slack"))
            channels.extend(batch)
            cursor = _optional_slack_next_cursor(data)
            if not cursor and len(batch) >= page_size and "response_metadata" not in data:
                if not allow_truncated:
                    raise ToolExecutionError(
                        ToolErrorKind.MALFORMED_OUTPUT,
                        "slack response field 'response_metadata.next_cursor' is required when conversations.list returns a full page; refusing to return unbounded evidence",
                        retryable=False,
                        circuit_breaker_failure=False,
                    )
                break
            if not cursor:
                break
            if page >= page_limit and not allow_truncated:
                _raise_pagination_truncated("slack", page_limit, "response_metadata.next_cursor")
        return channels

    def schedule_message(self, text: str, post_at: int, channel: str | None = None) -> dict[str, Any]:
        target_channel = _required_text(channel or self.default_channel, "Slack chat.scheduleMessage requires a channel")
        message = _required_text(text, "Slack chat.scheduleMessage requires message text")
        post_at = _required_positive_epoch_seconds(post_at, "Slack chat.scheduleMessage", "post_at")
        data = self.api_call("chat.scheduleMessage", {"channel": target_channel, "text": message, "post_at": post_at})
        _require_slack_fields(
            "chat.scheduleMessage",
            data,
            ("channel", "scheduled_message_id", "post_at"),
            expected_channel=target_channel,
            expected_post_at=post_at,
        )
        return data


class DiscordWebhookClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.webhook_url = _required_webhook_url(
            settings.discord_webhook_url,
            "DISCORD_WEBHOOK_URL",
        )
        self.client = httpx.Client(timeout=20.0)
        self.rate_limiter = rate_limiter or SharedRateLimiter(
            InMemoryRateLimitBackend(), limit=120, window_seconds=60
        )
        self.circuit_breaker = circuit_breaker or CircuitBreaker(name="discord")

    def post_to_discord(self, text: str) -> dict[str, Any]:
        message = _required_text(text, "Discord webhook requires message text")
        url = _discord_webhook_wait_url(self.webhook_url)

        def _send() -> dict[str, Any]:
            self.rate_limiter.check("discord")
            try:
                response = self.client.post(url, json={"content": message})
            except httpx.TimeoutException as exc:
                raise ToolExecutionError(
                    ToolErrorKind.RETRYABLE,
                    f"discord request timed out: {exc}",
                    retryable=True,
                    circuit_breaker_failure=True,
                ) from exc
            except httpx.HTTPError as exc:
                raise ToolExecutionError(
                    ToolErrorKind.RETRYABLE,
                    f"discord transport error: {redact_sensitive_text(exc)}",
                    retryable=True,
                    circuit_breaker_failure=True,
                ) from exc
            if response.status_code == 429:
                raise ToolExecutionError(
                    ToolErrorKind.RATE_LIMITED,
                    f"discord rate limited: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=True,
                    retry_after_seconds=_provider_retry_after_seconds(response.headers),
                    circuit_breaker_failure=False,
                )
            if response.status_code >= 500:
                raise ToolExecutionError(
                    ToolErrorKind.RETRYABLE,
                    f"discord upstream error {response.status_code}: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=True,
                    circuit_breaker_failure=True,
                )
            if response.status_code in {401, 403, 404}:
                raise ToolExecutionError(
                    ToolErrorKind.AUTHORIZATION,
                    f"discord webhook authorization failed {response.status_code}: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            if response.status_code >= 400:
                raise ToolExecutionError(
                    ToolErrorKind.PERMANENT,
                    f"discord webhook failed {response.status_code}: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            if not response.content:
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    "discord webhook wait response did not include a message body",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            try:
                payload = response.json()
            except ValueError as exc:
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    f"discord returned non-JSON response: {redact_sensitive_text(response.text, max_length=500)}",
                    retryable=False,
                    circuit_breaker_failure=False,
                ) from exc
            if not isinstance(payload, dict):
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    "discord webhook wait response must be a message object",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            data: dict[str, Any] = {"ok": True, **payload}
            _require_discord_message_confirmation(data)
            data.update({"provider": "discord", "content": message})
            return data

        return self.circuit_breaker.call(
            _send,
            should_record_failure=_counts_against_live_api_circuit,
        )

    def close(self) -> None:
        self.client.close()


class GenericAlertClient:
    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.approver_id = settings.approver_id
        self.rate_limiter = rate_limiter or SharedRateLimiter(
            InMemoryRateLimitBackend(), limit=120, window_seconds=60
        )
        self.circuit_breaker = circuit_breaker or CircuitBreaker(name="generic_webhook")

    def on_call_context(self, incident_id: str | None = None) -> dict[str, Any]:
        def _lookup() -> dict[str, Any]:
            self.rate_limiter.check("generic_webhook")
            if not self.approver_id:
                return {
                    "incident": {"id": incident_id, "source": "generic_webhook"},
                    "oncalls": [],
                    "escalation_policy_ids": [],
                    "oncall_scope": "generic_webhook_unconfigured",
                    "provider": "generic_webhook",
                }
            return {
                "incident": {
                    "id": incident_id,
                    "status": "triggered",
                    "urgency": "high",
                    "source": "generic_webhook",
                },
                "oncalls": [{"user": {"id": self.approver_id, "summary": self.approver_id}}],
                "escalation_policy_ids": ["generic_webhook"],
                "oncall_scope": "generic_webhook",
                "provider": "generic_webhook",
            }

        return self.circuit_breaker.call(
            _lookup,
            should_record_failure=_counts_against_live_api_circuit,
        )


class KubernetesClient:
    """Real Kubernetes integration via kubeconfig and kubectl."""

    def __init__(
        self,
        settings: SentinelSettings,
        rate_limiter: SharedRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ):
        self.namespace = _required_kubernetes_name(settings.kubernetes_namespace, "Kubernetes namespace")
        self.kubeconfig = settings.effective_kubeconfig
        self.timeout_seconds = settings.kubectl_timeout_seconds
        self.rate_limiter = rate_limiter or SharedRateLimiter(
            InMemoryRateLimitBackend(), limit=120, window_seconds=60
        )
        self.circuit_breaker = circuit_breaker or CircuitBreaker(name="kubernetes")

    def kubectl(self, args: list[str], *, input_text: str | None = None) -> dict[str, Any]:
        command = ["kubectl"]
        if self.kubeconfig:
            command += ["--kubeconfig", self.kubeconfig]
        command += args

        def _run() -> dict[str, Any]:
            self.rate_limiter.check("kubernetes")
            env = os.environ.copy()
            try:
                proc = subprocess.run(
                    command,
                    input=input_text,
                    text=True,
                    capture_output=True,
                    check=False,
                    env=env,
                    timeout=self.timeout_seconds,
                )
            except subprocess.TimeoutExpired as exc:
                raise ToolExecutionError(
                    ToolErrorKind.RETRYABLE,
                    f"kubectl timed out after {self.timeout_seconds:g}s: {_redacted_command(command)}",
                    retryable=True,
                ) from exc
            if proc.returncode != 0:
                detail = proc.stderr.strip() or proc.stdout.strip() or f"exit status {proc.returncode}"
                kind, retryable, circuit_breaker_failure = _kubectl_failure_classification(detail)
                raise ToolExecutionError(
                    kind,
                    f"kubectl failed: {redact_sensitive_text(detail, max_length=500)}",
                    retryable=retryable,
                    circuit_breaker_failure=circuit_breaker_failure,
                )
            out = proc.stdout.strip()
            try:
                return json.loads(out) if out else {"ok": True}
            except json.JSONDecodeError:
                return {"output": out}

        return self.circuit_breaker.call(
            _run,
            should_record_failure=_counts_against_live_api_circuit,
        )

    def list_pods(self, service: str) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        pods = self.kubectl(["get", "pods", "-n", self.namespace, "-l", f"app={service}", "-o", "json"])
        _require_kubernetes_items(pods, "pods")
        if pods["items"]:
            return pods
        selector = _deployment_selector(self.deployment(service))
        selected = self.kubectl(["get", "pods", "-n", self.namespace, "-l", selector, "-o", "json"])
        _require_kubernetes_items(selected, "pods")
        return selected

    def list_deployments(self) -> dict[str, Any]:
        deployments = self.kubectl(["get", "deployments", "-n", self.namespace, "-o", "json"])
        _require_kubernetes_items(deployments, "deployments")
        return deployments

    def deployment(self, service: str) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        deployment = self.kubectl(["get", "deployment", service, "-n", self.namespace, "-o", "json"])
        _require_kubernetes_object_confirmation("deployment read", deployment, "Deployment", service)
        return deployment

    def replica_sets_for_deployment(self, service: str) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        deployment = self.deployment(service)
        selector = _deployment_selector(deployment)
        replica_sets = self.kubectl(["get", "replicasets", "-n", self.namespace, "-l", selector, "-o", "json"])
        items = _require_kubernetes_items(replica_sets, "replicasets")
        return {"deployment": deployment, "replica_sets": _replica_sets_owned_by(deployment, items)}

    def rollout_revisions(self, service: str) -> dict[str, Any]:
        data = self.replica_sets_for_deployment(service)
        revisions = _replica_set_revisions(data.get("replica_sets", []))
        current = revisions[-1] if revisions else None
        previous = revisions[-2] if len(revisions) > 1 else None
        return {
            **data,
            "revisions": revisions,
            "current_revision": f"revision:{current}" if current is not None else None,
            "previous_revision": f"revision:{previous}" if previous is not None else None,
        }

    def rollout_undo(self, service: str, target: str | None = None) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        revision = _required_kubernetes_revision(target)
        args = ["rollout", "undo", f"deployment/{service}", "-n", self.namespace]
        args.append(f"--to-revision={revision}")
        undo = self.kubectl(args)
        _require_kubectl_output_confirmation("rollout undo", undo, service, ("rolled back",))
        status = self.rollout_status(service)
        _require_kubectl_output_confirmation("rollout status", status, service, ("successfully rolled out",))
        return {
            "target": f"revision:{revision}",
            "revision": int(revision),
            "undo": undo,
            "rollout_status": status,
            "verified": True,
        }

    def rollout_status(self, service: str) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        return self.kubectl(
            [
                "rollout",
                "status",
                f"deployment/{service}",
                "-n",
                self.namespace,
                f"--timeout={self.timeout_seconds:g}s",
            ]
        )

    def rollout_restart(self, service: str) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        restart = self.kubectl(["rollout", "restart", f"deployment/{service}", "-n", self.namespace])
        _require_kubectl_output_confirmation("rollout restart", restart, service, ("restarted",))
        status = self.rollout_status(service)
        _require_kubectl_output_confirmation("rollout status", status, service, ("successfully rolled out",))
        deployment = self.deployment(service)
        _require_kubernetes_restart_annotation_confirmation(deployment, service)
        return {"restart": restart, "rollout_status": status, "deployment": deployment, "verified": True}

    def scale(self, service: str, replicas: int) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        replicas = _required_kubernetes_replica_count(replicas)
        scale = self.kubectl(["scale", f"deployment/{service}", "-n", self.namespace, f"--replicas={replicas}"])
        _require_kubectl_output_confirmation("scale", scale, service, ("scaled",))
        deployment = self.deployment(service)
        _require_kubernetes_object_confirmation("deployment scale", deployment, "Deployment", service)
        _require_kubernetes_replicas_confirmation(deployment, service, replicas)
        _require_kubernetes_observed_generation_confirmation(deployment, service)
        return {"scale": scale, "deployment": deployment, "verified": True}

    def patch_deployment(self, service: str, patch: dict[str, Any]) -> dict[str, Any]:
        service = _required_kubernetes_name(service, "Kubernetes service/deployment")
        patch_result = self.kubectl(["patch", "deployment", service, "-n", self.namespace, "--type=merge", "-p", json.dumps(patch)])
        _require_kubectl_output_confirmation("patch deployment", patch_result, service, ("patched",))
        deployment = self.deployment(service)
        _require_kubernetes_object_confirmation("deployment patch", deployment, "Deployment", service)
        _require_kubernetes_merge_patch_readback(deployment, patch)
        return {"patch": patch_result, "deployment": deployment, "verified": True}

    def create_job(self, name: str, command: list[str]) -> dict[str, Any]:
        name = _required_kubernetes_name(name, "Kubernetes job")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) and item for item in command):
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "Kubernetes job creation requires a non-empty command list of strings",
                retryable=False,
            )
        manifest = {
            "apiVersion": "batch/v1",
            "kind": "Job",
            "metadata": {"name": name, "namespace": self.namespace},
            "spec": {
                "template": {
                    "spec": {
                        "restartPolicy": "Never",
                        "containers": [{"name": name, "image": "alpine:3.20", "command": command}],
                    }
                },
                "backoffLimit": 0,
            },
        }
        apply = self.kubectl(["apply", "-f", "-"], input_text=json.dumps(manifest))
        _require_kubectl_output_confirmation("job apply", apply, name, ("created", "configured", "unchanged"))
        job = self.kubectl(["get", "job", name, "-n", self.namespace, "-o", "json"])
        _require_kubernetes_object_confirmation("job apply", job, "Job", name)
        _require_kubernetes_job_command_confirmation(job, name, command)
        return {"apply": apply, "job": job, "verified": True}

    def drain_node(self, node: str) -> dict[str, Any]:
        node = _required_kubernetes_name(node, "Kubernetes node name", allow_dots=True)
        drain = self.kubectl(["drain", node, "--ignore-daemonsets", "--delete-emptydir-data"])
        _require_kubectl_output_confirmation("drain node", drain, node, ("drained",))
        node_readback = self.kubectl(["get", "node", node, "-o", "json"])
        _require_kubernetes_object_confirmation("node drain", node_readback, "Node", node)
        _require_kubernetes_node_unschedulable_confirmation(node_readback, node)
        return {"drain": drain, "node": node, "node_readback": node_readback, "verified": True}


@dataclass
class LiveProviderClients:
    datadog: DatadogClient
    github: GitHubClient
    pagerduty: PagerDutyClient
    slack: SlackClient
    kubernetes: KubernetesClient
    prometheus: PrometheusClient | None = None
    loki: LokiClient | None = None
    discord: DiscordWebhookClient | None = None
    generic_alerts: GenericAlertClient | None = None

    @classmethod
    def from_settings(cls, settings: SentinelSettings) -> "LiveProviderClients":
        backend = (
            RedisRateLimitBackend(settings.redis_url)
            if settings.redis_url
            else InMemoryRateLimitBackend()
        )
        rate_limiter = SharedRateLimiter(backend, limit=240, window_seconds=60)
        return cls(
            datadog=DatadogClient(settings, rate_limiter, shared_circuit_breaker("datadog")),
            github=GitHubClient(settings, rate_limiter, shared_circuit_breaker("github")),
            pagerduty=PagerDutyClient(settings, rate_limiter, shared_circuit_breaker("pagerduty")),
            slack=SlackClient(settings, rate_limiter, shared_circuit_breaker("slack")),
            kubernetes=KubernetesClient(settings, rate_limiter, shared_circuit_breaker("kubernetes")),
            prometheus=(
                PrometheusClient(settings, rate_limiter, shared_circuit_breaker("prometheus"))
                if settings.prometheus_url
                else None
            ),
            loki=(
                LokiClient(settings, rate_limiter, shared_circuit_breaker("loki"))
                if settings.loki_url
                else None
            ),
            discord=(
                DiscordWebhookClient(settings, rate_limiter, shared_circuit_breaker("discord"))
                if settings.discord_webhook_url
                else None
            ),
            generic_alerts=GenericAlertClient(settings, rate_limiter, shared_circuit_breaker("generic_webhook")),
        )

    def close(self) -> None:
        api_clients = tuple(
            client
            for client in (
                self.datadog.api,
                self.github.api,
                self.pagerduty.api,
                self.slack.api,
                self.prometheus.api if self.prometheus else None,
                self.loki.api if self.loki else None,
            )
            if client is not None
        )
        for client in api_clients:
            client.close()
        if self.discord is not None:
            self.discord.close()
        rate_limiters = {
            id(client.rate_limiter): client.rate_limiter
            for client in (*api_clients, self.kubernetes, self.discord, self.generic_alerts)
            if getattr(client, "rate_limiter", None) is not None
        }
        for rate_limiter in rate_limiters.values():
            rate_limiter.close()


def _extract_next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        if re.search(r'\brel="?next"?\b', part, flags=re.IGNORECASE):
            match = re.search(r"<([^>]+)>", part)
            if match:
                return match.group(1)
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                "github Link rel=next header did not include a parseable URL; refusing to return truncated evidence",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return None


def _resolve_api_url(base_url: str, path: str, provider: str) -> str:
    try:
        base = urlparse(base_url)
        target = urlparse(path)
    except ValueError as exc:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} pagination URL was malformed; refusing to send credentials",
            retryable=False,
            circuit_breaker_failure=False,
        ) from exc
    if not target.scheme and not target.netloc:
        if not path:
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"{provider} request path was empty; refusing to send credentials",
                retryable=False,
                circuit_breaker_failure=False,
            )
        return urljoin(f"{base_url}/", path.lstrip("/"))
    if not target.scheme or not target.netloc or target.scheme.lower() not in {"http", "https"}:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} pagination URL was malformed; refusing to send credentials",
            retryable=False,
            circuit_breaker_failure=False,
        )
    try:
        base_origin = _origin_tuple(base)
        target_origin = _origin_tuple(target)
    except ValueError as exc:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} pagination URL was malformed; refusing to send credentials",
            retryable=False,
            circuit_breaker_failure=False,
        ) from exc
    if base_origin != target_origin:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} pagination URL crossed API origin; refusing to send credentials",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if not _path_within_base(target.path, base.path):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} pagination URL crossed API base path; refusing to send credentials",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return path


def _normalize_api_base_url(base_url: str, provider: str) -> str:
    if not isinstance(base_url, str):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{provider} API base URL must be a non-empty http(s) URL",
            retryable=False,
            circuit_breaker_failure=False,
        )
    raw = base_url.strip()
    if not raw:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{provider} API base URL must be a non-empty http(s) URL",
            retryable=False,
            circuit_breaker_failure=False,
        )
    normalized = raw.rstrip("/")
    try:
        parsed = urlparse(normalized)
        _ = parsed.port
    except ValueError as exc:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{provider} API base URL was malformed; refusing to send credentials",
            retryable=False,
            circuit_breaker_failure=False,
        ) from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{provider} API base URL must be an http(s) URL with a host",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if parsed.username or parsed.password:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{provider} API base URL must not include credentials",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if parsed.query or parsed.fragment:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{provider} API base URL must not include a query string or fragment",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return normalized


def _required_webhook_url(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must be a non-empty http(s) URL",
            retryable=False,
            circuit_breaker_failure=False,
        )
    raw = value.strip()
    try:
        parsed = urlparse(raw)
        _ = parsed.port
    except ValueError as exc:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} was malformed; refusing to send webhook payload",
            retryable=False,
            circuit_breaker_failure=False,
        ) from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must be an http(s) URL with a host",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if parsed.username or parsed.password:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must not include URL userinfo credentials",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return raw


def _discord_webhook_wait_url(webhook_url: str) -> str:
    separator = "&" if urlparse(webhook_url).query else "?"
    return f"{webhook_url}{separator}wait=true"


def _origin_tuple(parsed) -> tuple[str, str, int | None]:
    port = parsed.port
    if port is None and parsed.scheme.lower() == "https":
        port = 443
    elif port is None and parsed.scheme.lower() == "http":
        port = 80
    return (parsed.scheme.lower(), (parsed.hostname or "").lower(), port)


def _path_within_base(target_path: str, base_path: str) -> bool:
    clean_base = base_path.rstrip("/")
    if not clean_base:
        return True
    return target_path == clean_base or target_path.startswith(f"{clean_base}/")


def _required_text(value: Any, message: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            message,
            retryable=False,
            circuit_breaker_failure=False,
        )
    return value.strip()


def _required_non_empty_string(value: Any, message: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            message,
            retryable=False,
            circuit_breaker_failure=False,
        )
    return value


def _optional_github_labels(labels: list[str] | None) -> list[str]:
    if labels is None:
        return []
    if not isinstance(labels, list):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "GitHub issue creation labels must be a list of non-empty strings",
            retryable=False,
            circuit_breaker_failure=False,
        )
    clean_labels: list[str] = []
    for label in labels:
        if not isinstance(label, str) or not label.strip():
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "GitHub issue creation labels must be a list of non-empty strings",
                retryable=False,
                circuit_breaker_failure=False,
            )
        clean_labels.append(label.strip())
    return clean_labels


def _optional_non_empty_strings(values: list[str] | None, field: str) -> list[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must be a list of non-empty strings",
            retryable=False,
            circuit_breaker_failure=False,
        )
    clean_values: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip():
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"{field} must be a list of non-empty strings",
                retryable=False,
                circuit_breaker_failure=False,
            )
        clean_values.append(value.strip())
    return clean_values


def _required_positive_epoch_seconds(value: Any, action: str, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit positive integer {field}",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return value


def _redacted_command(command: list[str]) -> str:
    return redact_sensitive_text(" ".join(command), max_length=500)


_KUBECTL_AUTHORIZATION_PATTERNS = (
    "forbidden",
    "unauthorized",
    "permission denied",
    "you must be logged in",
)

_KUBECTL_RATE_LIMIT_PATTERNS = (
    "too many requests",
    "rate limit",
    "throttl",
)

_KUBECTL_RETRYABLE_PATTERNS = (
    "connection refused",
    "connection reset",
    "context deadline exceeded",
    "i/o timeout",
    "no route to host",
    "serviceunavailable",
    "temporarily unavailable",
    "the server is currently unable to handle the request",
    "tls handshake timeout",
    "unable to connect to the server",
)


def _kubectl_failure_classification(detail: str) -> tuple[ToolErrorKind, bool, bool]:
    lowered = detail.lower()
    if any(pattern in lowered for pattern in _KUBECTL_RATE_LIMIT_PATTERNS):
        return (ToolErrorKind.RATE_LIMITED, True, False)
    if any(pattern in lowered for pattern in _KUBECTL_AUTHORIZATION_PATTERNS):
        return (ToolErrorKind.AUTHORIZATION, False, False)
    if any(pattern in lowered for pattern in _KUBECTL_RETRYABLE_PATTERNS):
        return (ToolErrorKind.RETRYABLE, True, True)
    return (ToolErrorKind.PERMANENT, False, False)


def _required_kubernetes_name(value: Any, field: str, *, allow_dots: bool = False) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must be an explicit Kubernetes resource name",
            retryable=False,
            circuit_breaker_failure=False,
        )
    name = value.strip()
    label = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?"
    pattern = rf"{label}(\.{label})*" if allow_dots else label
    max_length = 253 if allow_dots else 63
    if len(name) > max_length or re.fullmatch(pattern, name) is None:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must be a valid Kubernetes resource name, not {redact_sensitive_text(name, max_length=120)}",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return name


def _required_kubernetes_revision(target: str | None) -> str:
    if target is None or target == "":
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Kubernetes rollout target must use revision:<positive integer>",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if not isinstance(target, str):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Kubernetes rollout target must use revision:<positive integer>",
            retryable=False,
            circuit_breaker_failure=False,
        )
    target = target.strip()
    if not target:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Kubernetes rollout target must use revision:<positive integer>",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if not target.startswith("revision:"):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Kubernetes rollout target must use revision:<positive integer>",
            retryable=False,
            circuit_breaker_failure=False,
        )
    revision = target.split(":", 1)[1]
    if not revision.isdigit() or int(revision) <= 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Kubernetes rollout target must use revision:<positive integer>",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return revision


def _required_kubernetes_replica_count(replicas: Any) -> int:
    if isinstance(replicas, bool) or not isinstance(replicas, int) or replicas < 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Kubernetes scale requires an explicit non-negative integer replicas value",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return replicas


def _required_pagerduty_incident_status(status: Any) -> str:
    allowed_statuses = {"triggered", "acknowledged", "resolved"}
    if not isinstance(status, str) or not status.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "PagerDuty incident updates require an explicit incident status",
            retryable=False,
            circuit_breaker_failure=False,
        )
    status = status.strip()
    if status not in allowed_statuses:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"PagerDuty incident status must be one of: {', '.join(sorted(allowed_statuses))}",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return status


def _header_value(headers: dict[str, Any], name: str) -> str:
    expected = name.lower()
    for key, value in headers.items():
        if str(key).lower() == expected:
            return str(value)
    return ""


def _require_list(data: dict[str, Any], key: str, provider: str) -> list[dict[str, Any]]:
    value = data.get(key)
    if isinstance(value, list):
        return value
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} response field '{key}' must be a list",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _require_object_items(items: list[Any], provider: str, field: str) -> list[dict[str, Any]]:
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"{provider} response field '{field}[{index}]' must be an object",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return items


def _require_kubernetes_items(data: dict[str, Any], resource: str) -> list[dict[str, Any]]:
    try:
        items = _require_list(data, "items", "kubernetes")
    except ToolExecutionError as exc:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"kubernetes {resource} response field 'items' must be a list",
            retryable=False,
            circuit_breaker_failure=False,
        ) from exc
    items = _require_object_items(items, "kubernetes", f"{resource}.items")
    for index, item in enumerate(items):
        metadata = item.get("metadata")
        if not isinstance(metadata, dict) or not metadata.get("name"):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"kubernetes {resource} response missing confirmation field(s): items[{index}].metadata.name",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return items


def _optional_object(value: Any, provider: str, field: str) -> dict[str, Any] | None:
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} response field '{field}' must be an object",
        retryable=False,
        circuit_breaker_failure=False,
    )


def datadog_point_has_finite_numeric_value(point: Any) -> bool:
    if not isinstance(point, list | tuple) or len(point) < 2:
        return False
    value = point[1]
    if isinstance(value, bool):
        return False
    return isinstance(value, int | float) and math.isfinite(value)


def _require_datadog_metric_query_confirmation(data: dict[str, Any]) -> None:
    missing = []
    malformed = []
    status = data.get("status")
    if status is not None and status != "ok":
        malformed.append(f"status={status}")
    series = data.get("series")
    if not isinstance(series, list):
        missing.append("series")
    else:
        for index, item in enumerate(series):
            if not isinstance(item, dict):
                malformed.append(f"series[{index}]")
                continue
            pointlist = item.get("pointlist")
            if not isinstance(pointlist, list):
                malformed.append(f"series[{index}].pointlist")
            elif not pointlist:
                missing.append(f"series[{index}].pointlist")
            elif not any(datadog_point_has_finite_numeric_value(point) for point in pointlist):
                malformed.append(f"series[{index}].pointlist")
    if missing or malformed:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if malformed:
            details.append(f"malformed field(s): {', '.join(malformed)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Datadog metric query response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_datadog_monitor_items(items: list[Any], field: str) -> list[dict[str, Any]]:
    monitors = _require_object_items(items, "datadog", field)
    for index, monitor in enumerate(monitors):
        if monitor.get("id") is None:
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"Datadog {field} response missing confirmation field(s): {field}[{index}].id",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return monitors


def _require_datadog_event_items(items: list[Any], field: str) -> list[dict[str, Any]]:
    events = _require_object_items(items, "datadog", field)
    for index, event in enumerate(events):
        if not isinstance(event.get("id"), str) or not event.get("id"):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"Datadog {field} response missing confirmation field(s): {field}[{index}].id",
                retryable=False,
                circuit_breaker_failure=False,
        )
    return events


def _require_prometheus_success(data: dict[str, Any], action: str) -> None:
    if data.get("status") != "success":
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"prometheus {action} response did not include status=success",
            retryable=False,
            circuit_breaker_failure=False,
        )
    payload = data.get("data")
    if not isinstance(payload, dict):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"prometheus {action} response field 'data' must be an object",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _prometheus_result_items(data: dict[str, Any]) -> list[dict[str, Any]]:
    payload = data.get("data")
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, list):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            "prometheus response field 'data.result' must be a list",
            retryable=False,
            circuit_breaker_failure=False,
        )
    items = _require_object_items(result, "prometheus", "data.result")
    for index, item in enumerate(items):
        if not isinstance(item.get("metric"), dict):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"prometheus response field 'data.result[{index}].metric' must be an object",
                retryable=False,
                circuit_breaker_failure=False,
            )
        values = item.get("values")
        value = item.get("value")
        if "values" in item and not isinstance(values, list):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"prometheus response field 'data.result[{index}].values' must be a list",
                retryable=False,
                circuit_breaker_failure=False,
            )
        if "value" in item and not isinstance(value, list):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"prometheus response field 'data.result[{index}].value' must be a list",
                retryable=False,
                circuit_breaker_failure=False,
            )
        if not isinstance(values, list) and not isinstance(value, list):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"prometheus response field 'data.result[{index}]' must include value or values",
                retryable=False,
                circuit_breaker_failure=False,
            )
        if isinstance(values, list):
            for value_index, point in enumerate(values):
                _require_prometheus_sample_pair(
                    point,
                    f"data.result[{index}].values[{value_index}]",
                )
        if isinstance(value, list):
            _require_prometheus_sample_pair(value, f"data.result[{index}].value")
    return items


def _require_prometheus_sample_pair(point: Any, field: str) -> None:
    if not isinstance(point, list | tuple) or len(point) < 2:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"prometheus response field '{field}' must include timestamp and sample value",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if not _is_finite_number_like(point[0]):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"prometheus response field '{field}[0]' must be a finite timestamp",
            retryable=False,
            circuit_breaker_failure=False,
        )
    if not _is_number_like(point[1]):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"prometheus response field '{field}[1]' must be a numeric sample value",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _is_number_like(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


def _is_finite_number_like(value: Any) -> bool:
    if not _is_number_like(value):
        return False
    return math.isfinite(float(value))


def prometheus_result_has_finite_numeric_value(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    candidates = []
    if isinstance(item.get("values"), list):
        candidates.extend(item["values"])
    if isinstance(item.get("value"), list):
        candidates.append(item["value"])
    for point in candidates:
        if not isinstance(point, list | tuple) or len(point) < 2:
            continue
        try:
            value = float(point[1])
        except (TypeError, ValueError):
            continue
        if math.isfinite(value):
            return True
    return False


def _require_loki_success(
    data: dict[str, Any],
    action: str,
    *,
    expected_data_shape: str = "object",
) -> None:
    if data.get("status") != "success":
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"loki {action} response did not include status=success",
            retryable=False,
            circuit_breaker_failure=False,
        )
    payload = data.get("data")
    if expected_data_shape == "list":
        if isinstance(payload, list):
            return
        expected = "a list"
    else:
        if isinstance(payload, dict):
            return
        expected = "an object"
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"loki {action} response field 'data' must be {expected}",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _loki_result_items(data: dict[str, Any]) -> list[dict[str, Any]]:
    payload = data.get("data")
    result = payload.get("result") if isinstance(payload, dict) else None
    if not isinstance(result, list):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            "loki response field 'data.result' must be a list",
            retryable=False,
            circuit_breaker_failure=False,
        )
    items = _require_object_items(result, "loki", "data.result")
    for index, item in enumerate(items):
        if not isinstance(item.get("stream"), dict):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"loki response field 'data.result[{index}].stream' must be an object",
                retryable=False,
                circuit_breaker_failure=False,
            )
        values = item.get("values")
        if not isinstance(values, list):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"loki response field 'data.result[{index}].values' must be a list",
                retryable=False,
                circuit_breaker_failure=False,
            )
        for value_index, value in enumerate(values):
            if not isinstance(value, list | tuple) or len(value) < 2:
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    f"loki response field 'data.result[{index}].values[{value_index}]' must include timestamp and line",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            if not isinstance(value[0], str) or not value[0].strip():
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    f"loki response field 'data.result[{index}].values[{value_index}][0]' must be a timestamp string",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            if not isinstance(value[1], str) or not value[1].strip():
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    f"loki response field 'data.result[{index}].values[{value_index}][1]' must be a non-empty log line",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
    return items


def _require_github_issue_confirmation(
    data: dict[str, Any],
    *,
    expected_owner: str | None,
    expected_repo: str | None,
    expected_title: str,
) -> None:
    missing = []
    mismatched = []
    number = data.get("number")
    html_url = data.get("html_url")
    title = data.get("title")
    if not isinstance(number, int):
        missing.append("number")
    if not isinstance(html_url, str) or not html_url.strip():
        missing.append("html_url")
    elif isinstance(number, int) and not _github_issue_url_matches(html_url, expected_owner, expected_repo, number):
        mismatched.append(f"html_url={html_url}")
    if not isinstance(title, str) or not title.strip():
        missing.append("title")
    elif title != expected_title:
        mismatched.append(f"title={title}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"GitHub issue creation response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_github_content_confirmation(data: dict[str, Any], *, expected_path: str) -> None:
    missing = []
    mismatched = []
    path = data.get("path")
    if not isinstance(path, str) or not path:
        missing.append("path")
    elif path != expected_path:
        mismatched.append(f"path={path}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"GitHub contents response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


_GITHUB_API_HOST = "api.github.com"
_GITHUB_HTML_HOST = "github.com"


def _github_api_url_host_matches(parsed) -> bool:
    return _github_url_host_matches(parsed, _GITHUB_API_HOST)


def _github_html_url_host_matches(parsed) -> bool:
    return _github_url_host_matches(parsed, _GITHUB_HTML_HOST)


def _github_url_host_matches(parsed, expected_host: str) -> bool:
    try:
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme.lower() == "https"
        and (parsed.hostname or "").lower() == expected_host
        and port in {None, 443}
    )


def _github_issue_url_matches(html_url: str, owner: str | None, repo: str | None, number: int) -> bool:
    parsed = urlparse(html_url)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4:
        return False
    expected = [owner or "", repo or "", "issues", str(number)]
    return _github_html_url_host_matches(parsed) and [part.lower() for part in parts[-4:]] == [
        part.lower() for part in expected
    ]


def _require_github_file_update_confirmation(
    data: dict[str, Any],
    *,
    expected_path: str,
    expected_owner: str | None,
    expected_repo: str | None,
    expected_message: str,
) -> None:
    content = data.get("content")
    commit = data.get("commit")
    missing = []
    mismatched = []
    if not isinstance(content, dict) or not content.get("path"):
        missing.append("content.path")
    elif content.get("path") != expected_path:
        mismatched.append(f"content.path={content.get('path')}")
    if not isinstance(commit, dict):
        missing.append("commit.sha")
        missing.append("commit.url")
        missing.append("commit.message")
    else:
        commit_sha = commit.get("sha")
        if not isinstance(commit_sha, str) or not commit_sha:
            missing.append("commit.sha")
        commit_url = commit.get("html_url") or commit.get("url")
        if not isinstance(commit_url, str) or not commit_url.strip():
            missing.append("commit.url")
        elif isinstance(commit_sha, str) and commit_sha and not _github_commit_url_matches(
            commit_url,
            expected_owner,
            expected_repo,
            commit_sha,
        ):
            mismatched.append(f"commit.url={commit_url}")
        commit_message = commit.get("message")
        if not isinstance(commit_message, str) or not commit_message.strip():
            missing.append("commit.message")
        elif commit_message != expected_message:
            mismatched.append(f"commit.message={commit_message}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"GitHub file update response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_github_commit_items(
    items: list[Any],
    *,
    expected_owner: str | None,
    expected_repo: str | None,
) -> list[dict[str, Any]]:
    commits = _require_object_items(items, "github", "commits")
    for index, commit in enumerate(commits):
        missing = []
        mismatched = []
        sha = commit.get("sha")
        if not isinstance(sha, str) or not sha:
            missing.append(f"commits[{index}].sha")
        url = commit.get("html_url") or commit.get("url")
        if not isinstance(url, str) or not url.strip():
            missing.append(f"commits[{index}].url")
        elif isinstance(sha, str) and sha and not _github_commit_url_matches(url, expected_owner, expected_repo, sha):
            mismatched.append(f"commits[{index}].url={url}")
        if missing or mismatched:
            details = []
            if missing:
                details.append(f"missing confirmation field(s): {', '.join(missing)}")
            if mismatched:
                details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"GitHub commits response {'; '.join(details)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
        embedded_commit = commit.get("commit")
        if embedded_commit is not None and not isinstance(embedded_commit, dict):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"github response field 'commits[{index}].commit' must be an object",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return commits


def _github_commit_url_matches(url: str, owner: str | None, repo: str | None, sha: str) -> bool:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    expected_api = ["repos", owner or "", repo or "", "commits", sha]
    expected_html = [owner or "", repo or "", "commit", sha]
    lowered_parts = [part.lower() for part in parts]
    return (
        _github_api_url_host_matches(parsed)
        and lowered_parts[-5:] == [part.lower() for part in expected_api]
    ) or (
        _github_html_url_host_matches(parsed)
        and lowered_parts[-4:] == [part.lower() for part in expected_html]
    )


def _require_github_deployment_items(
    items: list[Any],
    *,
    expected_owner: str | None,
    expected_repo: str | None,
) -> list[dict[str, Any]]:
    deployments = _require_object_items(items, "github", "deployments")
    for index, deployment in enumerate(deployments):
        missing = []
        mismatched = []
        deployment_id = deployment.get("id")
        if not _usable_github_id(deployment_id):
            missing.append(f"deployments[{index}].id")
        url = deployment.get("url") or deployment.get("statuses_url")
        if not isinstance(url, str) or not url.strip():
            missing.append(f"deployments[{index}].url")
        elif _usable_github_id(deployment_id) and not _github_deployment_url_matches(
            url,
            expected_owner,
            expected_repo,
            deployment_id,
        ):
            mismatched.append(f"deployments[{index}].url={url}")
        if missing or mismatched:
            details = []
            if missing:
                details.append(f"missing confirmation field(s): {', '.join(missing)}")
            if mismatched:
                details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"GitHub deployments response {'; '.join(details)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return deployments


def _github_deployment_url_matches(
    url: str,
    owner: str | None,
    repo: str | None,
    deployment_id: Any,
) -> bool:
    parsed = urlparse(url)
    if not _github_api_url_host_matches(parsed):
        return False
    parts = [part for part in parsed.path.split("/") if part]
    expected = ["repos", owner or "", repo or "", "deployments", str(deployment_id)]
    lowered_parts = [part.lower() for part in parts]
    lowered_expected = [part.lower() for part in expected]
    return lowered_parts[-5:] == lowered_expected or lowered_parts[-6:] == lowered_expected + ["statuses"]


def _require_github_pull_request_confirmation(
    data: dict[str, Any],
    expected_number: int,
    *,
    expected_owner: str | None,
    expected_repo: str | None,
) -> None:
    missing = []
    mismatched = []
    number = data.get("number")
    if not isinstance(number, int):
        missing.append("number")
    elif number != expected_number:
        mismatched.append(f"number={number}")
    url = data.get("html_url") or data.get("url")
    if not isinstance(url, str) or not url.strip():
        missing.append("url")
    elif isinstance(number, int) and number == expected_number and not _github_pull_request_url_matches(
        url,
        expected_owner,
        expected_repo,
        expected_number,
    ):
        mismatched.append(f"url={url}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"GitHub pull request response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _github_pull_request_url_matches(
    url: str,
    owner: str | None,
    repo: str | None,
    number: int,
) -> bool:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    expected_api = ["repos", owner or "", repo or "", "pulls", str(number)]
    expected_html = [owner or "", repo or "", "pull", str(number)]
    lowered_parts = [part.lower() for part in parts]
    return (
        _github_api_url_host_matches(parsed)
        and lowered_parts[-5:] == [part.lower() for part in expected_api]
    ) or (
        _github_html_url_host_matches(parsed)
        and lowered_parts[-4:] == [part.lower() for part in expected_html]
    )


def _require_github_pull_request_items(
    items: list[Any],
    field: str,
    *,
    expected_owner: str | None,
    expected_repo: str | None,
) -> list[dict[str, Any]]:
    pull_requests = _require_object_items(items, "github", field)
    for index, pull_request in enumerate(pull_requests):
        missing = []
        mismatched = []
        number = pull_request.get("number")
        if not isinstance(number, int):
            missing.append(f"{field}[{index}].number")
        url = pull_request.get("html_url") or pull_request.get("url")
        if not isinstance(url, str) or not url.strip():
            missing.append(f"{field}[{index}].url")
        elif isinstance(number, int) and not _github_pull_request_url_matches(
            url,
            expected_owner,
            expected_repo,
            number,
        ):
            mismatched.append(f"{field}[{index}].url={url}")
        if missing or mismatched:
            details = []
            if missing:
                details.append(f"missing confirmation field(s): {', '.join(missing)}")
            if mismatched:
                details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"GitHub {field} response {'; '.join(details)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return pull_requests


def _require_github_pull_request_file_items(
    items: list[Any],
    *,
    expected_owner: str | None,
    expected_repo: str | None,
) -> list[dict[str, Any]]:
    files = _require_object_items(items, "github", "pull_request_files")
    for index, file_item in enumerate(files):
        missing = []
        mismatched = []
        filename = file_item.get("filename")
        if not isinstance(filename, str) or not filename.strip():
            missing.append(f"pull_request_files[{index}].filename")
        url = file_item.get("contents_url") or file_item.get("blob_url") or file_item.get("raw_url")
        if not isinstance(url, str) or not url.strip():
            missing.append(f"pull_request_files[{index}].url")
        elif isinstance(filename, str) and filename.strip() and not _github_pull_request_file_url_matches(
            url,
            expected_owner,
            expected_repo,
            filename,
        ):
            mismatched.append(f"pull_request_files[{index}].url={url}")
        if missing or mismatched:
            details = []
            if missing:
                details.append(f"missing confirmation field(s): {', '.join(missing)}")
            if mismatched:
                details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"GitHub pull_request_files response {'; '.join(details)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return files


def _github_pull_request_file_url_matches(
    url: str,
    owner: str | None,
    repo: str | None,
    filename: str,
) -> bool:
    parsed = urlparse(url)
    parts = [unquote(part) for part in parsed.path.split("/") if part]
    expected_owner = (owner or "").lower()
    expected_repo = (repo or "").lower()
    expected_filename = filename.strip("/")
    if len(parts) >= 5 and _github_api_url_host_matches(parsed) and parts[0].lower() == "repos":
        if parts[1].lower() == expected_owner and parts[2].lower() == expected_repo and parts[3].lower() == "contents":
            return "/".join(parts[4:]) == expected_filename
    if (
        len(parts) >= 5
        and _github_html_url_host_matches(parsed)
        and parts[0].lower() == expected_owner
        and parts[1].lower() == expected_repo
    ):
        if parts[2].lower() in {"blob", "raw"}:
            return "/".join(parts[4:]) == expected_filename
    return False


def _require_github_deployment_status_items(
    items: list[Any],
    *,
    expected_owner: str | None,
    expected_repo: str | None,
    expected_deployment_id: int | str,
) -> list[dict[str, Any]]:
    statuses = _require_object_items(items, "github", "deployment_statuses")
    for index, status in enumerate(statuses):
        missing = []
        mismatched = []
        status_id = status.get("id")
        if not _usable_github_id(status_id):
            missing.append(f"deployment_statuses[{index}].id")
        if not isinstance(status.get("state"), str) or not status.get("state"):
            missing.append(f"deployment_statuses[{index}].state")
        deployment_url = status.get("deployment_url")
        status_url = status.get("url")
        if isinstance(deployment_url, str) and deployment_url.strip():
            if not _github_deployment_url_matches(
                deployment_url,
                expected_owner,
                expected_repo,
                expected_deployment_id,
            ):
                mismatched.append(f"deployment_statuses[{index}].deployment_url={deployment_url}")
        elif isinstance(status_url, str) and status_url.strip() and _usable_github_id(status_id):
            if not _github_deployment_status_url_matches(
                status_url,
                expected_owner,
                expected_repo,
                expected_deployment_id,
                status_id,
            ):
                mismatched.append(f"deployment_statuses[{index}].url={status_url}")
        else:
            missing.append(f"deployment_statuses[{index}].deployment_url")
        if missing or mismatched:
            details = []
            if missing:
                details.append(f"missing confirmation field(s): {', '.join(missing)}")
            if mismatched:
                details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"GitHub deployment_statuses response {'; '.join(details)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return statuses


def _github_deployment_status_url_matches(
    url: str,
    owner: str | None,
    repo: str | None,
    deployment_id: int | str,
    status_id: Any,
) -> bool:
    parsed = urlparse(url)
    if not _github_api_url_host_matches(parsed):
        return False
    parts = [part for part in parsed.path.split("/") if part]
    expected = ["repos", owner or "", repo or "", "deployments", str(deployment_id), "statuses", str(status_id)]
    return [part.lower() for part in parts[-7:]] == [part.lower() for part in expected]


def _usable_github_id(value: Any) -> bool:
    return not isinstance(value, bool) and (
        isinstance(value, int) or (isinstance(value, str) and bool(value.strip()))
    )


def _require_github_status_confirmation(
    data: dict[str, Any],
    *,
    expected_owner: str | None,
    expected_repo: str | None,
) -> None:
    missing = []
    malformed = []
    mismatched = []
    if not isinstance(data.get("state"), str) or not data.get("state"):
        missing.append("state")
    _confirm_github_status_repository(data, expected_owner, expected_repo, missing, mismatched)
    statuses = data.get("statuses")
    if not isinstance(statuses, list):
        missing.append("statuses")
    else:
        for index, status in enumerate(statuses):
            if not isinstance(status, dict):
                malformed.append(f"statuses[{index}]")
    if missing or malformed or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if malformed:
            details.append(f"malformed field(s): {', '.join(malformed)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"GitHub commit status response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _confirm_github_status_repository(
    data: dict[str, Any],
    expected_owner: str | None,
    expected_repo: str | None,
    missing: list[str],
    mismatched: list[str],
) -> None:
    repository = data.get("repository")
    if isinstance(repository, dict):
        full_name = repository.get("full_name")
        if isinstance(full_name, str) and full_name.strip():
            if full_name.lower() != f"{expected_owner or ''}/{expected_repo or ''}".lower():
                mismatched.append(f"repository.full_name={full_name}")
            return

    url = data.get("repository_url") or data.get("url") or data.get("commit_url")
    if isinstance(url, str) and url.strip():
        if not _github_repo_url_matches(url, expected_owner, expected_repo):
            mismatched.append(f"repository_url={url}")
        return
    missing.append("repository.full_name")


def _github_repo_url_matches(url: str, owner: str | None, repo: str | None) -> bool:
    parsed = urlparse(url)
    parts = [part.lower() for part in parsed.path.split("/") if part]
    expected_owner = (owner or "").lower()
    expected_repo = (repo or "").lower()
    return (
        _github_api_url_host_matches(parsed)
        and len(parts) >= 3
        and parts[:3] == ["repos", expected_owner, expected_repo]
    ) or (
        _github_html_url_host_matches(parsed)
        and len(parts) >= 2
        and parts[:2] == [expected_owner, expected_repo]
    )


def _require_github_check_run_items(
    items: list[Any],
    *,
    expected_owner: str | None,
    expected_repo: str | None,
) -> list[dict[str, Any]]:
    check_runs = _require_object_items(items, "github", "check_runs")
    for index, check_run in enumerate(check_runs):
        missing = []
        mismatched = []
        check_run_id = check_run.get("id")
        if not _usable_github_id(check_run_id):
            missing.append(f"check_runs[{index}].id")
        if not isinstance(check_run.get("status"), str) or not check_run.get("status"):
            missing.append(f"check_runs[{index}].status")
        url = check_run.get("url") or check_run.get("html_url")
        if not isinstance(url, str) or not url.strip():
            missing.append(f"check_runs[{index}].url")
        elif _usable_github_id(check_run_id) and not _github_check_run_url_matches(
            url,
            expected_owner,
            expected_repo,
            check_run_id,
        ):
            mismatched.append(f"check_runs[{index}].url={url}")
        if missing or mismatched:
            details = []
            if missing:
                details.append(f"missing confirmation field(s): {', '.join(missing)}")
            if mismatched:
                details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"GitHub check_runs response {'; '.join(details)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return check_runs


def _github_check_run_url_matches(
    url: str,
    owner: str | None,
    repo: str | None,
    check_run_id: Any,
) -> bool:
    parsed = urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    expected_api = ["repos", owner or "", repo or "", "check-runs", str(check_run_id)]
    expected_html = [owner or "", repo or "", "runs", str(check_run_id)]
    lowered_parts = [part.lower() for part in parts]
    return (
        _github_api_url_host_matches(parsed)
        and lowered_parts[-5:] == [part.lower() for part in expected_api]
    ) or (
        _github_html_url_host_matches(parsed)
        and lowered_parts[-4:] == [part.lower() for part in expected_html]
    )


def _require_pagerduty_incident_read_confirmation(data: dict[str, Any], incident_id: str) -> None:
    incident = data.get("incident")
    missing = []
    mismatched = []
    if not isinstance(incident, dict):
        missing.append("incident")
    else:
        confirmed_id = incident.get("id")
        confirmed_status = incident.get("status")
        if not confirmed_id:
            missing.append("incident.id")
        elif confirmed_id != incident_id:
            mismatched.append(f"incident.id={confirmed_id}")
        if not isinstance(confirmed_status, str) or not confirmed_status:
            missing.append("incident.status")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"PagerDuty incident read response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_pagerduty_incident_items(items: list[Any], field: str) -> list[dict[str, Any]]:
    incidents = _require_object_items(items, "pagerduty", field)
    for index, incident in enumerate(incidents):
        missing = []
        if not incident.get("id"):
            missing.append(f"{field}[{index}].id")
        if not isinstance(incident.get("status"), str) or not incident.get("status"):
            missing.append(f"{field}[{index}].status")
        if missing:
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"PagerDuty {field} response missing confirmation field(s): {', '.join(missing)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return incidents


def _require_pagerduty_on_call_items(items: list[Any]) -> list[dict[str, Any]]:
    calls = _require_object_items(items, "pagerduty", "oncalls")
    for index, call in enumerate(calls):
        user = call.get("user")
        if not isinstance(user, dict) or not user.get("id"):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"PagerDuty oncalls response missing confirmation field(s): oncalls[{index}].user.id",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return calls


def _require_pagerduty_incident_status_confirmation(data: dict[str, Any], incident_id: str, status: str) -> None:
    incident = data.get("incident")
    missing = []
    mismatched = []
    if not isinstance(incident, dict):
        missing.append("incident")
    else:
        confirmed_id = incident.get("id")
        confirmed_status = incident.get("status")
        if not confirmed_id:
            missing.append("incident.id")
        elif confirmed_id != incident_id:
            mismatched.append(f"incident.id={confirmed_id}")
        if not confirmed_status:
            missing.append("incident.status")
        elif confirmed_status != status:
            mismatched.append(f"incident.status={confirmed_status}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"PagerDuty incident status update response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_kubectl_output_confirmation(
    operation: str,
    data: dict[str, Any],
    resource_name: str,
    accepted_phrases: tuple[str, ...],
) -> None:
    output = data.get("output")
    missing = []
    mismatched = []
    if not isinstance(output, str) or not output:
        missing.append("output")
    else:
        if not _text_mentions_kubernetes_resource(output, resource_name):
            mismatched.append(f"resource={resource_name}")
        if not any(phrase in output for phrase in accepted_phrases):
            mismatched.append(f"action in {accepted_phrases}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Kubernetes {operation} response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_kubernetes_object_confirmation(
    operation: str,
    data: dict[str, Any],
    expected_kind: str,
    expected_name: str,
) -> None:
    metadata = data.get("metadata")
    missing = []
    mismatched = []
    if not isinstance(metadata, dict):
        missing.append("metadata")
    else:
        name = metadata.get("name")
        if not name:
            missing.append("metadata.name")
        elif name != expected_name:
            mismatched.append(f"metadata.name={name}")
    kind = data.get("kind")
    if kind is not None and kind != expected_kind:
        mismatched.append(f"kind={kind}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Kubernetes {operation} readback response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_kubernetes_replicas_confirmation(deployment: dict[str, Any], service: str, replicas: int) -> None:
    observed = deployment.get("spec", {}).get("replicas") if isinstance(deployment.get("spec"), dict) else None
    if observed != replicas:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Kubernetes deployment scale readback mismatched replica count for {service}: expected {replicas}, observed {observed}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_kubernetes_observed_generation_confirmation(deployment: dict[str, Any], service: str) -> None:
    metadata = deployment.get("metadata")
    status = deployment.get("status")
    generation = metadata.get("generation") if isinstance(metadata, dict) else None
    observed_generation = status.get("observedGeneration") if isinstance(status, dict) else None
    missing = []
    malformed = []
    mismatched = []
    if not _usable_kubernetes_generation(generation):
        missing.append("metadata.generation")
    if not _usable_kubernetes_generation(observed_generation):
        missing.append("status.observedGeneration")
    if not missing:
        if int(observed_generation) < int(generation):
            mismatched.append("status.observedGeneration")
    if malformed or missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if malformed:
            details.append(f"malformed field(s): {', '.join(malformed)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Kubernetes deployment scale readback generation not observed for {service}: {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _usable_kubernetes_generation(value: Any) -> bool:
    if isinstance(value, bool):
        return False
    return isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit())


def _require_kubernetes_restart_annotation_confirmation(deployment: dict[str, Any], service: str) -> None:
    annotations = (
        deployment.get("spec", {})
        .get("template", {})
        .get("metadata", {})
        .get("annotations")
        if isinstance(deployment.get("spec"), dict)
        else None
    )
    restarted_at = annotations.get("kubectl.kubernetes.io/restartedAt") if isinstance(annotations, dict) else None
    if not isinstance(restarted_at, str) or not restarted_at.strip():
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Kubernetes rollout restart readback missing confirmation field(s): spec.template.metadata.annotations.kubectl.kubernetes.io/restartedAt for {service}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_kubernetes_merge_patch_readback(deployment: dict[str, Any], patch: dict[str, Any]) -> None:
    missing: list[str] = []
    mismatched: list[str] = []
    _collect_merge_patch_readback_mismatches(deployment, patch, (), missing, mismatched)
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing patched field(s): {', '.join(_safe_kubernetes_paths(missing))}")
        if mismatched:
            details.append(f"mismatched patched field(s): {', '.join(_safe_kubernetes_paths(mismatched))}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Kubernetes deployment patch readback {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _collect_merge_patch_readback_mismatches(
    actual: Any,
    expected: Any,
    path: tuple[str, ...],
    missing: list[str],
    mismatched: list[str],
) -> None:
    field_path = ".".join(path) if path else "deployment"
    if not isinstance(expected, dict):
        if actual != expected:
            mismatched.append(field_path)
        return
    if not isinstance(actual, dict):
        mismatched.append(field_path)
        return
    for key, expected_value in expected.items():
        child_path = (*path, str(key))
        child_field = ".".join(child_path)
        if expected_value is None:
            if key in actual and actual.get(key) is not None:
                mismatched.append(child_field)
            continue
        if key not in actual:
            missing.append(child_field)
            continue
        _collect_merge_patch_readback_mismatches(actual[key], expected_value, child_path, missing, mismatched)


def _safe_kubernetes_paths(paths: list[str]) -> list[str]:
    return [redact_sensitive_text(path, max_length=300) for path in paths]


def _require_kubernetes_job_command_confirmation(job: dict[str, Any], job_name: str, command: list[str]) -> None:
    containers = (
        job.get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers")
        if isinstance(job.get("spec"), dict)
        else None
    )
    if not isinstance(containers, list) or not containers:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            "Kubernetes job readback missing confirmation field(s): spec.template.spec.containers",
            retryable=False,
            circuit_breaker_failure=False,
        )
    for index, container in enumerate(containers):
        if not isinstance(container, dict):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"Kubernetes job readback malformed field(s): spec.template.spec.containers[{index}]",
                retryable=False,
                circuit_breaker_failure=False,
            )
        if container.get("name") == job_name:
            if container.get("command") != command:
                raise ToolExecutionError(
                    ToolErrorKind.MALFORMED_OUTPUT,
                    f"Kubernetes job readback mismatched confirmation field(s): spec.template.spec.containers[{index}].command",
                    retryable=False,
                    circuit_breaker_failure=False,
                )
            return
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        "Kubernetes job readback missing confirmation field(s): spec.template.spec.containers[].name",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _require_kubernetes_node_unschedulable_confirmation(node: dict[str, Any], node_name: str) -> None:
    spec = node.get("spec")
    observed = spec.get("unschedulable") if isinstance(spec, dict) else None
    if observed is not True:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Kubernetes node drain readback mismatched confirmation field(s): spec.unschedulable for {node_name}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _text_mentions_kubernetes_resource(text: str, resource_name: str) -> bool:
    pattern = rf"(?<![A-Za-z0-9-]){re.escape(resource_name)}(?![A-Za-z0-9-])"
    return re.search(pattern, text) is not None


def _optional_int(value: Any, provider: str, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        parsed = None
    elif isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        parsed = int(value.strip())
    else:
        parsed = None
    if parsed is None or parsed < 0:
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} response field '{field}' must be an integer",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return parsed


def _optional_bool(value: Any, provider: str, field: str) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} response field '{field}' must be a boolean",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _optional_nested_string(data: dict[str, Any], path: tuple[str, ...], provider: str, field: str) -> str | None:
    current: Any = data
    for index, item in enumerate(path):
        if not isinstance(current, dict):
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"{provider} response field '{'.'.join(path[:index])}' must be an object",
                retryable=False,
                circuit_breaker_failure=False,
            )
        if item not in current:
            return None
        current = current[item]
    if current is None:
        return None
    if isinstance(current, str):
        return current
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} response field '{field}' must be a string",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _optional_slack_next_cursor(data: dict[str, Any]) -> str | None:
    metadata = data.get("response_metadata")
    if metadata is None:
        return None
    if not isinstance(metadata, dict):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            "slack response field 'response_metadata' must be an object",
            retryable=False,
            circuit_breaker_failure=False,
        )
    cursor = metadata.get("next_cursor")
    if cursor is None:
        return None
    if isinstance(cursor, str):
        return cursor
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        "slack response field 'response_metadata.next_cursor' must be a string",
        retryable=False,
        circuit_breaker_failure=False,
    )


_SLACK_AUTHORIZATION_ERRORS = {
    "account_inactive",
    "ekm_access_denied",
    "invalid_auth",
    "missing_scope",
    "no_permission",
    "not_allowed_token_type",
    "not_authed",
    "token_revoked",
}

_SLACK_RATE_LIMIT_ERRORS = {
    "rate_limited",
    "ratelimited",
}


def _slack_error_text(data: dict[str, Any]) -> str:
    error = data.get("error")
    if isinstance(error, str) and error.strip():
        return error.strip()
    return "unknown_error"


def _slack_error_kind(error: str) -> ToolErrorKind:
    normalized = error.strip().lower()
    if normalized in _SLACK_RATE_LIMIT_ERRORS:
        return ToolErrorKind.RATE_LIMITED
    if normalized in _SLACK_AUTHORIZATION_ERRORS:
        return ToolErrorKind.AUTHORIZATION
    return ToolErrorKind.PERMANENT


def _slack_retry_after_seconds(data: dict[str, Any]) -> float | None:
    for candidate in (
        data.get("retry_after"),
        data.get("retry_after_seconds"),
        _get_nested(data, ("response_metadata", "retry_after")),
        _get_nested(data, ("response_metadata", "retry_after_seconds")),
    ):
        if candidate is None or isinstance(candidate, bool):
            continue
        try:
            seconds = float(candidate)
        except (TypeError, ValueError):
            continue
        if seconds >= 0:
            return seconds
    return None


def _safe_response_headers(headers: Any) -> dict[str, str]:
    sensitive_terms = ("authorization", "cookie", "token", "secret", "api-key", "api_key")
    safe: dict[str, str] = {}
    for key, value in dict(headers).items():
        lowered = str(key).lower()
        if any(term in lowered for term in sensitive_terms):
            continue
        safe[lowered] = str(value)[:500]
    return safe


def _retry_after_seconds(headers: Any) -> float | None:
    value = _header_value(dict(headers), "retry-after")
    if not value:
        return None
    try:
        seconds = float(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        seconds = (retry_at.astimezone(UTC) - datetime.now(UTC)).total_seconds()
    return max(0.0, seconds)


def _provider_retry_after_seconds(headers: Any) -> float | None:
    retry_after = _retry_after_seconds(headers)
    if retry_after is not None:
        return retry_after
    reset = _header_value(dict(headers), "x-ratelimit-reset")
    if not reset:
        return None
    try:
        reset_epoch = float(reset)
    except ValueError:
        return None
    return max(0.0, reset_epoch - time.time())


def _provider_rate_limited_response(provider: str, response: httpx.Response) -> bool:
    if provider != "github" or response.status_code != 403:
        return False
    remaining = _header_value(response.headers, "x-ratelimit-remaining")
    if remaining == "0":
        return True
    return "rate limit" in response.text.lower()


def _counts_against_live_api_circuit(error: Exception) -> bool:
    if isinstance(error, ToolExecutionError):
        if error.circuit_breaker_failure is not None:
            return error.circuit_breaker_failure
        return error.kind == ToolErrorKind.RETRYABLE
    return True


def _page_limit(requested: int | None, default: int, *, field: str = "max_pages") -> int:
    value = default if requested is None else requested
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must be a positive integer",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return value


def _raise_pagination_truncated(provider: str, page_limit: int, signal: str) -> None:
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        f"{provider} pagination exceeded configured page limit {page_limit} while {signal} indicated more results; refusing to return truncated evidence",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _get_nested(data: dict[str, Any], path: tuple[str, ...]) -> str | None:
    current: Any = data
    for item in path:
        if not isinstance(current, dict):
            return None
        current = current.get(item)
    return current if isinstance(current, str) and current else None


def _set_nested(data: dict[str, Any], path: tuple[str, ...], value: str) -> None:
    current = data
    for item in path[:-1]:
        current = current.setdefault(item, {})
    current[path[-1]] = value


def _cursor_page_size(body: dict[str, Any], provider: str) -> int | None:
    page = body.get("page")
    if page is None:
        return None
    if not isinstance(page, dict):
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"{provider} request field 'page' must be an object",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return _optional_int(page.get("limit"), provider, "page.limit")


def _slug_channel(name: str) -> str:
    slug = re.sub(r"[^a-z0-9-]+", "-", name.lower()).strip("-")
    return slug[:80] or "sentinel-incident"


def _require_slack_fields(
    method: str,
    data: dict[str, Any],
    fields: tuple[str, ...],
    *,
    expected_channel: str | None = None,
    expected_post_at: int | None = None,
    expected_text: str | None = None,
) -> None:
    missing = [field for field in fields if not data.get(field)]
    mismatched = []
    if expected_channel is not None and data.get("channel") and data.get("channel") != expected_channel:
        mismatched.append(f"channel={data.get('channel')}")
    if expected_post_at is not None and data.get("post_at") and str(data.get("post_at")) != str(expected_post_at):
        mismatched.append(f"post_at={data.get('post_at')}")
    if expected_text is not None:
        message = data.get("message")
        if not isinstance(message, dict):
            missing.append("message")
        else:
            confirmed_text = message.get("text")
            if not isinstance(confirmed_text, str) or not confirmed_text:
                missing.append("message.text")
            elif confirmed_text != expected_text:
                mismatched.append("message.text")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Slack {method} response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_discord_message_confirmation(data: dict[str, Any]) -> None:
    message_id = data.get("id")
    if isinstance(message_id, str) and message_id.strip():
        return
    raise ToolExecutionError(
        ToolErrorKind.MALFORMED_OUTPUT,
        "discord webhook response missing confirmation field(s): id",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _require_slack_channel_items(items: list[Any]) -> list[dict[str, Any]]:
    channels = _require_object_items(items, "slack", "channels")
    for index, channel in enumerate(channels):
        missing = []
        if not channel.get("id"):
            missing.append(f"channels[{index}].id")
        if not isinstance(channel.get("name"), str) or not channel.get("name"):
            missing.append(f"channels[{index}].name")
        if missing:
            raise ToolExecutionError(
                ToolErrorKind.MALFORMED_OUTPUT,
                f"Slack conversations.list response missing confirmation field(s): {', '.join(missing)}",
                retryable=False,
                circuit_breaker_failure=False,
            )
    return channels


def _require_slack_channel_confirmation(method: str, data: dict[str, Any], expected_name: str) -> None:
    channel = data.get("channel")
    missing = []
    mismatched = []
    if not isinstance(channel, dict):
        missing.append("channel")
    else:
        channel_id = channel.get("id")
        channel_name = channel.get("name")
        if not channel_id:
            missing.append("channel.id")
        if not channel_name:
            missing.append("channel.name")
        elif channel_name != expected_name:
            mismatched.append(f"channel.name={channel_name}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Slack {method} response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _require_slack_channel_info_confirmation(data: dict[str, Any], expected_channel: str) -> None:
    channel = data.get("channel")
    missing = []
    mismatched = []
    if not isinstance(channel, dict):
        missing.append("channel")
    else:
        channel_id = channel.get("id")
        if not channel_id:
            missing.append("channel.id")
        elif channel_id != expected_channel:
            mismatched.append(f"channel.id={channel_id}")
    if missing or mismatched:
        details = []
        if missing:
            details.append(f"missing confirmation field(s): {', '.join(missing)}")
        if mismatched:
            details.append(f"mismatched confirmation field(s): {', '.join(mismatched)}")
        raise ToolExecutionError(
            ToolErrorKind.MALFORMED_OUTPUT,
            f"Slack conversations.info response {'; '.join(details)}",
            retryable=False,
            circuit_breaker_failure=False,
        )


def _deployment_selector(deployment: dict[str, Any]) -> str:
    labels = (
        deployment.get("spec", {})
        .get("selector", {})
        .get("matchLabels", {})
    )
    if not isinstance(labels, dict) or not labels:
        name = deployment.get("metadata", {}).get("name", "unknown")
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"Deployment {name} does not expose matchLabels for ReplicaSet lookup",
            retryable=False,
        )
    parts = []
    for key, value in sorted(labels.items()):
        safe_key = _required_kubernetes_label_selector_text(
            key,
            "Kubernetes deployment selector label key",
        )
        safe_value = _required_kubernetes_label_selector_text(
            value,
            f"Kubernetes deployment selector label value for {safe_key}",
        )
        parts.append(f"{safe_key}={safe_value}")
    return ",".join(parts)


def _replica_sets_owned_by(deployment: dict[str, Any], replica_sets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    metadata = deployment.get("metadata")
    deployment_name = metadata.get("name") if isinstance(metadata, dict) else None
    deployment_uid = metadata.get("uid") if isinstance(metadata, dict) else None
    if not isinstance(deployment_name, str) or not deployment_name:
        return []
    owned = []
    for replica_set in replica_sets:
        rs_metadata = replica_set.get("metadata")
        owner_refs = rs_metadata.get("ownerReferences") if isinstance(rs_metadata, dict) else None
        if not isinstance(owner_refs, list):
            continue
        for owner in owner_refs:
            if not isinstance(owner, dict):
                continue
            if owner.get("kind") != "Deployment" or owner.get("name") != deployment_name:
                continue
            if owner.get("controller") is not True:
                continue
            if deployment_uid and owner.get("uid") != deployment_uid:
                continue
            owned.append(replica_set)
            break
    return owned


def _required_kubernetes_label_selector_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} must be a non-empty Kubernetes label selector component",
            retryable=False,
            circuit_breaker_failure=False,
        )
    text = value.strip()
    if any(item in text for item in (",", "=", "\n", "\r", "\t", " ")):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{field} contains invalid selector characters",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return text


def _replica_set_revisions(replica_sets: list[dict[str, Any]]) -> list[int]:
    revisions: set[int] = set()
    for replica_set in replica_sets:
        raw = (
            replica_set.get("metadata", {})
            .get("annotations", {})
            .get("deployment.kubernetes.io/revision")
        )
        if raw is None:
            continue
        try:
            revisions.add(int(raw))
        except (TypeError, ValueError):
            continue
    return sorted(revisions)


def _created_within(item: dict[str, Any], *, since: str | None, until: str | None) -> bool:
    created = _parse_datetime(item.get("created_at") or item.get("updated_at"))
    if not created:
        return True
    if since:
        since_at = _parse_datetime(since)
        if since_at and created < since_at:
            return False
    if until:
        until_at = _parse_datetime(until)
        if until_at and created > until_at:
            return False
    return True


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
