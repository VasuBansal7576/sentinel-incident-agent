from __future__ import annotations

import base64
from datetime import UTC, datetime
import time
import re
from typing import Any, Callable

from opentelemetry import trace

from sentinel.circuit_breaker import CircuitOpenError
from sentinel.config import SentinelSettings
from sentinel.errors import ToolAccessDenied, ToolErrorKind, ToolExecutionError, redact_sensitive_text
from sentinel.live_clients import (
    LiveProviderClients,
    datadog_point_has_finite_numeric_value,
    prometheus_result_has_finite_numeric_value,
)
from sentinel.models import Evidence, PermissionClass, ToolContract, ToolResult
from sentinel.slow_query import create_orders_user_id_index, run_slow_query
from sentinel.tools import ToolExecutionContext, ToolFactory, ToolRegistry, build_tool_contracts

LiveHandler = Callable[["LiveToolRouter", dict[str, Any]], dict[str, Any]]
MAX_RETRY_AFTER_SECONDS = 30.0


class RealTool:
    def __init__(self, contract: ToolContract, router: "LiveToolRouter", *, max_attempts: int = 3):
        self.contract = contract
        self.router = router
        self.max_attempts = max_attempts
        self.tracer = trace.get_tracer("sentinel.real_tools")

    def execute(self, payload: dict[str, Any], context: ToolExecutionContext) -> ToolResult:
        if self.contract.permission == PermissionClass.HUMAN_APPROVED_REMEDIATION and not context.approved:
            raise ToolAccessDenied(f"{self.contract.name} requires human approval")

        started = time.perf_counter()
        last_error: Exception | None = None
        attempts_made = 0
        with self.tracer.start_as_current_span(self.contract.name) as span:
            span.set_attribute("tool.name", self.contract.name)
            span.set_attribute("tool.implementation", "live")
            for attempt in range(1, self.max_attempts + 1):
                attempts_made = attempt
                try:
                    data = self.router.invoke(self.contract.name, payload)
                    evidence = _evidence_from_live_result(self.contract.name, payload, data)
                    span.set_attribute("tool.success", True)
                    return ToolResult(
                        tool_name=self.contract.name,
                        success=True,
                        data=data,
                        evidence=evidence,
                        duration_ms=(time.perf_counter() - started) * 1000,
                        attempt_count=attempt,
                    )
                except ToolExecutionError as error:
                    last_error = error
                    if not error.retryable or attempt == self.max_attempts:
                        break
                    time.sleep(_retry_delay_seconds(error, attempt))
                except CircuitOpenError as error:
                    last_error = error
                    break
                except RuntimeError as error:
                    last_error = error
                    break
                except Exception as error:
                    last_error = error
                    break

            span.set_attribute("tool.success", False)
            return ToolResult(
                tool_name=self.contract.name,
                success=False,
                data={},
                error_kind=_live_failure_kind(last_error).value,
                error_message=(
                    redact_sensitive_text(last_error, max_length=500)
                    if last_error
                    else "unknown live tool failure"
                ),
                duration_ms=(time.perf_counter() - started) * 1000,
                attempt_count=attempts_made or self.max_attempts,
            )


class LiveToolFactory(ToolFactory):
    """Factory for live API-backed tool adapters."""

    def __init__(self, clients: LiveProviderClients):
        self.clients = clients

    @classmethod
    def from_settings(cls, settings: SentinelSettings) -> "LiveToolFactory":
        return cls(LiveProviderClients.from_settings(settings))

    def build_registry(self) -> ToolRegistry:
        contracts = build_tool_contracts()
        _require_live_handler_coverage(contracts)
        router = LiveToolRouter(self.clients)
        tools = {contract.name: RealTool(contract, router) for contract in contracts}
        return ToolRegistry(contracts, tools)


def _live_failure_kind(error: Exception | None) -> ToolErrorKind:
    if isinstance(error, ToolExecutionError):
        return error.kind
    if isinstance(error, CircuitOpenError):
        return ToolErrorKind.RETRYABLE
    return ToolErrorKind.PERMANENT


def _require_live_handler_coverage(contracts: list[ToolContract]) -> None:
    contract_names = {contract.name for contract in contracts}
    handler_names = set(LIVE_TOOL_HANDLERS)
    missing = sorted(contract_names - handler_names)
    extra = sorted(handler_names - contract_names)
    if missing or extra:
        details = []
        if missing:
            details.append(f"missing live handler(s): {', '.join(missing)}")
        if extra:
            details.append(f"unregistered live handler(s): {', '.join(extra)}")
        raise RuntimeError(f"Live tool registry is inconsistent with tool contracts: {'; '.join(details)}")


class LiveToolRouter:
    def __init__(self, clients: LiveProviderClients):
        self.clients = clients

    def invoke(self, tool_name: str, payload: dict[str, Any]) -> dict[str, Any]:
        handler = LIVE_TOOL_HANDLERS.get(tool_name)
        if handler is None:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"No live implementation registered for {tool_name}",
                retryable=False,
            )
        result = handler(self, payload)
        result.update({"implementation": f"live::{tool_name}", "stub": False, "tool": tool_name})
        return result

    def service(self, payload: dict[str, Any]) -> str:
        return payload.get("service") or payload.get("affected_service") or "unknown-service"

    def required_service(self, payload: dict[str, Any], action: str) -> str:
        return _required_service(payload, action)

    def time_window(self, payload: dict[str, Any]) -> str:
        return payload.get("time_window", "now-30m")

    def time_window_end(self, payload: dict[str, Any]) -> str:
        return payload.get("time_window_end", "now")


def _required_mutation_service(payload: dict[str, Any], action: str) -> str:
    return _required_service(payload, action)


def _required_service(payload: dict[str, Any], action: str) -> str:
    service = payload.get("service") or payload.get("affected_service")
    if not isinstance(service, str) or not service.strip() or service.strip() == "unknown-service":
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit service or affected_service",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return service.strip()


def _required_replica_count(payload: dict[str, Any]) -> int:
    replicas = payload.get("replicas")
    if isinstance(replicas, bool):
        replicas = None
    if isinstance(replicas, int):
        count = replicas
    elif isinstance(replicas, str) and re.fullmatch(r"\d+", replicas.strip()):
        count = int(replicas.strip())
    else:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "infra.scale_replicas requires an explicit non-negative integer replicas value",
            retryable=False,
        )
    if count < 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "infra.scale_replicas requires an explicit non-negative integer replicas value",
            retryable=False,
        )
    return count


def _required_payload_string(payload: dict[str, Any], field: str, action: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit {field}",
            retryable=False,
    )
    return value.strip()


def _required_kubernetes_revision_target(payload: dict[str, Any], action: str) -> str:
    target = payload.get("target")
    if not isinstance(target, str) or not re.fullmatch(r"revision:\d+", target.strip()):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit Kubernetes rollback target revision:<positive integer>",
            retryable=False,
        )
    revision = target.strip().split(":", 1)[1]
    if int(revision) <= 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit Kubernetes rollback target revision:<positive integer>",
            retryable=False,
        )
    return target.strip()


def _required_path(payload: dict[str, Any], action: str) -> str:
    value = payload.get("path") or payload.get("file")
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit path or file",
            retryable=False,
        )
    return value.strip()


def _required_message_text(payload: dict[str, Any], action: str) -> str:
    value = payload.get("message") or payload.get("text")
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit message or text",
            retryable=False,
        )
    return value.strip()


def _required_body_text(payload: dict[str, Any], action: str) -> str:
    value = payload.get("body") or payload.get("content") or payload.get("message") or payload.get("text")
    if not isinstance(value, str) or not value.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit body, content, message, or text",
            retryable=False,
        )
    return value.strip()


def _required_epoch_seconds(payload: dict[str, Any], field: str, action: str) -> int:
    value = payload.get(field)
    if isinstance(value, bool):
        value = None
    if isinstance(value, int):
        seconds = value
    elif isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        seconds = int(value.strip())
    else:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit positive integer {field}",
            retryable=False,
        )
    if seconds <= 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires an explicit positive integer {field}",
            retryable=False,
        )
    return seconds


def _optional_positive_int(payload: dict[str, Any], field: str, action: str) -> int | None:
    if field not in payload or payload.get(field) is None:
        return None
    value = payload.get(field)
    if isinstance(value, bool):
        value = None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        parsed = int(value.strip())
    else:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires {field} to be a positive integer when provided",
            retryable=False,
        )
    if parsed <= 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires {field} to be a positive integer when provided",
            retryable=False,
        )
    return parsed


def _required_positive_int_value(value: Any, field: str, action: str) -> int:
    if isinstance(value, bool):
        value = None
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"\d+", value.strip()):
        parsed = int(value.strip())
    else:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires {field} to be a positive integer",
            retryable=False,
        )
    if parsed <= 0:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{action} requires {field} to be a positive integer",
            retryable=False,
        )
    return parsed


def _retry_delay_seconds(error: ToolExecutionError, attempt: int) -> float:
    if error.retry_after_seconds is not None:
        return min(max(0.0, error.retry_after_seconds), MAX_RETRY_AFTER_SECONDS)
    return 0.25 * (2 ** (attempt - 1))


def _dd_query(service: str, metric: str) -> str:
    return f"avg:{metric}{{service:{service}}}"


def _prometheus_query(service: str, metric: str) -> str:
    label = _prometheus_label_value(service)
    pod_prefix = _prometheus_regex_prefix_value(service)
    queries = {
        "trace.http.request.duration": (
            f"sum(rate(http_request_duration_seconds_sum{{service={label}}}[5m])) "
            f"/ clamp_min(sum(rate(http_request_duration_seconds_count{{service={label}}}[5m])), 1)"
        ),
        "trace.http.request.errors": f"sum(rate(http_requests_total{{service={label},status=~\"5..\"}}[5m]))",
        "queue.depth": f"queue_depth{{service={label}}}",
        "network.tcp.rtt": f"avg(network_tcp_rtt_seconds{{service={label}}})",
        "synthetics.browser.uptime": f"avg_over_time(up{{service={label}}}[5m])",
        "kubernetes.cpu.usage.total": f"sum(rate(container_cpu_usage_seconds_total{{pod=~{pod_prefix}}}[5m]))",
        "kubernetes.memory.usage": f"sum(container_memory_working_set_bytes{{pod=~{pod_prefix}}})",
    }
    return queries.get(metric, f"{metric}{{service={label}}}")


def _prometheus_label_value(value: str) -> str:
    return json_escape(value)


def _prometheus_regex_prefix_value(value: str) -> str:
    pattern = re.sub(r"([\\.^$|?*+()[\]{}])", r"\\\1", value) + ".*"
    return json_escape(pattern)


def json_escape(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _loki_selector(service: str, *terms: str) -> str:
    selector = f'{{service={json_escape(service)}}}'
    for term in terms:
        selector += f" |= {json_escape(term)}"
    return selector


def _datadog_observability_fallback_configured(router: LiveToolRouter) -> bool:
    datadog = getattr(router.clients, "datadog", None)
    if datadog is None:
        return False
    api = getattr(datadog, "api", None)
    headers = getattr(api, "headers", None)
    if isinstance(headers, dict):
        return bool(headers.get("Authorization")) or bool(headers.get("DD-API-KEY") and headers.get("DD-APPLICATION-KEY"))
    return True


def _fallback_to_datadog(
    router: LiveToolRouter,
    primary_error: ToolExecutionError | CircuitOpenError,
    fallback: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    if _datadog_observability_fallback_configured(router):
        data = fallback()
        return {**data, "provider": "datadog"}
    raise primary_error


def _require_datadog_observability_fallback(router: LiveToolRouter, primary_provider: str, tool_name: str) -> None:
    if _datadog_observability_fallback_configured(router):
        return
    raise ToolExecutionError(
        ToolErrorKind.AUTHORIZATION,
        f"{tool_name} requires {primary_provider} or configured Datadog credentials",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _window_epoch(value: str | None) -> int | None:
    if not value:
        return None
    if value == "now":
        return int(time.time())
    relative = re.fullmatch(r"now-(\d+)([mhd])", value)
    if relative:
        amount = int(relative.group(1))
        unit = relative.group(2)
        seconds = amount * {"m": 60, "h": 3600, "d": 86400}[unit]
        return int(time.time()) - seconds
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return int(parsed.astimezone(UTC).timestamp())


def _window_iso(value: str | None) -> str | None:
    epoch = _window_epoch(value)
    if epoch is None:
        return None
    return datetime.fromtimestamp(epoch, UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _github_window_kwargs(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, str]:
    kwargs: dict[str, str] = {}
    since = _window_iso(router.time_window(payload))
    until = _window_iso(router.time_window_end(payload))
    if since:
        kwargs["since"] = since
    if until:
        kwargs["until"] = until
    return kwargs


def _logs(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = router.required_service(payload, "observe.fetch_service_logs")
    if getattr(router.clients, "loki", None) is not None:
        try:
            data = router.clients.loki.query_range(
                _loki_selector(service),
                start_epoch=_window_epoch(router.time_window(payload)),
                end_epoch=_window_epoch(router.time_window_end(payload)),
            )
            return {"provider": "loki", "service": service, **data}
        except (ToolExecutionError, CircuitOpenError) as exc:
            return _fallback_to_datadog(router, exc, lambda: _datadog_logs(router, service, payload))
    _require_datadog_observability_fallback(router, "Loki", "observe.fetch_service_logs")
    return _datadog_logs(router, service, payload)


def _metric(metric: str) -> LiveHandler:
    def handler(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
        service = router.required_service(payload, "observability metric query")
        query = payload.get("prometheus_query")
        metric_name = str(payload.get("metric") or metric)
        if query is not None and (not isinstance(query, str) or not query.strip()):
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "observability metric query requires prometheus_query to be a non-empty string when provided",
                retryable=False,
                circuit_breaker_failure=False,
            )
        if getattr(router.clients, "prometheus", None) is not None:
            try:
                data = router.clients.prometheus.query_range(
                    query.strip() if isinstance(query, str) else _prometheus_query(service, metric_name),
                    start_epoch=_window_epoch(router.time_window(payload)),
                    end_epoch=_window_epoch(router.time_window_end(payload)),
                )
                return {"metric": metric_name, "service": service, "provider": "prometheus", "prometheus": data}
            except (ToolExecutionError, CircuitOpenError) as exc:
                return _fallback_to_datadog(router, exc, lambda: _datadog_metric(router, service, metric_name, payload))
        _require_datadog_observability_fallback(router, "Prometheus", "observability metric query")
        return _datadog_metric(router, service, metric_name, payload)

    return handler


def _datadog_logs(
    router: LiveToolRouter,
    service: str,
    payload: dict[str, Any],
    query: str | None = None,
) -> dict[str, Any]:
    data = router.clients.datadog.search_logs(
        query or f"service:{service}",
        start=router.time_window(payload),
        end=router.time_window_end(payload),
    )
    return {**data, "provider": "datadog"}


def _datadog_metric(router: LiveToolRouter, service: str, metric: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = router.clients.datadog.query_metric(
        _dd_query(service, metric),
        start_epoch=_window_epoch(router.time_window(payload)),
        end_epoch=_window_epoch(router.time_window_end(payload)),
    )
    return {"metric": metric, "service": service, "provider": "datadog", "datadog": data}


def _spans(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = router.required_service(payload, "observe.get_distributed_traces")
    if getattr(router.clients, "loki", None) is not None:
        try:
            data = router.clients.loki.query_range(
                _loki_selector(service, "trace"),
                start_epoch=_window_epoch(router.time_window(payload)),
                end_epoch=_window_epoch(router.time_window_end(payload)),
            )
            return {
                "provider": "loki",
                "service": service,
                **data,
                "spans": data.get("events", []),
                "query": data.get("query"),
            }
        except (ToolExecutionError, CircuitOpenError) as exc:
            return _fallback_to_datadog(router, exc, lambda: _datadog_spans(router, service, payload))
    _require_datadog_observability_fallback(router, "Loki", "observe.get_distributed_traces")
    return _datadog_spans(router, service, payload)


def _datadog_spans(router: LiveToolRouter, service: str, payload: dict[str, Any]) -> dict[str, Any]:
    data = router.clients.datadog.search_spans(
        f"service:{service}",
        start=router.time_window(payload),
        end=router.time_window_end(payload),
    )
    return {**data, "provider": "datadog"}


def _monitors(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    query = payload.get("query")
    if getattr(router.clients, "prometheus", None) is not None:
        try:
            return {"provider": "prometheus", **router.clients.prometheus.alerting_rules()}
        except (ToolExecutionError, CircuitOpenError) as exc:
            return _fallback_to_datadog(router, exc, lambda: _datadog_monitors(router, query, payload))
    _require_datadog_observability_fallback(router, "Prometheus", "observe.fetch_alerting_rules")
    return _datadog_monitors(router, query, payload)


def _datadog_monitors(router: LiveToolRouter, query: Any, payload: dict[str, Any]) -> dict[str, Any]:
    data = router.clients.datadog.list_monitors(
        query if query else router.required_service(payload, "observe.fetch_alerting_rules")
    )
    return {**data, "provider": "datadog"}


def _dashboard(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    if getattr(router.clients, "prometheus", None) is not None:
        dashboard_id = payload.get("dashboard_id") or "prometheus-targets"
        try:
            return {
                "provider": "prometheus",
                "dashboard_id": dashboard_id,
                **router.clients.prometheus.targets(),
            }
        except (ToolExecutionError, CircuitOpenError) as exc:
            return _fallback_to_datadog(router, exc, lambda: _datadog_dashboard(router, payload))
    _require_datadog_observability_fallback(router, "Prometheus", "observe.fetch_dashboard_snapshot")
    return _datadog_dashboard(router, payload)


def _datadog_dashboard(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    dashboard_id = _required_payload_string(
        payload,
        "dashboard_id",
        "observe.read_dashboard_snapshot",
    )
    data = router.clients.datadog.get_dashboard(dashboard_id)
    return {**data, "provider": "datadog"}


def _github_commits(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "commits": router.clients.github.commits(
            path=payload.get("path"),
            **_github_window_kwargs(router, payload),
        )
    }


def _github_pr(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    number = _resolve_pull_request_number(router, payload)
    return {
        "pull_request": router.clients.github.pull_request(number),
        "files": router.clients.github.pull_request_files(number),
    }


def _github_deployments(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    return _github_deployment_evidence(router, payload)


def _rollback_targets(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = router.required_service(payload, "repo.get_rollback_targets")
    rollout = router.clients.kubernetes.rollout_revisions(service)
    target = rollout.get("previous_revision")
    deployment_evidence = _github_deployment_evidence(router, payload)
    return {
        "service": service,
        "target": target,
        "target_source": "kubernetes_rollout_revision" if target else None,
        "rollout": rollout,
        **deployment_evidence,
    }


def _github_deployment_evidence(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    if hasattr(router.clients.github, "deployment_evidence"):
        return router.clients.github.deployment_evidence(
            allow_truncated=True,
            status_limit=3,
            **_github_window_kwargs(router, payload),
        )
    return {
        "deployments": router.clients.github.deployments(**_github_window_kwargs(router, payload)),
        "pagination": {
            "provider": "github",
            "resource": "deployments",
            "truncated": False,
        },
    }


def _resolve_pull_request_number(router: LiveToolRouter, payload: dict[str, Any]) -> int:
    explicit = payload.get("pull_request") or payload.get("pr")
    if explicit is not None and explicit != "":
        return _required_positive_int_value(explicit, "pull_request or pr", "repo.diff_pull_request")

    commits = router.clients.github.commits(per_page=10, **_github_window_kwargs(router, payload))
    commit_shas = _commit_shas(commits)
    for number in _pull_request_numbers_from_commits(commits):
        try:
            pull_request = router.clients.github.pull_request(number)
        except ToolExecutionError as exc:
            if _is_missing_github_resource(exc):
                continue
            raise
        if _pull_request_matches_incident_commits(router, pull_request, commit_shas):
            return number

    recent = router.clients.github.pull_requests(state="closed", per_page=20)
    for pull_request in recent:
        if _pull_request_matches_incident_commits(router, pull_request, commit_shas):
            return _required_positive_int_value(
                pull_request.get("number"),
                "pull_request.number",
                "repo.diff_pull_request",
            )

    raise ToolExecutionError(
        ToolErrorKind.PERMANENT,
        "No incident-window pull request could be inferred from live GitHub data",
        retryable=False,
    )


def _pull_request_numbers_from_commits(commits: list[dict[str, Any]]) -> list[int]:
    numbers: list[int] = []
    for commit in commits:
        message = str((commit.get("commit") or {}).get("message") or "")
        for match in re.finditer(r"#(\d+)", message):
            number = int(match.group(1))
            if number > 0 and number not in numbers:
                numbers.append(number)
    return numbers


def _commit_shas(commits: list[dict[str, Any]]) -> set[str]:
    shas = set()
    for commit in commits:
        sha = commit.get("sha")
        if isinstance(sha, str) and sha.strip():
            shas.add(sha.strip())
    return shas


def _pull_request_matches_commit(pull_request: dict[str, Any], commit_shas: set[str]) -> bool:
    if not commit_shas:
        return False
    candidates = [
        pull_request.get("merge_commit_sha"),
        _nested_string(pull_request, "head", "sha"),
        _nested_string(pull_request, "base", "sha"),
    ]
    return any(isinstance(candidate, str) and candidate.strip() in commit_shas for candidate in candidates)


def _pull_request_matches_incident_commits(
    router: LiveToolRouter,
    pull_request: dict[str, Any],
    commit_shas: set[str],
) -> bool:
    if _pull_request_matches_commit(pull_request, commit_shas):
        return True
    number = pull_request.get("number")
    if not isinstance(number, int) or number <= 0:
        return False
    commits = router.clients.github.pull_request_commits(number)
    return bool(_commit_shas(commits) & commit_shas)


def _nested_string(data: dict[str, Any], *path: str) -> str | None:
    current: Any = data
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current if isinstance(current, str) else None


def _github_status(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    ref = payload.get("ref") or payload.get("sha")
    if ref is None or ref == "":
        ref = _infer_incident_commit_sha(router, payload, "repo.read_ci_pipeline_status and repo.fetch_test_results")
        ref_source = "incident_window_commit"
    else:
        ref_source = "payload"
    ref = _required_payload_string({"ref": ref}, "ref", "GitHub status lookup")
    return {
        "ref": ref,
        "ref_source": ref_source,
        "status": router.clients.github.statuses(ref),
        "check_runs": router.clients.github.check_runs(ref),
    }


def _infer_incident_commit_sha(router: LiveToolRouter, payload: dict[str, Any], action: str) -> str:
    commits = router.clients.github.commits(per_page=1, **_github_window_kwargs(router, payload))
    for commit in commits:
        sha = commit.get("sha")
        if isinstance(sha, str) and sha.strip():
            return sha.strip()
    raise ToolExecutionError(
        ToolErrorKind.PERMANENT,
        f"{action} requires an explicit ref or sha, or at least one commit in the incident window",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _github_contents(paths: str | list[str]) -> LiveHandler:
    candidates = [paths] if isinstance(paths, str) else list(paths)

    def handler(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
        explicit_path = payload.get("path") or payload.get("file")
        ref = payload.get("ref")
        if explicit_path:
            return {
                "path": explicit_path,
                "content": router.clients.github.contents(explicit_path, ref=ref),
            }
        return _github_first_available_content(router, candidates, ref=ref)

    return handler


def _github_optional_contents(paths: list[str], *, absent_kind: str) -> LiveHandler:
    candidates = list(paths)

    def handler(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
        explicit_path = payload.get("path") or payload.get("file")
        ref = payload.get("ref")
        if explicit_path:
            return {
                "path": explicit_path,
                "content": router.clients.github.contents(explicit_path, ref=ref),
                "configured": True,
            }
        try:
            result = _github_first_available_content(router, candidates, ref=ref)
        except ToolExecutionError as exc:
            if not _is_missing_github_content(exc):
                raise
            return {
                "provider": "github",
                "path": None,
                "content": None,
                "configured": False,
                "absent_kind": absent_kind,
                "paths_checked": candidates,
            }
        result["configured"] = True
        return result

    return handler


def _github_first_available_content(
    router: LiveToolRouter,
    candidate_paths: list[str],
    *,
    ref: str | None = None,
) -> dict[str, Any]:
    last_missing: ToolExecutionError | None = None
    for path in candidate_paths:
        try:
            return {
                "path": path,
                "content": router.clients.github.contents(path, ref=ref),
            }
        except ToolExecutionError as exc:
            if not _is_missing_github_content(exc):
                raise
            last_missing = exc
    raise ToolExecutionError(
        ToolErrorKind.PERMANENT,
        f"None of the candidate GitHub content paths existed: {', '.join(candidate_paths)}",
        retryable=False,
        circuit_breaker_failure=False,
    ) from last_missing


def _is_missing_github_content(error: ToolExecutionError) -> bool:
    return _is_missing_github_resource(error)


def _is_missing_github_resource(error: ToolExecutionError) -> bool:
    if error.kind != ToolErrorKind.PERMANENT:
        return False
    message = str(error).lower()
    return "404" in message or "not found" in message or "none of the candidate github content paths existed" in message


def _github_blame(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    path = _optional_path(payload)
    path_source = "payload"
    if path is None:
        path = _infer_pull_request_file_path(router, payload, "repo.blame_file_line")
        path_source = "pull_request_files"
    line = _optional_positive_int(payload, "line", "repo.blame_file_line")
    commits = router.clients.github.commits(
        path=path,
        per_page=5,
        **_github_window_kwargs(router, payload),
    )
    return {
        "path": path,
        "line": line,
        "commits": commits,
        "blame_source": "github_commits_for_path",
        "path_source": path_source,
    }


def _optional_path(payload: dict[str, Any]) -> str | None:
    value = payload.get("path") or payload.get("file")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _infer_pull_request_file_path(router: LiveToolRouter, payload: dict[str, Any], action: str) -> str:
    number = _resolve_pull_request_number(router, payload)
    files = router.clients.github.pull_request_files(number)
    for item in files:
        filename = item.get("filename") or item.get("path")
        if isinstance(filename, str) and filename.strip():
            return filename.strip()
    raise ToolExecutionError(
        ToolErrorKind.PERMANENT,
        f"{action} requires an explicit path or file, or at least one file in the correlated pull request",
        retryable=False,
        circuit_breaker_failure=False,
    )


def _github_issue(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    title = _required_payload_string(payload, "title", "comms.create_jira_ticket")
    body = _required_body_text(payload, "comms.create_jira_ticket")
    labels = _github_issue_labels(payload.get("labels") or ["sentinel"])
    if not _github_write_enabled(router):
        return {
            "provider": "github",
            "action": "create_issue",
            "write_enabled": False,
            "write_skipped": True,
            "reason": "SENTINEL_GITHUB_WRITE_ENABLED is not true",
            "title": title,
            "labels": labels,
        }
    return router.clients.github.create_issue(title, body, labels=labels)


def _k8s_pods(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    return router.clients.kubernetes.list_pods(
        router.required_service(payload, "observe.check_pod_health")
    )


def _k8s_deployment(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    return router.clients.kubernetes.deployment(
        router.required_service(payload, "Kubernetes deployment read")
    )


def _k8s_rollback(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = _required_mutation_service(payload, "infra.rollback_deployment")
    target = _required_kubernetes_revision_target(payload, "infra.rollback_deployment")
    return router.clients.kubernetes.rollout_undo(service, target=target)


def _sqlite_add_database_index(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = _required_mutation_service(payload, "infra.add_database_index")
    table = payload.get("table") or "orders"
    column = payload.get("column") or "user_id"
    if table != "orders" or column != "user_id":
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "infra.add_database_index currently supports only orders.user_id for the real slow-query incident",
            retryable=False,
            circuit_breaker_failure=False,
        )
    result = create_orders_user_id_index()
    verification_query = run_slow_query()
    return {
        **result,
        "provider": "sqlite",
        "service": service,
        "table": table,
        "column": column,
        "verification_query": {
            "duration_ms": round(verification_query.duration_seconds * 1000, 3),
            "index_present": verification_query.index_present,
            "query_plan": verification_query.query_plan,
        },
    }


def _k8s_restart(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = _required_mutation_service(payload, "Kubernetes rollout restart")
    return router.clients.kubernetes.rollout_restart(service)


def _k8s_scale(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = _required_mutation_service(payload, "infra.scale_replicas")
    return router.clients.kubernetes.scale(service, _required_replica_count(payload))


def _k8s_patch(action: str) -> LiveHandler:
    def handler(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
        service = _required_mutation_service(payload, action)
        patch = payload.get("patch")
        if not isinstance(patch, dict) or not patch:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"{action} requires an explicit non-empty Kubernetes patch payload",
                retryable=False,
            )
        return router.clients.kubernetes.patch_deployment(service, patch)

    return handler


def _k8s_job(name: str) -> LiveHandler:
    def handler(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
        service = _required_mutation_service(payload, name)
        command = payload.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                f"{name} requires an explicit Kubernetes job command list",
                retryable=False,
            )
        return router.clients.kubernetes.create_job(
            payload.get("job_name") or f"sentinel-{name}-{service}".replace("_", "-"),
            command,
        )

    return handler


def _k8s_drain(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    node = payload.get("node") or payload.get("node_name")
    if not isinstance(node, str) or not node.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "infra.drain_node requires an explicit Kubernetes node or node_name",
            retryable=False,
        )
    return router.clients.kubernetes.drain_node(node.strip())


def _slack_post(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    message = _required_message_text(payload, "Slack or Discord post")
    slack_enabled = bool(getattr(getattr(router.clients, "slack", None), "enabled", True))
    if slack_enabled:
        data = router.clients.slack.post_message(message, channel=payload.get("channel"))
        return {"provider": "slack", **data}
    return post_to_discord(router, payload)


def post_to_discord(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    discord = getattr(router.clients, "discord", None)
    if discord is None:
        raise ToolExecutionError(
            ToolErrorKind.AUTHORIZATION,
            "SLACK_BOT_TOKEN is missing and DISCORD_WEBHOOK_URL is not configured",
            retryable=False,
            circuit_breaker_failure=False,
        )
    return discord.post_to_discord(_required_message_text(payload, "Discord post"))


def _external_status_page(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    raise ToolExecutionError(
        ToolErrorKind.PERMANENT,
        "comms.update_status_page is out of scope in SENTINEL v1; direct external customer communication remains human-owned",
        retryable=False,
    )


def _unsupported_v1_live_action(tool_name: str, reason: str) -> LiveHandler:
    def handler(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"{tool_name} is out of scope in SENTINEL v1; {reason}",
            retryable=False,
            circuit_breaker_failure=False,
        )

    return handler


def _slack_channel(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    slack_enabled = bool(getattr(getattr(router.clients, "slack", None), "enabled", True))
    if not slack_enabled:
        channel_name = _required_payload_string(payload, "channel_name", "comms.create_incident_channel")
        if getattr(router.clients, "discord", None) is None:
            raise ToolExecutionError(
                ToolErrorKind.AUTHORIZATION,
                "SLACK_BOT_TOKEN is missing and DISCORD_WEBHOOK_URL is not configured",
                retryable=False,
                circuit_breaker_failure=False,
            )
        return {
            "provider": "discord",
            "channel": {"id": "discord-webhook", "name": channel_name},
            "created": False,
            "reused": True,
        }
    return router.clients.slack.create_channel(
        _required_payload_string(payload, "channel_name", "comms.create_incident_channel")
    )


def _pagerduty_incident(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    if not bool(getattr(getattr(router.clients, "pagerduty", None), "enabled", True)):
        incident_id = payload.get("incident_id")
        return {
            "provider": "generic_webhook",
            "incident": {"id": incident_id, "source": "generic_webhook", "status": "triggered"},
        }
    incident_id = payload.get("incident_id")
    if incident_id:
        return router.clients.pagerduty.get_incident(incident_id)
    return {"incidents": router.clients.pagerduty.list_incidents(query=payload.get("query"))}


def _pagerduty_oncall(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    if not bool(getattr(getattr(router.clients, "pagerduty", None), "enabled", True)):
        generic = getattr(router.clients, "generic_alerts", None)
        if generic is None:
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "PAGERDUTY_API_KEY is missing and generic alert fallback is not configured",
                retryable=False,
                circuit_breaker_failure=False,
            )
        return generic.on_call_context(payload.get("incident_id"))
    incident_id = payload.get("incident_id")
    if incident_id:
        incident = router.clients.pagerduty.get_incident(incident_id).get("incident")
        policy_ids = _pagerduty_escalation_policy_ids(incident)
        if not policy_ids:
            return {
                "incident": incident,
                "oncalls": [],
                "escalation_policy_ids": [],
                "oncall_scope": "unconfirmed_incident_escalation_policy",
            }
        return {
            "incident": incident,
            "oncalls": router.clients.pagerduty.on_calls(escalation_policy_ids=policy_ids),
            "escalation_policy_ids": policy_ids,
            "oncall_scope": "incident_escalation_policy",
        }
    return {
        "oncalls": router.clients.pagerduty.on_calls(),
        "escalation_policy_ids": [],
        "oncall_scope": "account",
    }


def _pagerduty_escalation_policy_ids(incident: Any) -> list[str]:
    if not isinstance(incident, dict):
        return []
    candidates = [
        incident.get("escalation_policy_id"),
        _nested_string(incident, "escalation_policy", "id"),
        _nested_string(incident, "service", "escalation_policy", "id"),
    ]
    policy_ids: list[str] = []
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.strip() and candidate.strip() not in policy_ids:
            policy_ids.append(candidate.strip())
    return policy_ids


def _pagerduty_close(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    incident_id = _required_payload_string(payload, "incident_id", "comms.close_incident")
    return router.clients.pagerduty.update_incident_status(incident_id, "resolved", payload.get("requester_email"))


def _slack_schedule(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    return router.clients.slack.schedule_message(
        _required_message_text(payload, "Slack scheduled message"),
        _required_epoch_seconds(payload, "post_at", "Slack scheduled message"),
        channel=payload.get("channel"),
    )


def _github_runbook(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    path = payload.get("path") or "RUNBOOK.md"
    note = _required_body_text(payload, "comms.update_runbook")
    if not _github_write_enabled(router):
        return {
            "provider": "github",
            "action": "update_runbook",
            "write_enabled": False,
            "write_skipped": True,
            "reason": "SENTINEL_GITHUB_WRITE_ENABLED is not true",
            "path": path,
        }
    existing = router.clients.github.contents(path)
    sha = existing.get("sha")
    if not isinstance(sha, str) or not sha:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"GitHub runbook {path} did not include a file sha; refusing to overwrite",
            retryable=False,
        )
    current = _github_file_text(existing, path)
    body = _append_runbook_note(current, note)
    return router.clients.github.update_file(path, "SENTINEL runbook update", body, sha=sha)


def _github_write_enabled(router: LiveToolRouter) -> bool:
    return getattr(router.clients.github, "write_enabled", True) is True


def _github_issue_labels(value: Any) -> list[str]:
    if not isinstance(value, list):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "GitHub issue labels must be a list of non-empty strings",
            retryable=False,
            circuit_breaker_failure=False,
        )
    labels = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ToolExecutionError(
                ToolErrorKind.PERMANENT,
                "GitHub issue labels must be a list of non-empty strings",
                retryable=False,
                circuit_breaker_failure=False,
            )
        labels.append(item.strip())
    return labels


def _github_file_text(file_data: dict[str, Any], path: str) -> str:
    if file_data.get("type") not in (None, "file"):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"GitHub runbook {path} is not a file; refusing to overwrite",
            retryable=False,
        )
    if file_data.get("encoding") != "base64" or not isinstance(file_data.get("content"), str):
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"GitHub runbook {path} did not include base64 file content; refusing to overwrite",
            retryable=False,
        )
    try:
        raw = base64.b64decode("".join(file_data["content"].split()), validate=True)
        return raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            f"GitHub runbook {path} content is not valid UTF-8 text; refusing to overwrite",
            retryable=False,
        ) from exc


def _append_runbook_note(current: str, note: str) -> str:
    clean_current = current.rstrip()
    clean_note = str(note).strip()
    if not clean_note:
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "Runbook update content must not be empty",
            retryable=False,
        )
    if not clean_current:
        return f"{clean_note}\n"
    return f"{clean_current}\n\n{clean_note}\n"


def _db_slow_queries(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = router.required_service(payload, "observe.check_db_slow_queries")
    datadog_query = f"service:{service} @db.statement:*"
    if getattr(router.clients, "loki", None) is not None:
        try:
            data = router.clients.loki.query_range(
                _loki_selector(service, "db"),
                start_epoch=_window_epoch(router.time_window(payload)),
                end_epoch=_window_epoch(router.time_window_end(payload)),
            )
            return {"provider": "loki", "service": service, **data}
        except (ToolExecutionError, CircuitOpenError) as exc:
            return _fallback_to_datadog(router, exc, lambda: _datadog_logs(router, service, payload, datadog_query))
    _require_datadog_observability_fallback(router, "Loki", "observe.check_db_slow_queries")
    return _datadog_logs(router, service, payload, datadog_query)


def _cdn_logs(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = router.required_service(payload, "observe.fetch_cdn_logs")
    datadog_query = f"source:cdn {service}"
    if getattr(router.clients, "loki", None) is not None:
        try:
            data = router.clients.loki.query_range(
                _loki_selector(service, "cdn"),
                start_epoch=_window_epoch(router.time_window(payload)),
                end_epoch=_window_epoch(router.time_window_end(payload)),
            )
            return {"provider": "loki", "service": service, **data}
        except (ToolExecutionError, CircuitOpenError) as exc:
            return _fallback_to_datadog(router, exc, lambda: _datadog_logs(router, service, payload, datadog_query))
    _require_datadog_observability_fallback(router, "Loki", "observe.fetch_cdn_logs")
    return _datadog_logs(router, service, payload, datadog_query)


def _memory_cpu_usage(router: LiveToolRouter, payload: dict[str, Any]) -> dict[str, Any]:
    service = router.required_service(payload, "observe.get_memory_cpu_usage")
    if getattr(router.clients, "prometheus", None) is not None:
        try:
            return {
                "provider": "prometheus",
                "service": service,
                "cpu": router.clients.prometheus.query_range(_prometheus_query(service, "kubernetes.cpu.usage.total")),
                "memory": router.clients.prometheus.query_range(_prometheus_query(service, "kubernetes.memory.usage")),
            }
        except (ToolExecutionError, CircuitOpenError) as exc:
            return _fallback_to_datadog(router, exc, lambda: _datadog_memory_cpu_usage(router, service))
    _require_datadog_observability_fallback(router, "Prometheus", "observe.get_memory_cpu_usage")
    return _datadog_memory_cpu_usage(router, service)


def _datadog_memory_cpu_usage(router: LiveToolRouter, service: str) -> dict[str, Any]:
    return {
        "provider": "datadog",
        "cpu": router.clients.datadog.query_metric(_dd_query(service, "kubernetes.cpu.usage.total")),
        "memory": router.clients.datadog.query_metric(_dd_query(service, "kubernetes.memory.usage")),
    }


LIVE_TOOL_HANDLERS: dict[str, LiveHandler] = {
    "observe.fetch_service_logs": _logs,
    "observe.query_metrics_range": _metric("trace.http.request.duration"),
    "observe.get_distributed_traces": _spans,
    "observe.check_pod_health": _k8s_pods,
    "observe.get_error_rate_timeseries": _metric("trace.http.request.errors"),
    "observe.fetch_apm_data": _spans,
    "observe.read_queue_depth": _metric("queue.depth"),
    "observe.check_db_slow_queries": _db_slow_queries,
    "observe.get_network_latency": _metric("network.tcp.rtt"),
    "observe.fetch_cdn_logs": _cdn_logs,
    "observe.read_flame_graph": _spans,
    "observe.check_uptime_history": _metric("synthetics.browser.uptime"),
    "observe.get_memory_cpu_usage": _memory_cpu_usage,
    "observe.fetch_alerting_rules": _monitors,
    "observe.read_dashboard_snapshot": _dashboard,
    "repo.get_recent_commits": _github_commits,
    "repo.diff_pull_request": _github_pr,
    "repo.get_deploy_history": _github_deployments,
    "repo.read_ci_pipeline_status": _github_status,
    "repo.fetch_test_results": _github_status,
    "repo.blame_file_line": _github_blame,
    "repo.get_rollback_targets": _rollback_targets,
    "repo.read_changelog": _github_contents([
        "CHANGELOG.md",
        "changelog.md",
        "CHANGES.md",
        "RELEASE_NOTES.md",
        "docs/CHANGELOG.md",
    ]),
    "repo.check_dependency_changes": _github_contents([
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "Pipfile.lock",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "Cargo.toml",
        "Gemfile.lock",
        "pom.xml",
        "build.gradle",
        "gradle.lockfile",
    ]),
    "repo.get_feature_flags": _github_optional_contents([
        "feature-flags.yml",
        "feature-flags.yaml",
        "config/feature-flags.yml",
        "config/feature-flags.yaml",
        "config/feature_flags.yml",
        "config/feature_flags.yaml",
        "flags.yml",
        "flags.yaml",
        ".launchdarkly.json",
    ], absent_kind="feature_flags_not_configured"),
    "repo.fetch_pr_metadata": _github_pr,
    "repo.get_commit_author": _github_commits,
    "repo.read_deployment_config": _github_contents([
        "deployment.yml",
        "deployment.yaml",
        "k8s/deployment.yml",
        "k8s/deployment.yaml",
        "deploy/deployment.yml",
        "deploy/deployment.yaml",
        "helm/values.yaml",
        "charts/values.yaml",
        "Dockerfile",
        "docker-compose.yml",
        ".github/workflows/deploy.yml",
        ".github/workflows/deploy.yaml",
    ]),
    "infra.rollback_deployment": _k8s_rollback,
    "infra.spawn_service_investigator": _unsupported_v1_live_action("infra.spawn_service_investigator", "service investigator spawning is bound by the orchestrator"),
    "infra.scale_replicas": _unsupported_v1_live_action("infra.scale_replicas", "infrastructure scaling remains human-owned"),
    "infra.toggle_feature_flag": _unsupported_v1_live_action("infra.toggle_feature_flag", "feature-flag mutation remains human-owned"),
    "infra.add_database_index": _sqlite_add_database_index,
    "infra.flush_cache": _unsupported_v1_live_action("infra.flush_cache", "cache mutation remains human-owned"),
    "infra.update_rate_limit": _unsupported_v1_live_action("infra.update_rate_limit", "rate-limit mutation remains human-owned"),
    "infra.drain_node": _unsupported_v1_live_action("infra.drain_node", "node draining remains human-owned"),
    "infra.redeploy_service": _unsupported_v1_live_action("infra.redeploy_service", "Kubernetes changes beyond rollback remain human-owned"),
    "infra.modify_env_config": _unsupported_v1_live_action("infra.modify_env_config", "environment configuration mutation remains human-owned"),
    "infra.open_circuit_breaker": _unsupported_v1_live_action("infra.open_circuit_breaker", "circuit-breaker mutation remains human-owned"),
    "infra.run_migration": _unsupported_v1_live_action("infra.run_migration", "database migration execution remains human-owned"),
    "comms.post_to_slack": _slack_post,
    "comms.create_incident_channel": _slack_channel,
    "comms.page_oncall_engineer": _pagerduty_oncall,
    "comms.update_status_page": _external_status_page,
    "comms.write_post_mortem": _slack_post,
    "comms.notify_stakeholders": _slack_post,
    "comms.escalate_incident": _pagerduty_oncall,
    "comms.close_incident": _unsupported_v1_live_action("comms.close_incident", "incident resolution status remains owned by PagerDuty and humans"),
    "comms.create_jira_ticket": _github_issue,
    "comms.send_executive_summary": _slack_post,
    "comms.schedule_retro_meeting": _slack_schedule,
    "comms.update_runbook": _github_runbook,
}


def _evidence_from_live_result(
    tool_name: str,
    payload: dict[str, Any],
    data: dict[str, Any],
) -> list[Evidence]:
    service = payload.get("service") or payload.get("affected_service") or "unknown"
    window = payload.get("time_window", "live")
    count = _provider_evidence_count(tool_name, data)
    provenance = data.get("implementation", f"live::{tool_name}")
    provider = data.get("provider")
    provider_label = f" via {provider}" if isinstance(provider, str) and provider.strip() else ""
    if count <= 0:
        provenance = f"live_empty::{tool_name}"
        claim = f"{tool_name} completed live API call{provider_label} for {service}; no provider-confirming records were returned."
    else:
        claim = f"{tool_name} returned live API data{provider_label} for {service}; observed {count} provider item(s)."
    return [
        Evidence(
            source=tool_name,
            time_window=window,
            affected_service=service,
            claim=claim,
            provenance=provenance,
        )
    ]


_LIVE_EVIDENCE_ENVELOPE_KEYS = {
    "implementation",
    "stub",
    "tool",
    "query",
    "service",
    "affected_service",
    "time_window",
    "time_window_end",
    "metric",
    "path",
    "line",
    "target_source",
    "blame_source",
    "provider",
}


_OBSERVABILITY_METRIC_TOOLS = {
    "observe.query_metrics_range",
    "observe.get_error_rate_timeseries",
    "observe.read_queue_depth",
    "observe.get_network_latency",
    "observe.check_uptime_history",
    "observe.get_memory_cpu_usage",
}


_METRIC_TOOLS = _OBSERVABILITY_METRIC_TOOLS


_PAGERDUTY_ONCALL_TOOLS = {
    "comms.page_oncall_engineer",
    "comms.escalate_incident",
}


def _provider_evidence_count(tool_name: str, data: dict[str, Any]) -> int:
    if _is_write_skipped_dry_run(data):
        return 0
    if tool_name in _METRIC_TOOLS:
        return _count_observability_metric_series(data)
    if data.get("provider") == "loki":
        return _count_loki_log_entries(data)
    if data.get("provider") == "discord":
        return _count_confirmed_discord_messages(data)
    if tool_name in _PAGERDUTY_ONCALL_TOOLS:
        return _count_confirmed_pagerduty_oncalls(data)
    if tool_name == "infra.rollback_deployment":
        return _count_confirmed_kubernetes_rollback(data)
    return _count_provider_payload_items(data)


def _is_write_skipped_dry_run(data: dict[str, Any]) -> bool:
    return data.get("write_skipped") is True


def _count_confirmed_kubernetes_rollback(data: dict[str, Any]) -> int:
    if data.get("verified") is not True:
        return 0
    if not _kubectl_result_has_output(data.get("undo")):
        return 0
    if not _kubectl_result_has_output(data.get("rollout_status")):
        return 0
    return 1


def _kubectl_result_has_output(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    output = value.get("output")
    return isinstance(output, str) and bool(output.strip())


def _count_confirmed_pagerduty_oncalls(data: dict[str, Any]) -> int:
    oncalls = data.get("oncalls")
    if not isinstance(oncalls, list):
        return 0
    allowed_scopes = {"incident_escalation_policy", "generic_webhook"}
    if data.get("incident") is not None and data.get("oncall_scope") not in allowed_scopes:
        return 0
    return sum(1 for item in oncalls if _pagerduty_oncall_user_id(item))


def _pagerduty_oncall_user_id(item: Any) -> str | None:
    if not isinstance(item, dict):
        return None
    user = item.get("user")
    if not isinstance(user, dict):
        return None
    user_id = user.get("id")
    if isinstance(user_id, str) and user_id.strip():
        return user_id.strip()
    return None


def _count_confirmed_discord_messages(data: dict[str, Any]) -> int:
    message_id = data.get("id")
    content = data.get("content")
    if isinstance(message_id, str) and message_id.strip() and isinstance(content, str) and content.strip():
        return 1
    return 0


def _count_observability_metric_series(value: Any) -> int:
    if isinstance(value, dict):
        result = value.get("result")
        if isinstance(result, list):
            return sum(1 for item in result if prometheus_result_has_finite_numeric_value(item))
        series = value.get("series")
        if isinstance(series, list):
            return sum(_confirmed_metric_series_item_count(item) for item in series)
        return sum(
            _count_observability_metric_series(item)
            for key, item in value.items()
            if not key.startswith("_") and key not in _LIVE_EVIDENCE_ENVELOPE_KEYS
        )
    if isinstance(value, list):
        return sum(_count_observability_metric_series(item) for item in value)
    return 0


def _count_loki_log_entries(data: dict[str, Any]) -> int:
    streams = data.get("streams")
    if not isinstance(streams, list):
        streams = data.get("events")
    if not isinstance(streams, list):
        return 0
    total = 0
    for stream in streams:
        if not isinstance(stream, dict):
            continue
        values = stream.get("values")
        if not isinstance(values, list):
            continue
        total += sum(1 for value in values if _loki_log_entry_has_message(value))
    return total


def _loki_log_entry_has_message(value: Any) -> bool:
    if not isinstance(value, list | tuple) or len(value) < 2:
        return False
    timestamp = value[0]
    message = value[1]
    return isinstance(timestamp, str) and bool(timestamp.strip()) and isinstance(message, str) and bool(message.strip())


def _confirmed_metric_series_item_count(item: Any) -> int:
    if not isinstance(item, dict):
        return 0
    pointlist = item.get("pointlist")
    if isinstance(pointlist, list) and any(_datadog_point_has_numeric_value(point) for point in pointlist):
        return 1
    return 0


def _datadog_point_has_numeric_value(point: Any) -> bool:
    return datadog_point_has_finite_numeric_value(point)


def _count_provider_payload_items(data: dict[str, Any]) -> int:
    total = 0
    for key, value in data.items():
        if key.startswith("_") or key in _LIVE_EVIDENCE_ENVELOPE_KEYS:
            continue
        if isinstance(value, list):
            total += len(value)
        elif isinstance(value, dict):
            total += _count_provider_payload_items(value) or (1 if value else 0)
        elif _non_empty_provider_scalar(value):
            total += 1
    return total


def _non_empty_provider_scalar(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, bool):
        return value
    return isinstance(value, (int, float))
