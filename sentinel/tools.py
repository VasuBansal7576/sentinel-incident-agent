from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Iterable

from opentelemetry import trace

from sentinel.errors import ToolAccessDenied, ToolErrorKind, ToolExecutionError, redact_sensitive_text
from sentinel.models import (
    AuditEvent,
    Evidence,
    PermissionClass,
    StateName,
    ToolCallRecord,
    ToolContract,
    ToolNamespace,
    ToolResult,
)
from sentinel.simulated import SimulatedIncidentEnvironment
from sentinel.store import SQLiteInvestigationStore


OBSERVE_TOOLS = [
    "fetch_service_logs",
    "query_metrics_range",
    "get_distributed_traces",
    "check_pod_health",
    "get_error_rate_timeseries",
    "fetch_apm_data",
    "read_queue_depth",
    "check_db_slow_queries",
    "get_network_latency",
    "fetch_cdn_logs",
    "read_flame_graph",
    "check_uptime_history",
    "get_memory_cpu_usage",
    "fetch_alerting_rules",
    "read_dashboard_snapshot",
]

REPO_TOOLS = [
    "get_recent_commits",
    "diff_pull_request",
    "get_deploy_history",
    "read_ci_pipeline_status",
    "fetch_test_results",
    "blame_file_line",
    "get_rollback_targets",
    "read_changelog",
    "check_dependency_changes",
    "get_feature_flags",
    "fetch_pr_metadata",
    "get_commit_author",
    "read_deployment_config",
]

INFRA_TOOLS = [
    "rollback_deployment",
    "restart_service",
    "scale_replicas",
    "toggle_feature_flag",
    "add_database_index",
    "flush_cache",
    "update_rate_limit",
    "drain_node",
    "redeploy_service",
    "modify_env_config",
    "open_circuit_breaker",
    "run_migration",
]

COMMS_TOOLS = [
    "post_to_slack",
    "create_incident_channel",
    "page_oncall_engineer",
    "update_status_page",
    "write_post_mortem",
    "notify_stakeholders",
    "escalate_incident",
    "close_incident",
    "create_jira_ticket",
    "send_executive_summary",
    "schedule_retro_meeting",
    "update_runbook",
]


READ_STATES = [
    StateName.TRIAGE,
    StateName.EVIDENCE_COLLECTION,
    StateName.SERVICE_INVESTIGATION,
    StateName.CORRELATION,
    StateName.RESPONSE_PROPOSAL,
    StateName.REMEDIATION,
    StateName.POST_MORTEM,
]


class RateLimiter:
    def __init__(self, rate_per_second: float):
        self.min_interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._last_call = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.monotonic()


@dataclass
class ToolExecutionContext:
    investigation_id: str
    state: StateName
    approved: bool = False
    subagent_context_id: str | None = None


class SimulatedTool:
    def __init__(
        self,
        contract: ToolContract,
        environment: SimulatedIncidentEnvironment,
        *,
        max_attempts: int = 3,
        base_delay_seconds: float = 0.001,
    ):
        self.contract = contract
        self.environment = environment
        self.max_attempts = max_attempts
        self.base_delay_seconds = base_delay_seconds
        self.rate_limiter = RateLimiter(contract.rate_limit_per_second)
        self.tracer = trace.get_tracer("sentinel.tools")

    def execute(self, payload: dict[str, Any], context: ToolExecutionContext) -> ToolResult:
        if self.contract.permission == PermissionClass.HUMAN_APPROVED_REMEDIATION and not context.approved:
            raise ToolAccessDenied(f"{self.contract.name} requires human approval")

        started = time.perf_counter()
        attempts = 0
        last_error: ToolExecutionError | None = None

        with self.tracer.start_as_current_span(self.contract.name) as span:
            span.set_attribute("tool.name", self.contract.name)
            span.set_attribute("tool.namespace", self.contract.namespace.value)
            span.set_attribute("investigation.id", context.investigation_id)
            for attempt in range(1, self.max_attempts + 1):
                attempts = attempt
                self.rate_limiter.wait()
                try:
                    data = self.environment.invoke(self.contract, payload)
                    evidence = [
                        Evidence.model_validate(item)
                        for item in data.get("evidence", [])
                    ]
                    duration_ms = (time.perf_counter() - started) * 1000
                    span.set_attribute("tool.success", True)
                    return ToolResult(
                        tool_name=self.contract.name,
                        success=True,
                        data=data,
                        evidence=evidence,
                        duration_ms=duration_ms,
                        attempt_count=attempts,
                    )
                except ToolExecutionError as error:
                    last_error = error
                    if not error.retryable or attempt == self.max_attempts:
                        break
                    if self.base_delay_seconds:
                        time.sleep(self.base_delay_seconds * (2 ** (attempt - 1)))

            duration_ms = (time.perf_counter() - started) * 1000
            span.set_attribute("tool.success", False)
            span.set_attribute("tool.error_kind", last_error.kind.value if last_error else "unknown")
            return ToolResult(
                tool_name=self.contract.name,
                success=False,
                data={},
                error_kind=(last_error.kind.value if last_error else ToolErrorKind.PERMANENT.value),
                error_message=(
                    redact_sensitive_text(last_error, max_length=500)
                    if last_error
                    else "unknown tool error"
                ),
                duration_ms=duration_ms,
                attempt_count=attempts,
            )


class ToolRegistry:
    def __init__(self, contracts: Iterable[ToolContract], tools: dict[str, SimulatedTool]):
        self.contracts = {contract.name: contract for contract in contracts}
        self.tools = tools

    def __len__(self) -> int:
        return len(self.contracts)

    def get_contract(self, name: str) -> ToolContract:
        return self.contracts[name]

    def list_contracts(
        self,
        *,
        namespaces: set[ToolNamespace] | None = None,
        permissions: set[PermissionClass] | None = None,
    ) -> list[ToolContract]:
        contracts = list(self.contracts.values())
        if namespaces is not None:
            contracts = [contract for contract in contracts if contract.namespace in namespaces]
        if permissions is not None:
            contracts = [contract for contract in contracts if contract.permission in permissions]
        return sorted(contracts, key=lambda item: item.name)

    def names_for_namespace(self, namespace: ToolNamespace) -> list[str]:
        return sorted(
            contract.name
            for contract in self.contracts.values()
            if contract.namespace == namespace
        )

    def phase_allowed_names(self, state: StateName) -> list[str]:
        return sorted(
            contract.name
            for contract in self.contracts.values()
            if state in contract.phase_allowlist
        )


class ToolFactory:
    """Factory for 52 simulated tool adapters from declarative contracts."""

    def __init__(self, environment: SimulatedIncidentEnvironment):
        self.environment = environment

    def build_registry(self) -> ToolRegistry:
        contracts = build_tool_contracts()
        tools = {
            contract.name: SimulatedTool(contract, self.environment)
            for contract in contracts
        }
        return ToolRegistry(contracts, tools)


class ToolExecutor:
    def __init__(self, registry: ToolRegistry, store: SQLiteInvestigationStore):
        self.registry = registry
        self.store = store

    def invoke(
        self,
        tool_name: str,
        payload: dict[str, Any],
        *,
        investigation_id: str,
        state: StateName,
        allowed_tool_names: set[str] | None = None,
        approved: bool = False,
        subagent_context_id: str | None = None,
    ) -> ToolResult:
        input_hash = _hash_payload(payload)
        if tool_name not in self.registry.contracts:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error_kind=ToolErrorKind.PERMISSION_DENIED.value,
                error_message="Tool is not registered",
            )
            _attach_reasoning_trace(result, payload, None, investigation_id, state)
            self._record_call(investigation_id, state, result, input_hash, subagent_context_id)
            return result

        contract = self.registry.get_contract(tool_name)
        if allowed_tool_names is not None and tool_name not in allowed_tool_names:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error_kind=ToolErrorKind.PERMISSION_DENIED.value,
                error_message="Tool is outside scoped registry",
            )
            _attach_reasoning_trace(result, payload, contract, investigation_id, state)
            self._record_call(investigation_id, state, result, input_hash, subagent_context_id)
            return result

        if state not in contract.phase_allowlist:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error_kind=ToolErrorKind.PERMISSION_DENIED.value,
                error_message=f"{tool_name} is not allowed during {state.value}",
            )
            _attach_reasoning_trace(result, payload, contract, investigation_id, state)
            self._record_call(investigation_id, state, result, input_hash, subagent_context_id)
            return result

        try:
            result = self.registry.tools[tool_name].execute(
                payload,
                ToolExecutionContext(
                    investigation_id=investigation_id,
                    state=state,
                    approved=approved,
                    subagent_context_id=subagent_context_id,
                ),
            )
        except ToolExecutionError as error:
            result = ToolResult(
                tool_name=tool_name,
                success=False,
                error_kind=error.kind.value,
                error_message=redact_sensitive_text(error, max_length=500),
            )

        _attach_reasoning_trace(result, payload, contract, investigation_id, state)
        self._record_call(investigation_id, state, result, input_hash, subagent_context_id)
        return result

    def _record_call(
        self,
        investigation_id: str,
        state: StateName,
        result: ToolResult,
        input_hash: str,
        subagent_context_id: str | None,
    ) -> None:
        call = ToolCallRecord(
            investigation_id=investigation_id,
            tool_name=result.tool_name,
            state=state,
            duration_ms=result.duration_ms,
            input_hash=input_hash,
            output_hash=_hash_payload(result.model_dump(mode="json")),
            success=result.success,
            reasoning_trace=result.reasoning_trace,
            error_kind=result.error_kind,
            error_message=_redacted_error_message(result.error_message),
            subagent_context_id=subagent_context_id,
        )
        self.store.append_tool_call(call)
        self.store.append_audit_event(
            AuditEvent(
                investigation_id=investigation_id,
                event_type="tool_call",
                payload={
                    "tool_name": result.tool_name,
                    "success": result.success,
                    "reasoning_trace": result.reasoning_trace,
                    "error_kind": result.error_kind,
                    "error_message": call.error_message,
                    "subagent_context_id": subagent_context_id,
                },
            )
        )


def build_default_registry(environment: SimulatedIncidentEnvironment | None = None) -> ToolRegistry:
    from sentinel.scenarios import build_scenarios

    if environment is None:
        environment = SimulatedIncidentEnvironment(build_scenarios()["golden_path"])
    return ToolFactory(environment).build_registry()


def build_tool_contracts() -> list[ToolContract]:
    contracts: list[ToolContract] = []
    for short_name in OBSERVE_TOOLS:
        contracts.append(
            _contract(
                ToolNamespace.OBSERVE,
                short_name,
                PermissionClass.READ_ONLY,
                READ_STATES,
                "Read observability source material.",
            )
        )
    for short_name in REPO_TOOLS:
        contracts.append(
            _contract(
                ToolNamespace.REPO,
                short_name,
                PermissionClass.READ_ONLY,
                READ_STATES,
                "Read repository, deploy, and ownership source material.",
            )
        )
    for short_name in INFRA_TOOLS:
        contracts.append(
            _contract(
                ToolNamespace.INFRA,
                short_name,
                PermissionClass.HUMAN_APPROVED_REMEDIATION,
                [StateName.REMEDIATION],
                "Execute human-approved remediation against infrastructure.",
            )
        )
    for short_name in COMMS_TOOLS:
        contracts.append(
            _contract(
                ToolNamespace.COMMS,
                short_name,
                PermissionClass.COMMUNICATION,
                [
                    StateName.RECEIVED,
                    StateName.RESPONSE_PROPOSAL,
                    StateName.POST_MORTEM,
                ],
                "Communicate internally or produce incident documentation.",
            )
        )
    return contracts


def _contract(
    namespace: ToolNamespace,
    short_name: str,
    permission: PermissionClass,
    phase_allowlist: list[StateName],
    description: str,
) -> ToolContract:
    name = f"{namespace.value}.{short_name}"
    return ToolContract(
        name=name,
        namespace=namespace,
        permission=permission,
        description=description,
        input_schema={"service": "string", "time_window": "string"},
        output_schema={
            "observation": "string",
            "evidence": "list[Evidence]",
            "reasoning_trace": "string",
        },
        phase_allowlist=phase_allowlist,
    )


def _hash_payload(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _redacted_error_message(message: str | None) -> str | None:
    if not message:
        return None
    return redact_sensitive_text(message, max_length=500)


_TOOL_REASONING_PURPOSES = {
    "comms.create_incident_channel": "open a human-visible incident room before deeper investigation starts",
    "comms.post_to_slack": "notify the operator channel with the current investigation boundary and approval request",
    "observe.fetch_alerting_rules": "confirm the webhook came from the expected payment latency and error-rate alerts",
    "observe.fetch_service_logs": "look for concrete failure signatures before guessing at a code change",
    "observe.query_metrics_range": "measure whether latency actually moved enough to explain the page",
    "observe.check_db_slow_queries": "test the suspected database lookup path behind payment latency",
    "observe.get_distributed_traces": "connect request latency to the exact backend span doing the work",
    "observe.fetch_apm_data": "separate database wait from CPU, network, or dependency pressure",
    "observe.get_error_rate_timeseries": "verify impact before remediation and recovery after remediation",
    "observe.check_pod_health": "rule out crash-loop or readiness failure as the primary cause",
    "repo.get_deploy_history": "find the most recent service change inside the incident window",
    "repo.diff_pull_request": "inspect the deploy's code delta for the missing-index regression",
    "repo.fetch_pr_metadata": "tie the risky change to its PR, merge time, author, reviewers, and commit",
    "repo.blame_file_line": "identify the accountable author and exact lookup line",
    "repo.get_feature_flags": "check whether the risky path could be disabled without rollback",
    "repo.fetch_test_results": "look for the test gap that let the query regression ship",
    "repo.get_recent_commits": "cross-check commit history against deploy evidence",
    "repo.get_rollback_targets": "find the latest known-good target before asking for approval",
    "repo.read_ci_pipeline_status": "confirm CI health and whether query-plan coverage existed",
    "repo.read_deployment_config": "confirm the service can be rolled back through the standard controller",
    "infra.rollback_deployment": "execute only the human-approved rollback target",
    "infra.add_database_index": "execute only the human-approved SQLite index migration",
    "comms.write_post_mortem": "turn collected evidence into a factual incident record",
    "comms.create_jira_ticket": "capture the long-term index fix with an accountable owner",
    "comms.update_runbook": "preserve the lesson for the next payment latency incident",
}


def _attach_reasoning_trace(
    result: ToolResult,
    payload: dict[str, Any],
    contract: ToolContract | None,
    investigation_id: str,
    state: StateName,
) -> None:
    existing = result.reasoning_trace or result.data.get("reasoning_trace")
    if isinstance(existing, str) and existing.strip():
        trace = existing.strip()
    else:
        trace = _build_reasoning_trace(result, payload, contract, investigation_id, state)
    result.reasoning_trace = trace
    result.data.setdefault("reasoning_trace", trace)


def _build_reasoning_trace(
    result: ToolResult,
    payload: dict[str, Any],
    contract: ToolContract | None,
    investigation_id: str,
    state: StateName,
) -> str:
    service = payload.get("service") or payload.get("affected_service") or "unknown-service"
    tool_name = result.tool_name
    purpose = _TOOL_REASONING_PURPOSES.get(tool_name)
    if not purpose and contract is not None:
        purpose = contract.description.rstrip(".").lower()
    if not purpose:
        purpose = "validate whether the requested tool can contribute evidence"
    learned = _learned_from_result(result)
    return (
        f"Why: {purpose} for {service} during {state.value}. "
        f"Learned: {learned}"
    )


def _learned_from_result(result: ToolResult) -> str:
    if not result.success:
        return result.error_message or f"{result.tool_name} failed without a detailed error."
    observation = result.data.get("observation")
    if isinstance(observation, str) and observation.strip():
        return observation.strip()
    provider = result.data.get("provider")
    if isinstance(provider, str) and provider.strip():
        return f"{result.tool_name} completed through {provider.strip()}."
    status = result.data.get("status")
    if isinstance(status, str) and status.strip():
        return f"{result.tool_name} completed with status {status.strip()}."
    return f"{result.tool_name} completed successfully."
