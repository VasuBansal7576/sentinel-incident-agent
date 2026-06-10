from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.models import (
    AuditEvent,
    BlastRadiusReport,
    ConfidenceLevel,
    Evidence,
    RemediationReadinessReport,
    ServiceIncidentReport,
    StateName,
    ToolNamespace,
    ToolResult,
)
from sentinel.store import SQLiteInvestigationStore
from sentinel.time_windows import observability_payload, repository_payload
from sentinel.tools import ToolExecutionContext, ToolExecutor, ToolRegistry


@dataclass
class IsolatedSubagentContext:
    parent_investigation_id: str
    subagent_type: str
    service_name: str
    objective: str
    context_id: str = field(default_factory=lambda: f"ctx-{uuid4().hex[:10]}")
    memory: list[str] = field(default_factory=list)


class BaseSubagent:
    subagent_type = "base"

    def __init__(
        self,
        registry: ToolRegistry,
        executor: ToolExecutor,
        store: SQLiteInvestigationStore,
    ):
        self.registry = registry
        self.executor = executor
        self.store = store

    def scoped_tool_names(self) -> list[str]:
        raise NotImplementedError

    def _parent_state(self, investigation_id: str):
        try:
            return self.store.load_state(investigation_id)
        except KeyError:
            return None

    def _invoke(
        self,
        tool_name: str,
        payload: dict[str, Any],
        context: IsolatedSubagentContext,
    ):
        return self.executor.invoke(
            tool_name,
            payload,
            investigation_id=context.parent_investigation_id,
            state=StateName.SERVICE_INVESTIGATION,
            allowed_tool_names=set(self.scoped_tool_names()),
            subagent_context_id=context.context_id,
        )


class ServiceInvestigatorSubagent(BaseSubagent):
    subagent_type = "service_investigator"

    def scoped_tool_names(self) -> list[str]:
        return sorted(
            self.registry.names_for_namespace(ToolNamespace.OBSERVE)
            + self.registry.names_for_namespace(ToolNamespace.REPO)
        )

    def run(self, context: IsolatedSubagentContext) -> ServiceIncidentReport:
        parent_state = self._parent_state(context.parent_investigation_id)
        log_result = self._invoke(
            "observe.fetch_service_logs",
            observability_payload(parent_state, context.service_name),
            context,
        )
        commit_result = self._invoke(
            "repo.get_recent_commits",
            repository_payload(parent_state, context.service_name),
            context,
        )
        rollback_result = self._invoke(
            "repo.get_rollback_targets",
            repository_payload(parent_state, context.service_name),
            context,
        )
        evidence = log_result.evidence + commit_result.evidence + rollback_result.evidence
        gaps = [
            result.error_message or result.tool_name
            for result in [log_result, commit_result, rollback_result]
            if not result.success
        ]
        confidence = ConfidenceLevel.HIGH if not gaps else ConfidenceLevel.LOW
        target = rollback_result.data.get("target") if rollback_result.success else None
        if parent_state and parent_state.scenario_name == "live":
            source = _live_source(parent_state)
            rollback_target = target if _is_kubernetes_revision(target) else None
            return ServiceIncidentReport(
                service_name=context.service_name,
                local_diagnosis=(
                    f"{context.service_name} live evidence is consistent with degradation around "
                    f"{source}; parent reconciliation must confirm cross-service cause."
                ),
                confidence=confidence,
                evidence=evidence,
                contributing_factors=["Recent live change evidence", "Service-local telemetry symptoms"],
                suggested_fix=(
                    f"Propose rollback of {context.service_name} to {rollback_target} after structured approval."
                    if rollback_target
                    else f"Collect a Kubernetes rollout revision target for {context.service_name} before approval."
                ),
                rollback_target=rollback_target,
                estimated_user_impact=0,
                evidence_gaps=gaps,
                isolated_context_id=context.context_id,
                scoped_tool_names=self.scoped_tool_names(),
            )
        return ServiceIncidentReport(
            service_name=context.service_name,
            local_diagnosis=(
                f"{context.service_name} symptoms correlate with PR #847 and the "
                "orders.user_id missing-index regression."
            ),
            confidence=confidence,
            evidence=evidence,
            contributing_factors=["Recent deploy", "Missing database index"],
            suggested_fix="Rollback to v2.3.1 and create a follow-up index migration.",
            rollback_target=target,
            estimated_user_impact=18420 if context.service_name == "payment-service" else 6100,
            evidence_gaps=gaps,
            isolated_context_id=context.context_id,
            scoped_tool_names=self.scoped_tool_names(),
        )


class BlastRadiusSubagent(BaseSubagent):
    subagent_type = "blast_radius"

    def scoped_tool_names(self) -> list[str]:
        return [
            "observe.check_uptime_history",
            "observe.get_error_rate_timeseries",
            "observe.query_metrics_range",
        ]

    def run(self, context: IsolatedSubagentContext) -> BlastRadiusReport:
        parent_state = self._parent_state(context.parent_investigation_id)
        uptime = self._invoke(
            "observe.check_uptime_history",
            observability_payload(parent_state, context.service_name),
            context,
        )
        errors = self._invoke(
            "observe.get_error_rate_timeseries",
            observability_payload(parent_state, context.service_name),
            context,
        )
        evidence: list[Evidence] = uptime.evidence + errors.evidence
        live = bool(parent_state and parent_state.scenario_name == "live")
        return BlastRadiusReport(
            affected_services=[context.service_name],
            affected_users=int(uptime.data.get("affected_users", 0)),
            affected_flow=(
                f"{context.service_name} customer-facing flow"
                if live
                else "checkout payment authorization"
            ),
            evidence=evidence,
            isolated_context_id=context.context_id,
            scoped_tool_names=self.scoped_tool_names(),
        )


class RemediationReadinessSubagent(BaseSubagent):
    subagent_type = "remediation_readiness"

    def scoped_tool_names(self) -> list[str]:
        return [
            "repo.fetch_test_results",
            "repo.get_rollback_targets",
            "repo.read_ci_pipeline_status",
            "repo.read_deployment_config",
        ]

    def run(self, context: IsolatedSubagentContext) -> RemediationReadinessReport:
        parent_state = self._parent_state(context.parent_investigation_id)
        target = self._invoke(
            "repo.get_rollback_targets",
            repository_payload(parent_state, context.service_name),
            context,
        )
        ci = self._invoke(
            "repo.read_ci_pipeline_status",
            repository_payload(parent_state, context.service_name),
            context,
        )
        tests = self._invoke(
            "repo.fetch_test_results",
            repository_payload(parent_state, context.service_name),
            context,
        )
        blockers = [
            result.error_message or result.tool_name
            for result in [target, ci, tests]
            if not result.success
        ]
        raw_target = target.data.get("target") if target.success else None
        safe_target = (
            raw_target
            if not parent_state or parent_state.scenario_name != "live" or _is_kubernetes_revision(raw_target)
            else None
        )
        if parent_state and parent_state.scenario_name == "live" and not safe_target:
            blockers.append("No executable Kubernetes rollback revision target was confirmed.")
        return RemediationReadinessReport(
            safe_rollback_target=safe_target,
            blockers=blockers,
            evidence=target.evidence + ci.evidence + tests.evidence,
            isolated_context_id=context.context_id,
            scoped_tool_names=self.scoped_tool_names(),
        )


class SubagentLauncher:
    """Control-plane tool that spawns real isolated subagent contexts."""

    def __init__(
        self,
        registry: ToolRegistry,
        executor: ToolExecutor,
        store: SQLiteInvestigationStore,
    ):
        self.registry = registry
        self.executor = executor
        self.store = store

    def bind_spawn_tool(self) -> None:
        self.registry.tools["infra.spawn_service_investigator"] = ServiceInvestigatorSpawnTool(self)  # type: ignore[assignment]

    def service_investigator(self, investigation_id: str, service_name: str) -> ServiceIncidentReport:
        context = self._context(investigation_id, "service_investigator", service_name)
        return ServiceInvestigatorSubagent(self.registry, self.executor, self.store).run(context)

    def blast_radius(self, investigation_id: str, service_name: str) -> BlastRadiusReport:
        context = self._context(investigation_id, "blast_radius", service_name)
        return BlastRadiusSubagent(self.registry, self.executor, self.store).run(context)

    def remediation_readiness(
        self, investigation_id: str, service_name: str
    ) -> RemediationReadinessReport:
        context = self._context(investigation_id, "remediation_readiness", service_name)
        return RemediationReadinessSubagent(self.registry, self.executor, self.store).run(context)

    def _context(
        self, investigation_id: str, subagent_type: str, service_name: str
    ) -> IsolatedSubagentContext:
        context = IsolatedSubagentContext(
            parent_investigation_id=investigation_id,
            subagent_type=subagent_type,
            service_name=service_name,
            objective=f"Investigate {service_name} with scoped read-only tools.",
        )
        self.store.append_audit_event(
            AuditEvent(
                investigation_id=investigation_id,
                event_type="subagent_spawn",
                payload={
                    "subagent_type": subagent_type,
                    "service_name": service_name,
                    "context_id": context.context_id,
                },
            )
        )
        return context


class ServiceInvestigatorSpawnTool:
    def __init__(self, launcher: SubagentLauncher):
        self.launcher = launcher

    def execute(self, payload: dict[str, Any], context: ToolExecutionContext) -> ToolResult:
        service_name = _required_spawn_service_name(payload)
        report = self.launcher.service_investigator(context.investigation_id, service_name)
        evidence = report.evidence
        return ToolResult(
            tool_name="infra.spawn_service_investigator",
            success=True,
            data={
                "tool": "infra.spawn_service_investigator",
                "implementation": "subagent::service_investigator",
                "stub": False,
                "service": service_name,
                "service_report": report.model_dump(mode="json"),
                "observation": report.local_diagnosis,
                "evidence": [item.model_dump(mode="json") for item in evidence],
            },
            evidence=evidence,
        )


def _required_spawn_service_name(payload: dict[str, Any]) -> str:
    service_name = payload.get("service_name") or payload.get("service")
    if not isinstance(service_name, str) or not service_name.strip():
        raise ToolExecutionError(
            ToolErrorKind.PERMANENT,
            "infra.spawn_service_investigator requires service_name",
            retryable=False,
        )
    return service_name.strip()


def _live_source(parent_state) -> str:
    artifacts = parent_state.artifacts
    pull_request = artifacts.get("pull_request")
    if pull_request:
        title = artifacts.get("pull_request_title")
        return f"PR #{pull_request}{f' ({title})' if title else ''}"
    return (
        artifacts.get("deployment_ref")
        or artifacts.get("commit_sha")
        or artifacts.get("previous_deployment_ref")
        or "recent live deployment evidence"
    )


def _is_kubernetes_revision(target: Any) -> bool:
    return isinstance(target, str) and target.startswith("revision:") and target.split(":", 1)[1].isdigit()
