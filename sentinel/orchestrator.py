from __future__ import annotations

from pathlib import Path
from typing import Any
import re
import time

from sentinel.model_client import ModelBackedToolPlanner, ModelClient
from sentinel.models import (
    ApprovalCommand,
    ApprovalRequest,
    AuditEvent,
    BlastRadiusReport,
    ConfidenceLevel,
    Diagnosis,
    Evidence,
    IncidentScenario,
    InvestigationState,
    InvestigationStatus,
    PlanStep,
    PostMortem,
    Recommendation,
    RemediationReadinessReport,
    RemediationResult,
    ServiceIncidentReport,
    StateName,
    STATE_MACHINE,
    now_utc,
)
from sentinel.scenarios import build_scenarios
from sentinel.replay import ReplayIncidentEnvironment
from sentinel.store import SQLiteInvestigationStore
from sentinel.subagents import SubagentLauncher
from sentinel.time_windows import (
    live_time_window_artifacts,
    observability_payload,
    repository_payload,
)
from sentinel.tools import ToolExecutor, ToolFactory, ToolRegistry


class SentinelOrchestrator:
    """Custom 8-state incident investigation orchestrator."""

    def __init__(
        self,
        *,
        store: SQLiteInvestigationStore | None = None,
        model_client: ModelClient | None = None,
        db_path: str | Path = ":memory:",
    ):
        self.store = store or SQLiteInvestigationStore(db_path)
        self.model_client = model_client or ModelBackedToolPlanner()
        self.registry: ToolRegistry | None = None
        self.executor: ToolExecutor | None = None
        self.environment: ReplayIncidentEnvironment | None = None
        self.subagents: SubagentLauncher | None = None

    def run_scenario(self, scenario_name: str = "golden_path", *, auto_approve: bool = True) -> InvestigationState:
        scenario = build_scenarios()[scenario_name]
        self._wire_scenario(scenario)
        state = InvestigationState(
            incident_id=scenario.incident_id,
            scenario_name=scenario.name,
            trigger_kind=scenario.trigger_kind,
            affected_services=list(scenario.affected_services),
            service_priority=self._prioritize_services(scenario.affected_services),
            context_summary="New investigation attached to external incident system of record.",
        )
        self._audit(state, "investigation_created", {"incident_id": scenario.incident_id})
        self.store.remember_idempotency_key(
            f"{scenario.incident_id}:trigger",
            "trigger",
            state.id,
        )
        self._checkpoint(state)
        if scenario.trigger_kind == "watch":
            return self._run_watch(state)
        return self._run_incident(state, auto_approve=auto_approve)

    def run_live_incident(
        self,
        *,
        incident_id: str,
        affected_services: list[str],
        webhook_payload: dict[str, Any] | None = None,
        auto_approve: bool = False,
        investigation_id: str | None = None,
    ) -> InvestigationState:
        if self.registry is None or self.executor is None or self.subagents is None:
            raise RuntimeError("Live registry, executor, and subagents must be wired before run_live_incident")
        services = affected_services or ["payment-service"]
        state_kwargs: dict[str, Any] = {}
        received_state: InvestigationState | None = None
        if investigation_id:
            state_kwargs["id"] = investigation_id
            try:
                received_state = self.store.load_state(investigation_id)
            except KeyError:
                received_state = None
        state = InvestigationState(
            **state_kwargs,
            incident_id=incident_id,
            scenario_name="live",
            trigger_kind="incident",
            affected_services=list(services),
            service_priority=self._prioritize_services(services),
            context_summary="Live PagerDuty webhook accepted; investigation attached to external incident system of record.",
        )
        if received_state is not None:
            state.artifacts.update(received_state.artifacts)
            state.audit_events.extend(received_state.audit_events)
            if state.artifacts.get("webhook_source") == "generic_webhook":
                state.context_summary = (
                    "Generic webhook accepted; live investigation attached to free alert source."
                )
        state.artifacts.update(live_time_window_artifacts(webhook_payload))
        if _is_slow_query_webhook(webhook_payload):
            state.artifacts["slow_query_incident"] = True
        self._audit(
            state,
            "live_webhook_received",
            {
                "incident_id": incident_id,
                "payload_keys": sorted((webhook_payload or {}).keys()),
                "observability_window": state.artifacts.get("observability_window"),
                "repo_window": state.artifacts.get("repo_window"),
            },
        )
        self.store.remember_idempotency_key(f"{incident_id}:trigger", "trigger", state.id)
        self._checkpoint(state)
        return self._run_incident(state, auto_approve=auto_approve)

    def resume_with_approval(
        self,
        investigation_id: str,
        approval_command: ApprovalCommand,
    ) -> InvestigationState:
        if self.registry is None or self.executor is None:
            raise RuntimeError("Registry and executor must be wired before resume_with_approval")
        state = self.store.load_state(investigation_id)
        if state.status == InvestigationStatus.COMPLETED:
            return state
        if state.status != InvestigationStatus.WAITING_FOR_APPROVAL:
            raise RuntimeError(
                f"Investigation {investigation_id} is {state.status.value}, not waiting for approval"
            )
        if not state.approval_request:
            raise RuntimeError(f"Investigation {investigation_id} has no approval request")
        rejection_reason = self._approval_command_rejection_reason(state, approval_command)
        if rejection_reason:
            return self._reject_approval_command(state, approval_command, rejection_reason)
        if not self.store.remember_idempotency_key(
            approval_command.idempotency_key,
            "approval_command",
            state.id,
        ):
            return self.store.load_state(investigation_id)

        state.approval_command = approval_command
        self._audit(
            state,
            "approval_command_received",
            {
                "request_id": approval_command.request_id,
                "approver_id": approval_command.approver_id,
                "decision": approval_command.decision,
            },
        )
        decision_detail = (
            "Authorized approver approved the exact rollback request."
            if approval_command.decision == "approve"
            else "Authorized approver rejected the exact rollback request."
        )
        self._add_step(
            state,
            len(state.plan_steps) + 1,
            "Receive structured human approval",
            decision_detail,
        )
        self._checkpoint(state)
        return self._continue_after_approval(state)

    def _approval_command_rejection_reason(
        self,
        state: InvestigationState,
        approval_command: ApprovalCommand,
    ) -> str | None:
        if state.status != InvestigationStatus.WAITING_FOR_APPROVAL or state.current_state != StateName.RESPONSE_PROPOSAL:
            return "Approval command cannot be accepted outside the waiting response proposal state."
        approval_request = state.approval_request
        if not approval_request:
            return "Investigation has no active approval request."
        if approval_command.request_id != approval_request.id:
            return "Approval command did not match the active approval request."
        if not _approval_slack_notification_confirmed(state):
            return "Approval request Slack notification was not confirmed for the active approval request."
        if approval_command.approver_id not in approval_request.approver_ids:
            return "Approval command was not sent by an authorized approver."
        if approval_request.expires_at < now_utc():
            return "Approval request expired before the command was accepted."
        _, _, refusal = _approved_remediation_scope(state)
        if refusal:
            return refusal
        return None

    def _reject_approval_command(
        self,
        state: InvestigationState,
        approval_command: ApprovalCommand,
        reason: str,
    ) -> InvestigationState:
        state.status = InvestigationStatus.WAITING_FOR_APPROVAL
        state.current_state = StateName.RESPONSE_PROPOSAL
        state.approval_command = None
        self._audit(
            state,
            "approval_command_rejected",
            {
                "request_id": approval_command.request_id,
                "approver_id": approval_command.approver_id,
                "decision": approval_command.decision,
                "reason": reason,
            },
        )
        self._add_step(
            state,
            len(state.plan_steps) + 1,
            "Reject invalid approval command",
            reason,
        )
        self._checkpoint(state)
        return state

    def _wire_scenario(self, scenario: IncidentScenario) -> None:
        self.environment = ReplayIncidentEnvironment(scenario)
        self.registry = ToolFactory(self.environment).build_registry()
        self.executor = ToolExecutor(self.registry, self.store)
        self.subagents = SubagentLauncher(self.registry, self.executor, self.store)
        self.subagents.bind_spawn_tool()

    def _run_incident(self, state: InvestigationState, *, auto_approve: bool) -> InvestigationState:
        assert self.registry and self.executor and self.subagents
        primary_service = state.service_priority[0] if state.service_priority else "payment-service"
        secondary_service = (
            state.service_priority[1]
            if len(state.service_priority) > 1
            else primary_service
        )
        if state.artifacts.get("slow_query_incident") is True:
            return self._run_slow_query_incident(state, primary_service, auto_approve=auto_approve)

        self._transition(state, StateName.RECEIVED)
        received_plan = self._plan(state, "Create incident channel and acknowledge investigation")
        self._tool_step(
            state,
            1,
            "Create incident channel",
            received_plan[0],
            {
                "service": primary_service,
                "channel_name": f"inc-{state.incident_id}-{primary_service}",
            },
        )
        self._tool_step(
            state,
            2,
            "Post investigation acknowledgement",
            received_plan[1],
            self._comms_payload(
                state,
                primary_service,
                {"message": "SENTINEL is investigating."},
            ),
        )
        next_step = 3
        if state.scenario_name == "live":
            self._tool_step(
                state,
                next_step,
                "Fetch PagerDuty incident and on-call context",
                "comms.page_oncall_engineer",
                self._comms_payload(
                    state,
                    primary_service,
                    {"incident_id": state.incident_id},
                ),
            )
            next_step += 1

        self._transition(state, StateName.TRIAGE)
        triage_plan = self._plan(state, "Establish affected services, severity, and time window")
        triage_payloads = [
            observability_payload(state, primary_service),
            observability_payload(state, primary_service),
            observability_payload(state, primary_service),
            repository_payload(state, primary_service),
            observability_payload(state, primary_service),
        ]
        for offset, (tool_name, payload) in enumerate(zip(triage_plan, triage_payloads), start=next_step):
            self._tool_step(state, offset, f"Triage with {tool_name}", tool_name, payload)

        self._transition(state, StateName.EVIDENCE_COLLECTION)
        evidence_plan = self._plan(state, "Collect observability and repository evidence")
        evidence_payloads = [
            observability_payload(state, primary_service),
            observability_payload(state, secondary_service),
            observability_payload(state, primary_service),
            observability_payload(state, primary_service),
            observability_payload(state, primary_service),
            self._repo_payload(state, primary_service),
            self._repo_payload(state, primary_service),
            self._repo_payload(state, primary_service),
            self._blame_payload(state, primary_service),
            repository_payload(state, primary_service),
        ]
        for offset, (tool_name, payload) in enumerate(zip(evidence_plan, evidence_payloads), start=next_step + len(triage_payloads)):
            self._tool_step(state, offset, f"Evidence collection with {tool_name}", tool_name, payload)

        state.diagnosis = self._derive_diagnosis(state)
        if state.diagnosis.confidence == ConfidenceLevel.INSUFFICIENT:
            return self._finish_insufficient_confidence(state)

        self._transition(state, StateName.SERVICE_INVESTIGATION)
        if self._should_spawn_service_investigators(state):
            service_reports = [
                report
                for service in state.affected_services
                if (report := self._spawn_service_investigator(state, service)) is not None
            ]
        else:
            service_reports = []
        state.service_reports = service_reports
        step_number = 18
        for report in service_reports:
            self._add_step(
                state,
                step_number,
                f"Spawn {report.service_name} Service Investigator",
                "Isolated read-only context returned a typed report.",
            )
            step_number += 1

        blast_report = self.subagents.blast_radius(state.id, primary_service)
        readiness_report = self.subagents.remediation_readiness(state.id, primary_service)
        state.blast_radius_report = blast_report
        state.remediation_readiness_report = readiness_report
        state.evidence.extend(blast_report.evidence + readiness_report.evidence)
        self._add_step(state, step_number, "Spawn Blast Radius subagent", "Scoped observe tools estimated affected users and flow.")
        step_number += 1
        self._add_step(state, step_number, "Spawn Remediation Readiness subagent", "Scoped repo tools checked rollback readiness.")
        self._checkpoint(state)

        self._transition(state, StateName.CORRELATION)
        state.diagnosis = self._reconcile_evidence(state, service_reports, blast_report, readiness_report)
        self._add_step(state, len(state.plan_steps) + 1, "Reconcile service findings", state.diagnosis.summary)
        self._checkpoint(state)
        if state.diagnosis.confidence == ConfidenceLevel.INSUFFICIENT:
            return self._finish_insufficient_confidence(state)

        self._transition(state, StateName.RESPONSE_PROPOSAL)
        state.recommendation = self._build_recommendation(state)
        if not state.recommendation.executable:
            if state.diagnosis:
                gap = "No executable Kubernetes rollback revision target was confirmed."
                if gap not in state.diagnosis.evidence_gaps:
                    state.diagnosis.evidence_gaps.append(gap)
            return self._finish_insufficient_confidence(
                state,
                message=(
                    f"Insufficient confidence: collect Kubernetes rollout revision evidence "
                    f"for {primary_service} before remediation."
                ),
                detail="Next evidence: Kubernetes rollout revision target.",
            )
        approver_ids = _authorized_approver_ids(state)
        if not approver_ids:
            if state.diagnosis:
                gap = "No PagerDuty on-call authorized approver was confirmed."
                if gap not in state.diagnosis.evidence_gaps:
                    state.diagnosis.evidence_gaps.append(gap)
            return self._finish_insufficient_confidence(
                state,
                message=(
                    f"Insufficient confidence: collect PagerDuty on-call approver evidence "
                    f"for {primary_service} before remediation."
                ),
                detail="Next evidence: PagerDuty on-call authorized approver.",
            )
        approval_request = ApprovalRequest(
            incident_id=state.incident_id,
            remediation=state.recommendation,
            approver_ids=approver_ids,
            approval_snapshot={
                "diagnosis": state.diagnosis.summary if state.diagnosis else "",
                "confidence": state.diagnosis.confidence.value if state.diagnosis else "",
                "evidence_count": len(state.evidence),
                "state": state.current_state.value,
                "status": state.status.value,
                "recommendation": state.recommendation.model_dump(mode="json") if state.recommendation else None,
                "artifacts": state.artifacts,
            },
            idempotency_key=f"{state.id}:approval:rollback-{primary_service}",
        )
        state.approval_request = approval_request
        approval_notification = self._invoke_tool(
            state,
            "comms.post_to_slack",
            self._comms_payload(
                state,
                primary_service,
                {
                    "approval_request_id": approval_request.id,
                    "message": self._approval_proposal_message(state, approval_request),
                },
            ),
        )
        self._add_step(
            state,
            len(state.plan_steps) + 1,
            "Request structured rollback approval",
            (
                "Approval request posted to Slack."
                if approval_notification.success
                else approval_notification.error_message or "Approval request notification failed."
            ),
            tool_name="comms.post_to_slack",
        )
        approval_notification_confirmed = approval_notification.success
        if state.scenario_name == "live":
            approval_notification_confirmed = _tool_result_confirmed_for_live(
                approval_notification,
                "comms.post_to_slack",
            )
        if not approval_notification_confirmed:
            state.status = InvestigationStatus.FAILED
            state.approval_request = None
            state.context_summary = (
                "Approval request notification failed; no active approval request was created."
            )
            error_message = (
                approval_notification.error_message
                if not approval_notification.success
                else "Approval request notification lacked provider-confirming Slack evidence."
            )
            self._audit(
                state,
                "approval_request_notification_failed",
                {
                    "tool_name": "comms.post_to_slack",
                    "error_kind": approval_notification.error_kind,
                    "error_message": error_message,
                },
            )
            self._checkpoint(state)
            return state

        state.artifacts["approval_slack_notified"] = True
        state.artifacts["approval_slack_notification_request_id"] = approval_request.id
        notification_provider = approval_notification.data.get("provider")
        if isinstance(notification_provider, str) and notification_provider.strip():
            state.artifacts["approval_notification_provider"] = notification_provider.strip()
        state.status = InvestigationStatus.WAITING_FOR_APPROVAL

        if auto_approve:
            state.approval_command = ApprovalCommand(
                request_id=approval_request.id,
                approver_id=approver_ids[0],
                decision="approve",
                idempotency_key=f"{state.id}:approval-command:rollback-{primary_service}",
            )
            self.store.remember_idempotency_key(
                state.approval_command.idempotency_key,
                "approval_command",
                state.id,
            )
            self._add_step(state, len(state.plan_steps) + 1, "Receive structured human approval", "Authorized approver approved the exact rollback request.")
            self._checkpoint(state)

        if not state.approval_command:
            self._checkpoint(state)
            return state

        return self._continue_after_approval(state)

    def _continue_after_approval(self, state: InvestigationState) -> InvestigationState:
        primary_service = state.service_priority[0] if state.service_priority else "payment-service"
        if state.approval_command:
            rejection_reason = self._approval_command_rejection_reason(state, state.approval_command)
            if rejection_reason:
                return self._reject_approval_command(state, state.approval_command, rejection_reason)
        state.status = InvestigationStatus.RUNNING
        self._transition(state, StateName.REMEDIATION)
        self._execute_remediation(state)
        remediation_detail = (
            state.remediation_result.message
            if state.remediation_result
            else "Remediation did not produce a result."
        )
        self._add_step(
            state,
            len(state.plan_steps) + 1,
            "Execute approved remediation and verify mitigation",
            remediation_detail,
        )
        self._checkpoint(state)

        self._transition(state, StateName.POST_MORTEM)
        state.post_mortem = self._build_post_mortem(state)
        post_mortem_message = self._post_mortem_message(state.post_mortem)
        for tool_name, payload in [
            (
                "comms.write_post_mortem",
                self._comms_payload(
                    state,
                    primary_service,
                    {
                        "incident_id": state.incident_id,
                        "message": post_mortem_message,
                    },
                ),
            ),
            (
                "comms.create_jira_ticket",
                self._comms_payload(
                    state,
                    primary_service,
                    {
                        "owner": "payments-platform",
                        "title": f"SENTINEL follow-up: {state.incident_id} {primary_service}",
                        "body": post_mortem_message,
                    },
                ),
            ),
            (
                "comms.update_runbook",
                self._comms_payload(
                    state,
                    primary_service,
                    {
                        "runbook": "payments latency",
                        "content": f"## SENTINEL update for {state.incident_id}\n{post_mortem_message}",
                    },
                ),
            ),
            ("comms.post_to_slack", self._comms_payload(state, primary_service, {"message": post_mortem_message})),
        ]:
            self._invoke_tool(state, tool_name, payload)
        self._add_step(state, len(state.plan_steps) + 1, "Draft post-mortem and follow-up", "Facts, inferences, action item, runbook update, and Slack draft were produced.")
        state.status = InvestigationStatus.COMPLETED
        self._checkpoint(state)
        return state

    def _run_slow_query_incident(
        self,
        state: InvestigationState,
        primary_service: str,
        *,
        auto_approve: bool,
    ) -> InvestigationState:
        self._transition(state, StateName.RECEIVED)
        self._tool_step(
            state,
            1,
            "Create incident channel",
            "comms.create_incident_channel",
            {
                "service": primary_service,
                "channel_name": f"inc-{state.incident_id}-{primary_service}",
            },
        )
        self._tool_step(
            state,
            2,
            "Post investigation acknowledgement",
            "comms.post_to_slack",
            self._comms_payload(
                state,
                primary_service,
                {"message": "SENTINEL is investigating a real /slow-query latency alert."},
            ),
        )
        self._tool_step(
            state,
            3,
            "Fetch generic webhook approver context",
            "comms.page_oncall_engineer",
            self._comms_payload(
                state,
                primary_service,
                {"incident_id": state.incident_id},
            ),
        )

        self._transition(state, StateName.TRIAGE)
        logs = self._invoke_tool(
            state,
            "observe.fetch_service_logs",
            observability_payload(state, primary_service),
        )
        self._add_step(
            state,
            4,
            "Read real Loki application logs",
            _tool_step_detail(logs),
            tool_name="observe.fetch_service_logs",
        )
        metrics = self._invoke_tool(
            state,
            "observe.query_metrics_range",
            self._slow_query_metric_payload(state, primary_service),
        )
        self._add_step(
            state,
            5,
            "Read real Prometheus latency metric",
            _tool_step_detail(metrics),
            tool_name="observe.query_metrics_range",
        )
        db_logs = self._invoke_tool(
            state,
            "observe.check_db_slow_queries",
            observability_payload(state, primary_service),
        )
        self._add_step(
            state,
            6,
            "Confirm slow SQLite query evidence",
            _tool_step_detail(db_logs),
            tool_name="observe.check_db_slow_queries",
        )

        state.diagnosis = self._derive_slow_query_diagnosis(state, logs, metrics, db_logs)
        self._transition(state, StateName.CORRELATION)
        self._add_step(state, 7, "Correlate Prometheus and Loki evidence", state.diagnosis.summary)
        if state.diagnosis.confidence == ConfidenceLevel.INSUFFICIENT:
            return self._finish_insufficient_confidence(
                state,
                message="Insufficient confidence: collect real Prometheus latency and Loki slow-query logs before remediation.",
                detail="Next evidence: real slow-query metric and log lines.",
            )

        self._transition(state, StateName.RESPONSE_PROPOSAL)
        state.recommendation = Recommendation(
            remediation_type="add_database_index",
            affected_service=primary_service,
            command="add_index orders.user_id",
            evidence_summary=state.diagnosis.summary,
            risk="Creates a SQLite index on orders.user_id; human approval required before mutating the live incident database.",
            rollback_plan="The migration is idempotent: CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id).",
            rollback_target="orders.user_id",
            executable=True,
        )
        approver_ids = _authorized_approver_ids(state)
        if not approver_ids:
            return self._finish_insufficient_confidence(
                state,
                message="Insufficient confidence: no generic webhook approver was configured.",
                detail="Next evidence: configured SENTINEL_APPROVER_ID.",
            )
        approval_request = ApprovalRequest(
            incident_id=state.incident_id,
            remediation=state.recommendation,
            approver_ids=approver_ids,
            approval_snapshot={
                "diagnosis": state.diagnosis.summary,
                "confidence": state.diagnosis.confidence.value,
                "evidence_count": len(state.evidence),
                "state": state.current_state.value,
                "status": state.status.value,
                "recommendation": state.recommendation.model_dump(mode="json"),
                "artifacts": state.artifacts,
            },
            idempotency_key=f"{state.id}:approval:add-index-{primary_service}",
        )
        state.approval_request = approval_request
        approval_notification = self._invoke_tool(
            state,
            "comms.post_to_slack",
            self._comms_payload(
                state,
                primary_service,
                {
                    "approval_request_id": approval_request.id,
                    "message": self._approval_proposal_message(state, approval_request),
                },
            ),
        )
        self._add_step(
            state,
            8,
            "Request structured add-index approval",
            (
                "Approval request posted to Discord."
                if approval_notification.success
                else approval_notification.error_message or "Approval request notification failed."
            ),
            tool_name="comms.post_to_slack",
        )
        approval_notification_confirmed = (
            _tool_result_confirmed_for_live(approval_notification, "comms.post_to_slack")
            if state.scenario_name == "live"
            else approval_notification.success
        )
        if not approval_notification_confirmed:
            state.status = InvestigationStatus.FAILED
            state.approval_request = None
            state.context_summary = "Approval request notification failed; no active approval request was created."
            self._audit(
                state,
                "approval_request_notification_failed",
                {
                    "tool_name": "comms.post_to_slack",
                    "error_kind": approval_notification.error_kind,
                    "error_message": (
                        approval_notification.error_message
                        if not approval_notification.success
                        else "Approval request notification lacked provider-confirming Slack evidence."
                    ),
                },
            )
            self._checkpoint(state)
            return state

        state.artifacts["approval_slack_notified"] = True
        state.artifacts["approval_slack_notification_request_id"] = approval_request.id
        notification_provider = approval_notification.data.get("provider")
        if isinstance(notification_provider, str) and notification_provider.strip():
            state.artifacts["approval_notification_provider"] = notification_provider.strip()
        state.status = InvestigationStatus.WAITING_FOR_APPROVAL
        if auto_approve:
            state.approval_command = ApprovalCommand(
                request_id=approval_request.id,
                approver_id=approver_ids[0],
                decision="approve",
                idempotency_key=f"{state.id}:approval-command:add-index-{primary_service}",
            )
            self.store.remember_idempotency_key(
                state.approval_command.idempotency_key,
                "approval_command",
                state.id,
            )
            self._add_step(state, 9, "Receive structured human approval", "Authorized approver approved the exact add-index request.")
            self._checkpoint(state)
            return self._continue_after_approval(state)
        self._checkpoint(state)
        return state

    def _run_watch(self, state: InvestigationState) -> InvestigationState:
        self._transition(state, StateName.RECEIVED)
        for index, tool_name in enumerate(self._plan(state, "Acknowledge proactive Watch"), start=1):
            self._tool_step(state, index, f"Watch acknowledgement with {tool_name}", tool_name, {"service": "checkout-service"})

        self._transition(state, StateName.TRIAGE)
        for index, tool_name in enumerate(self._plan(state, "Triage Watch anomaly"), start=2):
            self._tool_step(state, index, f"Watch triage with {tool_name}", tool_name, {"service": "checkout-service"})

        self._transition(state, StateName.EVIDENCE_COLLECTION)
        for index, tool_name in enumerate(self._plan(state, "Collect Watch evidence"), start=5):
            self._tool_step(state, index, f"Watch evidence with {tool_name}", tool_name, {"service": "checkout-service"})

        self._transition(state, StateName.CORRELATION)
        self._invoke_tool(state, "observe.check_uptime_history", {"service": "checkout-service"})
        state.diagnosis = Diagnosis(
            summary="Watch observed checkout error rate trending up before alert threshold.",
            confidence=ConfidenceLevel.MEDIUM,
            evidence=state.evidence,
            evidence_gaps=["Watch has no incident powers and cannot execute remediation."],
        )
        self._add_step(state, 8, "Correlate Watch evidence", state.diagnosis.summary)

        self._transition(state, StateName.RESPONSE_PROPOSAL)
        self._invoke_tool(
            state,
            "comms.post_to_slack",
            {"service": "checkout-service", "message": "Watch anomaly detected; monitoring only."},
        )
        self._add_step(state, 9, "Post Watch update", "No remediation requested or executed.")

        self._transition(state, StateName.POST_MORTEM)
        self._invoke_tool(
            state,
            "comms.update_runbook",
            {
                "service": "checkout-service",
                "content": "## SENTINEL Watch update\nWatch detected checkout anomaly and remained monitoring-only.",
            },
        )
        state.status = InvestigationStatus.COMPLETED
        self._checkpoint(state)
        return state

    def _plan(self, state: InvestigationState, objective: str) -> list[str]:
        assert self.registry
        available = [
            contract
            for contract in self.registry.list_contracts()
            if state.current_state in contract.phase_allowlist
        ]
        return self.model_client.plan_tools(
            state=state,
            available_contracts=available,
            objective=objective,
            all_contracts=self.registry.list_contracts(),
        )

    def _tool_step(
        self,
        state: InvestigationState,
        number: int,
        action: str,
        tool_name: str,
        payload: dict[str, Any],
    ):
        result = self._invoke_tool(state, tool_name, payload)
        self._add_step(
            state,
            number,
            action,
            _tool_step_detail(result),
            tool_name=tool_name,
        )

    def _comms_payload(
        self,
        state: InvestigationState,
        service: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        routed = {"service": service, **payload}
        channel = state.artifacts.get("slack_channel_id")
        if channel:
            routed.setdefault("channel", channel)
        return routed

    def _approval_proposal_message(
        self,
        state: InvestigationState,
        approval_request: ApprovalRequest,
    ) -> str:
        recommendation = approval_request.remediation
        diagnosis = state.diagnosis.summary if state.diagnosis else "Diagnosis unavailable."
        evidence_summary = recommendation.evidence_summary or diagnosis
        confidence = state.diagnosis.confidence.value if state.diagnosis else "unknown"
        return (
            f"SENTINEL rollback proposal for {recommendation.affected_service}\n"
            f"Diagnosis: {diagnosis}\n"
            f"Confidence: {confidence}\n"
            f"Evidence summary: {evidence_summary} Evidence records collected: {len(state.evidence)}.\n"
            f"Recommendation: {recommendation.command}\n"
            f"Approval request id: {approval_request.id}\n"
            "Human approval boundary: remediation will not execute from Slack text or reactions; "
            "submit the structured approval command with this exact approval_request_id."
        )

    def _post_mortem_message(self, post_mortem: PostMortem) -> str:
        action_items = ", ".join(post_mortem.proposed_action_items) or "No proposed action items."
        timeline = "\n".join(f"- {item}" for item in post_mortem.timeline)
        facts = "\n".join(f"- {item}" for item in post_mortem.facts)
        return (
            f"{post_mortem.summary}\n"
            f"Timeline:\n{timeline}\n"
            f"Facts:\n{facts}\n"
            f"Action items: {action_items}"
        )

    def _invoke_tool(
        self,
        state: InvestigationState,
        tool_name: str,
        payload: dict[str, Any],
        *,
        approved: bool = False,
    ):
        assert self.executor
        result = self.executor.invoke(
            tool_name,
            payload,
            investigation_id=state.id,
            state=state.current_state,
            approved=approved,
        )
        if result.success:
            state.evidence.extend(result.evidence)
            self._collect_artifacts_from_result(state, result.data)
        else:
            gap = Evidence(
                source=tool_name,
                time_window=payload.get("time_window", "unknown"),
                affected_service=payload.get("service", "unknown"),
                claim=f"evidence gap: {tool_name} failed with {result.error_kind}",
                provenance=f"{state.scenario_name}:{tool_name}:failure",
            )
            state.evidence.append(gap)
        state.tool_calls = self.store.list_tool_calls(state.id)
        self._checkpoint(state)
        return result

    def _spawn_service_investigator(
        self,
        state: InvestigationState,
        service_name: str,
    ) -> ServiceIncidentReport | None:
        result = self._invoke_tool(
            state,
            "infra.spawn_service_investigator",
            {
                "service": service_name,
                "service_name": service_name,
                "objective": f"Investigate {service_name} with scoped read-only tools.",
            },
        )
        if not result.success:
            return None
        service_report = result.data.get("service_report")
        if not isinstance(service_report, dict):
            state.evidence.append(
                Evidence(
                    source="infra.spawn_service_investigator",
                    time_window="unknown",
                    affected_service=service_name,
                    claim="evidence gap: service investigator did not return ServiceIncidentReport",
                    provenance=f"{state.scenario_name}:infra.spawn_service_investigator:contract",
                )
            )
            return None
        return ServiceIncidentReport.model_validate(service_report)

    def _repo_payload(self, state: InvestigationState, service: str) -> dict[str, Any]:
        payload: dict[str, Any] = repository_payload(state, service)
        pr_number = state.artifacts.get("pull_request")
        if pr_number:
            payload["pull_request"] = pr_number
        elif state.scenario_name != "live":
            payload["pull_request"] = 847
        ref = state.artifacts.get("deployment_ref") or state.artifacts.get("commit_sha")
        if ref:
            payload["ref"] = ref
        return payload

    def _blame_payload(self, state: InvestigationState, service: str) -> dict[str, Any]:
        payload = self._repo_payload(state, service)
        if state.scenario_name != "live":
            payload.update({"file": "orders.py", "line": 84})
        elif state.artifacts.get("changed_file"):
            payload["path"] = state.artifacts["changed_file"]
        return payload

    def _slow_query_metric_payload(self, state: InvestigationState, service: str) -> dict[str, Any]:
        payload = observability_payload(state, service)
        payload.update(
            {
                "metric": "sentinel.slow_query.duration",
                "prometheus_query": f'sentinel_slow_query_last_duration_seconds{{service="{_prometheus_label_value(service)}"}}',
            }
        )
        return payload

    def _derive_slow_query_diagnosis(
        self,
        state: InvestigationState,
        logs,
        metrics,
        db_logs,
    ) -> Diagnosis:
        latest_seconds = _latest_prometheus_value(metrics.data)
        state.artifacts["slow_query_prometheus_latest_seconds"] = latest_seconds
        state.artifacts["slow_query_loki_missing_index"] = _loki_mentions_missing_index(logs.data) or _loki_mentions_missing_index(db_logs.data)
        metric_ok = latest_seconds is not None and latest_seconds > 0
        loki_ok = state.artifacts["slow_query_loki_missing_index"] is True
        if not metric_ok or not loki_ok:
            gaps = []
            if not metric_ok:
                gaps.append("Prometheus did not return a real /slow-query latency sample.")
            if not loki_ok:
                gaps.append("Loki did not return a slow-query log mentioning the missing orders.user_id index.")
            return Diagnosis(
                summary="Insufficient confidence: real Prometheus and Loki evidence did not both prove the missing-index incident.",
                confidence=ConfidenceLevel.INSUFFICIENT,
                evidence=state.evidence,
                evidence_gaps=gaps,
            )
        duration_ms = latest_seconds * 1000
        return Diagnosis(
            summary=(
                "Real /slow-query incident: Prometheus recorded "
                f"{duration_ms:.1f}ms latency and Loki logs show SELECT * FROM orders "
                "WHERE user_id = ? using a sequential scan because orders.user_id has no index. "
                "Root cause: missing SQLite index orders.user_id."
            ),
            confidence=ConfidenceLevel.HIGH,
            evidence=state.evidence,
        )

    def _collect_artifacts_from_result(self, state: InvestigationState, data: dict[str, Any]) -> None:
        provider = data.get("provider")
        tool_name = data.get("tool")
        if isinstance(provider, str) and provider.strip() and isinstance(tool_name, str) and tool_name.strip():
            providers = state.artifacts.setdefault("live_tool_providers", {})
            if isinstance(providers, dict):
                providers[tool_name] = provider.strip()
            if tool_name.startswith("comms."):
                state.artifacts.setdefault("comms_provider", provider.strip())
                content = data.get("content")
                if provider.strip() == "discord" and isinstance(content, str) and content.strip():
                    state.artifacts["last_discord_message"] = content.strip()

        channel = data.get("channel")
        if isinstance(channel, dict):
            channel_id = channel.get("id")
            channel_name = channel.get("name")
            if channel_id:
                state.artifacts.setdefault("slack_channel_id", channel_id)
            if channel_name:
                state.artifacts.setdefault("slack_channel_name", channel_name)
        elif isinstance(channel, str) and channel:
            state.artifacts.setdefault("slack_channel_id", channel)

        incident = data.get("incident")
        if isinstance(incident, dict):
            if incident.get("status"):
                state.artifacts.setdefault("pagerduty_incident_status", incident["status"])
            if incident.get("urgency"):
                state.artifacts.setdefault("pagerduty_incident_urgency", incident["urgency"])
            html_url = incident.get("html_url") or incident.get("self")
            if html_url:
                state.artifacts.setdefault("pagerduty_incident_url", html_url)

        oncalls = data.get("oncalls")
        oncall_scope = data.get("oncall_scope")
        policy_ids = data.get("escalation_policy_ids")
        if isinstance(oncall_scope, str) and oncall_scope:
            state.artifacts.setdefault("pagerduty_oncall_scope", oncall_scope)
        if isinstance(policy_ids, list) and all(isinstance(item, str) for item in policy_ids):
            state.artifacts.setdefault("pagerduty_escalation_policy_ids", list(policy_ids))
        if isinstance(oncalls, list) and oncalls:
            user = oncalls[0].get("user") if isinstance(oncalls[0], dict) else None
            if isinstance(user, dict):
                if state.scenario_name == "live":
                    user_id = user.get("id")
                    scoped_oncall = oncall_scope in {"incident_escalation_policy", "generic_webhook"}
                else:
                    user_id = user.get("id") or user.get("summary")
                    scoped_oncall = True
                if user_id and scoped_oncall:
                    state.artifacts.setdefault("pagerduty_oncall_user", user_id)
                    if oncall_scope == "generic_webhook":
                        state.artifacts.setdefault("generic_webhook_approver", user_id)
        paged_user = data.get("paged_user")
        if state.scenario_name != "live" and isinstance(paged_user, str) and paged_user:
            state.artifacts.setdefault("pagerduty_oncall_user", paged_user)

        target = data.get("target")
        if _is_executable_live_target(target):
            state.artifacts.setdefault("rollback_target", target)

        rollout = data.get("rollout")
        if isinstance(rollout, dict):
            previous_revision = rollout.get("previous_revision")
            current_revision = rollout.get("current_revision")
            if current_revision:
                state.artifacts.setdefault("current_rollout_revision", current_revision)
            if _is_executable_live_target(previous_revision):
                state.artifacts.setdefault("rollback_target", previous_revision)

        deployments = data.get("deployments")
        if isinstance(deployments, list) and deployments:
            latest = deployments[0]
            latest_summary = _deployment_artifact_summary(latest)
            if latest_summary:
                state.artifacts.setdefault("latest_deployment", latest_summary)
            ref = latest.get("ref") or latest.get("sha")
            if ref:
                state.artifacts.setdefault("deployment_ref", ref)
            sha = latest.get("sha")
            if sha:
                state.artifacts.setdefault("commit_sha", sha)
            latest_status = _deployment_latest_status(latest)
            if latest_status:
                state.artifacts.setdefault("latest_deployment_status", latest_status)
            latest_environment = _deployment_environment(latest)
            if latest_environment:
                state.artifacts.setdefault("latest_deployment_environment", latest_environment)
            if len(deployments) > 1:
                previous = deployments[1]
                previous_summary = _deployment_artifact_summary(previous)
                if previous_summary:
                    state.artifacts.setdefault("previous_deployment", previous_summary)
                previous_ref = previous.get("ref") or previous.get("sha")
                if previous_ref:
                    state.artifacts.setdefault("previous_deployment_ref", previous_ref)
                previous_status = _deployment_latest_status(previous)
                if previous_status:
                    state.artifacts.setdefault("previous_deployment_status", previous_status)
                previous_target = _deployment_rollout_target(previous)
                if previous_target:
                    state.artifacts.setdefault("rollback_target", previous_target)

        commits = data.get("commits")
        if isinstance(commits, list) and commits:
            first = commits[0]
            sha = first.get("sha")
            if sha:
                state.artifacts.setdefault("commit_sha", sha)
            message = str((first.get("commit") or {}).get("message") or "")
            match = re.search(r"#(\d+)", message)
            if match:
                state.artifacts.setdefault("pull_request", int(match.group(1)))

        pull_request = data.get("pull_request")
        if isinstance(pull_request, dict):
            number = pull_request.get("number")
            if number:
                state.artifacts["pull_request"] = number
            if pull_request.get("title"):
                state.artifacts["pull_request_title"] = pull_request["title"]
            if pull_request.get("head", {}).get("sha"):
                state.artifacts.setdefault("commit_sha", pull_request["head"]["sha"])

        files = data.get("files")
        if isinstance(files, list) and files:
            filename = files[0].get("filename")
            if filename:
                state.artifacts.setdefault("changed_file", filename)

    def _derive_diagnosis(self, state: InvestigationState) -> Diagnosis:
        failed_trace = any(
            call.tool_name == "observe.get_distributed_traces" and not call.success
            for call in self.store.list_tool_calls(state.id)
        )
        if failed_trace:
            return Diagnosis(
                summary="Insufficient confidence because trace evidence is unavailable.",
                confidence=ConfidenceLevel.INSUFFICIENT,
                evidence=state.evidence,
                evidence_gaps=["observe.get_distributed_traces unavailable; collect trace evidence next."],
            )
        if state.scenario_name == "live":
            source = _live_change_artifact(state)
            if not source:
                return Diagnosis(
                    summary="Insufficient confidence because no live change artifact was found for the incident window.",
                    confidence=ConfidenceLevel.INSUFFICIENT,
                    evidence=state.evidence,
                    evidence_gaps=[
                        "Collect a recent deployment, commit, or pull request artifact before proposing rollback.",
                    ],
                )
            pr = state.artifacts.get("pull_request")
            title = state.artifacts.get("pull_request_title")
            title_part = f" ({title})" if title else ""
            return Diagnosis(
                summary=f"Live evidence correlates {primary_source(source, title_part)} with {state.service_priority[0] if state.service_priority else 'the affected service'} degradation.",
                confidence=ConfidenceLevel.MEDIUM,
                evidence=state.evidence,
            )
        return Diagnosis(
            summary=(
                "PR #847 by @alice added SELECT * FROM orders WHERE user_id = ? "
                "without an index on orders.user_id, causing sequential scans. "
                "Query time: 4ms \u2192 2.3s (575x)."
            ),
            confidence=ConfidenceLevel.HIGH,
            evidence=state.evidence,
        )

    def _reconcile_evidence(
        self,
        state: InvestigationState,
        service_reports: list[ServiceIncidentReport],
        blast_report: BlastRadiusReport,
        readiness_report: RemediationReadinessReport,
    ) -> Diagnosis:
        gaps = [gap for report in service_reports for gap in report.evidence_gaps]
        gaps.extend(readiness_report.blockers)
        confidence = ConfidenceLevel.HIGH if not gaps else ConfidenceLevel.LOW
        if state.scenario_name == "live":
            source = _live_change_artifact(state)
            if not source:
                gaps.append(
                    "No live deployment, commit, or pull request artifact was collected for the incident window."
                )
                confidence = ConfidenceLevel.INSUFFICIENT
                source = "missing live change evidence"
            summary = (
                f"Reconciled live evidence points to {source} as the likely change associated "
                f"with {state.service_priority[0] if state.service_priority else 'the affected service'} degradation."
            )
        else:
            summary = (
                "PR #847 by @alice added SELECT * FROM orders WHERE user_id = ? "
                "without an index on orders.user_id, causing sequential scans. "
                f"Query time: 4ms \u2192 2.3s (575x). Affected users: "
                f"{blast_report.affected_users} in checkout payment authorization. "
                "Confirmed missing index: orders.user_id."
            )
        return Diagnosis(
            summary=summary,
            confidence=confidence,
            evidence=state.evidence,
            evidence_gaps=gaps,
        )

    def _build_recommendation(self, state: InvestigationState) -> Recommendation:
        primary_service = state.service_priority[0] if state.service_priority else "payment-service"
        target = _validated_remediation_target(state)
        if not target and state.scenario_name == "live":
            return Recommendation(
                remediation_type="rollback",
                affected_service=primary_service,
                command=f"collect Kubernetes rollout revision target for {primary_service} before rollback",
                evidence_summary=state.diagnosis.summary if state.diagnosis else "",
                risk="Live rollback cannot execute safely without an explicit Kubernetes revision target.",
                rollback_plan=(
                    f"Collect repo.get_rollback_targets evidence for {primary_service}, confirm a "
                    "revision:<n> target, then request a new structured approval."
                ),
                rollback_target=None,
                executable=False,
            )
        if not target and state.scenario_name != "live":
            target = "v2.3.1"
        command = f"rollback {primary_service} to {target}"
        return Recommendation(
            remediation_type="rollback",
            affected_service=primary_service,
            command=command,
            evidence_summary=state.diagnosis.summary if state.diagnosis else "",
            risk=(
                "Requires human approval; rollback mitigates the incident, while "
                "add_index :orders, :user_id is the durable correction."
            ),
            rollback_plan=(
                f"Restore {primary_service} to {target}; verify payment latency recovers, "
                "then create the add_index follow-up."
            ),
            rollback_target=target,
            executable=True,
        )

    def _execute_remediation(self, state: InvestigationState) -> None:
        primary_service = state.service_priority[0] if state.service_priority else "payment-service"
        remediation_idem = f"{state.id}:remediation:rollback-{primary_service}"
        if not state.approval_request or not state.approval_command:
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=primary_service,
                status="refused",
                idempotency_key=remediation_idem,
                message="No valid human approval was present.",
            )
            return
        if state.approval_command.request_id != state.approval_request.id:
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=primary_service,
                status="refused",
                idempotency_key=remediation_idem,
                message="Approval command did not match the approval request.",
            )
            return
        if not _approval_slack_notification_confirmed(state):
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=primary_service,
                status="refused",
                idempotency_key=remediation_idem,
                message="Approval request Slack notification was not confirmed for the active approval request.",
            )
            return
        if state.approval_command.approver_id not in state.approval_request.approver_ids:
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=primary_service,
                status="refused",
                idempotency_key=remediation_idem,
                message="Approval command was not sent by an authorized approver.",
            )
            return
        if state.approval_request.expires_at < now_utc():
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=primary_service,
                status="refused",
                idempotency_key=remediation_idem,
                message="Approval request expired before remediation execution.",
            )
            return
        if state.approval_command.decision != "approve":
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=primary_service,
                status="refused",
                idempotency_key=remediation_idem,
                message="Approval command rejected remediation.",
            )
            return

        if state.approval_request.remediation.remediation_type == "add_database_index":
            self._execute_add_index_remediation(state)
            return

        approved_service, target, refusal = _approved_rollback_scope(state)
        if refusal:
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=approved_service or primary_service,
                status="refused",
                idempotency_key=remediation_idem,
                message=refusal,
            )
            return
        assert approved_service is not None

        idem = f"{state.id}:remediation:rollback-{approved_service}"
        if not self.store.remember_idempotency_key(idem, "remediation", state.id):
            state.remediation_result = RemediationResult(
                action="rollback",
                affected_service=approved_service,
                status="skipped",
                idempotency_key=idem,
                message="Duplicate remediation suppressed by idempotency key.",
            )
            return

        rollback_payload = {"service": approved_service}
        if target:
            rollback_payload["target"] = target
        rollback = self._invoke_tool(
            state,
            "infra.rollback_deployment",
            rollback_payload,
            approved=True,
        )
        verify = self._invoke_tool(
            state,
            "observe.get_error_rate_timeseries",
            (
                observability_payload(state, approved_service)
                if state.scenario_name == "live"
                else {"service": approved_service, "time_window": "post-rollback"}
            ),
        )
        if state.scenario_name == "live":
            rollback_confirmed = _tool_result_confirmed_for_live(
                rollback,
                "infra.rollback_deployment",
            )
            verify_confirmed = _tool_result_confirmed_for_live(
                verify,
                "observe.get_error_rate_timeseries",
            )
        else:
            rollback_confirmed = rollback.success
            verify_confirmed = verify.success
        remediation_executed = rollback_confirmed and verify_confirmed
        state.remediation_result = RemediationResult(
            action="rollback",
            affected_service=approved_service,
            status="executed" if remediation_executed else "failed",
            idempotency_key=idem,
            evidence=rollback.evidence + verify.evidence,
            message=(
                f"Rollback executed and {approved_service} metrics recovered toward baseline."
                if remediation_executed
                else f"Rollback did not produce provider-confirming execution and verification evidence for {approved_service}."
            ),
        )

    def _execute_add_index_remediation(self, state: InvestigationState) -> None:
        primary_service = state.service_priority[0] if state.service_priority else "payment-service"
        approved_service, target, refusal = _approved_add_index_scope(state)
        idem = f"{state.id}:remediation:add-index-{approved_service or primary_service}"
        if refusal:
            state.remediation_result = RemediationResult(
                action="add_database_index",
                affected_service=approved_service or primary_service,
                status="refused",
                idempotency_key=idem,
                message=refusal,
            )
            return
        assert approved_service is not None
        if not self.store.remember_idempotency_key(idem, "remediation", state.id):
            state.remediation_result = RemediationResult(
                action="add_database_index",
                affected_service=approved_service,
                status="skipped",
                idempotency_key=idem,
                message="Duplicate add-index remediation suppressed by idempotency key.",
            )
            return
        migration = self._invoke_tool(
            state,
            "infra.add_database_index",
            {
                "service": approved_service,
                "table": "orders",
                "column": "user_id",
                "target": target or "orders.user_id",
            },
            approved=True,
        )
        if state.scenario_name == "live":
            time.sleep(6)
        verify = self._invoke_tool(
            state,
            "observe.query_metrics_range",
            self._slow_query_metric_payload(state, approved_service),
        )
        latest_seconds = _latest_prometheus_value(verify.data)
        state.artifacts["slow_query_prometheus_after_fix_seconds"] = latest_seconds
        migration_confirmed = (
            _tool_result_confirmed_for_live(migration, "infra.add_database_index")
            if state.scenario_name == "live"
            else migration.success
        )
        verify_confirmed = (
            _tool_result_confirmed_for_live(verify, "observe.query_metrics_range")
            if state.scenario_name == "live"
            else verify.success
        )
        before = state.artifacts.get("slow_query_prometheus_latest_seconds")
        improved = (
            isinstance(before, (int, float))
            and isinstance(latest_seconds, (int, float))
            and latest_seconds < before
        )
        executed = migration_confirmed and verify_confirmed and improved
        before_ms = float(before) * 1000 if isinstance(before, (int, float)) else None
        after_ms = float(latest_seconds) * 1000 if isinstance(latest_seconds, (int, float)) else None
        improvement = (
            f"real Prometheus latency improved from {before_ms:.1f}ms to {after_ms:.1f}ms"
            if before_ms is not None and after_ms is not None
            else "real Prometheus latency verification was inconclusive"
        )
        state.remediation_result = RemediationResult(
            action="add_database_index",
            affected_service=approved_service,
            status="executed" if executed else "failed",
            idempotency_key=idem,
            evidence=migration.evidence + verify.evidence,
            message=(
                f"Created idx_orders_user_id on orders(user_id); {improvement}."
                if executed
                else f"Index migration did not produce complete provider-confirming evidence; {improvement}."
            ),
        )

    def _build_post_mortem(self, state: InvestigationState) -> PostMortem:
        primary_service = state.service_priority[0] if state.service_priority else "payment-service"
        if state.scenario_name == "live":
            if state.artifacts.get("slow_query_incident") is True:
                before = state.artifacts.get("slow_query_prometheus_latest_seconds")
                after = state.artifacts.get("slow_query_prometheus_after_fix_seconds")
                before_text = f"{float(before) * 1000:.1f}ms" if isinstance(before, (int, float)) else "unknown"
                after_text = f"{float(after) * 1000:.1f}ms" if isinstance(after, (int, float)) else "unknown"
                return PostMortem(
                    summary=(
                        f"{primary_service} /slow-query incident was caused by a real missing SQLite "
                        "index on orders.user_id and mitigated by creating idx_orders_user_id."
                    ),
                    timeline=[
                        "Generic Prometheus alert webhook received by SENTINEL.",
                        "SENTINEL read real Loki app logs for /slow-query slow-query events.",
                        f"SENTINEL read real Prometheus latency: before fix {before_text}.",
                        "SENTINEL requested human approval for add_index orders.user_id.",
                        "Authorized approver approved the exact add-index request.",
                        "SENTINEL executed CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id).",
                        f"SENTINEL verified real Prometheus latency after fix: {after_text}.",
                        "SENTINEL posted the full incident timeline to Discord.",
                    ],
                    facts=[
                        "The app executed SELECT * FROM orders WHERE user_id = ? against SQLite.",
                        "Loki logs showed the query using a sequential scan while the index was missing.",
                        f"Prometheus recorded /slow-query latency before fix: {before_text}.",
                        f"Prometheus recorded /slow-query latency after fix: {after_text}.",
                        "The approved remediation created idx_orders_user_id on orders(user_id).",
                    ],
                    inferences=[
                        "The missing orders.user_id index was the real root cause of the latency spike.",
                    ],
                    contributing_factors=[
                        "The slow endpoint intentionally started with no index on orders.user_id.",
                    ],
                    proposed_action_items=[
                        "Keep idx_orders_user_id in the schema before enabling this query path.",
                    ],
                    accepted_action_items=[
                        "SENTINEL created idx_orders_user_id after human approval.",
                    ],
                )
            source = state.artifacts.get("pull_request") or state.artifacts.get("deployment_ref") or state.artifacts.get("commit_sha") or "recent deploy"
            return PostMortem(
                summary=f"{primary_service} live incident investigation completed with rollback recommendation.",
                timeline=[
                    "PagerDuty webhook received by SENTINEL.",
                    "SENTINEL gathered live observability, repository, infrastructure, and communication evidence.",
                    "SENTINEL proposed a human-approved rollback remediation.",
                ],
                facts=[
                    f"Affected service: {primary_service}.",
                    f"Primary change artifact: {source}.",
                ],
                inferences=[
                    "The live change artifact is the likely remediation candidate based on collected evidence.",
                ],
                contributing_factors=["Requires human review against live production context."],
                proposed_action_items=["Review rollout evidence and approve or reject rollback."],
                accepted_action_items=[],
            )
        return PostMortem(
            summary=(
                f"{primary_service} latency incident caused by PR #847 commit abc1234 "
                "was mitigated by rollback to v2.3.1."
            ),
            timeline=[
                "02:58 UTC: payment-service v2.3.2 deployed from PR #847 commit abc1234 by @alice.",
                "03:12 UTC: PagerDuty incident opened in the incident system of record.",
                "03:13 UTC: logs showed slow SELECT * FROM orders WHERE user_id = ? calls.",
                "03:14 UTC: metrics showed payment latency moved from 4ms to 2.3s.",
                "03:15 UTC: PR diff and blame linked the missing orders.user_id index to @alice.",
                "03:16 UTC: SENTINEL requested human approval for rollback and proposed add_index follow-up.",
                "03:17 UTC: Authorized approver approved rollback.",
                "03:18 UTC: rollback to v2.3.1 executed and metrics recovered.",
                "03:19 UTC: SENTINEL posted the full incident timeline to Discord.",
            ],
            facts=[
                "PR #847 commit abc1234 was authored by @alice.",
                "PR #847 added SELECT * FROM orders WHERE user_id = ?.",
                "orders.user_id had no supporting index.",
                "orders.user_id query latency increased from 4ms to 2.3s (575x).",
                "payment-service rollback to v2.3.1 executed after human approval.",
            ],
            inferences=[
                "The missing index caused sequential scans and was the causal factor for the latency regression.",
                "A migration test focused on high-cardinality user lookup would have caught the risk.",
            ],
            contributing_factors=[
                "Query plan regression was not covered by tests.",
                "Deploy happened shortly before the alert window.",
            ],
            proposed_action_items=[
                "Add an index on orders.user_id.",
                "Add regression tests for checkout order lookup latency.",
            ],
            accepted_action_items=[
                "payments-platform owns SRE-1847 to add orders.user_id index.",
            ],
        )

    def _finish_insufficient_confidence(
        self,
        state: InvestigationState,
        *,
        message: str = "Insufficient confidence: collect trace evidence before remediation.",
        detail: str = "Next evidence: distributed traces.",
    ) -> InvestigationState:
        self._transition(state, StateName.RESPONSE_PROPOSAL)
        state.status = InvestigationStatus.INSUFFICIENT_CONFIDENCE
        self._invoke_tool(
            state,
            "comms.post_to_slack",
            self._comms_payload(
                state,
                state.service_priority[0] if state.service_priority else "unknown-service",
                {"message": message},
            ),
        )
        self._add_step(state, len(state.plan_steps) + 1, "Return Insufficient Confidence", detail)
        self._checkpoint(state)
        return state

    def _transition(self, state: InvestigationState, state_name: StateName) -> None:
        if state_name not in STATE_MACHINE:
            raise ValueError(f"Invalid state: {state_name}")
        state.current_state = state_name
        self._audit(state, "state_transition", {"state": state_name.value})
        self._checkpoint(state)

    def _add_step(
        self,
        state: InvestigationState,
        number: int,
        action: str,
        detail: str,
        *,
        tool_name: str | None = None,
    ) -> None:
        state.plan_steps.append(
            PlanStep(
                number=number,
                state=state.current_state,
                action=action,
                detail=detail,
                tool_name=tool_name,
            )
        )

    def _audit(self, state: InvestigationState, event_type: str, payload: dict[str, Any]) -> None:
        event = AuditEvent(
            investigation_id=state.id,
            event_type=event_type,
            payload=payload,
        )
        state.audit_events.append(event)
        self.store.append_audit_event(event)

    def _checkpoint(self, state: InvestigationState) -> None:
        state.tool_calls = self.store.list_tool_calls(state.id)
        self.store.save_state(state)

    def _prioritize_services(self, services: list[str]) -> list[str]:
        return list(dict.fromkeys(services))

    def _should_spawn_service_investigators(self, state: InvestigationState) -> bool:
        return len(state.affected_services) > 1


def _flatten_evidence(groups) -> list[Evidence]:
    flattened: list[Evidence] = []
    for group in groups:
        flattened.extend(group)
    return flattened


def _is_slow_query_webhook(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    haystack = jsonish_text(payload).lower()
    return "slow-query" in haystack or "slow_query" in haystack or "sentinelslowquerylatency" in haystack


def _prometheus_label_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _latest_prometheus_value(data: dict[str, Any]) -> float | None:
    prometheus = data.get("prometheus") if isinstance(data, dict) else None
    result = prometheus.get("result") if isinstance(prometheus, dict) else None
    if not isinstance(result, list):
        return None
    latest: tuple[float, float] | None = None
    for item in result:
        if not isinstance(item, dict):
            continue
        points = item.get("values")
        if isinstance(points, list):
            candidates = points
        else:
            value = item.get("value")
            candidates = [value] if isinstance(value, list) else []
        for point in candidates:
            if not isinstance(point, list) or len(point) < 2:
                continue
            try:
                timestamp = float(point[0])
                sample = float(point[1])
            except (TypeError, ValueError):
                continue
            if latest is None or timestamp >= latest[0]:
                latest = (timestamp, sample)
    return latest[1] if latest is not None else None


def _loki_mentions_missing_index(data: dict[str, Any]) -> bool:
    text = jsonish_text(data).lower()
    return (
        "slow_query" in text
        and "orders" in text
        and "user_id" in text
        and ("missing_index" in text or "missing index" in text or "scan orders" in text or "sequential scan" in text)
    )


def jsonish_text(value: Any) -> str:
    try:
        import json

        return json.dumps(value, sort_keys=True, default=str)
    except Exception:
        return str(value)


def _tool_step_detail(result) -> str:
    if result.success:
        observation = result.data.get("observation") if isinstance(result.data, dict) else None
        if isinstance(observation, str) and observation.strip():
            return observation
        provider = result.data.get("provider") if isinstance(result.data, dict) else None
        if isinstance(provider, str) and provider.strip():
            return f"{result.tool_name} completed via {provider.strip()}."
        return f"{result.tool_name} completed."
    return result.error_message or "tool failed"


def _authorized_approver_ids(state: InvestigationState) -> list[str]:
    if state.scenario_name != "live":
        return ["eng-oncall"]
    candidate = state.artifacts.get("pagerduty_oncall_user")
    if isinstance(candidate, str) and candidate.strip():
        return [candidate.strip()]
    return []


def _approval_slack_notification_confirmed(state: InvestigationState) -> bool:
    if state.scenario_name != "live":
        return True
    approval_request = state.approval_request
    if not approval_request:
        return False
    return (
        state.artifacts.get("approval_slack_notified") is True
        and state.artifacts.get("approval_slack_notification_request_id") == approval_request.id
    )


def _approved_rollback_scope(state: InvestigationState) -> tuple[str | None, str | None, str | None]:
    approval_request = state.approval_request
    if not approval_request:
        return None, None, "Investigation has no active approval request."
    remediation = approval_request.remediation
    primary_service = state.service_priority[0] if state.service_priority else None
    if remediation.remediation_type != "rollback":
        return remediation.affected_service, None, "Approved remediation was not a rollback."
    if not remediation.executable:
        return remediation.affected_service, None, "Approved remediation was not executable."
    if not primary_service:
        return remediation.affected_service, None, "Investigation has no primary service for rollback."
    if remediation.affected_service != primary_service:
        return (
            remediation.affected_service,
            None,
            "Approved rollback service did not match the current Investigation state.",
        )
    target = remediation.rollback_target or _target_from_rollback_command(
        remediation.command,
        remediation.affected_service,
    )
    if state.scenario_name == "live" and not _is_executable_live_target(target):
        return (
            remediation.affected_service,
            target,
            "Live rollback requires the approved recommendation to include an explicit Kubernetes revision target.",
        )
    if not target and state.scenario_name != "live":
        return remediation.affected_service, "v2.3.1", None
    return remediation.affected_service, target, None


def _approved_remediation_scope(state: InvestigationState) -> tuple[str | None, str | None, str | None]:
    approval_request = state.approval_request
    if not approval_request:
        return None, None, "Investigation has no active approval request."
    if approval_request.remediation.remediation_type == "add_database_index":
        return _approved_add_index_scope(state)
    return _approved_rollback_scope(state)


def _approved_add_index_scope(state: InvestigationState) -> tuple[str | None, str | None, str | None]:
    approval_request = state.approval_request
    if not approval_request:
        return None, None, "Investigation has no active approval request."
    remediation = approval_request.remediation
    primary_service = state.service_priority[0] if state.service_priority else None
    if remediation.remediation_type != "add_database_index":
        return remediation.affected_service, None, "Approved remediation was not an add-index migration."
    if not remediation.executable:
        return remediation.affected_service, None, "Approved remediation was not executable."
    if not primary_service:
        return remediation.affected_service, None, "Investigation has no primary service for index migration."
    if remediation.affected_service != primary_service:
        return (
            remediation.affected_service,
            None,
            "Approved add-index service did not match the current Investigation state.",
        )
    target = remediation.rollback_target or remediation.command.removeprefix("add_index").strip()
    normalized = target.replace(":", ".").replace(" ", "")
    if normalized not in {"orders.user_id", ".orders.user_id"}:
        return (
            remediation.affected_service,
            target,
            "Approved add-index target did not match orders.user_id.",
        )
    return remediation.affected_service, "orders.user_id", None


def _validated_remediation_target(state: InvestigationState) -> str | None:
    target = (
        state.remediation_readiness_report.safe_rollback_target
        if state.remediation_readiness_report
        else state.artifacts.get("rollback_target")
    )
    if state.scenario_name == "live" and not _is_executable_live_target(target):
        return None
    return target


def _tool_result_confirmed_for_live(result, tool_name: str) -> bool:
    if not result.success:
        return False
    live_evidence = [
        evidence
        for evidence in result.evidence
        if evidence.source == tool_name and evidence.provenance.startswith(("live::", "live_empty::"))
    ]
    return any(evidence.provenance == f"live::{tool_name}" for evidence in live_evidence)


def _is_executable_live_target(target: Any) -> bool:
    return isinstance(target, str) and bool(re.fullmatch(r"revision:\d+", target))


def _target_from_rollback_command(command: str, service: str) -> str | None:
    prefix = f"rollback {service} to "
    if not isinstance(command, str) or not command.startswith(prefix):
        return None
    target = command[len(prefix) :].strip()
    return target or None


def _live_change_artifact(state: InvestigationState) -> str | None:
    pr = state.artifacts.get("pull_request")
    if pr:
        return f"PR #{pr}"
    deployment = state.artifacts.get("deployment_ref")
    if deployment:
        return f"deployment {deployment}"
    commit = state.artifacts.get("commit_sha")
    if commit:
        return f"commit {commit}"
    return None


def _deployment_rollout_target(deployment: dict[str, Any]) -> str | None:
    metadata = deployment.get("metadata") if isinstance(deployment, dict) else None
    payload = deployment.get("payload") if isinstance(deployment, dict) else None
    candidates = [
        deployment.get("kubernetes_revision") if isinstance(deployment, dict) else None,
        deployment.get("k8s_revision") if isinstance(deployment, dict) else None,
        metadata.get("kubernetes_revision") if isinstance(metadata, dict) else None,
        metadata.get("k8s_revision") if isinstance(metadata, dict) else None,
        payload.get("kubernetes_revision") if isinstance(payload, dict) else None,
        payload.get("k8s_revision") if isinstance(payload, dict) else None,
    ]
    for candidate in candidates:
        if isinstance(candidate, int):
            return f"revision:{candidate}"
        if isinstance(candidate, str):
            if candidate.isdigit():
                return f"revision:{candidate}"
            if _is_executable_live_target(candidate):
                return candidate
    return None


def _deployment_artifact_summary(deployment: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("id", "sha", "ref", "html_url"):
        value = deployment.get(key)
        if isinstance(value, (str, int)) and value:
            summary[key] = value
    environment = _deployment_environment(deployment)
    if environment:
        summary["environment"] = environment
    latest_status = _deployment_latest_status(deployment)
    if latest_status:
        summary["latest_status"] = latest_status
    rollout_target = _deployment_rollout_target(deployment)
    if rollout_target:
        summary["rollout_target"] = rollout_target
    return summary


def _deployment_latest_status(deployment: dict[str, Any]) -> str | None:
    latest_status = deployment.get("latest_status")
    if isinstance(latest_status, dict):
        state = latest_status.get("state") or latest_status.get("status")
        return str(state) if state else None
    statuses = deployment.get("statuses")
    if isinstance(statuses, list) and statuses:
        first = statuses[0]
        if isinstance(first, dict):
            state = first.get("state") or first.get("status")
            return str(state) if state else None
    return None


def _deployment_environment(deployment: dict[str, Any]) -> str | None:
    environment = deployment.get("environment")
    if environment:
        return str(environment)
    latest_status = deployment.get("latest_status")
    if isinstance(latest_status, dict) and latest_status.get("environment"):
        return str(latest_status["environment"])
    return None


def primary_source(source: str, title_part: str) -> str:
    return f"{source}{title_part}".strip()
