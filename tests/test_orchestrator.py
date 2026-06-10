from datetime import timedelta

from sentinel.errors import ToolErrorKind, ToolExecutionError
from sentinel.models import (
    AuditEvent,
    ApprovalCommand,
    ApprovalRequest,
    ConfidenceLevel,
    Diagnosis,
    Evidence,
    InvestigationState,
    InvestigationStatus,
    Recommendation,
    STATE_MACHINE,
    ToolResult,
    now_utc,
)
from sentinel.orchestrator import SentinelOrchestrator, _tool_result_confirmed_for_live, _tool_step_detail
from sentinel.scenarios import build_scenarios
from sentinel.replay import ReplayIncidentEnvironment
from sentinel.store import SQLiteInvestigationStore
from sentinel.subagents import SubagentLauncher
from sentinel.time_windows import LIVE_OBSERVABILITY_WINDOW, LIVE_REPOSITORY_WINDOW
from sentinel.tools import ToolExecutor, ToolFactory


def test_golden_path_runs_8_state_26_step_post_mortem_flow(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    state = SentinelOrchestrator(store=store).run_scenario("golden_path")
    loaded = store.load_state(state.id)

    assert len(STATE_MACHINE) == 8
    assert state.status == InvestigationStatus.COMPLETED
    assert state.current_state.value == "post_mortem"
    assert len(state.plan_steps) == 26
    assert len(state.tool_calls) >= 26
    assert all(call.reasoning_trace for call in state.tool_calls)
    assert state.diagnosis is not None
    assert state.diagnosis.confidence == ConfidenceLevel.HIGH
    assert (
        "PR #847 by @alice added SELECT * FROM orders WHERE user_id = ? "
        "without an index on orders.user_id, causing sequential scans. "
        "Query time: 4ms \u2192 2.3s (575x)."
    ) in state.diagnosis.summary
    assert "missing index" in state.diagnosis.summary
    assert "orders.user_id" in state.diagnosis.summary
    assert state.remediation_result is not None
    assert state.remediation_result.status == "executed"
    assert state.post_mortem is not None
    assert state.post_mortem.facts
    assert state.post_mortem.inferences
    assert loaded.id == state.id
    assert store.count_rows("tool_calls") >= 26
    assert store.count_rows("schema_migrations") >= 2


def test_subagents_have_isolated_contexts_and_scoped_registries():
    state = SentinelOrchestrator().run_scenario("golden_path")

    service_contexts = {report.isolated_context_id for report in state.service_reports}
    assert len(service_contexts) == 2
    for report in state.service_reports:
        assert report.scoped_tool_names
        assert all(name.startswith(("observe.", "repo.")) for name in report.scoped_tool_names)
        assert not any(name.startswith(("infra.", "comms.")) for name in report.scoped_tool_names)

    assert state.blast_radius_report is not None
    assert state.remediation_readiness_report is not None
    all_contexts = {
        *service_contexts,
        state.blast_radius_report.isolated_context_id,
        state.remediation_readiness_report.isolated_context_id,
    }
    assert len(all_contexts) == 4
    assert all(name.startswith("observe.") for name in state.blast_radius_report.scoped_tool_names)
    assert all(
        name.startswith("repo.")
        for name in state.remediation_readiness_report.scoped_tool_names
    )


def test_service_investigator_tool_output_is_consumed_by_reconciliation():
    state = SentinelOrchestrator().run_scenario("golden_path")

    spawn_calls = [
        call for call in state.tool_calls if call.tool_name == "infra.spawn_service_investigator"
    ]
    assert len(spawn_calls) == len(state.service_reports) == 2
    assert state.blast_radius_report is not None
    assert state.remediation_readiness_report is not None

    service_report = state.service_reports[0].model_copy(
        update={"evidence_gaps": ["service-local dependency graph evidence missing"]}
    )
    diagnosis = SentinelOrchestrator()._reconcile_evidence(
        state,
        [service_report],
        state.blast_radius_report,
        state.remediation_readiness_report,
    )

    assert diagnosis.confidence == ConfidenceLevel.LOW
    assert "service-local dependency graph evidence missing" in diagnosis.evidence_gaps


def test_degraded_trace_scenario_returns_insufficient_confidence_without_rollback():
    state = SentinelOrchestrator().run_scenario("tool_degraded")

    assert state.status == InvestigationStatus.INSUFFICIENT_CONFIDENCE
    assert state.diagnosis is not None
    assert state.diagnosis.confidence == ConfidenceLevel.INSUFFICIENT
    assert state.diagnosis.evidence_gaps
    assert "infra.rollback_deployment" not in [call.tool_name for call in state.tool_calls]


def test_watch_scenario_does_not_gain_incident_powers():
    state = SentinelOrchestrator().run_scenario("watch")

    assert state.status == InvestigationStatus.COMPLETED
    assert state.trigger_kind == "watch"
    assert state.diagnosis is not None
    assert state.diagnosis.confidence == ConfidenceLevel.MEDIUM
    assert "infra.rollback_deployment" not in [call.tool_name for call in state.tool_calls]


def test_live_tool_step_detail_falls_back_when_observation_missing():
    result = ToolResult(
        tool_name="comms.create_incident_channel",
        success=True,
        data={"provider": "discord"},
    )

    assert _tool_step_detail(result) == "comms.create_incident_channel completed via discord."


def test_live_remediation_confirmation_rejects_empty_provider_rollback_evidence():
    result = ToolResult(
        tool_name="infra.rollback_deployment",
        success=True,
        evidence=[
            Evidence(
                source="infra.rollback_deployment",
                time_window="live",
                affected_service="payment-service",
                claim="Kubernetes adapter completed without provider-confirming receipt",
                provenance="live_empty::infra.rollback_deployment",
            )
        ],
    )

    assert _tool_result_confirmed_for_live(result, "infra.rollback_deployment") is False


def test_live_remediation_confirmation_rejects_success_without_live_evidence():
    result = ToolResult(
        tool_name="infra.rollback_deployment",
        success=True,
        evidence=[],
    )

    assert _tool_result_confirmed_for_live(result, "infra.rollback_deployment") is False


def test_replay_remediation_uses_success_semantics_without_live_evidence(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")

    state = SentinelOrchestrator(store=store).run_scenario("golden_path")

    assert state.remediation_result is not None
    assert state.remediation_result.status == "executed"


def test_live_remediation_confirmation_accepts_verified_provider_rollback_evidence():
    result = ToolResult(
        tool_name="infra.rollback_deployment",
        success=True,
        evidence=[
            Evidence(
                source="infra.rollback_deployment",
                time_window="live",
                affected_service="payment-service",
                claim="Kubernetes rollout undo returned a verified receipt",
                provenance="live::infra.rollback_deployment",
            )
        ],
    )

    assert _tool_result_confirmed_for_live(result, "infra.rollback_deployment") is True


def test_live_incident_waits_for_structured_approval_before_remediation(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-APPROVAL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )
    loaded = store.load_state(state.id)

    assert state.status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert state.current_state.value == "response_proposal"
    assert state.approval_request is not None
    assert state.recommendation is not None
    assert state.approval_command is None
    assert state.remediation_result is None
    assert state.post_mortem is None
    assert "infra.rollback_deployment" not in [call.tool_name for call in state.tool_calls]
    assert "comms.page_oncall_engineer" in [call.tool_name for call in state.tool_calls]
    assert state.artifacts["pagerduty_oncall_user"] == "eng-oncall"
    assert state.artifacts["approval_slack_notified"] is True
    assert state.artifacts["approval_slack_notification_request_id"] == state.approval_request.id
    assert state.approval_request.approver_ids == ["eng-oncall"]
    assert loaded.status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert loaded.artifacts["approval_slack_notified"] is True
    assert loaded.artifacts["approval_slack_notification_request_id"] == loaded.approval_request.id


def test_live_incident_preserves_receiver_webhook_artifacts(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)
    received = InvestigationState(
        id="inv-generic-preserved",
        incident_id="FREE-GENERIC-1",
        scenario_name="live",
        affected_services=["payment-service"],
        service_priority=["payment-service"],
    )
    received.artifacts["webhook_source"] = "generic_webhook"
    received.artifacts["generic_webhook_received"] = True
    received.artifacts["webhook_ingress"] = {
        "source": "generic_webhook",
        "incident_id": "FREE-GENERIC-1",
        "affected_services": ["payment-service"],
        "payload_keys": ["alerts", "commonLabels", "groupKey", "groupLabels", "source"],
    }
    received.audit_events.append(
        AuditEvent(
            investigation_id=received.id,
            event_type="generic_webhook_accepted",
            payload=received.artifacts["webhook_ingress"],
        )
    )
    store.save_state(received)

    state = orchestrator.run_live_incident(
        incident_id="FREE-GENERIC-1",
        affected_services=["payment-service"],
        webhook_payload={"source": "generic_webhook"},
        auto_approve=False,
        investigation_id=received.id,
    )
    loaded = store.load_state(received.id)

    assert state.artifacts["webhook_source"] == "generic_webhook"
    assert state.artifacts["generic_webhook_received"] is True
    assert state.artifacts["webhook_ingress"] == received.artifacts["webhook_ingress"]
    assert state.context_summary == "Generic webhook accepted; live investigation attached to free alert source."
    assert [event.event_type for event in loaded.audit_events[:2]] == [
        "generic_webhook_accepted",
        "live_webhook_received",
    ]


def test_live_approval_request_uses_pagerduty_oncall_identity(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_environment(
        store,
        _LiveOncallEnvironment(build_scenarios()["golden_path"], "pd-user-42"),
    )

    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-ONCALL-APPROVER",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    assert waiting.status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert waiting.approval_request is not None
    assert waiting.approval_request.approver_ids == ["pd-user-42"]

    rejected = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id=waiting.approval_request.id,
            approver_id="eng-oncall",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:wrong-approver",
        ),
    )
    assert rejected.status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert rejected.approval_command is None

    approved = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id=waiting.approval_request.id,
            approver_id="pd-user-42",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:pagerduty-approver",
        ),
    )

    assert approved.status == InvestigationStatus.COMPLETED
    assert approved.remediation_result is not None
    assert approved.remediation_result.status == "executed"


def test_live_incident_without_pagerduty_oncall_approver_does_not_request_approval(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_environment(
        store,
        _LiveNoOncallEnvironment(build_scenarios()["golden_path"]),
    )

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-NO-ONCALL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    assert state.status == InvestigationStatus.INSUFFICIENT_CONFIDENCE
    assert state.approval_request is None
    assert state.remediation_result is None
    assert state.diagnosis is not None
    assert "No PagerDuty on-call authorized approver was confirmed." in state.diagnosis.evidence_gaps
    assert "infra.rollback_deployment" not in [call.tool_name for call in state.tool_calls]


def test_live_approval_proposal_message_contains_diagnosis_evidence_recommendation_and_boundary():
    orchestrator = SentinelOrchestrator()
    state = InvestigationState(
        incident_id="PD-LIVE-APPROVAL",
        scenario_name="live",
        affected_services=["checkout-service"],
        service_priority=["checkout-service"],
        diagnosis=Diagnosis(
            summary="Checkout latency correlates with deployment sha-live-new.",
            confidence=ConfidenceLevel.HIGH,
        ),
        recommendation=Recommendation(
            remediation_type="rollback",
            affected_service="checkout-service",
            command="rollback checkout-service to revision:41",
            evidence_summary="Datadog logs, GitHub deploys, PagerDuty incident, Slack channel, and Kubernetes pods confirm impact.",
            risk="Requires human approval.",
            rollback_plan="Restore checkout-service to revision:41.",
        ),
        evidence=[
            Evidence(
                source="observe.fetch_service_logs",
                time_window="live",
                affected_service="checkout-service",
                claim="Datadog logs returned event ids.",
                provenance="live::observe.fetch_service_logs",
            )
        ],
    )
    approval = ApprovalRequest(
        id="approval-live-123",
        incident_id=state.incident_id,
        remediation=state.recommendation,
        approver_ids=["eng-oncall"],
        approval_snapshot={"diagnosis": state.diagnosis.summary},
        idempotency_key="inv:approval:rollback-checkout-service",
    )

    message = orchestrator._approval_proposal_message(state, approval)

    assert "Diagnosis: Checkout latency correlates with deployment sha-live-new." in message
    assert "Evidence summary: Datadog logs, GitHub deploys, PagerDuty incident, Slack channel, and Kubernetes pods confirm impact." in message
    assert "Evidence records collected: 1." in message
    assert "Recommendation: rollback checkout-service to revision:41" in message
    assert "Approval request id: approval-live-123" in message
    assert "will not execute from Slack text or reactions" in message
    assert "structured approval command" in message


def test_live_incident_resumes_after_matching_approval_command(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)
    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-APPROVAL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    approved = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id=waiting.approval_request.id,
            approver_id="eng-oncall",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:test",
        ),
    )
    loaded = store.load_state(waiting.id)

    assert approved.status == InvestigationStatus.COMPLETED
    assert approved.current_state.value == "post_mortem"
    assert approved.remediation_result is not None
    assert approved.remediation_result.status == "executed"
    assert approved.post_mortem is not None
    assert "infra.rollback_deployment" in [call.tool_name for call in approved.tool_calls]
    assert loaded.status == InvestigationStatus.COMPLETED


def test_live_approval_executes_the_approved_rollback_target_not_mutable_state(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    environment = _RecordingLiveEnvironment(build_scenarios()["golden_path"])
    orchestrator = _live_orchestrator_with_environment(store, environment)
    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-APPROVED-TARGET",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )
    assert waiting.approval_request is not None
    assert waiting.approval_request.remediation.rollback_target == "revision:41"

    waiting.artifacts["rollback_target"] = "revision:99"
    assert waiting.remediation_readiness_report is not None
    waiting.remediation_readiness_report.safe_rollback_target = "revision:99"
    store.save_state(waiting)

    approved = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id=waiting.approval_request.id,
            approver_id="eng-oncall",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:approved-target",
        ),
    )

    assert approved.remediation_result is not None
    assert approved.remediation_result.status == "executed"
    assert environment.rollback_payloads == [
        {"service": "payment-service", "target": "revision:41"}
    ]


def test_live_remediation_refuses_stale_approval_slack_notification_proof():
    orchestrator = SentinelOrchestrator()
    recommendation = Recommendation(
        remediation_type="rollback",
        affected_service="payment-service",
        command="rollback payment-service to revision:41",
        evidence_summary="Live evidence identifies the bad deployment.",
        risk="Requires human approval.",
        rollback_plan="Restore payment-service to revision:41.",
        rollback_target="revision:41",
        executable=True,
    )
    state = InvestigationState(
        incident_id="PD-LIVE-REMEDIATION-GUARD",
        scenario_name="live",
        affected_services=["payment-service"],
        service_priority=["payment-service"],
        recommendation=recommendation,
        approval_request=ApprovalRequest(
            id="approval-current",
            incident_id="PD-LIVE-REMEDIATION-GUARD",
            remediation=recommendation,
            approver_ids=["eng-oncall"],
            approval_snapshot={"diagnosis": "live diagnosis"},
            idempotency_key="PD-LIVE-REMEDIATION-GUARD:approval:rollback-payment-service",
            expires_at=now_utc() + timedelta(minutes=5),
        ),
        approval_command=ApprovalCommand(
            request_id="approval-current",
            approver_id="eng-oncall",
            decision="approve",
            idempotency_key="PD-LIVE-REMEDIATION-GUARD:approval-command:accepted",
        ),
        artifacts={
            "approval_slack_notified": True,
            "approval_slack_notification_request_id": "approval-old",
        },
    )

    orchestrator._execute_remediation(state)

    assert state.remediation_result is not None
    assert state.remediation_result.status == "refused"
    assert state.remediation_result.message == (
        "Approval request Slack notification was not confirmed for the active approval request."
    )


def test_duplicate_approval_command_returns_current_state_without_reprocessing(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)
    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-DUPLICATE-APPROVAL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )
    command = ApprovalCommand(
        request_id=waiting.approval_request.id,
        approver_id="eng-oncall",
        decision="approve",
        idempotency_key=f"{waiting.id}:approval-command:duplicate",
    )

    approved = orchestrator.resume_with_approval(waiting.id, command)
    duplicate = orchestrator.resume_with_approval(waiting.id, command)

    assert duplicate.status == InvestigationStatus.COMPLETED
    assert duplicate.id == approved.id
    assert [call.tool_name for call in duplicate.tool_calls].count("infra.rollback_deployment") == 1
    assert [
        step.action for step in duplicate.plan_steps
    ].count("Receive structured human approval") == 1


def test_mismatched_approval_command_stays_at_human_boundary(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)
    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-MISMATCHED-APPROVAL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    state = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id="approval-other",
            approver_id="eng-oncall",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:mismatched",
        ),
    )

    _assert_approval_boundary_held(state, store)
    assert "Approval command did not match the active approval request." in [
        step.detail for step in state.plan_steps
    ]


def test_stale_approval_slack_notification_stays_at_human_boundary(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)
    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-STALE-SLACK-APPROVAL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )
    assert waiting.approval_request is not None
    waiting.artifacts["approval_slack_notification_request_id"] = "approval-old"
    store.save_state(waiting)

    state = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id=waiting.approval_request.id,
            approver_id="eng-oncall",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:stale-slack-proof",
        ),
    )

    _assert_approval_boundary_held(state, store)
    assert "Approval request Slack notification was not confirmed for the active approval request." in [
        step.detail for step in state.plan_steps
    ]


def test_unauthorized_approval_command_stays_at_human_boundary(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)
    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-UNAUTHORIZED-APPROVAL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    state = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id=waiting.approval_request.id,
            approver_id="random-user",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:unauthorized",
        ),
    )

    _assert_approval_boundary_held(state, store)
    assert "Approval command was not sent by an authorized approver." in [
        step.detail for step in state.plan_steps
    ]


def test_expired_approval_command_stays_at_human_boundary(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)
    waiting = orchestrator.run_live_incident(
        incident_id="PD-LIVE-EXPIRED-APPROVAL",
        affected_services=["payment-service", "api-gateway"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )
    waiting.approval_request.expires_at = now_utc() - timedelta(minutes=1)
    store.save_state(waiting)

    state = orchestrator.resume_with_approval(
        waiting.id,
        ApprovalCommand(
            request_id=waiting.approval_request.id,
            approver_id="eng-oncall",
            decision="approve",
            idempotency_key=f"{waiting.id}:approval-command:expired",
        ),
    )

    _assert_approval_boundary_held(state, store)
    assert "Approval request expired before the command was accepted." in [
        step.detail for step in state.plan_steps
    ]


def test_live_single_service_skips_service_investigator_fanout(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-SINGLE",
        affected_services=["checkout-service"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    assert state.status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert state.service_reports == []
    assert not any("Service Investigator" in step.action for step in state.plan_steps)
    assert state.blast_radius_report is not None
    assert state.remediation_readiness_report is not None
    assert state.remediation_readiness_report.safe_rollback_target == "revision:41"


def test_live_service_investigator_reports_do_not_emit_demo_constants(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-MULTI",
        affected_services=["checkout-service", "inventory-service"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    assert [report.service_name for report in state.service_reports] == [
        "checkout-service",
        "inventory-service",
    ]
    report_text = "\n".join(
        [
            *[report.local_diagnosis for report in state.service_reports],
            *[report.suggested_fix for report in state.service_reports],
            *[
                " ".join(report.contributing_factors)
                for report in state.service_reports
            ],
        ]
    )
    assert "PR #847" not in report_text
    assert "v2.3.1" not in report_text
    assert "orders.user_id" not in report_text
    assert "Spawn checkout-service Service Investigator" in [
        step.action for step in state.plan_steps
    ]
    assert "Spawn inventory-service Service Investigator" in [
        step.action for step in state.plan_steps
    ]
    assert "Spawn payment Service Investigator" not in [
        step.action for step in state.plan_steps
    ]
    assert "Spawn API gateway Service Investigator" not in [
        step.action for step in state.plan_steps
    ]


def test_live_slow_query_path_uses_groq_plan_and_service_investigators(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_environment(
        store,
        _SlowQueryLiveEnvironment(build_scenarios()["golden_path"]),
    )
    orchestrator.model_client = _GroqPlanner()

    state = orchestrator.run_live_incident(
        incident_id="LIVE-SLOW-TEST",
        affected_services=["payment-service", "checkout-service"],
        webhook_payload={
            "source": "prometheus",
            "commonLabels": {
                "alertname": "SentinelSlowQueryLatency",
                "service": "payment-service",
                "route": "/slow-query",
            },
            "commonAnnotations": {
                "summary": "payment-service /slow-query latency spike from missing SQLite index",
            },
        },
        auto_approve=False,
    )

    assert state.status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert state.current_state.value == "response_proposal"
    assert [report.service_name for report in state.service_reports] == [
        "payment-service",
        "checkout-service",
    ]
    assert any(call.tool_name == "infra.spawn_service_investigator" for call in state.tool_calls)
    assert any(step.action == "Spawn payment-service Service Investigator" for step in state.plan_steps)
    assert {plan["provider"] for plan in state.artifacts["model_tool_plans"]} == {"groq"}
    assert all(plan["model_rationale"] for plan in state.artifacts["model_tool_plans"])
    assert "evidence_collection" in [
        event.payload["state"]
        for event in state.audit_events
        if event.event_type == "state_transition"
    ]


def test_live_incident_derives_provider_windows_from_webhook_timestamp(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-WINDOWS",
        affected_services=["checkout-service", "inventory-service"],
        webhook_payload={
            "event": {
                "event_type": "incident.triggered",
                "occurred_at": "2024-01-15T03:12:00Z",
                "data": {"id": "PD-LIVE-WINDOWS"},
            }
        },
        auto_approve=False,
    )

    evidence_windows = {
        item.time_window
        for item in state.evidence
        if item.source.startswith(("observe.", "repo."))
    }
    assert state.artifacts["incident_occurred_at"] == "2024-01-15T03:12:00Z"
    assert state.artifacts["observability_window"] == "2024-01-15T02:42:00Z"
    assert state.artifacts["observability_window_end"] == "2024-01-15T03:27:00Z"
    assert state.artifacts["repo_window"] == "2024-01-14T21:12:00Z"
    assert "02:30-03:30 UTC" not in evidence_windows
    assert "last 6h" not in evidence_windows
    assert "2024-01-15T02:42:00Z" in evidence_windows
    assert "2024-01-14T21:12:00Z" in evidence_windows


def test_live_incident_falls_back_to_relative_provider_windows(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = _live_orchestrator_with_replay_tools(store)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-WINDOW-FALLBACK",
        affected_services=["checkout-service", "inventory-service"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    evidence_windows = {
        item.time_window
        for item in state.evidence
        if item.source.startswith(("observe.", "repo."))
    }
    assert state.artifacts["observability_window"] == LIVE_OBSERVABILITY_WINDOW
    assert state.artifacts["repo_window"] == LIVE_REPOSITORY_WINDOW
    assert "02:30-03:30 UTC" not in evidence_windows
    assert "last 6h" not in evidence_windows
    assert LIVE_OBSERVABILITY_WINDOW in evidence_windows
    assert LIVE_REPOSITORY_WINDOW in evidence_windows


def test_live_incident_without_change_artifact_returns_insufficient_confidence(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    environment = ReplayIncidentEnvironment(build_scenarios()["golden_path"])
    orchestrator = _live_orchestrator_with_environment(store, environment)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-NO-CHANGE",
        affected_services=["checkout-service", "inventory-service"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    assert state.status == InvestigationStatus.INSUFFICIENT_CONFIDENCE
    assert state.diagnosis is not None
    assert state.diagnosis.confidence == ConfidenceLevel.INSUFFICIENT
    assert "no live change artifact" in state.diagnosis.summary
    assert state.approval_request is None
    assert state.recommendation is None
    assert "infra.rollback_deployment" not in [call.tool_name for call in state.tool_calls]


def test_live_incident_without_kubernetes_revision_target_does_not_request_approval(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    environment = _LiveNoRollbackTargetEnvironment(build_scenarios()["golden_path"])
    orchestrator = _live_orchestrator_with_environment(store, environment)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-NO-ROLLBACK-TARGET",
        affected_services=["checkout-service", "inventory-service"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )

    assert state.status == InvestigationStatus.INSUFFICIENT_CONFIDENCE
    assert state.recommendation is not None
    assert state.recommendation.executable is False
    assert "revision target" in state.recommendation.command
    assert state.approval_request is None
    assert "No executable Kubernetes rollback revision target was confirmed." in state.diagnosis.evidence_gaps
    assert "infra.rollback_deployment" not in [call.tool_name for call in state.tool_calls]


def test_live_incident_fails_closed_when_approval_slack_notification_fails(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    environment = _ApprovalSlackFailureEnvironment(build_scenarios()["golden_path"])
    orchestrator = _live_orchestrator_with_environment(store, environment)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-SLACK-FAIL",
        affected_services=["checkout-service", "inventory-service"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )
    loaded = store.load_state(state.id)
    tool_names = [call.tool_name for call in state.tool_calls]

    assert state.status == InvestigationStatus.FAILED
    assert state.current_state.value == "response_proposal"
    assert state.recommendation is not None
    assert state.approval_request is None
    assert state.approval_command is None
    assert state.remediation_result is None
    assert state.context_summary == "Approval request notification failed; no active approval request was created."
    assert "infra.rollback_deployment" not in tool_names
    assert [call.success for call in state.tool_calls if call.tool_name == "comms.post_to_slack"] == [
        True,
        False,
    ]
    assert "approval_request_notification_failed" in [event.event_type for event in state.audit_events]
    assert loaded.status == InvestigationStatus.FAILED
    assert loaded.approval_request is None


def test_live_incident_fails_closed_when_approval_slack_notification_lacks_provider_receipt(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    environment = _ApprovalSlackUnconfirmedEnvironment(build_scenarios()["golden_path"])
    orchestrator = _live_orchestrator_with_environment(store, environment)

    state = orchestrator.run_live_incident(
        incident_id="PD-LIVE-SLACK-EMPTY",
        affected_services=["checkout-service", "inventory-service"],
        webhook_payload={"source": "test"},
        auto_approve=False,
    )
    audit = [event for event in state.audit_events if event.event_type == "approval_request_notification_failed"]

    assert state.status == InvestigationStatus.FAILED
    assert state.current_state.value == "response_proposal"
    assert state.approval_request is None
    assert state.approval_command is None
    assert state.remediation_result is None
    assert "approval_slack_notified" not in state.artifacts
    assert any(
        evidence.source == "comms.post_to_slack"
        and evidence.provenance == "live_empty::comms.post_to_slack"
        for evidence in state.evidence
    )
    assert audit
    assert audit[-1].payload["error_message"] == (
        "Approval request notification lacked provider-confirming Slack evidence."
    )


def _assert_approval_boundary_held(
    state,
    store: SQLiteInvestigationStore,
) -> None:
    loaded = store.load_state(state.id)
    tool_names = [call.tool_name for call in state.tool_calls]

    assert state.status == InvestigationStatus.WAITING_FOR_APPROVAL
    assert state.current_state.value == "response_proposal"
    assert state.approval_command is None
    assert state.remediation_result is None
    assert state.post_mortem is None
    assert "infra.rollback_deployment" not in tool_names
    assert "comms.write_post_mortem" not in tool_names
    assert "approval_command_rejected" in [
        event.event_type for event in state.audit_events
    ]
    assert "Reject invalid approval command" in [step.action for step in state.plan_steps]
    assert loaded.status == InvestigationStatus.WAITING_FOR_APPROVAL


def _live_orchestrator_with_replay_tools(store: SQLiteInvestigationStore) -> SentinelOrchestrator:
    environment = _LiveShapedReplayEnvironment(build_scenarios()["golden_path"])
    return _live_orchestrator_with_environment(store, environment)


def _live_orchestrator_with_environment(
    store: SQLiteInvestigationStore,
    environment: ReplayIncidentEnvironment,
) -> SentinelOrchestrator:
    registry = ToolFactory(environment).build_registry()
    executor = ToolExecutor(registry, store)
    orchestrator = SentinelOrchestrator(store=store)
    orchestrator.registry = registry
    orchestrator.executor = executor
    orchestrator.subagents = SubagentLauncher(registry, executor, store)
    orchestrator.subagents.bind_spawn_tool()
    return orchestrator


class _LiveShapedReplayEnvironment(ReplayIncidentEnvironment):
    def invoke(self, contract, payload):
        data = super().invoke(contract, payload)
        if contract.name == "repo.get_deploy_history":
            data.pop("deploys", None)
            data["deployments"] = [
                {"sha": "sha-live-new", "ref": "main"},
                {"sha": "sha-live-old", "ref": "release-2026-06-02"},
            ]
        elif contract.name in {"repo.diff_pull_request", "repo.fetch_pr_metadata"}:
            data["pull_request"] = {
                "number": 912,
                "title": "Fix checkout latency",
                "head": {"sha": "sha-live-pr"},
            }
            data["files"] = [{"filename": "checkout/payment.py"}]
        elif contract.name == "repo.get_recent_commits":
            data["commits"] = [
                {
                    "sha": "sha-live-new",
                    "commit": {"message": "Merge pull request #912 from checkout/fix"},
                }
            ]
        elif contract.name == "repo.get_rollback_targets":
            data["target"] = "revision:41"
            data["rollout"] = {
                "current_revision": "revision:42",
                "previous_revision": "revision:41",
                "revisions": [40, 41, 42],
            }
        elif contract.name == "comms.page_oncall_engineer":
            data.pop("paged_user", None)
            data["incident"] = {
                "id": payload.get("incident_id") or "PD-LIVE-SIMULATED",
                "status": "triggered",
                "urgency": "high",
            }
            data["escalation_policy_ids"] = ["EP-live"]
            data["oncall_scope"] = "incident_escalation_policy"
            data["oncalls"] = [{"user": {"id": "eng-oncall"}}]
        data["evidence"] = [
            {
                "source": contract.name,
                "time_window": payload.get("time_window", "live"),
                "affected_service": payload.get("service", "unknown"),
                "claim": f"{contract.name} returned live-shaped provider evidence.",
                "provenance": f"live::{contract.name}",
            }
        ]
        return data


class _SlowQueryLiveEnvironment(_LiveShapedReplayEnvironment):
    def invoke(self, contract, payload):
        data = super().invoke(contract, payload)
        if contract.name == "observe.query_metrics_range":
            data["provider"] = "prometheus"
            data["prometheus"] = {
                "result": [
                    {
                        "metric": {"service": payload.get("service", "payment-service")},
                        "value": [1710000000, "0.145"],
                    }
                ]
            }
        elif contract.name in {
            "observe.fetch_service_logs",
            "observe.check_db_slow_queries",
            "observe.get_distributed_traces",
            "observe.fetch_apm_data",
        }:
            data["provider"] = "loki"
            data["events"] = [
                {
                    "message": (
                        "slow_query SELECT * FROM orders WHERE user_id = ? "
                        "used sequential scan; missing_index orders.user_id"
                    )
                }
            ]
        elif contract.name == "comms.create_incident_channel":
            data["provider"] = "discord"
            data["channel"] = {"id": "discord-webhook", "name": payload.get("channel_name")}
        elif contract.name == "comms.post_to_slack":
            data["provider"] = "discord"
            data["content"] = payload.get("message", "SENTINEL live test message")
        return data


class _GroqPlanner:
    def __init__(self):
        self.last_decision = {}

    def plan_tools(self, *, state, available_contracts, objective, all_contracts=None):
        selected = [contract.name for contract in available_contracts[:3]]
        self.last_decision = {
            "source": "model",
            "provider": "groq",
            "model": "llama-3.3-70b-versatile",
            "endpoint": "https://api.groq.com/openai/v1/responses",
            "current_state": state.current_state.value,
            "objective": objective,
            "eligible_tool_count": len(available_contracts),
            "selected_tools": selected,
            "model_rationale": "Use the live slow-query evidence path and keep remediation approval gated.",
        }
        return selected


class _RecordingLiveEnvironment(_LiveShapedReplayEnvironment):
    def __init__(self, scenario):
        super().__init__(scenario)
        self.rollback_payloads = []

    def invoke(self, contract, payload):
        if contract.name == "infra.rollback_deployment":
            self.rollback_payloads.append(dict(payload))
        return super().invoke(contract, payload)


class _LiveOncallEnvironment(_LiveShapedReplayEnvironment):
    def __init__(self, scenario, oncall_user: str):
        super().__init__(scenario)
        self.oncall_user = oncall_user

    def invoke(self, contract, payload):
        data = super().invoke(contract, payload)
        if contract.name == "comms.page_oncall_engineer":
            data["oncalls"] = [{"user": {"id": self.oncall_user}}]
        return data


class _LiveNoOncallEnvironment(_LiveShapedReplayEnvironment):
    def invoke(self, contract, payload):
        data = super().invoke(contract, payload)
        if contract.name == "comms.page_oncall_engineer":
            data.pop("paged_user", None)
            data["oncalls"] = []
        return data


class _ApprovalSlackFailureEnvironment(_LiveShapedReplayEnvironment):
    def invoke(self, contract, payload):
        if contract.name == "comms.post_to_slack" and payload.get("approval_request_id"):
            raise ToolExecutionError(
                ToolErrorKind.RETRYABLE,
                "Slack approval notification failed",
                retryable=True,
            )
        return super().invoke(contract, payload)


class _ApprovalSlackUnconfirmedEnvironment(_LiveShapedReplayEnvironment):
    def invoke(self, contract, payload):
        data = super().invoke(contract, payload)
        if contract.name == "comms.post_to_slack" and payload.get("approval_request_id"):
            data["evidence"] = [
                {
                    "source": "comms.post_to_slack",
                    "time_window": payload.get("time_window", "live"),
                    "affected_service": payload.get("service", "unknown"),
                    "claim": "Slack adapter completed without provider-confirming receipt",
                    "provenance": "live_empty::comms.post_to_slack",
                }
            ]
        return data


class _LiveNoRollbackTargetEnvironment(_LiveShapedReplayEnvironment):
    def invoke(self, contract, payload):
        data = super().invoke(contract, payload)
        if contract.name == "repo.get_rollback_targets":
            data["target"] = "release-2026-06-02"
            data.pop("rollout", None)
        return data
