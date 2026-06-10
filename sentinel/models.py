from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def now_utc() -> datetime:
    return datetime.now(UTC)


class ToolNamespace(StrEnum):
    OBSERVE = "observe"
    REPO = "repo"
    INFRA = "infra"
    COMMS = "comms"


class PermissionClass(StrEnum):
    READ_ONLY = "read_only"
    COMMUNICATION = "communication"
    HUMAN_APPROVED_REMEDIATION = "human_approved_remediation"


class ConfidenceLevel(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INSUFFICIENT = "insufficient"


class InvestigationStatus(StrEnum):
    RUNNING = "running"
    WAITING_FOR_APPROVAL = "waiting_for_approval"
    COMPLETED = "completed"
    INSUFFICIENT_CONFIDENCE = "insufficient_confidence"
    FAILED = "failed"


class StateName(StrEnum):
    RECEIVED = "received"
    TRIAGE = "triage"
    EVIDENCE_COLLECTION = "evidence_collection"
    SERVICE_INVESTIGATION = "service_investigation"
    CORRELATION = "correlation"
    RESPONSE_PROPOSAL = "response_proposal"
    REMEDIATION = "remediation"
    POST_MORTEM = "post_mortem"


STATE_MACHINE: tuple[StateName, ...] = (
    StateName.RECEIVED,
    StateName.TRIAGE,
    StateName.EVIDENCE_COLLECTION,
    StateName.SERVICE_INVESTIGATION,
    StateName.CORRELATION,
    StateName.RESPONSE_PROPOSAL,
    StateName.REMEDIATION,
    StateName.POST_MORTEM,
)


class Evidence(BaseModel):
    source: str
    time_window: str
    affected_service: str
    claim: str
    provenance: str


class DiagnosisConfidenceBlock(BaseModel):
    confidence_percent: int = Field(ge=0, le=100)
    supporting_signals: list[str] = Field(default_factory=list)
    conflicting_signals: list[str] = Field(default_factory=list)
    top_alternative_hypothesis: str
    unconfirmed_hypotheses: list[str] = Field(default_factory=list)


def default_confidence_block() -> DiagnosisConfidenceBlock:
    return DiagnosisConfidenceBlock(
        confidence_percent=0,
        supporting_signals=[],
        conflicting_signals=[],
        top_alternative_hypothesis="No alternative hypothesis has been evaluated yet.",
    )


class Diagnosis(BaseModel):
    summary: str
    confidence: ConfidenceLevel
    evidence: list[Evidence] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    evidence_gaps: list[str] = Field(default_factory=list)
    confidence_block: DiagnosisConfidenceBlock = Field(default_factory=default_confidence_block)


class Recommendation(BaseModel):
    remediation_type: str
    affected_service: str
    command: str
    evidence_summary: str
    risk: str
    rollback_plan: str
    rollback_target: str | None = None
    executable: bool = True


class ApprovalRequest(BaseModel):
    id: str = Field(default_factory=lambda: f"approval-{uuid4().hex[:10]}")
    incident_id: str
    remediation: Recommendation
    requested_by: str = "SENTINEL"
    approver_ids: list[str]
    expires_at: datetime = Field(default_factory=lambda: now_utc() + timedelta(minutes=15))
    approval_snapshot: dict[str, Any]
    idempotency_key: str


class ApprovalCommand(BaseModel):
    request_id: str
    approver_id: str
    decision: Literal["approve", "reject"]
    idempotency_key: str


class RemediationResult(BaseModel):
    action: str
    affected_service: str
    status: Literal["executed", "skipped", "refused", "failed"]
    idempotency_key: str
    evidence: list[Evidence] = Field(default_factory=list)
    message: str


class PostMortem(BaseModel):
    summary: str
    timeline: list[str]
    facts: list[str]
    inferences: list[str]
    contributing_factors: list[str]
    proposed_action_items: list[str]
    accepted_action_items: list[str]


class ToolContract(BaseModel):
    name: str
    namespace: ToolNamespace
    permission: PermissionClass
    description: str
    input_schema: dict[str, str]
    output_schema: dict[str, str]
    phase_allowlist: list[StateName]
    retryable: bool = True
    rate_limit_per_second: float = 100.0


class ToolResult(BaseModel):
    tool_name: str
    success: bool
    data: dict[str, Any] = Field(default_factory=dict)
    reasoning_trace: str = ""
    error_kind: str | None = None
    error_message: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    duration_ms: float = 0.0
    attempt_count: int = 1


class ToolCallRecord(BaseModel):
    id: str = Field(default_factory=lambda: f"tool-{uuid4().hex[:10]}")
    investigation_id: str
    tool_name: str
    state: StateName
    timestamp: datetime = Field(default_factory=now_utc)
    duration_ms: float
    input_hash: str
    output_hash: str
    cost: float = 0.0
    success: bool
    reasoning_trace: str = ""
    error_kind: str | None = None
    error_message: str | None = None
    subagent_context_id: str | None = None


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: f"audit-{uuid4().hex[:10]}")
    investigation_id: str
    event_type: str
    timestamp: datetime = Field(default_factory=now_utc)
    payload: dict[str, Any] = Field(default_factory=dict)


class ServiceIncidentReport(BaseModel):
    service_name: str
    local_diagnosis: str
    confidence: ConfidenceLevel
    evidence: list[Evidence]
    contributing_factors: list[str]
    suggested_fix: str
    rollback_target: str | None
    estimated_user_impact: int
    evidence_gaps: list[str] = Field(default_factory=list)
    conflicts: list[str] = Field(default_factory=list)
    isolated_context_id: str
    scoped_tool_names: list[str]


class BlastRadiusReport(BaseModel):
    affected_services: list[str]
    affected_users: int
    affected_flow: str
    evidence: list[Evidence]
    isolated_context_id: str
    scoped_tool_names: list[str]


class RemediationReadinessReport(BaseModel):
    safe_rollback_target: str | None
    blockers: list[str]
    evidence: list[Evidence]
    isolated_context_id: str
    scoped_tool_names: list[str]


class PlanStep(BaseModel):
    number: int
    state: StateName
    action: str
    detail: str
    tool_name: str | None = None
    subagent_context_id: str | None = None


class InvestigationState(BaseModel):
    model_config = ConfigDict(use_enum_values=False)

    id: str = Field(default_factory=lambda: f"inv-{uuid4().hex[:10]}")
    incident_id: str
    scenario_name: str
    trigger_kind: Literal["incident", "watch"] = "incident"
    current_state: StateName = StateName.RECEIVED
    status: InvestigationStatus = InvestigationStatus.RUNNING
    affected_services: list[str] = Field(default_factory=list)
    service_priority: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    diagnosis: Diagnosis | None = None
    recommendation: Recommendation | None = None
    approval_request: ApprovalRequest | None = None
    approval_command: ApprovalCommand | None = None
    remediation_result: RemediationResult | None = None
    post_mortem: PostMortem | None = None
    service_reports: list[ServiceIncidentReport] = Field(default_factory=list)
    blast_radius_report: BlastRadiusReport | None = None
    remediation_readiness_report: RemediationReadinessReport | None = None
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    audit_events: list[AuditEvent] = Field(default_factory=list)
    plan_steps: list[PlanStep] = Field(default_factory=list)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    context_summary: str = ""


class ScenarioOracle(BaseModel):
    expected_root_cause: str
    expected_recommendation: str | None
    required_evidence_terms: list[str]
    forbidden_tools: list[str] = Field(default_factory=list)
    allowed_confidence: list[ConfidenceLevel]


class IncidentScenario(BaseModel):
    name: str
    trigger_kind: Literal["incident", "watch"]
    incident_id: str
    affected_services: list[str]
    degraded_tools: dict[str, str] = Field(default_factory=dict)
    transient_failures: dict[str, int] = Field(default_factory=dict)
    oracle: ScenarioOracle


class EvaluationResult(BaseModel):
    scenario_name: str
    passed: bool
    score: float
    checks: dict[str, bool]
    investigation_id: str
