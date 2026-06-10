from __future__ import annotations

from dataclasses import replace

from fastapi.testclient import TestClient

from sentinel.config import SentinelSettings
from sentinel.models import ConfidenceLevel, Diagnosis, InvestigationState, StateName, ToolCallRecord
from sentinel.orchestrator import SentinelOrchestrator
from sentinel.store import SQLiteInvestigationStore
from sentinel.webapp import create_app


def test_diagnosis_includes_visible_confidence_block(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    state = SentinelOrchestrator(store=store).run_scenario("golden_path")

    assert state.diagnosis is not None
    block = state.diagnosis.confidence_block
    assert block.confidence_percent == 92
    assert block.supporting_signals
    assert block.top_alternative_hypothesis
    assert isinstance(block.conflicting_signals, list)


def test_failed_or_missing_credential_tool_becomes_explicit_uncertainty(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    orchestrator = SentinelOrchestrator(store=store)
    state = InvestigationState(
        incident_id="PD-MISSING-CREDENTIAL",
        scenario_name="live",
        affected_services=["payment-service"],
        service_priority=["payment-service"],
    )
    store.save_state(state)
    store.append_tool_call(
        ToolCallRecord(
            investigation_id=state.id,
            tool_name="repo.get_deploy_history",
            state=StateName.EVIDENCE_COLLECTION,
            duration_ms=1.0,
            input_hash="input",
            output_hash="output",
            success=False,
            error_kind="authorization",
            error_message="GITHUB_TOKEN credential is missing",
        )
    )

    diagnosis = orchestrator._with_confidence_block(
        state,
        Diagnosis(
            summary="Insufficient confidence because repo evidence is unavailable.",
            confidence=ConfidenceLevel.INSUFFICIENT,
        ),
        top_alternative_hypothesis="The recent deploy may still be the causal trigger.",
    )

    assert diagnosis.confidence_block.unconfirmed_hypotheses
    note = diagnosis.confidence_block.unconfirmed_hypotheses[0]
    assert "repo.get_deploy_history could not confirm it" in note
    assert "credential or authorization missing" in note
    assert note in diagnosis.evidence_gaps


def test_remediation_audit_endpoint_exposes_schema(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "sentinel.db")
    state = SentinelOrchestrator(store=store).run_scenario("golden_path")
    settings = replace(
        SentinelSettings.from_env(),
        environment="development",
        api_token=None,
        database_url=None,
        redis_url=None,
    )
    app = create_app(settings)
    app.state.store = store

    response = TestClient(app).get(f"/investigations/{state.id}/audit")

    assert response.status_code == 200
    body = response.json()
    assert body["investigation_id"] == state.id
    remediation_audits = body["remediation_audits"]
    assert len(remediation_audits) == 1
    audit = remediation_audits[0]
    assert audit["schema_version"] == "remediation_audit.v1"
    assert audit["approval_request"]["id"] == state.approval_request.id
    assert audit["authorizer"]["approver_id"] == state.approval_command.approver_id
    assert audit["scope"]["affected_service"] == "payment-service"
    assert audit["action"]["name"] == "rollback"
    assert audit["verification_result"]["verified"] is True
    assert audit["timestamp"]
