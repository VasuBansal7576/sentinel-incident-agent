from __future__ import annotations

from sentinel.orchestrator import SentinelOrchestrator
from sentinel.store import SQLiteInvestigationStore


def test_operational_memory_persists_incident_and_feeds_second_triage_context(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "memory.db")

    first = SentinelOrchestrator(store=store).run_scenario("golden_path")
    second = SentinelOrchestrator(store=store).run_scenario("golden_path")

    assert first.status.value == "completed"
    assert second.status.value == "completed"
    assert store.count_rows("incident_fingerprints") >= 2
    assert store.count_rows("service_profiles") >= 1
    assert store.count_rows("approved_remediations") >= 1
    assert store.count_rows("runbook_snippets") >= 1

    hint_events = [
        event
        for event in second.audit_events
        if event.event_type == "operational_memory_hints_loaded"
    ]
    assert hint_events
    hints = hint_events[0].payload["planner_context_hints"]
    assert len(hints) == 1
    assert "Similar prior incident" in hints[0]
    assert first.incident_id in hints[0]
    assert "Operational memory hints" in second.context_summary


def test_service_context_loaded_at_evidence_collection_after_prior_run(tmp_path):
    store = SQLiteInvestigationStore(tmp_path / "memory.db")

    SentinelOrchestrator(store=store).run_scenario("golden_path")
    second = SentinelOrchestrator(store=store).run_scenario("golden_path")

    events = [
        event
        for event in second.audit_events
        if event.event_type == "service_context_loaded"
    ]
    assert events
    payload = events[0].payload
    assert payload["state"] == "evidence_collection"
    assert payload["service_name"] == "payment-service"
    assert payload["service_context"]["profile"]["service_name"] == "payment-service"
    assert payload["service_context"]["approved_remediations"]
