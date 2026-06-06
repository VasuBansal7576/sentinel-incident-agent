from __future__ import annotations

from pathlib import Path

from sentinel.models import EvaluationResult, IncidentScenario
from sentinel.orchestrator import SentinelOrchestrator
from sentinel.scenarios import build_scenarios
from sentinel.store import SQLiteInvestigationStore


class EvaluationHarness:
    def __init__(self, *, db_path: str | Path = ":memory:"):
        self.store = SQLiteInvestigationStore(db_path)
        self.scenarios = build_scenarios()

    def run_all(self) -> list[EvaluationResult]:
        return [self.run_one(name) for name in self.scenarios]

    def run_one(self, scenario_name: str) -> EvaluationResult:
        scenario = self.scenarios[scenario_name]
        orchestrator = SentinelOrchestrator(store=self.store)
        state = orchestrator.run_scenario(scenario_name)
        checks = self._score_checks(scenario, state)
        score = sum(1 for passed in checks.values() if passed) / len(checks)
        result = EvaluationResult(
            scenario_name=scenario_name,
            passed=all(checks.values()),
            score=score,
            checks=checks,
            investigation_id=state.id,
        )
        self.store.record_evaluation(result)
        return result

    def _score_checks(self, scenario: IncidentScenario, state) -> dict[str, bool]:
        oracle = scenario.oracle
        evidence_text = " ".join(item.claim for item in state.evidence)
        tool_names = [call.tool_name for call in state.tool_calls]
        diagnosis_text = state.diagnosis.summary if state.diagnosis else ""
        recommendation_text = state.recommendation.command if state.recommendation else ""
        return {
            "status_terminal": state.status.value in {
                "completed",
                "insufficient_confidence",
            },
            "confidence_allowed": (
                state.diagnosis is not None
                and state.diagnosis.confidence in oracle.allowed_confidence
            ),
            "required_evidence": all(
                term.lower() in (evidence_text + " " + diagnosis_text).lower()
                for term in oracle.required_evidence_terms
            ),
            "recommendation": (
                oracle.expected_recommendation is None
                or oracle.expected_recommendation.lower() in recommendation_text.lower()
            ),
            "forbidden_tools": all(name not in tool_names for name in oracle.forbidden_tools),
            "human_approval_boundary": (
                "infra.rollback_deployment" not in tool_names
                or state.approval_command is not None
            ),
        }

