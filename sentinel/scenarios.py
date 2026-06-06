from __future__ import annotations

from sentinel.models import ConfidenceLevel, IncidentScenario, ScenarioOracle


def build_scenarios() -> dict[str, IncidentScenario]:
    golden_oracle = ScenarioOracle(
        expected_root_cause=(
            "PR #847 by @alice at commit abc1234 introduced SELECT * FROM orders WHERE "
            "user_id = ? without an index on orders.user_id"
        ),
        expected_recommendation="rollback payment-service to v2.3.1",
        required_evidence_terms=[
            "PR #847",
            "abc1234",
            "@alice",
            "orders.user_id",
            "SELECT * FROM orders WHERE user_id = ?",
            "v2.3.1",
            "2.3s",
            "575x",
        ],
        allowed_confidence=[ConfidenceLevel.HIGH],
    )
    degraded_oracle = ScenarioOracle(
        expected_root_cause="insufficient confidence because trace evidence is unavailable",
        expected_recommendation=None,
        required_evidence_terms=["evidence gap", "observe.get_distributed_traces"],
        forbidden_tools=["infra.rollback_deployment"],
        allowed_confidence=[ConfidenceLevel.INSUFFICIENT, ConfidenceLevel.LOW],
    )
    watch_oracle = ScenarioOracle(
        expected_root_cause="checkout error rate is trending up before alert threshold",
        expected_recommendation=None,
        required_evidence_terms=["trending up", "Watch"],
        forbidden_tools=["infra.rollback_deployment"],
        allowed_confidence=[ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW],
    )

    return {
        "golden_path": IncidentScenario(
            name="golden_path",
            trigger_kind="incident",
            incident_id="PD-2026-06-03-0312",
            affected_services=["payment-service", "api-gateway"],
            transient_failures={"observe.fetch_service_logs": 1},
            oracle=golden_oracle,
        ),
        "tool_degraded": IncidentScenario(
            name="tool_degraded",
            trigger_kind="incident",
            incident_id="PD-2026-06-03-0417",
            affected_services=["payment-service", "api-gateway"],
            degraded_tools={
                "observe.get_distributed_traces": "trace backend unavailable during incident"
            },
            oracle=degraded_oracle,
        ),
        "watch": IncidentScenario(
            name="watch",
            trigger_kind="watch",
            incident_id="WATCH-2026-06-03-0250",
            affected_services=["checkout-service"],
            oracle=watch_oracle,
        ),
    }
