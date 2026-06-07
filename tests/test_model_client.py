import json as jsonlib

from sentinel.model_client import ModelBackedToolPlanner
from sentinel.models import InvestigationState, StateName
from sentinel.tools import build_tool_contracts


class _ResponsesAPIResult:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _RecordingResponsesClient:
    def __init__(self):
        self.requests = []

    def post(self, url, *, headers, json):
        self.requests.append({"url": url, "headers": headers, "json": json})
        planner_input = jsonlib.loads(json["input"][1]["content"][0]["text"])
        selected_by_state = {
            "triage": ["observe.query_metrics_range"],
            "evidence_collection": ["observe.fetch_service_logs"],
        }
        return _ResponsesAPIResult(
            {"output_text": jsonlib.dumps({"tools": selected_by_state[planner_input["current_state"]]})}
        )


def test_model_backed_planner_uses_full_registry_and_selects_by_incident_state():
    contracts = build_tool_contracts()
    client = _RecordingResponsesClient()
    planner = ModelBackedToolPlanner(
        api_key="unit-test-key",
        http_client=client,
        model="gpt-5.5",
    )

    triage_state = InvestigationState(
        incident_id="PD-123",
        scenario_name="unit",
        current_state=StateName.TRIAGE,
        affected_services=["payment-service"],
    )
    evidence_state = triage_state.model_copy(update={"current_state": StateName.EVIDENCE_COLLECTION})

    triage_plan = planner.plan_tools(
        state=triage_state,
        available_contracts=[
            contract for contract in contracts if StateName.TRIAGE in contract.phase_allowlist
        ],
        all_contracts=contracts,
        objective="Establish impact",
    )
    evidence_plan = planner.plan_tools(
        state=evidence_state,
        available_contracts=[
            contract for contract in contracts if StateName.EVIDENCE_COLLECTION in contract.phase_allowlist
        ],
        all_contracts=contracts,
        objective="Collect source material",
    )

    assert triage_plan == ["observe.query_metrics_range"]
    assert evidence_plan == ["observe.fetch_service_logs"]
    assert triage_plan != evidence_plan
    assert len(client.requests) == 2
    first_request = client.requests[0]
    assert first_request["json"]["model"] == "gpt-5.5"
    assert first_request["headers"]["Authorization"] == "Bearer unit-test-key"
    planner_input = jsonlib.loads(first_request["json"]["input"][1]["content"][0]["text"])
    assert len(planner_input["tool_schemas"]) == 52
    assert "observe.query_metrics_range" in planner_input["eligible_tool_names"]
    assert "infra.rollback_deployment" not in planner_input["eligible_tool_names"]


def test_model_backed_planner_uses_groq_env_and_records_decision(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("GROQ_API_KEY", "groq-unit-test-key")
    monkeypatch.setenv("SENTINEL_MODEL", "llama-3.3-70b-versatile")
    contracts = build_tool_contracts()
    client = _RecordingResponsesClient()
    planner = ModelBackedToolPlanner(http_client=client)
    state = InvestigationState(
        incident_id="PD-GROQ",
        scenario_name="unit",
        current_state=StateName.TRIAGE,
        affected_services=["payment-service"],
    )

    plan = planner.plan_tools(
        state=state,
        available_contracts=[
            contract for contract in contracts if StateName.TRIAGE in contract.phase_allowlist
        ],
        all_contracts=contracts,
        objective="Establish impact",
    )

    assert plan == ["observe.query_metrics_range"]
    assert client.requests[0]["url"] == "https://api.groq.com/openai/v1/responses"
    assert client.requests[0]["headers"]["Authorization"] == "Bearer groq-unit-test-key"
    assert client.requests[0]["json"]["model"] == "llama-3.3-70b-versatile"
    assert planner.last_decision["source"] == "model"
    assert planner.last_decision["provider"] == "groq"
    assert planner.last_decision["selected_tools"] == ["observe.query_metrics_range"]
