from __future__ import annotations

import json
import os
from typing import Any, Protocol

import httpx

from sentinel.models import InvestigationState, StateName, ToolContract


class ModelClient(Protocol):
    def plan_tools(
        self,
        *,
        state: InvestigationState,
        available_contracts: list[ToolContract],
        objective: str,
        all_contracts: list[ToolContract] | None = None,
    ) -> list[str]:
        ...


class DeterministicIncidentModelClient:
    """Typed model client used for deterministic replay and tests."""

    def plan_tools(
        self,
        *,
        state: InvestigationState,
        available_contracts: list[ToolContract],
        objective: str,
        all_contracts: list[ToolContract] | None = None,
    ) -> list[str]:
        available = {contract.name for contract in available_contracts}
        desired = self._desired_plan(state.current_state, state.trigger_kind)
        return [name for name in desired if name in available]

    def _desired_plan(self, state_name: StateName, trigger_kind: str) -> list[str]:
        if trigger_kind == "watch":
            return {
                StateName.RECEIVED: ["comms.post_to_slack"],
                StateName.TRIAGE: [
                    "observe.get_error_rate_timeseries",
                    "observe.query_metrics_range",
                    "observe.fetch_alerting_rules",
                ],
                StateName.EVIDENCE_COLLECTION: [
                    "observe.fetch_service_logs",
                    "observe.fetch_apm_data",
                    "repo.get_feature_flags",
                ],
                StateName.CORRELATION: ["observe.check_uptime_history"],
                StateName.RESPONSE_PROPOSAL: ["comms.post_to_slack"],
                StateName.POST_MORTEM: ["comms.update_runbook"],
            }.get(state_name, [])

        return {
            StateName.RECEIVED: [
                "comms.create_incident_channel",
                "comms.post_to_slack",
            ],
            StateName.TRIAGE: [
                "observe.fetch_alerting_rules",
                "observe.get_error_rate_timeseries",
                "observe.query_metrics_range",
                "repo.get_deploy_history",
                "observe.check_pod_health",
            ],
            StateName.EVIDENCE_COLLECTION: [
                "observe.fetch_service_logs",
                "observe.fetch_service_logs",
                "observe.get_distributed_traces",
                "observe.check_db_slow_queries",
                "observe.fetch_apm_data",
                "repo.diff_pull_request",
                "repo.fetch_pr_metadata",
                "repo.fetch_test_results",
                "repo.blame_file_line",
                "repo.get_feature_flags",
            ],
            StateName.CORRELATION: [
                "observe.check_uptime_history",
                "repo.get_rollback_targets",
                "repo.read_deployment_config",
            ],
            StateName.RESPONSE_PROPOSAL: ["comms.post_to_slack"],
            StateName.REMEDIATION: ["infra.rollback_deployment", "observe.get_error_rate_timeseries"],
            StateName.POST_MORTEM: [
                "comms.write_post_mortem",
                "comms.create_jira_ticket",
                "comms.update_runbook",
                "comms.post_to_slack",
            ],
        }.get(state_name, [])


class ModelBackedToolPlanner:
    def __init__(
        self,
        *,
        model: str | None = None,
        api_key: str | None = None,
        http_client: httpx.Client | None = None,
        deterministic_client: DeterministicIncidentModelClient | None = None,
        endpoint: str | None = None,
    ):
        self.model = model or os.getenv("SENTINEL_MODEL") or os.getenv("OPENAI_MODEL") or "gpt-5.5"
        self.api_key = api_key if api_key is not None else os.getenv("OPENAI_API_KEY") or os.getenv("GROQ_API_KEY")
        self.http_client = http_client or httpx.Client(timeout=30.0)
        self.deterministic_client = deterministic_client or DeterministicIncidentModelClient()
        self.endpoint = endpoint or os.getenv("SENTINEL_MODEL_ENDPOINT") or _default_endpoint(self.api_key)
        self.last_decision: dict[str, Any] = {}

    def plan_tools(
        self,
        *,
        state: InvestigationState,
        available_contracts: list[ToolContract],
        objective: str,
        all_contracts: list[ToolContract] | None = None,
    ) -> list[str]:
        if not self.api_key:
            planned = self._deterministic_plan(
                state=state,
                available_contracts=available_contracts,
                objective=objective,
                all_contracts=all_contracts,
            )
            self.last_decision = self._decision_trace(
                state=state,
                objective=objective,
                available_contracts=available_contracts,
                selected_tools=planned,
                source="deterministic_fallback",
                fallback_reason="missing_api_key",
            )
            return planned

        available_names = {contract.name for contract in available_contracts}
        try:
            response = self.http_client.post(
                self.endpoint,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json=self._request_body(
                    state=state,
                    objective=objective,
                    available_contracts=available_contracts,
                    all_contracts=all_contracts or available_contracts,
                ),
            )
            response.raise_for_status()
            response_payload = response.json()
            raw_text = _response_text(response_payload)
            selected = _extract_tool_names(response_payload)
        except Exception as exc:
            planned = self._deterministic_plan(
                state=state,
                available_contracts=available_contracts,
                objective=objective,
                all_contracts=all_contracts,
            )
            self.last_decision = self._decision_trace(
                state=state,
                objective=objective,
                available_contracts=available_contracts,
                selected_tools=planned,
                source="deterministic_fallback",
                fallback_reason=type(exc).__name__,
            )
            return planned

        planned = [name for name in selected if name in available_names]
        if planned:
            self.last_decision = self._decision_trace(
                state=state,
                objective=objective,
                available_contracts=available_contracts,
                selected_tools=planned,
                source="model",
                raw_response_text=raw_text,
            )
            return planned
        planned = self._deterministic_plan(
            state=state,
            available_contracts=available_contracts,
            objective=objective,
            all_contracts=all_contracts,
        )
        self.last_decision = self._decision_trace(
            state=state,
            objective=objective,
            available_contracts=available_contracts,
            selected_tools=planned,
            source="deterministic_fallback",
            fallback_reason="model_returned_no_eligible_tools",
            raw_response_text=raw_text,
        )
        return planned

    def _deterministic_plan(
        self,
        *,
        state: InvestigationState,
        available_contracts: list[ToolContract],
        objective: str,
        all_contracts: list[ToolContract] | None,
    ) -> list[str]:
        return self.deterministic_client.plan_tools(
            state=state,
            available_contracts=available_contracts,
            objective=objective,
            all_contracts=all_contracts,
        )

    def _request_body(
        self,
        *,
        state: InvestigationState,
        objective: str,
        available_contracts: list[ToolContract],
        all_contracts: list[ToolContract],
    ) -> dict[str, Any]:
        tool_schemas = [_tool_schema(contract) for contract in all_contracts]
        eligible_tool_names = [contract.name for contract in available_contracts]
        planner_input = {
            "objective": objective,
            "current_state": state.current_state.value,
            "trigger_kind": state.trigger_kind,
            "incident_id": state.incident_id,
            "affected_services": state.affected_services,
            "service_priority": state.service_priority,
            "context_summary": state.context_summary,
            "evidence_count": len(state.evidence),
            "tool_schemas": tool_schemas,
            "eligible_tool_names": eligible_tool_names,
        }
        return {
            "model": self.model,
            "input": [
                {
                    "role": "system",
                    "content": [
                        {
                            "type": "input_text",
                            "text": (
                                "You are SENTINEL's incident planner. Select the next tool calls "
                                "from eligible_tool_names only. Return strict JSON with two keys: "
                                "tools, an ordered list of tool names, and rationale, a brief "
                                "string explaining the operational reason for the selected tools. "
                                "Do not invent tools."
                            ),
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": json.dumps(planner_input)}],
                },
            ],
            "text": {"format": {"type": "json_object"}},
        }

    def _decision_trace(
        self,
        *,
        state: InvestigationState,
        objective: str,
        available_contracts: list[ToolContract],
        selected_tools: list[str],
        source: str,
        fallback_reason: str | None = None,
        raw_response_text: str | None = None,
    ) -> dict[str, Any]:
        trace = {
            "source": source,
            "provider": _provider_from_endpoint(self.endpoint),
            "model": self.model,
            "endpoint": self.endpoint,
            "current_state": state.current_state.value,
            "objective": objective,
            "eligible_tool_count": len(available_contracts),
            "selected_tools": selected_tools,
        }
        if fallback_reason:
            trace["fallback_reason"] = fallback_reason
        if raw_response_text:
            trace["model_raw_text"] = raw_response_text[:2000]
            rationale = _extract_rationale(raw_response_text)
            if rationale:
                trace["model_rationale"] = rationale
        return trace


def _default_endpoint(api_key: str | None) -> str:
    if api_key and os.getenv("GROQ_API_KEY") == api_key and not os.getenv("OPENAI_API_KEY"):
        return "https://api.groq.com/openai/v1/responses"
    return "https://api.openai.com/v1/responses"


def _provider_from_endpoint(endpoint: str) -> str:
    if "groq.com" in endpoint.lower():
        return "groq"
    if "openai.com" in endpoint.lower():
        return "openai"
    return "custom"


def _extract_rationale(raw_text: str) -> str | None:
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return None
    rationale = parsed.get("rationale")
    if isinstance(rationale, str) and rationale.strip():
        return rationale.strip()[:1000]
    return None


def _tool_schema(contract: ToolContract) -> dict[str, Any]:
    return {
        "name": contract.name,
        "namespace": contract.namespace.value,
        "permission": contract.permission.value,
        "description": contract.description,
        "input_schema": contract.input_schema,
        "output_schema": contract.output_schema,
        "phase_allowlist": [state.value for state in contract.phase_allowlist],
    }


def _extract_tool_names(payload: dict[str, Any]) -> list[str]:
    raw_text = _response_text(payload)
    if not raw_text:
        return []
    try:
        parsed = json.loads(raw_text)
    except json.JSONDecodeError:
        return []
    tools = parsed.get("tools")
    if not isinstance(tools, list):
        return []
    return [tool for tool in tools if isinstance(tool, str)]


def _response_text(payload: dict[str, Any]) -> str:
    output_text = payload.get("output_text")
    if isinstance(output_text, str):
        return output_text
    chunks: list[str] = []
    for item in payload.get("output", []):
        if not isinstance(item, dict):
            continue
        for content in item.get("content", []):
            if isinstance(content, dict) and isinstance(content.get("text"), str):
                chunks.append(content["text"])
    return "".join(chunks)
