# Model-Driven Planner Proof

Date: 2026-06-06

Status: direct app-level model-backed planner proof captured with Groq's OpenAI-compatible Responses endpoint.

This document exists for the reviewer concern that the deterministic demo is only a scripted chain. SENTINEL has a model-backed planner boundary in `sentinel/model_client.py`: the orchestrator sends the full 52-tool registry plus the current phase's eligible tools, and the planner returns ordered tool names. The deterministic client is the reproducible fallback, not the only path.

## Direct App Planner Proof

I exercised the unmodified `ModelBackedToolPlanner.plan_tools(...)` path with a Groq-hosted model through the planner's configurable endpoint, API key, model, and HTTP client constructor arguments. The API key stayed in ignored local `.env`; this proof output is sanitized.

Command shape:

```bash
python3 - <<'PY'
# Loads GROQ_API_KEY and SENTINEL_MODEL from ignored .env.
# Instantiates ModelBackedToolPlanner with:
#   endpoint="https://api.groq.com/openai/v1/responses"
#   model="llama-3.3-70b-versatile"
# Sends build_tool_contracts() plus triage-eligible contracts.
# Prints sanitized planner/request/response evidence.
PY
```

Sanitized output:

```text
proof_status model_response_parsed
endpoint https://api.groq.com/openai/v1/responses
model llama-3.3-70b-versatile
http_status 200
incident_id MODEL-PROOF-001
incident_state triage
objective Establish customer impact and pick the first evidence tool for triage.
registry_tools_sent 52
eligible_tools_sent 28
model_raw_text {   "tools": [        "observe.fetch_service_logs",        "observe.get_distributed_traces",        "observe.check_pod_health"    ] }
planner_returned_tools observe.fetch_service_logs,observe.get_distributed_traces,observe.check_pod_health
selected_tool_was_eligible True
```

The model selected only triage-eligible tools, and the planner returned the same model-selected list. Remediation tools such as `infra.rollback_deployment` were not eligible in this phase.

## Model Reasoning Capture

For the video and reviewer narrative, I also ran the same app planner boundary with a one-off prompt extension that asked the hosted model to include a concise `rationale` field. The selection/filtering path remained `ModelBackedToolPlanner.plan_tools(...)`; the extension only made the model's reasoning visible in the sanitized proof output.

```text
proof_status model_response_parsed
endpoint https://api.groq.com/openai/v1/responses
model llama-3.3-70b-versatile
http_status 200
incident_id MODEL-PROOF-001
incident_state triage
trigger_kind incident
affected_services payment-service
objective Establish customer impact and pick the first evidence tool for triage.
registry_tools_sent 52
eligible_tools_sent 28
model_selected_tools observe.fetch_service_logs,observe.get_distributed_traces,observe.check_pod_health
planner_returned_tools observe.fetch_service_logs,observe.get_distributed_traces,observe.check_pod_health
selected_tool_was_eligible True
model_reasoning The first selected tool, observe.fetch_service_logs, fits the incident state because it provides immediate visibility into recent service behavior, which is essential for understanding the current incident's impact and scope during the triage phase.
```

## What To Show In The Video

Show `sentinel/model_client.py`:

- `ModelBackedToolPlanner.plan_tools(...)` posts to a hosted Responses-compatible endpoint when an API key exists.
- The request includes `tool_schemas` for all 52 tools.
- The request includes `eligible_tool_names` for the current phase only.
- Returned tool names are filtered against eligible tools before execution.
- If the hosted call fails or has no key, SENTINEL uses the deterministic client for repeatable demos and tests.

Say this clearly:

```text
The deterministic run is the reproducible proof path. The planner boundary is model-backed: with a key, it sends all 52 tool schemas and phase-eligible tool names to a hosted model, then executes only eligible returned tools. In the direct Groq-backed proof, the model selected observe.fetch_service_logs, observe.get_distributed_traces, and observe.check_pod_health for a triage incident, and the app planner returned that same eligible list without deterministic fallback.
```
