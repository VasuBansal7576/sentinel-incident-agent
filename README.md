SENTINEL is a production-shaped incident agent. The deterministic path proves 26-step long-horizon orchestration with 37 tool calls. The live path proves real operational integration: Prometheus metrics → Loki logs → missing index diagnosis → human approval → idx_orders_user_id creation → verified fix → Discord timeline.

# SENTINEL

SENTINEL is a self-hosted DevOps incident investigation agent for the first painful minutes of on-call response. It attaches an Investigation to an incoming alert, gathers evidence through a typed 52-tool registry, constrains tool access by phase, spawns isolated service investigators when triage justifies fan-out, asks for explicit human approval before changing infrastructure, and writes an evidence-backed incident timeline.

The submission has two proof paths:

- **Deterministic path:** `python3 scripts/run_sentinel_demo.py` exercises the full 26-step state machine with 37 recorded tool calls, structured evidence, scoped subagents, approval, remediation, verification, and post-mortem output.
- **Live path:** `python3 scripts/run_real_slow_query_incident.py --summary-output .sentinel/real-slow-query-summary.json` deploys SENTINEL, Prometheus, and Loki to a local kind cluster; generates real `/slow-query` latency; receives a real Prometheus alert payload; reads real Prometheus and Loki evidence; requests approval; creates `idx_orders_user_id`; verifies latency improvement; and posts the full timeline to Discord.

## Why This Exists

At 3am, the slow part of incident response is reconstructing truth across metrics, logs, deploys, infrastructure state, communication tools, and prior context. SENTINEL narrows that evidence-gathering window without replacing the incident system of record. It is autonomous in investigation and conservative in authority: it can propose and execute a fix only after a structured approval command from an authorized approver.

## Architecture

- `sentinel.models`: Pydantic domain contracts, approvals, evidence, recommendations, remediation results, and the Investigation state machine.
- `sentinel.tools`: declarative 52-tool registry across `observe.*`, `repo.*`, `infra.*`, and `comms.*`, with typed contracts, phase allowlists, rate limits, retries, audit records, and reasoning traces.
- `sentinel.orchestrator`: phase controller for long-horizon investigations, approval gating, evidence composition, remediation verification, and post-mortem generation.
- `sentinel.subagents`: Service Investigator, Blast Radius, and Remediation Readiness subagents with isolated contexts and scoped tool sets.
- `sentinel.real_tools` and `sentinel.live_clients`: provider-backed adapters with pagination, OAuth/token auth, circuit breakers, Redis-backed rate counters, and fail-closed error normalization.
- `sentinel.slow_query`: real SQLite workload used by the live proof; it exposes `/slow-query`, emits metrics, pushes logs to Loki, and creates the approved `orders.user_id` index.
- `sentinel.webapp`: FastAPI webhook receiver, approval endpoint, OAuth endpoints, readiness checks, metrics endpoint, and live investigation status API.
- `sentinel.evaluation`: scenario oracle harness for golden path, degraded-tool behavior, and Watch safety.

## Model-Driven Tool Use

The state machine defines what phase SENTINEL is in and which tools are safe in that phase. Within those constraints, the model-facing planner selects the evidence-gathering steps from the 52-tool registry. Tool calls carry reasoning traces, consume structured outputs from earlier calls, and are recorded with input/output hashes so the reviewer can see why each step happened.

This is the intended trust boundary: deterministic guardrails for safety, model-directed tool choice for investigation.

## Run The Deterministic Proof

```bash
python3 scripts/run_sentinel_demo.py
```

This prints a record-ready incident timeline and writes a local recording summary under `.sentinel/`. The path proves:

- 26-step state-machine execution.
- 37 tool calls in one investigation session.
- scoped service investigators with isolated context IDs.
- structured approval before remediation.
- mitigation verification and post-mortem generation.

## Run The Live Proof

Set a real Discord webhook URL in `.env`:

```bash
python3 scripts/configure_discord_webhook.py --from-stdin --test-post
```

Then run:

```bash
python3 scripts/run_real_slow_query_incident.py --summary-output .sentinel/real-slow-query-summary.json
```

The live run creates a local kind cluster, deploys SENTINEL with Prometheus and Loki, drives load against `/slow-query`, waits for a real Prometheus alert, posts the alert to `/webhooks/generic`, waits for human approval, creates `idx_orders_user_id`, verifies the real latency drop, and posts the timeline to Discord.

The last successful live proof showed:

- Prometheus latency before fix: `162.6ms`.
- Prometheus latency after fix: `5.4ms`.
- Loki evidence: sequential scan on `SELECT * FROM orders WHERE user_id = ?`.
- Approved remediation: `CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)`.
- Discord timeline: alert received, evidence read, approval received, index created, fix verified.

## Deployment

For the local production-shaped stack:

```bash
docker compose up --build
```

Compose starts SENTINEL, PostgreSQL, Redis, Prometheus, and Loki. In production mode, SENTINEL requires `SENTINEL_API_TOKEN`, `DATABASE_URL`, and `REDIS_URL`; webhook and OAuth secrets must be provided through environment variables, not checked into the repository.

The webhook receiver exposes:

```text
POST /webhooks/generic
POST /webhooks/pagerduty
GET  /investigations/{investigation_id}
POST /investigations/{investigation_id}/approval
GET  /metrics
GET  /ready
GET  /ready/live
```

## Additional Cloud Integrations

The submission proof centers on Prometheus, Loki, kind, SQLite, and Discord because those can be demonstrated end-to-end with real local infrastructure and a free notification target. The codebase also contains additional integration surfaces for Datadog, PagerDuty, Slack, GitHub, OAuth token storage, Kubernetes rollback, and provider connectivity checks. Treat those as extension points unless they are run with real credentials in the target environment.

## Tests

```bash
pytest -q
docker compose config -q
python3 -m compileall -q sentinel scripts tests
```

Opt-in live gates exist for environments with credentials and a running receiver:

```bash
RUN_LIVE_TESTS=1 pytest tests/test_live_connectivity.py
RUN_FREE_TIER_LIVE_E2E_TESTS=1 SENTINEL_LIVE_RECEIVER_URL=http://localhost:8000 pytest tests/test_free_tier_live_e2e.py
```

## Reviewer Proof Artifacts

- [MEMO.md](MEMO.md): one-page build memo and defended design decision.
- [architecture.md](architecture.md): architecture diagram and reviewer file map for the 52-tool registry, planner, subagents, live proof, and production scaffolding.
- [docs/live-proof.md](docs/live-proof.md): redacted Prometheus, Loki, SQLite, and Discord evidence from the live run.
- [docs/model-driven-proof.md](docs/model-driven-proof.md): hosted model-backed planner proof using the 52-tool registry.
- [docs/subagent-proof.md](docs/subagent-proof.md): isolated service-investigator proof with scoped tools and structured reports.
- Native unedited Codex trace: submitted separately as the email attachment required by `Problem.md`; it is intentionally not committed because it must remain unedited and may contain local/private material.
- [codex-traces-redacted.jsonl](codex-traces-redacted.jsonl): public-safe redacted trace copy for repository review convenience only; do not use it as a substitute for the native unedited Codex trace attachment.
