SENTINEL is a production-shaped incident agent. The deterministic path proves 26-step long-horizon orchestration with 37 tool calls. The latest credentialed live path proves 34 real tool calls across Groq, GitHub, Prometheus, Loki, SQLite, generic webhook, and Discord: model tool planning -> metrics -> logs -> repo evidence -> subagents -> missing index diagnosis -> human approval -> idx_orders_user_id creation -> verified fix -> Discord timeline.

# SENTINEL

SENTINEL is a self-hosted DevOps incident investigation agent for the first painful minutes of on-call response. It attaches an Investigation to an incoming alert, gathers evidence through a typed 52-tool registry, constrains tool access by phase, spawns isolated service investigators when triage justifies fan-out, asks for explicit human approval before changing infrastructure, and writes an evidence-backed incident timeline.

The submission has two proof paths:

- **Deterministic path:** `python3 scripts/run_sentinel_demo.py` exercises the full 26-step state machine with 37 recorded tool calls, structured evidence, scoped subagents, approval, remediation, verification, and post-mortem output.
- **Credentialed live path:** `scripts/record_credentialed_live_e2e.sh` starts the local production-shaped stack; prompts for real Groq, GitHub, Discord, database, Redis, and API credentials; generates real `/slow-query` latency; receives a real generic Prometheus alert payload; executes 34 recorded tool calls; reads real Prometheus, Loki, GitHub, and SQLite evidence; restarts and resumes from a SQLite checkpoint; requests approval; creates `idx_orders_user_id`; verifies latency improvement; and posts the full timeline to Discord.

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

Then run the credentialed live proof:

```bash
python3 scripts/preflight_credentialed_live_e2e.py
scripts/record_credentialed_live_e2e.sh
```

The live run starts the local Docker Compose stack, drives load against `/slow-query`, waits for a real Prometheus alert, posts the alert to `/webhooks/generic`, records Groq model tool plans, reads GitHub evidence, spawns service-investigator subagents, restarts the receiver to prove checkpoint recovery, waits for human approval, creates `idx_orders_user_id`, verifies the real latency drop, and posts the timeline to Discord.

The last successful live proof showed:

- Tool calls: `34`.
- Prometheus latency before fix: `115.2ms`.
- Prometheus latency after fix: `1.2ms`.
- Loki evidence: sequential scan on `SELECT * FROM orders WHERE user_id = ?`.
- GitHub evidence: recent commits and rollback-target evidence from a live GitHub API call.
- Prometheus checks: alerting rules, target health, error rate, queue depth, network RTT, uptime, CPU, and memory.
- Approved remediation: `CREATE INDEX IF NOT EXISTS idx_orders_user_id ON orders(user_id)`.
- Discord timeline: alert received, evidence read, approval received, index created, fix verified.

## Run A Credentialed Real E2E

For a video run with real credentials, Groq-backed model selection, real GitHub/Discord/API calls, checkpoint restart, structured approval, and a full log:

```bash
python3 scripts/preflight_credentialed_live_e2e.py
scripts/record_credentialed_live_e2e.sh
```

The recording wrapper loads `.env` if present, prompts only for required missing values, tees terminal output to `.sentinel/live-run-<timestamp>.log`, and writes the structured proof log to `.sentinel/live-run-<timestamp>.structured.log`. Optional Datadog, PagerDuty, and Slack credentials are read from the environment without blocking prompts; pass `--prompt-optional-integrations` only when you want to enter them interactively. The runner posts a real generic webhook payload, restarts the receiver at the approval checkpoint, and fails unless the final status shows 20+ tool calls, a Groq model plan with rationale, subagent evidence, provider-specific proof for the real APIs used, Discord notification, checkpoint recovery, approval, remediation, and verification.

The credential prompt still asks for `DATABASE_URL` with the local Docker PostgreSQL default, because that is the production-shaped database configuration. For the exact video checkpoint proof, the default runner then asks for `SQLITE_CHECKPOINT_DATABASE_URL` and uses that file-backed SQLite store at `sqlite:////data/sentinel-live-checkpoint.sqlite3` so the restart proof is visibly a SQLite resume. Use `--checkpoint-backend postgres` only when you want the local Docker PostgreSQL store instead of the exact SQLite checkpoint proof.

After the run, independently verify the captured log:

```bash
python3 scripts/verify_credentialed_live_log.py .sentinel/live-run-<timestamp>.log
```

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

The submission proof centers on Groq, GitHub, Prometheus, Loki, SQLite, generic webhooks, and Discord because those were demonstrated end-to-end with real credentials and local operational infrastructure. The codebase also contains additional integration surfaces for Datadog, PagerDuty, Slack, GitHub OAuth, Kubernetes rollback, OAuth token storage, and provider connectivity checks. Treat those as extension points unless they are run with real credentials in the target environment.

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
