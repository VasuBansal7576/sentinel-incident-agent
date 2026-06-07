# Video Strategy

Target length: 4:00

Lead with the deterministic path for the 20+ tool-call requirement. Then use the live path as integration proof.

## 0:00-0:30 - Problem

Show `README.md` and say:

```text
This is SENTINEL, a production-shaped incident agent for the first 20 minutes after a 3am on-call page. The pain is not lack of data; it is reconstructing truth across metrics, logs, deploys, infra, repo context, and team channels before anyone can act.
```

Point at:

- `observe`, `repo`, `infra`, `comms` namespaces in `sentinel/tools.py`.
- The state machine in `sentinel/models.py`.

## 0:30-1:45 - Deterministic Long-Horizon Demo

Run:

```bash
python3 scripts/run_sentinel_demo.py --summary-output .sentinel/recording-demo-summary.json
```

Show the fresh output:

```text
Full run: 37 tool calls, 26 plan steps, status=completed
```

Say:

```text
This is the long-horizon proof. SENTINEL executes 26 plan steps and 37 recorded tool calls in one investigation session. It gathers evidence, spawns isolated service investigators, reconciles reports, requests approval, executes the approved remediation, verifies recovery, and drafts the post-mortem.
```

Then show `docs/model-driven-proof.md`:

```text
The deterministic run is reproducible. The planner boundary is model-backed: with a key, SENTINEL sends all 52 tool schemas and the current phase's eligible tools to a hosted model. In the direct Groq-backed proof, `llama-3.3-70b-versatile` selected `observe.fetch_service_logs`, `observe.get_distributed_traces`, and `observe.check_pod_health` from 28 triage-eligible tools, and the app planner returned that same list without deterministic fallback.
```

## 1:45-2:45 - Live Proof

Show `docs/live-proof.md`.

Say:

```text
The live path proves this is not only a replay. It deployed SENTINEL, Prometheus, and Loki in kind, generated real /slow-query latency, received a real generic Prometheus alert, read real Prometheus and Loki evidence, requested human approval, created idx_orders_user_id, verified Prometheus latency improved from 162.6ms to 5.4ms, and posted the timeline to Discord.
```

Show:

- Prometheus before fix: `162.6ms`.
- Prometheus after fix: `5.4ms`.
- Loki sequential-scan log.
- Discord timeline.

## 2:45-3:25 - Code Walkthrough

Open:

- `sentinel/orchestrator.py`
- `sentinel/subagents.py`
- `sentinel/tools.py`

Say:

```text
The important boundary is autonomy inside deterministic safety. The phase controller decides what is safe in each phase. The planner chooses tools from the eligible set. `infra.spawn_service_investigator` creates isolated subagent contexts. Those subagents only get observe and repo tools; infra and comms attempts are denied. The parent consumes structured ServiceIncidentReport objects and owns final communication and remediation.
```

Show `docs/subagent-proof.md`:

- `infra.spawn_service_investigator`.
- Sample `subagent_context_id`.
- Observe/repo scoped tools.
- Denied `infra.rollback_deployment` and `comms.post_to_slack`.
- Parent reconciliation consuming two reports.

## 3:25-3:45 - Production Scaffolding

Show:

- `pytest -q` output.
- `docker compose config -q` output.
- `sentinel/live_clients.py` or `sentinel/rate_limiters.py` for retries, rate limits, and typed provider failures.

Say:

```text
This is structured for deployment rather than as a notebook. The build has typed provider errors, retryable failure classification, rate limits, audit hashes, an evaluation harness, unit and integration tests, and Docker Compose deployment shape.
```

## 3:45-4:00 - Divergence Moment

Say:

```text
One place I diverged from the model was orchestration. I considered a framework-style agent stack (LangChain/CrewAI) but chose a custom phase controller with deterministic guardrails because frameworks abstract away checkpointing and typed error recovery that production incident response requires.
```

Close with:

```text
SENTINEL is autonomous where autonomy helps: evidence gathering and correlation. It is deterministic where production safety matters: tool boundaries, approval, mutation scope, and verification.
```
