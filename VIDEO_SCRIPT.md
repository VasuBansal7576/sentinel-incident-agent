# SENTINEL 3-Minute Video Script

## 0:00-0:30 - The Problem

"This is SENTINEL, a production-shaped incident agent for the worst part of on-call: the first 20 minutes after a 3am page. The problem is not that teams lack data. The problem is that the responder has to open metrics, logs, deploy history, Kubernetes state, repository context, and team channels, then manually reconstruct what happened before they can act. SENTINEL attaches an Investigation to the alert, gathers evidence, proposes a fix, waits for human approval, executes only the approved action, verifies the result, and writes the timeline."

Show:

- `README.md` opening sentence.
- The four namespaces in `sentinel/tools.py`: `observe`, `repo`, `infra`, `comms`.
- The state machine in `sentinel/models.py`.

## 0:30-1:30 - Deterministic Demo

"First I will run the deterministic proof. This is the long-horizon path: 26 state-machine steps and 37 tool calls in one session."

Run:

```bash
python3 scripts/run_sentinel_demo.py
```

Narrate while the output scrolls:

"The important thing is not just the final answer. Watch the state transitions: received, triage, evidence collection, service investigation, correlation, response proposal, remediation, post-mortem. Each phase exposes a scoped set of tools. The model-facing planner chooses which tools to call from the 52-tool registry, and the executor records the reasoning trace, input hash, output hash, phase, duration, and success for every call."

Show:

- The final `completed` / `post_mortem` status.
- The tool-call count.
- A few reasoning traces from the terminal output or `.sentinel/recording-demo-summary.json`.
- `sentinel/tools.py` `build_tool_contracts()` to show 52 typed tools across four namespaces.

Line to say clearly:

"This is not a chain of hand-coded if-statements. The state machine constrains what is safe; the model chooses evidence gathering within those guardrails."

## 1:30-2:30 - Live Proof

"Now the live proof. This run deploys SENTINEL, Prometheus, and Loki into kind. The app exposes `/slow-query`, which performs a real SQLite query without an index. A load thread pushes latency high enough for Prometheus to alert. SENTINEL receives the real alert payload through `/webhooks/generic`, reads real Prometheus metrics and real Loki logs, diagnoses the missing `orders.user_id` index, asks for approval, creates `idx_orders_user_id`, verifies the metric improvement, and posts the timeline to Discord."

Show the saved proof:

```bash
python3 - <<'PY'
import json
from pathlib import Path
data = json.loads(Path(".sentinel/real-slow-query-summary.json").read_text())
print(data["diagnosis"])
print(data["remediation_result"]["message"])
print(data["last_discord_message"])
PY
```

Narrate the numbers:

"The live proof recorded `/slow-query` latency at 162.6ms before the fix and 5.4ms after the fix. Loki showed the sequential scan. The approved remediation created `idx_orders_user_id` on `orders(user_id)`. Discord received the full incident timeline."

Show:

- `kubectl get pods -n sentinel-real`.
- The Discord message in the browser or from the summary output.
- The line in the timeline that says Prometheus before fix and after fix.

## 2:30-3:15 - Divergence And Code Walkthrough

"One place where I diverged from the model was the submission claim around enterprise providers. The model pushed toward saying every provider path was live-proven. I cut that claim. The proof path here is real Prometheus, Loki, kind, SQLite, and Discord. Datadog, PagerDuty, Slack, GitHub OAuth, and broader Kubernetes paths are implemented as additional cloud integrations unless a reviewer runs them with their own credentials."

"The most substantive code is the boundary between autonomous investigation and deterministic safety."

Open:

- `sentinel/orchestrator.py`
- `sentinel/subagents.py`
- `sentinel/tools.py`

Point out:

- In `orchestrator.py`, the phase controller transitions the Investigation and calls `_tool_step`; approval is rejected unless request ID, approver, expiry, notification proof, and remediation scope all match.
- In `subagents.py`, each Service Investigator receives an `IsolatedSubagentContext`, a scoped tool set, and returns a typed report to the parent.
- In `tools.py`, `build_tool_contracts()` creates the 52-tool registry and `ToolExecutor.invoke()` denies tools outside the scoped registry or current phase.
- In `model_client.py`, the production planner calls the model with tool schemas and current state, while tests can inject deterministic clients for reproducible evaluation.

Closing line:

"SENTINEL is autonomous where autonomy helps: evidence gathering and correlation. It is deterministic where determinism matters: tool boundaries, approval, mutation scope, and verification."
