# MEMO: SENTINEL

## What I Built

SENTINEL is a self-hosted incident investigation agent. It receives an alert, creates a durable Investigation, moves through an 8-state incident flow, exposes a typed 52-tool registry across `observe`, `repo`, `infra`, and `comms`, lets the model choose safe phase-eligible tools, records evidence and audit hashes, proposes remediation, requires structured human approval, executes only the approved action, verifies the result, and drafts a post-mortem.

The deterministic proof run covers the long-horizon path: 26 plan steps, 37 recorded tool calls, scoped service investigators, approval snapshots, rollback, verification, and post-mortem output. The live proof uses Prometheus, Loki, kind, SQLite, and Discord to trigger a real `/slow-query` alert, diagnose the missing `orders.user_id` index, receive approval, create `idx_orders_user_id`, verify latency improved from `162.6ms` to `5.4ms`, and post the timeline to Discord.

## What I Cut

I cut the claim that every enterprise provider path is live-proven in the submission environment. The proof path is real local operational infrastructure: Prometheus, Loki, kind, SQLite, and Discord. Datadog, PagerDuty, Slack, GitHub OAuth, and broader Kubernetes paths are additional cloud integrations unless a reviewer runs them with their own credentials.

I also cut unrestricted autonomy. SENTINEL can investigate and recommend, but production mutation requires a specific approval request, an authorized approver, a structured approval command, an approval snapshot, idempotency, and a final scope check immediately before execution.

## More Time

More time would add a larger incident corpus, hosted-provider validation runs with reviewer credentials, durable worker queues, Slack interactive approvals, incident-system writeback, cost telemetry, and repeated live runs across more incident types than the missing-index path.

## Decision I Defend

I defend triage-gated service investigators. Spawning subagents for every alert is noisy and expensive. SENTINEL first establishes scope, then fans out only when multiple services or unclear blast radius justify it. Each Service Investigator gets isolated context and read-only scoped tools; the parent Investigation reconciles structured reports instead of averaging confidence or picking the loudest local diagnosis. That keeps multi-service investigation useful without surrendering safety or coherence.

I also considered a framework-style agent stack (LangChain/CrewAI) but chose a custom phase controller with deterministic guardrails because frameworks abstract away checkpointing and typed error recovery that production incident response requires.
