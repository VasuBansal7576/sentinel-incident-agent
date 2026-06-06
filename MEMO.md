# MEMO: SENTINEL

## What I Built

SENTINEL is a self-hosted incident investigation agent that attaches an Investigation to an incoming alert, runs an 8-state investigation, gathers evidence through 52 typed tools across four namespaces, spawns isolated subagents with scoped registries, proposes fixes, requires structured human approval, executes the approved remediation, verifies the result, and drafts a post-mortem.

The deterministic proof runs a 26-step incident flow with 35 tool calls, durable state, typed errors, retries with exponential backoff, rate limiting, structured evidence, approval snapshots, and post-mortem output. The live proof deploys SENTINEL with Prometheus and Loki on kind, triggers a real `/slow-query` latency incident, diagnoses a missing SQLite index from real metrics and logs, receives human approval, creates `idx_orders_user_id`, verifies latency improved from 162.6ms to 5.4ms, and posts the timeline to Discord.

The orchestrator defines phases (TRIAGE, INVESTIGATE, DIAGNOSE, PROPOSE) but the model selects which tools to call within each phase from the 52-tool registry. The state machine constrains the phase transitions; the model decides the evidence gathering. This is not a deterministic workflow with agent seasoning — it is an agent with deterministic guardrails.

## What I Cut

I cut any claim that every external enterprise integration is fully proven in the submission environment. The strongest proof path uses real local operational infrastructure: Prometheus, Loki, kind, SQLite, and Discord. Datadog, PagerDuty, Slack, GitHub OAuth, and broader Kubernetes paths are present as additional integration surfaces, but the submitted live proof does not depend on credentials a reviewer may not have.

I also cut fully autonomous remediation. SENTINEL can investigate and propose a fix autonomously, but changing infrastructure requires an exact approval request, an authorized approver, a structured approval command, a one-shot approval snapshot, and a final scope recheck immediately before execution.

## What More Time Would Address

More time would add a larger incident corpus, richer scenario generation from historical incidents, persistent worker queues, Slack interactive approval components, incident-system writeback, better cost telemetry, and repeated live runs against hosted provider accounts.

## Decision I Would Defend

I would defend triage-gated service investigators. Spawning subagents on every alert is noisy and expensive. SENTINEL first establishes scope, then fans out only when multiple affected services or unclear blast radius justify it. Each Service Investigator gets isolated context and read-only scoped tools, and the parent performs evidence reconciliation instead of averaging confidence or picking the loudest report. That keeps multi-service incident investigation fast without surrendering coherence or safety.
