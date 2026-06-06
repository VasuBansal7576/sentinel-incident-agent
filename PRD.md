# PRD: SENTINEL Autonomous Incident Investigation Agent

## Problem Statement

Modern on-call work still depends on a tired human manually reconstructing truth across too many operational systems. When an incident fires at 3am, the responder opens metrics, logs, traces, deploy history, Kubernetes state, repository history, runbooks, and team channels, then mentally correlates all of it before the team can confidently say what happened and what to do next.

SENTINEL exists to reduce that evidence-gathering window without replacing the incident system of record. It owns an Investigation attached to an incoming alert. It does not own paging policy, incident lifecycle, external customer communication, or production authority without human approval.

The hackathon product goal is narrow and demonstrable: prove a production-shaped autonomous incident agent with 50+ typed tools, at least four namespaces, model-driven tool selection, isolated subagents, long-horizon execution, deployable scaffolding, typed errors, backoff, rate limiting, evaluation, unit/integration coverage, and composable tool outputs.

## Single Submission Story

SENTINEL has two proof paths:

- **Deterministic path:** proves long-horizon orchestration through a 26-step incident flow with 35 tool calls, scoped subagents, phase-constrained tool access, approval gating, remediation verification, and post-mortem generation.
- **Live path:** proves real operational integration through Prometheus metrics, Loki logs, a real `/slow-query` latency spike, missing-index diagnosis, human approval, `idx_orders_user_id` creation, verified latency improvement, and a Discord timeline.

The product story is not "rollback only." The product story is: SENTINEL investigates incidents and proposes fixes; in v1, remediation requires human approval. The live proof shows an approved index creation.

## Solution

SENTINEL is a self-hosted DevOps incident response agent that runs as a single service runtime in v1. It receives incident triggers, creates or resumes a durable Investigation, gathers evidence through a declarative tool registry, orchestrates investigation phases, spawns bounded service investigators only when triage proves the need, reconciles evidence across services, posts human-facing updates, requests structured approval for executable remediation, and records audit events throughout.

The runtime follows a phase controller pattern. The state machine controls phase transitions and exposes only phase-appropriate tools. The model-facing planner chooses evidence-gathering tools within those constraints. Invalid tool access is denied and audited rather than silently substituted.

SENTINEL v1 has four canonical tool namespaces:

- `observe.*` for logs, metrics, traces, error rates, SLO burn, dashboards, monitors, anomaly detection, and incident timeline evidence.
- `repo.*` for deploy history, commits, pull requests, code ownership, diffs, feature flags, migrations, and runbook references.
- `infra.*` for Kubernetes health, pods, rollouts, resource pressure, restarts, ingress state, database signals, queue health, rollback execution, and approved index creation.
- `comms.*` for alert context, internal updates, approval requests, stakeholder summaries, post-mortems, action items, and audit-visible communications.

## Trust Boundaries

- SENTINEL may investigate autonomously.
- SENTINEL may recommend a fix only when it can cite evidence.
- SENTINEL may execute remediation only after a specific approval request is approved by an authorized approver.
- Approval is one-shot and state-bound; stale or mismatched approvals are rejected.
- Remediation execution rechecks scope immediately before mutation.
- Watches and proactive triggers can start investigations but cannot execute incident powers by themselves.
- External customer communication remains out of scope.

## User Stories

1. As an on-call engineer, I want SENTINEL to attach an Investigation to an incoming incident alert, so that I get help without replacing my incident system of record.
2. As an on-call engineer, I want SENTINEL to acknowledge that it is investigating, so that the incident channel knows evidence collection has started.
3. As an on-call engineer, I want SENTINEL to fetch logs, metrics, traces, deploy history, repository context, and pod health, so that the first diagnostic pass happens before I open every tool manually.
4. As an on-call engineer, I want SENTINEL to preserve source citations for every evidence claim, so that I can trust why it reached a conclusion.
5. As an on-call engineer, I want SENTINEL to distinguish evidence from inference, so that I can see which claims are observed and which claims are reasoned.
6. As an on-call engineer, I want SENTINEL to identify affected services during triage, so that investigation effort follows blast radius instead of the first noisy alert.
7. As an on-call engineer, I want SENTINEL to continue from durable investigation state after a restart, so that an agent crash does not lose the incident timeline.
8. As an on-call engineer, I want SENTINEL to produce categorical confidence levels, so that I can quickly interpret whether it is confident, uncertain, or blocked by missing evidence.
9. As an on-call engineer, I want SENTINEL to say Insufficient Confidence when evidence is weak, so that it does not make a polished but unsafe recommendation.
10. As an on-call engineer, I want SENTINEL to name the next evidence it needs when confidence is insufficient, so that I know the fastest way to unblock the investigation.
11. As an on-call engineer, I want SENTINEL to post concise internal updates, so that I can monitor progress without reading raw traces.
12. As an on-call engineer, I want SENTINEL to propose remediation only when evidence links the symptom to a concrete cause, so that production changes are grounded.
13. As an on-call engineer, I want SENTINEL to ask for explicit human approval before remediation, so that production authority stays under human control.
14. As an on-call engineer, I want SENTINEL to execute only the exact approved remediation, so that a broad approval cannot be reused for a different action.
15. As an on-call engineer, I want SENTINEL to recheck approval immediately before execution, so that stale or revoked approvals are not used.
16. As an on-call engineer, I want SENTINEL to verify mitigation after remediation, so that we know whether the incident actually improved.
17. As an on-call engineer, I want SENTINEL to generate a post-mortem draft, so that incident cleanup starts from a factual timeline instead of a blank page.
18. As an incident commander, I want SENTINEL to keep human-facing communication owned by the parent Investigation, so that updates stay coherent across services.
19. As an incident commander, I want SENTINEL to reconcile conflicting service findings, so that the final diagnosis does not pick the loudest subagent report.
20. As an incident commander, I want SENTINEL to mark unresolved conflicts explicitly, so that the team can decide whether to continue investigating or mitigate.
21. As an incident commander, I want SENTINEL to separate immediate mitigation from long-term correction, so that the post-mortem does not overclaim.
22. As an incident commander, I want SENTINEL to identify customer-facing blast radius, so that impact communication is proportional to the incident.
23. As an incident commander, I want SENTINEL to preserve audit events, so that the incident record can be reviewed after the fact.
24. As an incident commander, I want SENTINEL to avoid external customer communication in v1, so that public messaging remains a human responsibility.
25. As a service owner, I want SENTINEL to spawn a Service Investigator only for affected services, so that my service is not investigated on every alert.
26. As a service owner, I want a Service Investigator to use only read-only service-scoped tools, so that investigation cannot mutate my service state.
27. As a service owner, I want the Service Investigator Report to include local diagnosis, evidence, confidence, conflicts, and gaps, so that I can evaluate the claim quickly.
28. As a service owner, I want action items to have accountable owners, so that post-mortem follow-up does not dissolve into vague recommendations.
29. As a platform engineer, I want a declarative tool registry, so that adding tools does not require changing the orchestration core.
30. As a platform engineer, I want each tool contract to define input, output, permission class, namespace, and failure modes, so that model-driven tool use remains bounded.
31. As a platform engineer, I want phase-filtered tool access, so that the model cannot call remediation tools during triage or evidence collection.
32. As a platform engineer, I want invalid tool access to be denied and audited, so that unsafe behavior is visible and testable.
33. As a platform engineer, I want typed tool outputs to compose into later tool inputs, so that long-horizon investigations can build on prior results.
34. As a platform engineer, I want tool failures to affect confidence, so that missing evidence changes the diagnosis instead of being ignored.
35. As a platform engineer, I want exponential backoff and rate limiting around tool calls, so that investigation does not overload upstream systems.
36. As a platform engineer, I want normalized typed errors, so that failures can be retried, surfaced, or scored consistently.
37. As a platform engineer, I want structured logging with timestamp, duration, input hash, output hash, cost, and success, so that traces are useful without storing raw sensitive payloads.
38. As a platform engineer, I want evidence retention without raw sensitive source material retention, so that the system preserves audit value while limiting data exposure.
39. As a platform engineer, I want explicit store migrations, so that schema changes are controlled and reproducible.
40. As a platform engineer, I want idempotency keys for triggers, approvals, and remediations, so that retries do not duplicate incident work.
41. As a platform engineer, I want a provider-agnostic model client, so that the runtime is not welded to one model vendor.
42. As a platform engineer, I want malformed model output to fail safely, so that invalid JSON or missing fields cannot silently proceed.
43. As an evaluator, I want a controlled deterministic incident path, so that the full product can be tested without production credentials.
44. As an evaluator, I want a live operational proof path, so that the system demonstrates real metrics, logs, approval, mutation, verification, and communication.
45. As a hackathon judge, I want traces showing more than 20 tool calls, so that the system demonstrates genuine long-horizon agent execution.
46. As a hackathon judge, I want at least 52 coherent tool contracts across four namespaces, so that the tool surface is broad but still architected.
47. As a hackathon judge, I want subagents with isolated contexts and structured reports, so that orchestration complexity is visible and meaningful.
48. As a hackathon judge, I want production scaffolding around the demo, so that it looks like an engineering artifact rather than a scripted prompt.
49. As a hackathon judge, I want a one-page MEMO defending a key design decision, so that the builder can explain an architectural tradeoff.

## Implementation Decisions

- SENTINEL owns Investigations, not incident lifecycle.
- The runtime is a single deployable FastAPI service backed by durable state.
- Tools are declared in a Tool Registry with namespace, permission class, schema, retry behavior, failure modes, and audit boundaries.
- The registry contains 52 tool contracts across `observe`, `repo`, `infra`, and `comms`.
- The deterministic proof uses a controlled incident environment for repeatable evaluation.
- The live proof uses real Prometheus, Loki, SQLite, kind, and Discord integrations.
- Additional provider adapters are available for environments with external credentials, but the submission proof does not require them.
- Human approval is required for all remediation in v1.
- Approval requests must be specific and include action, affected service, evidence summary, expected effect, risks, expiry, and idempotency key.
- Approval commands are structured; free-form chat is not treated as production approval.
- Only authorized approvers may approve remediation.
- Approval is one-shot and state-bound.
- Remediation execution records a Remediation Result and triggers verification.
- Post-mortems separate facts from inferences.
- Action items require accountable owners.
- Parent Investigation owns all human-facing incident communication.
- Service Investigators are spawned only after triage identifies multiple affected services or unclear blast radius.
- Each Service Investigator receives isolated context and read-only scoped tools.
- The parent reconciles service findings instead of averaging confidence or selecting the loudest report.
- Insufficient Confidence is an acceptable product outcome when evidence is weak, conflicting, or unavailable.

## Testing Decisions

Good tests for SENTINEL must verify the operational contract rather than only checking that a prompt returns plausible text. A passing test should prove that the system gathered the right evidence, respected tool permissions, handled failures explicitly, produced a grounded diagnosis, requested safe approval, executed only approved remediation, preserved audit state, and generated a post-mortem with facts separated from inferences.

Primary seams:

- Tool registry: 52 coherent contracts, namespaces, permission classes, phase allowlists, and composable schemas.
- Phase controller: each phase can call only its Phase Tool Set and denied access is audited.
- Model client: deterministic outputs for repeatable tests, provider-agnostic boundary for hosted models.
- Store: durable state, migrations, audit events, idempotency keys, and evidence retention boundaries.
- Subagents: isolated context, scoped read-only tools, report contracts, concurrency caps, and service priority.
- Approval: authorized approver checks, structured command parsing, one-shot snapshots, expiry, and state revalidation.
- Remediation: execution only after approval, idempotency, and mitigation verification.
- Evaluation: golden path, degraded-tool behavior, Watch safety, and long-horizon trace checks.

## Out Of Scope

- Replacing the incident system of record.
- Fully autonomous remediation without human approval.
- Direct external customer communication.
- Persisting raw logs, traces, pull request bodies, chat threads, or other sensitive source material beyond structured evidence.
- Multi-tenant SaaS operation, billing, workspace administration, and enterprise identity management.
- A distributed agent control plane.
- Automatically creating accepted action items without a human owner.
- Guaranteeing root cause in every incident.
