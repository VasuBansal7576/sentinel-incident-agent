# SENTINEL Implementation Issues

No external issue tracker or triage label vocabulary is configured in this workspace, so these are ready-to-publish issue drafts in dependency order. They follow the SENTINEL glossary from `CONTEXT.md` and treat PagerDuty, not SENTINEL, as the Incident System of Record.

Each issue is a tracer-bullet slice: narrow enough for one agent to own, but complete enough to demo or verify through the product path.

## Proposed Breakdown

1. **PagerDuty Trigger Starts A Durable Investigation**
   - **Type:** AFK
   - **Blocked by:** None - can start immediately
   - **User stories covered:** 1, 2, 7, 23, 42

2. **Phase-Gated Triage Uses The Tool Registry**
   - **Type:** AFK
   - **Blocked by:** Issue 1
   - **User stories covered:** 6, 30, 31, 32, 33, 38, 53

3. **Golden Path Evidence Produces A Cited Diagnosis**
   - **Type:** AFK
   - **Blocked by:** Issue 2
   - **User stories covered:** 3, 4, 5, 8, 12, 29, 34, 39, 47

4. **Degraded Tools Produce Evidence Gaps And Insufficient Confidence**
   - **Type:** AFK
   - **Blocked by:** Issue 3
   - **User stories covered:** 8, 9, 10, 35, 36, 37, 44, 48

5. **Triage-Gated Service Investigators Return Scoped Reports**
   - **Type:** AFK
   - **Blocked by:** Issue 3
   - **User stories covered:** 18, 25, 26, 27, 58, 59

6. **Parent Reconciles Service Findings Into One Outcome**
   - **Type:** AFK
   - **Blocked by:** Issue 5
   - **User stories covered:** 19, 20, 57

7. **Rollback Proposal Parks At Structured Human Approval**
   - **Type:** AFK
   - **Blocked by:** Issues 3, 6
   - **User stories covered:** 11, 13, 18, 24

8. **Approved Rollback Executes Once And Verifies Mitigation**
   - **Type:** AFK
   - **Blocked by:** Issue 7
   - **User stories covered:** 14, 15, 16, 21, 42

9. **Post-Mortem Draft Separates Facts, Inferences, And Follow-Up**
   - **Type:** AFK
   - **Blocked by:** Issue 8
   - **User stories covered:** 17, 21, 22, 28

10. **Watch Trigger Starts Investigation Without Incident Powers**
    - **Type:** AFK
    - **Blocked by:** Issues 2, 4
    - **User stories covered:** 49

11. **Deployable Runtime Serves The Investigation API**
    - **Type:** AFK
    - **Blocked by:** Issues 1, 7
    - **User stories covered:** 40, 41, 43, 45, 55, 60

12. **Live Provider Preflight Fails Closed Before Investigation**
    - **Type:** AFK
    - **Blocked by:** Issue 11
    - **User stories covered:** 36, 37, 39, 43, 55

13. **Live PagerDuty Webhook Runs A Proposal-Only Proof Path**
    - **Type:** HITL
    - **Blocked by:** Issues 3, 7, 11, 12
    - **User stories covered:** 1, 2, 3, 11, 12, 13, 55

14. **Live Approval Resumes Kubernetes Rollback Safely**
    - **Type:** HITL
    - **Blocked by:** Issues 8, 12, 13
    - **User stories covered:** 14, 15, 16, 21, 42, 55

15. **Scenario Evaluation Proves Hackathon Requirements**
    - **Type:** AFK
    - **Blocked by:** Issues 1-14
    - **User stories covered:** 46, 47, 48, 49, 50, 51, 52, 54, 56

## Approval Questions

- Does this granularity feel right, or should the live production path be merged back into fewer issues?
- Are Issues 13 and 14 correctly marked HITL because they require real credentials, live systems, and approval behavior?
- Should Evidence Reconciliation remain its own issue, or be merged back into Service Investigators?
- Is the dependency order correct for how you want agents to pick up work?

---

## 1. PagerDuty Trigger Starts A Durable Investigation

**Type:** AFK

**User stories covered:** 1, 2, 7, 23, 42

## What to build

Receive a PagerDuty-shaped incident trigger, verify the webhook signature when configured, create or resume exactly one durable Investigation attached to the external incident id, record audit events, and expose the Investigation State by id.

## Acceptance criteria

- [ ] Valid signed webhooks create exactly one Investigation attached to the PagerDuty incident id.
- [ ] Invalid webhook signatures are rejected before Investigation state or live provider work is created.
- [ ] Duplicate trigger retries are suppressed with an idempotency key and return the existing Investigation.
- [ ] The status API returns phase, evidence summary, confidence, diagnosis, recommendation, approval request, remediation result, and audit metadata.
- [ ] Investigation status exposes redacted `evidence_gaps` and `failed_tool_calls`, including redacted failed-tool error messages, for operator triage.
- [ ] Restarting the service does not lose active Investigation State.

## Blocked by

None - can start immediately.

---

## 2. Phase-Gated Triage Uses The Tool Registry

**Type:** AFK

**User stories covered:** 6, 30, 31, 32, 33, 38, 53

## What to build

Run the Triage phase through the declarative Tool Registry and Phase Controller so SENTINEL establishes affected services, time window, service priority, and blast radius while exposing only phase-appropriate tools and auditing denied tool access.

## Acceptance criteria

- [ ] The registry declares at least 52 typed tool contracts across `observe.*`, `repo.*`, `infra.*`, and `comms.*`.
- [ ] Each tool contract declares namespace, permission class, typed input, typed output, retry behavior, failure modes, and audit boundaries.
- [ ] Triage can call only its Phase Tool Set.
- [ ] Invalid tool access is denied and audited rather than substituted with a nearby tool.
- [ ] Tool execution emits timestamp, duration, input hash, output hash, success, failure type, and correlation identifiers without retaining sensitive raw source material.

## Blocked by

- Issue 1

---

## 3. Golden Path Evidence Produces A Cited Diagnosis

**Type:** AFK

**User stories covered:** 3, 4, 5, 8, 12, 29, 34, 39, 47

## What to build

For the bad-deploy missing-index Golden Path Scenario, gather observability, repository, infrastructure, and communication evidence; compose artifacts from earlier tools into later tool inputs; and produce a cited Diagnosis with categorical confidence.

## Acceptance criteria

- [ ] Evidence Collection queries logs, metrics, traces, deploy history, pull requests, pod health, and database signals for the Investigation time window.
- [ ] Evidence records source, affected service, time window, claim, and provenance rather than raw provider payloads.
- [ ] Repository and infrastructure tools consume structured artifacts produced by earlier observability and deploy-history tools.
- [ ] The Diagnosis links the payment regression to the recent deploy and missing-index query evidence.
- [ ] A rollback Recommendation is produced only when evidence links symptoms to a recent deploy and safe rollback target.

## Blocked by

- Issue 2

---

## 4. Degraded Tools Produce Evidence Gaps And Insufficient Confidence

**Type:** AFK

**User stories covered:** 8, 9, 10, 35, 36, 37, 44, 48

## What to build

Run the same Investigation path when one or more upstream tools fail, timeout, rate-limit, or return malformed data, then surface normalized failures as evidence gaps that lower confidence or produce Insufficient Confidence with next evidence to collect.

## Acceptance criteria

- [ ] External calls use bounded retries with exponential backoff and rate limiting.
- [ ] Retryable, permanent, authorization, rate-limit, timeout, and malformed-output failures normalize into typed errors.
- [ ] Tool failures are persisted as audit-visible evidence gaps. Failed tools are returned through status as redacted evidence gaps and compact failed-tool summaries.
- [ ] Missing or conflicting required evidence changes confidence instead of being ignored.
- [ ] When evidence cannot support a reliable Diagnosis, SENTINEL returns Insufficient Confidence with the next evidence needed.

## Blocked by

- Issue 3

---

## 5. Triage-Gated Service Investigators Return Scoped Reports

**Type:** AFK

**User stories covered:** 18, 25, 26, 27, 58, 59

## What to build

When Triage identifies multiple affected services or unclear blast radius, spawn bounded Service Investigators with isolated context and read-only service-scoped tools, then return typed Service Investigator Reports to the Parent Investigation.

## Acceptance criteria

- [ ] No Service Investigator spawns until Triage establishes multiple affected services or unclear blast radius.
- [ ] Each Service Investigator receives isolated context and only read-only scoped tools.
- [ ] Concurrency is capped and service priority determines investigation order.
- [ ] Each Service Investigator returns a typed report with local diagnosis, evidence, confidence, conflicts, and evidence gaps.
- [ ] Parent Investigation remains the owner of human-facing communication while subagents investigate.

## Blocked by

- Issue 3

---

## 6. Parent Reconciles Service Findings Into One Outcome

**Type:** AFK

**User stories covered:** 19, 20, 57

## What to build

Have the Parent Investigation compare Service Investigator Reports, identify shared upstream causes, mark unresolved conflicts explicitly, and produce either one reconciled Diagnosis or Insufficient Confidence with the next evidence to collect.

## Acceptance criteria

- [ ] Reconciliation compares report evidence, confidence, conflicts, and gaps instead of averaging confidence scores.
- [ ] Shared upstream causes are cited with reconciled evidence across affected services.
- [ ] Conflicting service-local findings are preserved explicitly in Investigation State.
- [ ] The final Diagnosis cites reconciled evidence rather than the highest-confidence report alone.
- [ ] If conflicts or gaps prevent a safe Diagnosis, the Parent Investigation returns Insufficient Confidence with concrete next evidence.

## Blocked by

- Issue 5

---

## 7. Rollback Proposal Parks At Structured Human Approval

**Type:** AFK

**User stories covered:** 11, 13, 18, 24

## What to build

Post an internal Slack update and a specific Approval Request for rollback, then park the Investigation at `waiting_for_approval` until a structured Approval Command arrives from an Authorized Approver.

## Acceptance criteria

- [ ] Approval Request includes request id, action, affected service, evidence summary, expected effect, risk, expiry, authorized approvers, approval snapshot, and idempotency key.
- [ ] In live mode, authorized approvers are derived only from PagerDuty incident escalation policy on-call evidence with confirmed `user.id` values, then exposed on Investigation status.
- [ ] Incident metadata, account-wide on-call reads, and legacy shortcut fields such as `paged_user` do not count as live remediation authority.
- [ ] If no live Authorized Approver can be confirmed, SENTINEL returns Insufficient Confidence instead of requesting approval.
- [ ] Free-form Slack text is not accepted as approval.
- [ ] SENTINEL does not perform external customer communication in v1.
- [ ] Waiting Investigations survive restart without losing the approval request or approval snapshot.
- [ ] Non-rollback recommendations remain recommendations and cannot become executable remediation in v1.

## Blocked by

- Issue 3
- Issue 6

---

## 8. Approved Rollback Executes Once And Verifies Mitigation

**Type:** AFK

**User stories covered:** 14, 15, 16, 21, 42

## What to build

Resume a waiting Investigation from a structured Approval Command, validate the approver and state-bound approval snapshot immediately before execution, execute only the exact approved rollback once, and verify mitigation through fresh evidence.

## Acceptance criteria

- [ ] Approval for one request cannot authorize a different remediation, service, rollback target, or Investigation state.
- [ ] Expired, revoked, duplicate, unauthorized, or malformed Approval Commands are refused and audited.
- [ ] Duplicate approval or remediation retries do not execute rollback twice.
- [ ] Remediation Execution rechecks approval immediately before calling the rollback tool.
- [ ] Mitigation verification runs after rollback and records a Remediation Result.
- [ ] Rollback mitigation is recorded separately from Long-Term Correction.

## Blocked by

- Issue 7

---

## 9. Post-Mortem Draft Separates Facts, Inferences, And Follow-Up

**Type:** AFK

**User stories covered:** 17, 21, 22, 28

## What to build

Generate a Post-Mortem draft from completed Investigation State that reconstructs the timeline, blast radius, facts, inferences, contributing factors, mitigation, Long-Term Correction, Proposed Action Items, and Accepted Action Items.

## Acceptance criteria

- [ ] The Post-Mortem timeline is derived from Investigation State and audit events.
- [ ] Facts are separated from inferred likely causes.
- [ ] Rollback mitigation is not presented as a permanent fix.
- [ ] Proposed Action Items are distinct from Accepted Action Items.
- [ ] Accepted Action Items require accountable owners.
- [ ] Internal follow-up communication is audit-visible.

## Blocked by

- Issue 8

---

## 10. Watch Trigger Starts Investigation Without Incident Powers

**Type:** AFK

**User stories covered:** 49

## What to build

Allow a proactive Watch to trigger Autonomous Investigation for an anomaly before a PagerDuty Incident exists while preserving the v1 boundary that Watches cannot own incident lifecycle, page people, request approval, or execute remediation.

## Acceptance criteria

- [ ] Watch triggers create Investigations linked to a Watch id, not a SENTINEL-owned incident lifecycle.
- [ ] Watch Investigations can collect evidence and produce Diagnosis or Insufficient Confidence.
- [ ] Watch Investigations cannot request approval or execute remediation unless promoted into an Incident by the external system of record or explicit human confirmation.
- [ ] Watch scenarios are covered by deterministic integration tests and scenario oracles.

## Blocked by

- Issue 2
- Issue 4

---

## 11. Deployable Runtime Serves The Investigation API

**Type:** AFK

**User stories covered:** 40, 41, 43, 45, 55, 60

## What to build

Package SENTINEL as a single FastAPI service that serves webhook, status, approval, readiness, and OAuth install paths; uses SQLite locally and production storage when configured; and fails production readiness checks when required secrets or backing services are missing.

## Acceptance criteria

- [ ] The runtime starts as one service and exposes webhook, Investigation status, approval, readiness, and authenticated OAuth install endpoints.
- [ ] OAuth install endpoints fail before issuing one-time state unless provider client id, client secret, and redirect URI are configured.
- [ ] Local mode works with durable SQLite state and explicit migrations.
- [ ] Production mode can use PostgreSQL for Investigation State and Redis for shared rate limiting.
- [ ] Production readiness fails closed when the API token, PagerDuty webhook secret, required provider credentials, Redis, PostgreSQL, or kubeconfig are missing.
- [ ] Prompt templates and model provider selection are versioned or reproducible enough to interpret traces.
- [ ] Docker Compose validates the production-shaped service, PostgreSQL, Redis, and healthcheck wiring.

## Blocked by

- Issue 1
- Issue 7

---

## 12. Live Provider Preflight Fails Closed Before Investigation

**Type:** AFK

**User stories covered:** 36, 37, 39, 43, 55

## What to build

Add a live connectivity preflight that checks Datadog, GitHub, PagerDuty, Slack, and Kubernetes using the same credential sources, pagination rules, circuit breakers, rate limits, and malformed-response handling that live Investigations will use.

## Acceptance criteria

- [ ] Datadog, GitHub, PagerDuty, Slack, and Kubernetes checks each prove at least one real read path before reporting healthy.
- [ ] Missing credentials, authorization failures, rate limits, timeouts, transport errors, and malformed provider responses produce typed, operator-readable failures.
- [ ] Provider pagination is bounded and rejects malformed pagination fields, including invalid GitHub `Link rel=next` URLs and malformed Datadog monitor page counts, rather than silently truncating evidence.
- [ ] Circuit breakers count upstream failures consistently, do not treat caller errors as provider outages, and surface open provider circuits as retryable evidence gaps during live Investigation.
- [ ] Preflight output is redacted and does not persist raw sensitive source material.
- [ ] Operators can run the same preflight against a deployed receiver before posting a PagerDuty webhook, with structured failures for receiver readiness, operator auth, malformed responses, and unreachable receivers.
- [ ] Connectivity checks, live demo scripts, trigger scripts, and live HTTP E2E gates share deployed-receiver preflight semantics, refusing malformed 2xx `/ready` or `/live/connectivity` bodies before webhook submission.

## Blocked by

- Issue 11

---

## 13. Live PagerDuty Webhook Runs A Proposal-Only Proof Path

**Type:** HITL

**User stories covered:** 1, 2, 3, 11, 12, 13, 55

## What to build

With real credentials supplied, receive a live PagerDuty-shaped webhook, create or resume the matching Investigation, gather live provider evidence, post the rollback proposal to Slack, and park at `waiting_for_approval` without attempting remediation.

## Acceptance criteria

- [ ] A signed live webhook creates or resumes the requested Investigation idempotently.
- [ ] The live Investigation gathers evidence from Datadog, GitHub, PagerDuty, Slack, and Kubernetes through typed tool contracts.
- [ ] The Slack update includes the Diagnosis, evidence summary, rollback Recommendation, approval request id, and explicit human approval boundary.
- [ ] The Investigation status exposes the PagerDuty-derived Authorized Approver ids that may approve remediation, and counts PagerDuty provider proof only when incident-scoped on-call user evidence is confirmed.
- [ ] The proof path succeeds only when the same requested incident reaches `waiting_for_approval` with a recommendation, provider-confirming Slack evidence, and a successful Slack notification for the current Approval Request; approval is refused if that current-request Slack proof is missing or stale.
- [ ] The proof path fails if rollback is attempted or executed before structured approval.
- [ ] Operator scripts can trigger the webhook, poll status, and report structured receiver or connectivity failures.
- [ ] Live demo and trigger scripts share deployed-receiver preflight behavior with the connectivity checker, including malformed 2xx refusal before webhook submission.

## Blocked by

- Issue 3
- Issue 7
- Issue 11
- Issue 12

---

## 14. Live Approval Resumes Kubernetes Rollback Safely

**Type:** HITL

**User stories covered:** 14, 15, 16, 21, 42, 55

## What to build

With a waiting live Investigation and real kubeconfig, accept a structured Approval Command from an Authorized Approver, recheck the approval snapshot, execute only the exact Kubernetes rollback once, and verify mitigation with fresh live evidence.

## Acceptance criteria

- [ ] Approval commands require the exact approval request id, one of the PagerDuty incident-scoped Authorized Approver identities, decision, current Investigation State, and unexpired approval snapshot.
- [ ] Unauthorized, malformed, expired, duplicate, or state-mismatched approvals are refused and audited.
- [ ] The Kubernetes rollback command requires an explicit target and produces a verified rollout or revision receipt.
- [ ] The same approval or remediation idempotency key cannot execute rollback twice.
- [ ] A successful live tool call without a `live::<tool>` evidence receipt does not count as approval notification, rollback execution, or mitigation verification proof.
- [ ] Post-rollback mitigation verification gathers fresh live evidence and records a Remediation Result.
- [ ] Operator scripts, the opt-in live approval E2E gate, and the deployed HTTP approval E2E gate can submit approval and prove rollback executed only after approval.

## Blocked by

- Issue 8
- Issue 12
- Issue 13

---

## 15. Scenario Evaluation Proves Hackathon Requirements

**Type:** AFK

**User stories covered:** 46, 47, 48, 49, 50, 51, 52, 54, 56

## What to build

Build an evaluation harness and submission proof package that scores the Golden Path, degraded-tool, and Watch scenarios against Scenario Oracles while demonstrating long-horizon execution, subagent isolation, tool breadth, composable outputs, production scaffolding, tests, traces, and the MEMO decision.

## Acceptance criteria

- [ ] Golden Path scenario proves bad deploy, missing-index Diagnosis, rollback Recommendation, approval safety, mitigation verification, and Post-Mortem drafting.
- [ ] Degraded-tool scenario proves lower confidence or Insufficient Confidence with explicit evidence gaps.
- [ ] Watch scenario proves proactive investigation without incident powers.
- [ ] Full incident loop tests cover trigger, evidence, Diagnosis, approval, rollback, mitigation verification, audit state, and Post-Mortem.
- [ ] At least one run produces a trace with more than 20 meaningful tool calls.
- [ ] Scenario Oracles score required evidence, Diagnosis, Recommendation, forbidden actions, confidence, and Post-Mortem fact boundaries.
- [ ] MEMO defends triage-gated Service Investigators against always-on subagent fanout.

## Blocked by

- Issue 1
- Issue 2
- Issue 3
- Issue 4
- Issue 5
- Issue 6
- Issue 7
- Issue 8
- Issue 9
- Issue 10
- Issue 11
- Issue 12
- Issue 13
- Issue 14
