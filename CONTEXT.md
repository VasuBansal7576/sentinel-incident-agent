# SENTINEL Incident Response

SENTINEL is the domain of investigating and responding to production incidents. It distinguishes agent-led investigation from human-approved production changes.

## Language

**Incident**:
A production condition where service reliability, correctness, or customer experience is degraded enough to require coordinated response.
_Avoid_: Alert, outage

**Alert**:
A signal that may indicate an **Incident** but has not yet been confirmed as one.
_Avoid_: Page, notification

**Incident System of Record**:
The external system that owns the official lifecycle, status, and identity of an **Incident**.
_Avoid_: SENTINEL incident store, investigation record

**Affected Service**:
A service whose reliability, correctness, or customer-facing behavior is implicated in an **Incident** or **Watch**.
_Avoid_: Broken service, target service

**Blast Radius**:
The services, users, requests, or business flows affected by an **Incident** or **Watch**.
_Avoid_: Impact, scope

**Service Priority**:
The triage ranking of suspected **Affected Services** based on impact, severity, evidence, dependency centrality, and recency of change.
_Avoid_: Importance, ordering

**Investigation**:
The agent-owned body of evidence, reasoning, diagnoses, and recommendations attached to an **Alert** or **Incident**.
_Avoid_: Incident, case

**Investigation State**:
The current authoritative record of an **Investigation**'s evidence, hypotheses, diagnoses, recommendations, approvals, and remediations.
_Avoid_: Model memory, chat history

**Investigation Store**:
The durable home for **Investigation State**, **Audit Events**, **Idempotency Keys**, and **Incident Evaluation** results.
_Avoid_: Model memory, chat transcript

**Source Material**:
Raw incident-related data collected from observability, repository, infrastructure, or communication systems.
_Avoid_: Evidence, finding

**Sensitive Source Material**:
Raw incident-related data that contains secrets, credentials, personal data, or other data that must not appear directly in durable audit records.
_Avoid_: Audit payload, safe data

**Incident Scenario**:
A controlled incident narrative with source material, expected evidence, expected diagnosis, and expected response constraints.
_Avoid_: Test case, replay incident

**Golden Path Scenario**:
The primary **Incident Scenario** used to demonstrate SENTINEL's core investigation, approval, remediation, audit, and post-mortem workflow.
_Avoid_: Demo, happy path

**Incident Evaluation**:
An assessment of a SENTINEL run against an **Incident Scenario** across investigation path, evidence, diagnosis, approvals, remediation safety, and documentation.
_Avoid_: Final-answer grading, demo check

**Evaluation Scenario Set**:
The collection of **Incident Scenarios** used to evaluate SENTINEL's investigation depth and safety boundaries.
_Avoid_: Scenario backlog, demo list

**Scenario Oracle**:
The expected truth for an **Incident Scenario**, including evidence, diagnosis, confidence, allowed actions, forbidden actions, evidence gaps, and post-mortem facts.
_Avoid_: Expected answer, golden output

**Replay Incident Environment**:
A controlled environment that supplies **Source Material** and accepts approved remediation-like actions for **Incident Scenarios**.
_Avoid_: replay integration, production claim

**Evidence**:
A bounded observation derived from **Source Material** with source, time window, affected service, claim, and provenance.
_Avoid_: Raw logs, metric dump

**Investigation Phase**:
A named stage in an **Investigation** that gives the **Investigation State** a clear progress boundary.
_Avoid_: Step, model turn

**Phase Controller**:
The workflow authority that manages **Investigation Phase** transitions, persistence, approval boundaries, and completion criteria.
_Avoid_: Planner, orchestrator

**Triage**:
The **Investigation Phase** that establishes affected services, time window, severity, and initial scope.
_Avoid_: Intake, first look

**Service Investigator**:
A scoped subagent that investigates one **Affected Service** during an **Investigation**.
_Avoid_: Worker agent, child agent

**Service Investigator Limit**:
The maximum number of **Service Investigators** that may run concurrently for one **Parent Investigation**.
_Avoid_: Unlimited fan-out, subagent pool

**Isolated Investigator Context**:
A separate reasoning workspace given to a **Service Investigator** with only service-scoped inputs and tools.
_Avoid_: Parent context, shared context

**Service Investigator Report**:
A structured finding returned by a **Service Investigator** to the **Parent Investigation**.
_Avoid_: Chat transcript, subagent summary

**Local Diagnosis**:
A service-scoped explanation produced by a **Service Investigator** before parent-level reconciliation.
_Avoid_: Incident diagnosis, root cause

**Parent Investigation**:
The top-level **Investigation** that owns cross-service coordination, human-facing communication, and final response decisions.
_Avoid_: Main agent, coordinator

**Evidence Collection**:
The **Investigation Phase** that gathers observations relevant to the **Incident** or **Watch**.
_Avoid_: Fetching, data pull

**Correlation**:
The **Investigation Phase** that links evidence into candidate causal chains.
_Avoid_: Analysis, matching

**Evidence Reconciliation**:
The parent-led comparison of service-level findings to resolve conflicts and identify shared causes.
_Avoid_: Confidence averaging, report merging

**Response Proposal**:
The **Investigation Phase** that converts a **Diagnosis** into recommended remediations, risks, and approval options.
_Avoid_: Fix plan, action plan

**Insufficient Confidence**:
An investigation outcome where the available evidence does not support a reliable **Diagnosis**.
_Avoid_: Failure, no answer

**Post-Mortem**:
A retrospective document produced from completed **Investigation State** after an **Incident**.
_Avoid_: Investigation, report

**Post-Mortem Fact**:
A post-mortem statement directly supported by **Investigation State** without inference.
_Avoid_: Narrative detail, generated detail

**Post-Mortem Inference**:
A post-mortem statement that interprets **Evidence** to explain cause, contribution, or risk.
_Avoid_: Fact, assumption

**Proposed Action Item**:
A follow-up task suggested by SENTINEL that has not yet been accepted by a human.
_Avoid_: Action item, ticket

**Accepted Action Item**:
A follow-up task accepted by a human with an accountable owner.
_Avoid_: Proposed action item, orphan ticket

**Service Owner**:
The person or team accountable for the reliability and changes of an **Affected Service**.
_Avoid_: Code author, assignee

**Incident Commander**:
The person accountable for coordinating the response to an **Incident**.
_Avoid_: On-call engineer, approver

**Watch**:
The agent-owned tracking of an anomalous condition that has not yet become an **Incident**.
_Avoid_: Incident, alert

**Watch Promotion**:
The explicit transition where a **Watch** is treated as an **Incident** after human confirmation or recognition by the **Incident System of Record**.
_Avoid_: Auto-incident, escalation

**Autonomous Investigation**:
The agent-led process of gathering evidence, correlating changes, and producing a **Diagnosis** without waiting for a human.
_Avoid_: Autonomous remediation, auto-fix

**Diagnosis**:
A supported explanation of the likely cause of an **Incident**.
_Avoid_: Guess, summary

**Confidence Level**:
An evidence-grounded category that expresses how strongly a **Diagnosis** is supported.
_Avoid_: Probability, score

**Recommendation**:
A proposed **Remediation** with supporting evidence and expected risk.
_Avoid_: Suggestion, advice

**Remediation**:
A production-changing action intended to reduce or resolve the impact of an **Incident**.
_Avoid_: Fix, action

**Executable Remediation**:
A **Remediation** that SENTINEL is allowed to carry out after **Human Approval** and **Remediation Execution**.
_Avoid_: Supported fix, automatic action

**Non-Executable Recommendation**:
A **Recommendation** that SENTINEL may propose but is not allowed to carry out in v1.
_Avoid_: Unsupported fix, rejected action

**Incident Mitigation**:
A response that reduces or stops current incident impact without necessarily correcting the underlying cause.
_Avoid_: Root fix, permanent fix

**Long-Term Correction**:
A follow-up response intended to address the underlying cause or prevent recurrence after immediate incident impact is controlled.
_Avoid_: Immediate remediation, hotfix

**Remediation Execution**:
The safety-checked carrying out of an approved **Remediation** against current production state.
_Avoid_: Direct tool call, blind execution

**Remediation Result**:
The recorded outcome of **Remediation Execution**, including executed, skipped, refused, or failed.
_Avoid_: Tool output, status

**Idempotency Key**:
A stable identifier that lets SENTINEL recognize duplicate triggers, approvals, or remediation executions.
_Avoid_: Request ID, run ID

**Audit Event**:
A reviewable record of a SENTINEL decision, tool interaction, state transition, approval, or remediation outcome.
_Avoid_: Log line, trace entry

**Human Approval**:
An explicit decision by an accountable person that authorizes a **Remediation**.
_Avoid_: Passive approval, implicit approval

**Authorized Approver**:
A human identity recognized as allowed to approve an **Approval Request** for a specific **Incident**.
_Avoid_: Slack user, channel member

**Approval Request**:
A specific request for **Human Approval** that names the exact remediation, evidence, impact, risk, rollback plan, and expiry.
_Avoid_: Permission prompt, confirmation

**Approval Command**:
A structured command or interaction payload that grants or rejects a specific **Approval Request**.
_Avoid_: Free-form reply, casual confirmation

**Approval Snapshot**:
The specific **Investigation State** facts that an **Approval Request** is based on.
_Avoid_: Current state, latest facts

**Tool Permission Class**:
A category that defines whether SENTINEL may execute a tool autonomously or only after **Human Approval**.
_Avoid_: Tool type, tool group

**Tool Registry**:
The catalog of tools SENTINEL may choose from, including the invocation constraints needed to use each tool safely.
_Avoid_: Dispatcher, tool list

**Tool Namespace**:
A domain grouping for registered tools that share the same incident-response responsibility.
_Avoid_: Module, package

**Tool Contract**:
The declared interface, permission, execution policy, error behavior, and output role a registered tool must satisfy.
_Avoid_: Implementation, replay shortcut

**Replay Adapter**:
A v1 tool implementation that satisfies a **Tool Contract** against the **Replay Incident Environment** instead of a production integration.
_Avoid_: Shortcut tool, placeholder

**Phase Tool Set**:
The phase-specific subset of the **Tool Registry** available to a model or subagent during the current **Investigation Phase**.
_Avoid_: Tool registry, allowed tools

**Tool Result**:
A structured outcome returned by a registered tool that can contribute to investigation state or future tool calls.
_Avoid_: Text output, raw response

**Composable Tool Chain**:
A workflow where one **Tool Result** supplies typed input to a later tool call.
_Avoid_: Tool sequence, prompt-only chaining

**Tool Failure**:
An unsuccessful or degraded tool invocation that limits what SENTINEL can observe or do during an **Investigation**.
_Avoid_: Error, exception

**Model Output Failure**:
A model response that cannot be accepted because it violates the required structured output contract.
_Avoid_: Bad response, parse error

**Tool Access Denial**:
A rejected tool invocation where the requested tool is outside the current **Phase Tool Set** or permission boundary.
_Avoid_: Tool failure, ignored call

**Evidence Gap**:
Missing or incomplete **Source Material** that could materially affect a **Diagnosis** or **Confidence Level**.
_Avoid_: Missing data, limitation

**Internal Incident Update**:
A team-facing message that shares investigation progress or recommendations inside the incident response workspace.
_Avoid_: Public update, stakeholder notice

**External Communication**:
A message sent outside the immediate incident response team about incident status, impact, or resolution.
_Avoid_: Update, announcement

## Relationships

- An **Alert** may become an **Incident** after **Autonomous Investigation**.
- An **Incident System of Record** owns the official lifecycle of an **Incident**.
- An **Investigation** belongs to exactly one **Alert** or **Incident**.
- An **Investigation** has exactly one **Investigation State**.
- The **Investigation Store** persists **Investigation State**, **Audit Events**, **Idempotency Keys**, and **Incident Evaluation** results.
- An **Incident Scenario** may drive one or more **Investigations** or **Watches**.
- The **Golden Path Scenario** is the bad-deploy missing-index **Incident Scenario** for the payment service.
- The **Golden Path Scenario** exercises a representative subset of **Tool Contracts**, not every registered tool.
- The v1 **Evaluation Scenario Set** contains the **Golden Path Scenario**, one tool-degraded **Incident Scenario**, and one **Watch** scenario.
- Each **Incident Scenario** has exactly one **Scenario Oracle**.
- An **Incident Evaluation** assesses one SENTINEL run against one **Incident Scenario**.
- A **Replay Incident Environment** supplies **Source Material** for **Incident Scenarios**.
- An **Investigation** produces zero or more **Audit Events**.
- An **Audit Event** may reference **Source Material** or **Sensitive Source Material** by hash or durable reference.
- An **Audit Event** may cite derived **Evidence**, an **Approval Request**, or a **Remediation Result**.
- **Source Material** may produce zero or more pieces of **Evidence**.
- **Investigation State** contains **Evidence**, not unbounded **Source Material**.
- An **Investigation** proceeds through **Triage**, **Evidence Collection**, **Correlation**, **Diagnosis**, and **Response Proposal**.
- A **Phase Controller** governs progress between **Investigation Phases**.
- The model proposes work inside the current **Investigation Phase**.
- **Triage** identifies zero or more **Affected Services** and estimates the **Blast Radius**.
- **Triage** assigns **Service Priority** when there are more suspected **Affected Services** than the **Service Investigator Limit** allows.
- A **Parent Investigation** owns human-facing communication for an **Investigation**.
- A **Service Investigator** belongs to exactly one **Investigation** and investigates exactly one **Affected Service**.
- A **Service Investigator** runs inside exactly one **Isolated Investigator Context**.
- A **Parent Investigation** enforces a **Service Investigator Limit** of three concurrent **Service Investigators** in v1.
- A **Service Investigator** may be created only after **Triage** finds multiple **Affected Services** or an unclear **Blast Radius**.
- A **Service Investigator** receives the **Triage** summary and assigned **Affected Service**, not parent or sibling scratch reasoning.
- A **Service Investigator** returns a **Service Investigator Report** to the **Parent Investigation** and does not send human-facing messages.
- A **Service Investigator Report** contains a **Local Diagnosis**, cited **Evidence**, **Confidence Level**, **Evidence Gaps**, **Tool Failures**, dependency notes, and parent-reconciliation notes.
- A **Service Investigator Report** does not contain the final incident-level **Diagnosis** or a human-facing **Recommendation**.
- **Evidence Reconciliation** compares findings from one or more **Service Investigators**.
- **Evidence Reconciliation** produces either a reconciled **Diagnosis** or **Insufficient Confidence**.
- A **Watch** is not an **Incident** unless confirmed by a human or the **Incident System of Record**.
- A **Watch** may collect **Evidence** and send **Internal Incident Updates** before **Watch Promotion**.
- A **Watch** may not produce **Remediation** or **External Communication** before **Watch Promotion**.
- **Watch Promotion** requires human confirmation or recognition by the **Incident System of Record**.
- An **Autonomous Investigation** produces one or more **Diagnoses**.
- A **Diagnosis** cites one or more pieces of **Evidence**.
- A **Diagnosis** has exactly one **Confidence Level**.
- A **Diagnosis** supports one or more **Recommendations**.
- A **Recommendation** may produce one or more **Approval Requests**.
- An **Approval Request** includes exactly one **Approval Snapshot**.
- An **Approval Request** may be approved only by an **Authorized Approver**.
- An **Approval Command** refers to exactly one **Approval Request**.
- An **Approval Request** may authorize exactly one **Remediation**.
- A **Recommendation** may become a **Remediation** only after **Human Approval** of an unexpired **Approval Request** whose **Approval Snapshot** still matches the **Investigation State**.
- A **Recommendation** may be either an **Executable Remediation** or a **Non-Executable Recommendation**.
- The **Golden Path Scenario** executes rollback as its **Executable Remediation**.
- A **Recommendation** may address **Incident Mitigation**, **Long-Term Correction**, or both.
- The **Golden Path Scenario** treats rollback as **Incident Mitigation** and adding an `orders.user_id` index as **Long-Term Correction**.
- **Remediation Execution** requires current **Investigation State** to still match the approved **Approval Snapshot**.
- **Remediation Execution** produces exactly one **Remediation Result**.
- External triggers, **Approval Requests**, and **Remediation Executions** have **Idempotency Keys**.
- A duplicate external trigger resumes or returns the existing **Investigation**.
- A duplicate **Remediation Execution** returns the existing **Remediation Result**.
- A **Post-Mortem** consumes completed **Investigation State**.
- A **Post-Mortem** contains **Post-Mortem Facts**, **Post-Mortem Inferences**, and **Proposed Action Items**.
- A **Post-Mortem Fact** must be directly supported by **Investigation State**.
- A **Post-Mortem Inference** must cite **Evidence** and a **Confidence Level**.
- A **Proposed Action Item** may become an **Accepted Action Item** only after human acceptance and assignment to a **Service Owner** or **Incident Commander**.
- The **Golden Path Scenario** proposes the missing-index **Long-Term Correction** as a **Proposed Action Item** for the payment **Service Owner**.
- The **Tool Registry** groups model-callable tools into `observe.*`, `repo.*`, `infra.*`, and `comms.*` **Tool Namespaces**.
- The **Tool Registry** contains 52 model-callable **Tool Contracts** in v1.
- A **Tool Contract** may be implemented by a **Replay Adapter** in v1.
- A **Replay Adapter** must satisfy the same schema, permission, retry, rate-limit, error, audit, and output-role expectations as a production integration.
- A tool belongs to exactly one **Tool Permission Class**.
- The **Tool Registry** defines the available tools and their invocation constraints.
- A **Phase Tool Set** is derived from the **Tool Registry** using the current **Investigation Phase**, actor, scope, **Tool Permission Class**, and **Investigation State**.
- The model chooses tools from the current **Phase Tool Set**.
- A **Tool Result** may become **Source Material**, **Evidence**, an **Approval Request**, a **Remediation Result**, or typed input in a **Composable Tool Chain**.
- A **Composable Tool Chain** uses structured **Tool Results**, not prompt-only text summaries.
- A tool request outside the current **Phase Tool Set** produces a **Tool Access Denial**.
- A **Tool Access Denial** produces an **Audit Event** and returns a reason to the model.
- A **Tool Failure** may create an **Evidence Gap**.
- A **Model Output Failure** may create an **Evidence Gap** or block the current **Investigation Phase**.
- An **Evidence Gap** may reduce a **Confidence Level** or produce **Insufficient Confidence**.
- **Investigation State** records **Tool Failures**, **Model Output Failures**, and **Evidence Gaps** that affect the investigation.
- An **Internal Incident Update** may be sent autonomously during an **Incident**.
- An **External Communication** requires **Human Approval**.

## Example dialogue

> **Dev:** "Can SENTINEL roll back the payment service as soon as it finds the bad deploy?"
> **Domain expert:** "No. SENTINEL can complete the **Autonomous Investigation** and propose rollback as a **Recommendation**, but rollback is a **Remediation** and requires **Human Approval**."

## Flagged ambiguities

- "Autonomous" was used to mean both independent investigation and independent production changes; resolved: SENTINEL performs **Autonomous Investigation**, while **Remediation** requires **Human Approval**.
- "Update" was used to mean both team-facing incident progress and external stakeholder communication; resolved: **Internal Incident Updates** may be autonomous, while **External Communications** require **Human Approval**.
- "Incident" was used to include SENTINEL-owned investigation state; resolved: the **Incident System of Record** owns the **Incident**, while SENTINEL owns the **Investigation** and **Watch**.
- "Memory" was used loosely for long-horizon continuity; resolved: **Investigation State** is the durable investigation record, while model context is only a temporary reasoning workspace.
- "Durable store" was broad enough to mix chat history, model context, and system records; resolved: the **Investigation Store** persists investigation records, audit records, idempotency records, and evaluation results.
- "Evidence" was used loosely for raw logs, metrics, traces, and diffs; resolved: raw inputs are **Source Material**, while **Evidence** is a bounded observation derived from them.
- "Plan" was broad enough to imply model-owned workflow control; resolved: the **Phase Controller** owns phase transitions, while the model proposes work inside the current phase.
- "Post-mortem generation" was discussed alongside investigation; resolved: a **Post-Mortem** is a downstream document that consumes completed **Investigation State**, not an **Investigation Phase**.
- "Post-mortem" was initially broad enough to include generated narrative as fact; resolved: **Post-Mortem Facts**, **Post-Mortem Inferences**, and **Proposed Action Items** are distinct.
- "Action item" was initially broad enough to imply ticket creation without accountability; resolved: a **Proposed Action Item** becomes an **Accepted Action Item** only with human acceptance and an accountable owner.
- "Subagent" was initially framed as per-alert orchestration; resolved: a **Service Investigator** is created only after **Triage** finds multiple **Affected Services** or an unclear **Blast Radius**.
- "Parallel subagents" was broad enough to imply unlimited fan-out; resolved: a **Parent Investigation** enforces a v1 **Service Investigator Limit** of three concurrent **Service Investigators**.
- "Top affected services" was broad enough to imply hidden ranking; resolved: **Triage** assigns **Service Priority** using impact, severity, evidence, dependency centrality, and recency of change.
- "Isolated context" was broad enough to mean a helper call with a new name; resolved: a **Service Investigator** runs in an **Isolated Investigator Context** and returns a **Service Investigator Report**.
- "Service report" was broad enough to include incident-level conclusions; resolved: a **Service Investigator Report** contains a **Local Diagnosis**, not the final incident-level **Diagnosis**.
- "Slack communication" was broad enough to imply subagents or tools could post directly; resolved: the **Parent Investigation** owns human-facing communication.
- "Confidence" was initially framed as a ranking signal between service reports; resolved: the parent performs **Evidence Reconciliation** and may return **Insufficient Confidence** instead of picking the highest-confidence report.
- "Confidence score" was used like a model probability; resolved: a **Confidence Level** is an evidence-grounded category based on evidence quality, causal fit, conflicts, and missing evidence.
- "Approve rollback" was too vague for production changes; resolved: **Human Approval** applies to a specific **Approval Request**, not a broad intent to fix the incident.
- "Approval" was broad enough to imply any channel participant could approve; resolved: only an **Authorized Approver** may approve an **Approval Request**.
- "Slack approval" was broad enough to include casual natural-language replies; resolved: **Human Approval** requires a structured **Approval Command** tied to an **Approval Request**.
- "Add index" was initially framed like a possible executed remediation; resolved: v1 may recommend it as a **Non-Executable Recommendation**, while rollback is the **Golden Path Scenario**'s **Executable Remediation**.
- "Fix" was broad enough to mix immediate incident relief with recurrence prevention; resolved: rollback is **Incident Mitigation**, while adding the missing index is **Long-Term Correction**.
- "Approval" was initially reusable by implication; resolved: **Human Approval** is valid only for the unexpired **Approval Request** and **Approval Snapshot** it approves.
- "Execute after approval" was initially direct by implication; resolved: approved remediations still go through **Remediation Execution** and produce a **Remediation Result**.
- "Retry" was initially treated as an execution detail; resolved: duplicate triggers, approvals, and remediation executions are recognized by **Idempotency Keys**.
- "50+ tools" was initially framed as a list; resolved: SENTINEL uses a **Tool Registry** rather than a hand-written dispatcher.
- "Tool namespace" was broad enough to include platform internals; resolved: v1 model-callable tools use the `observe.*`, `repo.*`, `infra.*`, and `comms.*` **Tool Namespaces** only.
- "Replay-only tool" was broad enough to imply a replay-only or padded tool; resolved: v1 uses **Replay Adapters** that satisfy real **Tool Contracts**.
- "Golden Path tool usage" was broad enough to imply all 52 tools should be called; resolved: the **Golden Path Scenario** demonstrates depth with a representative subset while the remaining **Tool Contracts** are validated separately.
- "Tool access" was broad enough to imply every registered tool is visible in every phase; resolved: the model chooses from a **Phase Tool Set** derived from the **Tool Registry**.
- "Invalid tool call" was broad enough to imply silent dropping or automatic substitution; resolved: invalid tool requests produce a **Tool Access Denial**.
- "Composable tools" was initially broad enough to mean sequential text summaries; resolved: a **Composable Tool Chain** passes structured **Tool Results** as typed inputs to later tools.
- "Tool failure" was initially easy to hide as executor noise; resolved: material failures become **Tool Failures** and may create **Evidence Gaps** that affect confidence.
- "Malformed structured output" was broad enough to imply best-effort parsing; resolved: invalid model responses become **Model Output Failures** and are not guessed into shape.
- "Integration" was initially broad enough to imply full production SaaS connectivity; resolved: v1 may use a **Replay Incident Environment** for controlled incident scenarios while preserving production-shaped tool contracts.
- "Eval" was initially broad enough to mean final-answer grading; resolved: an **Incident Evaluation** scores the investigation path, evidence quality, diagnosis, approval gating, remediation safety, and documentation.
- "Eval breadth" was broad enough to imply many shallow scenarios; resolved: the v1 **Evaluation Scenario Set** contains three focused scenarios.
- "Expected answer" was broad enough to imply exact final wording; resolved: a **Scenario Oracle** defines expected truth and safety constraints without requiring identical prose.
- "Demo scenario" was broad enough to splinter into multiple examples; resolved: the **Golden Path Scenario** is the payment-service bad deploy that introduces a missing `orders.user_id` index.
- "Proactive anomaly detection" was broad enough to imply incident powers; resolved: a **Watch** can collect evidence and update the team, but cannot remediate or communicate externally before **Watch Promotion**.
- "Audit log" was broad enough to imply raw payload storage; resolved: **Audit Events** are durable records that reference **Sensitive Source Material** by hash or durable reference instead of embedding it.
