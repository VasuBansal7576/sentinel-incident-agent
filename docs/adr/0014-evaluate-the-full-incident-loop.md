# Evaluate the full incident loop

SENTINEL evaluates the full incident loop rather than only the final diagnosis prose. Each incident evaluation scores phase progression, relevant tool use, tool-output composition, evidence quality, diagnosis correctness, confidence level appropriateness, approval gating, remediation safety, and post-mortem completeness.

**Considered Options**

- Score only whether the final diagnosis text is correct
- Score tool-call count and final output shape
- Score the full auditable investigation and response path

**Consequences**

A lucky final answer with poor evidence or unsafe approvals should fail. The eval harness must preserve intermediate investigation state and tool traces, which makes evaluations heavier but much more aligned with production incident-response quality.
