# Specific approval requests

SENTINEL requires human approval against a specific approval request before executing remediation. Each approval request must include the diagnosis, confidence level, cited evidence, exact remediation action, expected impact, rollback plan, risk, and expiry, so the human authorizes a concrete production change rather than a vague intent.

**Considered Options**

- Ask for broad approval to fix the incident
- Ask for approval per tool call without incident context
- Ask for approval of a specific remediation request with evidence and rollback details

**Consequences**

Approval prompts are longer, but they are safer and auditable under on-call pressure. The remediation executor must reject approvals that do not map to an unexpired approval request.
