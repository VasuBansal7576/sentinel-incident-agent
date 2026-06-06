# Human-approved scoped remediation

SENTINEL v1 can execute a remediation only after an exact structured approval command from an authorized approver. The approved action may be a rollback in the deterministic path or an index creation in the live slow-query proof, but the runtime must execute only the action, service, and target described in the active Approval Request.

**Considered Options**

- Execute any high-confidence remediation automatically
- Recommend remediations but execute none in v1
- Execute a narrow set of approved remediations with explicit scope checks

**Consequences**

The product remains useful during an incident without turning model confidence into production authority. Approval prompts, evals, and post-mortems must clearly distinguish proposed fixes, approved actions, executed actions, and verified outcomes.
