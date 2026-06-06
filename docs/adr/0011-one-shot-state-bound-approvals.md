# One-shot state-bound approvals

SENTINEL treats approval requests as one-shot and state-bound. An approval is valid only for the unexpired approval request and approval snapshot it was issued against, and it is invalidated if the diagnosis, target service version, blast radius, or recommended remediation changes before execution.

**Considered Options**

- Allow broad approvals to remain valid until the incident resolves
- Expire approvals only by timeout
- Bind approvals to both timeout and investigation state

**Consequences**

The remediation path must reject stale approvals and issue a new approval request when incident facts change. This creates extra Slack prompts in changing incidents, but prevents humans from accidentally authorizing production changes against facts that are no longer true.
