# Isolated service investigator contexts

SENTINEL service investigators run in isolated model contexts rather than inheriting the parent investigation's full conversation. Each service investigator receives a separate system prompt, the triage summary, its assigned affected service, service-scoped source material references, and a service-scoped phase tool set, then returns a typed service investigator report to the parent.

**Considered Options**

- Implement service investigators as helper functions sharing parent context
- Give service investigators full parent and sibling reasoning context
- Run service investigators in isolated contexts with scoped inputs and tools

**Consequences**

Subagent orchestration is real enough to satisfy the brief and reduces cross-service reasoning contamination. The parent must explicitly pass the scoped context each investigator needs and reconcile structured reports instead of relying on shared scratch reasoning.
