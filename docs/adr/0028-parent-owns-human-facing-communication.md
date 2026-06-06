# Parent owns human-facing communication

SENTINEL routes human-facing Slack communication through the parent investigation. Service investigators remain read-only and return structured findings to the parent, while tools may prepare message payloads but do not decide when human-facing messages are sent or what incident state they represent.

**Considered Options**

- Let any service investigator post findings directly to Slack
- Let communication tools send messages whenever invoked
- Route human-facing communication through the parent investigation

**Consequences**

Slack updates remain coherent at the incident level instead of leaking partial service-level conclusions. The parent must distinguish scoped candidate findings from reconciled incident-level updates, and tests should verify that service investigators cannot send human-facing messages directly.
