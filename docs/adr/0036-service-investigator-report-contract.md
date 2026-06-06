# Service investigator report contract

SENTINEL service investigators return structured service investigator reports with service name, scoped time window, evidence IDs, local diagnosis, confidence level, evidence gaps, tool failures, suspected upstream or downstream dependencies, suggested local mitigation, and parent-reconciliation notes. These reports do not contain final incident-level diagnoses or human-facing recommendations.

**Considered Options**

- Let service investigators return freeform summaries
- Let service investigators produce final incident-level recommendations
- Require typed local reports for parent reconciliation

**Consequences**

The parent can reconcile service-level findings without confusing local symptoms for incident-level truth. Service investigators remain useful and isolated, while final diagnosis, approval prompts, and human-facing recommendations stay owned by the parent investigation.
