# SENTINEL does not own the incident lifecycle

SENTINEL does not act as the incident system of record in v1. Existing tools such as PagerDuty own incident identity, status, escalation, and lifecycle, while SENTINEL owns investigations attached to those incidents and watches for proactive anomaly detection.

**Considered Options**

- Make SENTINEL the incident system of record
- Mirror incidents from PagerDuty into a parallel SENTINEL lifecycle
- Attach SENTINEL investigations to incidents owned by existing alerting tools

**Consequences**

SENTINEL can focus on removing the investigation burden without replacing trusted incident-management workflows. The product must model investigations and watches separately from incidents, and integrations must preserve external incident identity rather than inventing a competing one.
