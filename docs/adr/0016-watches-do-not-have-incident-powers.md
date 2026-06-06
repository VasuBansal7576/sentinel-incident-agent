# Watches do not have incident powers

SENTINEL watches may collect evidence, continue monitoring, update the internal team, and recommend watchful waiting or escalation, but they cannot execute remediation or external communication before watch promotion. A watch is promoted only by human confirmation or recognition by the incident system of record.

**Considered Options**

- Let proactive watches execute low-risk remediations automatically
- Treat watches exactly like incidents once anomaly confidence is high
- Keep watches limited until human or system-of-record promotion

**Consequences**

Proactive detection can reduce surprise without giving unconfirmed anomalies production-changing authority. The product must model watch promotion explicitly and reject incident-only actions while a condition is still only a watch.
