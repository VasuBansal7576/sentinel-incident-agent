# Service priority for triage fanout

When triage suspects more affected services than the service investigator limit allows, SENTINEL ranks services by service priority. Service priority considers customer impact, alert severity, evidence strength, dependency centrality, and recency of change, and the resulting ranking is recorded in investigation state before service investigators are spawned.

**Considered Options**

- Spawn investigators for the first services mentioned by the alert
- Randomly or alphabetically choose services when fanout exceeds the cap
- Rank suspected services by service priority and record the decision

**Consequences**

The parent investigation can explain why it investigated some services before others when the blast radius is broad. Uninvestigated suspected services remain visible as evidence gaps rather than disappearing from the incident narrative.
