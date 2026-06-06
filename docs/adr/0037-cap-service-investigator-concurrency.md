# Cap service investigator concurrency

SENTINEL v1 caps concurrent service investigators at three per parent investigation. Triage prioritizes the most implicated affected services first, and if more than three services are plausibly involved, the parent investigates the top three, records evidence gaps for the rest, reconciles findings, and decides whether more service investigation is needed.

**Considered Options**

- Spawn one service investigator for every possibly affected service
- Avoid parallel service investigators entirely
- Cap concurrent service investigators and prioritize by triage evidence

**Consequences**

Subagents improve response speed without creating uncontrolled cost, latency, and reasoning fan-out. The parent investigation must prioritize suspected services explicitly and surface uninvestigated services as evidence gaps instead of pretending the whole blast radius was covered.
