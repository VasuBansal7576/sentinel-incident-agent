# Service investigators spawn after triage

SENTINEL creates service-level investigators only after triage identifies multiple affected services or an unclear blast radius. The parent investigation establishes scope first, then delegates read-only service investigations while retaining cross-service correlation and response proposal responsibility.

**Considered Options**

- Spawn service investigators immediately for every alert
- Avoid subagents and investigate all services sequentially
- Spawn service investigators after triage establishes a multi-service or unclear scope

**Consequences**

The architecture demonstrates real isolated subagent orchestration without racing agents on every alert. This keeps simple incidents cheaper and more deterministic, while still using parallel investigation when sequential service analysis would slow down incident response.
