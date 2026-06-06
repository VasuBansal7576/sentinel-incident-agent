# Typed tool-output composition

SENTINEL demonstrates composable tool inputs and outputs through typed tool results that become inputs to later tool calls. The primary demo chain connects deploy history, pull-request diffing, slow-query checks, rollback target selection, and approval request creation through structured values rather than prompt-only text summaries.

**Considered Options**

- Let the model read tool outputs as prose and decide what to type next
- Hard-code one fixed demo chain
- Return typed tool results that can feed later registered tools

**Consequences**

The build can prove tool composition without relying on brittle string copying through the model context. Tool schemas must expose stable identifiers such as deployment IDs, commit SHAs, affected services, time windows, rollback targets, and diagnosis IDs.
