# Golden path exercises representative tool subset

SENTINEL's golden path run does not call every one of the 52 registered tools. It must exercise at least 20 coherent tool calls across `observe.*`, `repo.*`, `infra.*`, and `comms.*`, including a composable tool chain and a service-investigator branch, while the remaining tool contracts are registry-validated and covered by focused tests.

**Considered Options**

- Force the golden path to call all 52 tools
- Reduce the registry to only golden-path tools
- Exercise a deep representative subset and validate the rest separately

**Consequences**

The demo proves long-horizon autonomy and tool composition without adding meaningless calls for count theater. The test suite must still prove that the full 52-tool registry is coherent, typed, permissioned, and executable through deterministic adapters.
