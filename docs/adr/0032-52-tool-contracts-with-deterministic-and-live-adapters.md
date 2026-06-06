# 52 tool contracts with deterministic and live adapters

SENTINEL v1 keeps the 52-tool registry from the product idea, but treats each tool as a production-shaped contract rather than a claim that every provider is fully proven in the submission environment. Tool adapters must preserve schemas, permission classes, retry and rate-limit policies, typed errors, audit events, and composable output roles.

**Considered Options**

- Reduce the registry to only the tools used in the primary proof path
- Pretend all 52 tools are fully integrated external provider tools
- Keep 52 coherent tool contracts with deterministic and live adapter paths

**Consequences**

The build satisfies the hackathon's 50+ tool requirement without padding or dishonesty. The deterministic path can exercise a focused subset deeply, while registry validation proves the wider tool surface remains coherent and production-shaped.
