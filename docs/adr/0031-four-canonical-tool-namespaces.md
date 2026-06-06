# Four canonical tool namespaces

SENTINEL v1 uses four canonical model-callable tool namespaces: `observe.*` for runtime source material, `repo.*` for code and deploy context, `infra.*` for production-changing or production-adjacent actions, and `comms.*` for internal updates, approval requests, post-mortems, and external communication payloads. Platform internals such as evaluation, state management, and administration are not counted as model-callable tool namespaces.

**Considered Options**

- Keep adding namespaces as implementation concerns appear
- Put every tool into one flat registry
- Use four incident-response namespaces and keep platform internals separate

**Consequences**

The 50+ tool requirement is satisfied through a coherent incident-response surface rather than padding with internal machinery. The implementation must keep model-callable tools under the four namespaces and treat eval, state, and admin behavior as platform code.
