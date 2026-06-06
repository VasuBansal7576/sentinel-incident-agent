# Three-scenario evaluation set

SENTINEL v1 uses three incident scenarios for evaluation breadth: the golden path bad-deploy missing-index scenario, a tool-degraded scenario where key observability data is rate-limited and confidence must drop, and a watch scenario where proactive anomaly detection must not gain incident powers.

**Considered Options**

- Evaluate only the golden path
- Build many shallow incident scenarios
- Use three focused scenarios that cover depth and safety boundaries

**Consequences**

The evaluation harness can prove the core incident workflow, degraded-tool behavior, and watch safety boundary without pulling build time away from the primary demo. The scenario set remains small enough to implement deeply and clear enough to explain in the MEMO and video.
