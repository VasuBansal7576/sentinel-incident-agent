# Tool failures affect confidence

SENTINEL records material tool failures in investigation state, retries according to the tool registry policy, and continues only when the remaining evidence supports a bounded claim. Missing or degraded source material becomes an evidence gap that can lower the diagnosis confidence level or force an insufficient-confidence outcome.

**Considered Options**

- Stop the whole investigation on any external tool failure
- Hide tool failures inside executor logs and keep reasoning normally
- Record material tool failures and reflect evidence gaps in confidence

**Consequences**

The agent can remain useful during partial outages or rate limits without pretending unavailable evidence was collected. Diagnoses and post-mortems must surface material evidence gaps, and evals should include scenarios where key tools fail or return degraded results.
