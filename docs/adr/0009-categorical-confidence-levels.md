# Categorical confidence levels

SENTINEL represents diagnosis confidence as categorical confidence levels rather than raw model probabilities. Confidence levels are based on evidence quality, causal fit, resolved conflicts, and missing evidence, and they determine whether the agent may present approval-ready remediation options or must ask for more evidence.

**Considered Options**

- Expose the model's numeric probability directly
- Use no confidence signal and rely on prose explanations
- Use categorical confidence levels grounded in evidence

**Consequences**

Approval prompts become easier to review under pressure, and evals can assert whether the agent acted appropriately for the confidence level. The system must explain why a diagnosis reached its confidence level instead of treating confidence as a decorative number.
