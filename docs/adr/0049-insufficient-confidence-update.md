# Insufficient confidence update

When SENTINEL cannot reach a reliable diagnosis, it sends an internal update that states insufficient confidence, strongest candidate hypotheses, cited evidence, evidence gaps, failed or degraded tools, and the next evidence to collect. It does not produce an approval request, executable remediation, or confident post-mortem root cause from insufficient evidence.

**Considered Options**

- Force a best-guess diagnosis for every incident
- Stay silent until confidence improves
- Send an insufficient-confidence update with candidates and next evidence

**Consequences**

The team still receives useful investigation progress without mistaking uncertainty for a production-ready recommendation. The parent investigation must represent insufficient confidence as an actionable outcome and prevent downstream approval or root-cause documentation paths from treating it as a diagnosis.
