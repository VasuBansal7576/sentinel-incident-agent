# Parent reconciles service findings

When service investigators return conflicting findings, the parent investigation performs evidence reconciliation rather than averaging confidence scores or selecting the highest-confidence report. The parent compares evidence, identifies shared upstream causes, marks conflicts explicitly, and either produces a reconciled diagnosis or returns insufficient confidence with the next evidence to collect.

**Considered Options**

- Pick the highest-confidence service report
- Average confidence scores across service reports
- Reconcile evidence at the parent level before final diagnosis

**Consequences**

The parent remains accountable for cross-service diagnosis, which prevents isolated service investigators from overfitting to local symptoms. The system must represent conflicting evidence and insufficient confidence as first-class outcomes instead of forcing every investigation to end with a confident root cause.
