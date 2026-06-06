# Separate mitigation from correction

SENTINEL separates immediate incident mitigation from long-term correction in the golden path scenario. Rollback is the executable incident mitigation because it restores the last known safe version quickly, while adding the missing `orders.user_id` index is a non-executable long-term correction that should be reviewed after the incident.

**Considered Options**

- Treat rollback as the complete fix
- Treat index creation as the primary approved remediation
- Present rollback as mitigation and index creation as long-term correction

**Consequences**

The approval prompt can recommend a safe immediate action without hiding the underlying cause. Post-mortems and action items must preserve this distinction so the incident can resolve quickly while the recurrence-prevention work remains visible.
