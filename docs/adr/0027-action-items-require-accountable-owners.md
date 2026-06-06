# Action items require accountable owners

SENTINEL may draft proposed action items after an incident, but they become accepted action items only after a human accepts them and assigns an accountable service owner or incident commander. In the golden path scenario, adding the missing `orders.user_id` index is assigned to the payment service owner rather than created as an orphan ticket.

**Considered Options**

- Let SENTINEL create tickets automatically for every proposed action item
- Keep action items only in the post-mortem text
- Require human acceptance and accountable ownership before action items become real tickets

**Consequences**

Post-mortems produce follow-up work that can actually be owned and tracked. The documentation workflow must distinguish proposed action items from accepted action items and should prevent ticket creation when no accountable owner is known.
