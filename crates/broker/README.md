# crates/broker
- **Owns:** the model key outside the model, one-time tickets, the passkey spend grant, reservations, receipts, model streams, model intake.
- **Never owns:** authority from a prompt, or any network beyond the model endpoint.
- **May depend on:** canon, aura, gate.
- **Bricks:** 62, 63, 129, 138 (NORTH-STAR.md).
