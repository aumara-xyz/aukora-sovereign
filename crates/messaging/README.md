# crates/messaging
- **Owns:** node-to-node messages from owner-approved contacts, contact approval cards, owner-session sends, refusing strangers, the transport slot.
- **Never owns:** authority: a message is never authority.
- **May depend on:** canon, gate, nostr, relay.
- **Bricks:** 8, 60, 71, 123, 133, 134, 135, 137 (NORTH-STAR.md).

The supervisor implements `MessagingTxn` for contact cards and `OwnerSessionTxn`
for direct sends from the signed-in owner shell. The latter requires no card per
message and has no engine-origin route. The original `ApprovedSend` card API is
retained for callers that need it; owner-session sends cannot carry disclosures.

The private SQLite store retains incoming and outgoing text in
`messaging_messages`; the existing no-follow, owner-only file and directory checks
apply. Its additive `messaging_history_meta` schema stays separate from the v1
base schema so predecessor releases can still read their contacts and outbox.
Inbox data and replay reservations commit together. A pending audit body is
retained before Aura appends, then reconciled by message id after interruption;
only reconciled messages appear in reads or become publishable. Repeating an
uncertain submission retains the same signed envelope id.

Signed Aura observations include message direction, public contact key, rumor and
envelope ids, contact-approval receipt, and creation/observation times. They contain
no message text, content digest, or secret key. Public relays additionally observe
the recipient `p` tag, connection IP addresses and timing; NIP-59 hides the sender
and text inside the gift wrap.
