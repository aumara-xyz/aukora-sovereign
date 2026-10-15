# crates/nostr
- **Owns:** node and agent Nostr identities, events, BIP-340 signatures, NIP-44 and NIP-59 envelopes, the transport interface (Nostr now, Bluetooth mesh later).
- **Never owns:** authority, or relay I/O.
- **May depend on:** canon.
- **Bricks:** 11, 69, 121, 123, 136 (NORTH-STAR.md).
