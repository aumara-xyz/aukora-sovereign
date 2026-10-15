# portal/
The co-presence Point-and-Bloom page: two screens face each other; each shows a signed QR code that rotates every second and reads the other's: face, seen you, handshake, bloom. Evidence, never authority.

**Bricks:** 76, 78, 118, 132 (NORTH-STAR.md).

`contracts.ts` and `contract.json` freeze the page-to-engine boundary for worker 18.
They provide no camera, signing, receipt parser, network, or authorization engine.
Receipt input stays opaque bytes so the co-presence reader can retain its decimal
coordinates. Legacy `copresence.v0` verification keeps its signed `t_B` core and
inclusive ten-second window.

New exchanges use a separate `copresence.v1` domain and require their own versioned
schema and pinned vectors before being enabled. Both timestamps, the selected
method, every attempt, nonces, identities, and the full context must be bound; the
first frame cannot reveal its nonce. `verdict-table.v1.json` records the expected
legacy outcomes and already-pinned fixture hashes for worker 18; the conductor pins
the table. The contract names the already-pinned approved text and removes only its
trailing newline.

An exchange has no network interface. Post-ceremony export or opt-in relay delivery
must be composed separately. A relationship bloom, receipt, or claimed location
never grants authority; self-reported position has no confidence percentage.
