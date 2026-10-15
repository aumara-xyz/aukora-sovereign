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

`mount.ts` exports `mountPortal(host, options)`, composing the page, browser engine,
strict-durability IndexedDB attempt journal, camera, separate QR and relationship
bloom canvases, WebAudio token matching, and local accelerometer observations.
`contextFormatPinned` is supplied by the host's conductor-controlled data policy;
the browser has no default approval for an unpinned context format. `node` and
`deviceEpoch` come from the host. `legacyVerifier` adapts the Rust receipt reader;
the browser never parses decimal legacy receipts with the canonical frame codec.
Native camera decoding uses `BarcodeDetector`; hosts without it supply `decode`.
The optional host callback `personNostrKeys(receiptBytes)` resolves the completed
exchange to `{ local, peer }`: the two people's row-113 person-nostr x-only public
keys, each 32 raw bytes. The host supplies keys from its person bindings; a receipt
alone supplies neither. The callback may return null, or null for either key. In
that case the relationship canvas stays empty and receipt export still works.
Node ids, device keys and receipt hashes are never substituted for person keys.

The portal's person display v2 sorts those keys bytewise and uses the existing
`pentora.bloom.v1` pairing digest as the root of the pinned Rust WASM
`pentora_expand`. The host supplies that export through `pentora`: 32 raw root
bytes in, 142 bytes out (32 display-digest bytes, then 110 trits). Rust applies
`pentora.display.v1`; the page places bytes 32..141 using the pinned geometry's
`mutable_indices`, in order. Any other length or trit above 2 refuses. Missing
adapters and malformed expansions leave the canvas hidden; clearing or replacing
an exchange cancels pending drawing. There is no JavaScript trit fallback.

`crates/copresence/vectors/person-bloom-v2.json` records this display composition
for conductor pinning. The legacy `crates/pentora/vectors/bloom-v1.json` and its
direct-commitment renderer remain unchanged. This composition follows Light's
documented two-person, separate-domain, Sovereign-display design; the available
Light reference has no executable bloom implementation to compare against.
The host's TypeScript pipeline serves these modules and `style.css`; geometry is
the already-pinned Pentora JSON imported as data before an exchange.

The method and exact shared context are fixed before the first optical frame.
Every exchange and received frame reserves a durable attempt before decode.
Cancelled reservations remain counted; storage failure prevents acceptance.
Nonce commitments precede targeted reveals. Receipt signatures bind both reveal
timestamps, both participants, counters, method, layers, exact context and intent.
The four-frame transcript is ordered A FACE, B FACE, A SEENYOU, B SEENYOU.
Sound checks the peer's nonce-derived acoustic token. Motion requires a local
acceleration event; these channel claims do not prove physical proximity.
Export remains a private manual download; this module opens no network channel.
