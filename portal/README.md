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
The host supplies `pentora`, an adapter to the pinned Rust WASM `pentora_expand`:
32 raw receipt-digest bytes in, 110 trits out. Rust applies `pentora.display.v1`;
the page places the trits using the pinned geometry's `mutable_indices`. A missing
adapter or malformed expansion refuses; there is no JavaScript derivation fallback.
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
