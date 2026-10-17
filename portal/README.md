# portal/
The co-presence Point-and-Bloom page: two screens face each other; each shows a signed QR code that rotates every second and reads the other's: face, seen you, handshake, bloom. Evidence, never authority.

**Bricks:** 76, 78, 118, 132 (NORTH-STAR.md).

The node serves this folder on the owner origin only. `node/` is the node-backed pairing port for the owner's pairing
scene (durable device keys, the node's pinned context, the node's verdict) and `phone/` is the phone's page at
`/pair`. The node side, the context format, the endpoints and what a pairing proves: `COPRESENCE-NODE.md`.

`contracts.ts` and `contract.json` freeze the page-to-engine boundary for worker 18.
They provide no camera, signing, receipt parser, network, or authorization engine.
Receipt input stays opaque bytes so the co-presence reader can retain its decimal
coordinates. Legacy `copresence.v0` verification keeps its signed `t_B` core and
inclusive ten-second window.

`ReceiptVerdict` uses the original `verdict`, `code` and `positionSource` fields.
The `UNDETERMINED` arm also permits `code: null` for a verified receipt without a
position assessment, matching the pinned genuine and intent receipt outcomes.
`SUSPICIOUS` and `UNDETERMINED` with a non-null refusal code are refusals.
`CONSISTENT_CLAIMED` retains `positionSource: "SELF_REPORTED_UNVERIFIABLE"`.
The context exchange reports `UNDETERMINED` with `code: null`; it makes no position
claim. `verdict.ts` validates and copies these shapes before receipt publication;
unknown fields or malformed codes refuse. This changes no receipt wire format.

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
keys, each 32 raw bytes. The host supplies keys from its verified person bindings; a receipt
alone supplies neither. The callback may return null, or null for either key. In
that case the relationship canvas stays empty and receipt export still works.
The adapter validates the byte lengths, copies and sorts the two keys; key
provenance belongs to the host. Node ids, device keys and receipt hashes are never
substituted for person keys.

The engine resolves and copies the two person keys after verifying the receipt.
Its `bloomDigest` observation is the `pentora.bloom.v1` pairing root, never the
receipt core hash; `personNostrKeys` carries the same copied inputs to the page.
Both remain null when either key is unknown. The digest stays null if its adapter
is unavailable; display resolution never delays receipt publication. These are
local session values; no receipt or optical frame gains a field.
`bloomDigest` and `showBloom` retain their byte-array interfaces. `showBloom`
returns the separate `pentora.display.v1` display digest.

The host supplies `pentora` through `bindPairingPentora` from `bloom/index.ts`.
That adapter binds Rust's `pentora_pairing_digest` and `pentora_pairing_expand`
exports. Rust sorts the raw keys bytewise and computes the pairing root, then
applies the shared `pentora_expand` display derivation. The digest export returns
32 bytes; the expansion returns 142 bytes (32 display-digest bytes and 110 trits).
Both use the existing WASM result descriptor and release functions. Invalid
lengths and trits above 2 refuse. There is no JavaScript hash or trit fallback.

`bloom/geometry-data.ts` packages the exact coordinates, mutable indices and edges
from the pinned geometry table as a static browser module. The renderer places
each trit using `mutable_indices`, leaving the centre unassigned. Missing adapters
and malformed expansions leave the canvas hidden; clearing or replacing an
exchange cancels pending drawing. Display failure does not prevent receipt export.

`bloom/person-bloom-v2.json` records this display composition for conductor pinning.
The legacy `crates/pentora/vectors/bloom-v1.json` stays unchanged. This composition follows Light's
documented two-person, separate-domain, Sovereign-display design; the available
Light reference has no executable bloom implementation to compare against.
The host's TypeScript pipeline serves these modules and `style.css`, including
the packaged geometry data.

The method and exact shared context are fixed before the first optical frame.
Every exchange and received frame reserves a durable attempt before decode.
Cancelled reservations remain counted; storage failure prevents acceptance.
Nonce commitments precede targeted reveals. Receipt signatures bind both reveal
timestamps, both participants, counters, method, layers, exact context and intent.
The four-frame transcript is ordered A FACE, B FACE, A SEENYOU, B SEENYOU.
Sound checks the peer's nonce-derived acoustic token. Motion requires a local
acceleration event; these channel claims do not prove physical proximity.
Export remains a private manual download; this module opens no network channel.
