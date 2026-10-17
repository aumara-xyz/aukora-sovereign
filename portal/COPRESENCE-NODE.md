# Co-presence on the node

The owner's first journey ends by pairing a second device, their phone, screen to screen. This page is the node
side: how the phone reaches the node, what the transcript binds, the endpoints, what is stored, and what a
verified pairing proves. Bricks 47, 76, 77, 78, 118, 132 (NORTH-STAR.md).

## What it proves, and what it does not

- **What the node checks** (`supervisor::pairing::submit`, then `copresence::v1::verify_receipt`): the receipt is
  canonical v1 JSON; its context is exactly the pinned one (this node in both participants, these two device keys,
  the pinned context bytes, screen-to-screen, no sound, motion or intent layer); both P-256 signatures verify over one
  core digest, which commits to that context, both nonces, both timestamps and a transcript digest; the two
  timestamps are at most 10 s apart, the second is fresh (from 7 s before to 3 s after the node's clock: the verifier's 10 s, shifted by the 3 s a device clock may run ahead), both fall inside the
  pairing window; and the receipt has not been spent. Then it spends it once.
- **What the node does not check:** the frames themselves never reach it. It does not check each nonce against its
  FACE commitment, and it does not recompute the transcript digest from the four frames: it only sees the 32 bytes
  both keys signed. Those checks are each device's, in the browser engine (`portal/engine.ts`: the reveal against the
  commitment, the transcript rebuilt from the frames, the HANDSHAKE core compared with its own); the Rust exchange
  state machine (`crates/copresence/src/v1/exchange.rs`) does the same but the node does not run it for pairing.
- **So a verified pairing shows:** two device keys, the ones the node registered at start and join, both signed one
  core binding this node's context within a few seconds of each other, and the node accepted that once. That two
  honest engines also exchanged light is what those engines enforce; two colluding keys could sign a core without
  any exchange.
- **Does not prove:** that a human was present, that the two screens were physically near each other (a fast video
  relay can carry the light), who held either device, or anything about location. One person can pair two of their
  own devices; that is the point here. A receipt grants no permission, device scope or authority. Adding a device
  to AUMLOK's authority membership (`aumlok::devices::add_device`) still needs the owner's passkey and is not done here.

## Flow

1. **Start.** The owner's screen (owner frame, bound owner-frame session, after the passkey sign-in that follows the
   AUMLOK bind) makes or loads its device key and calls `POST /api/pairing/start {deviceKey}`. The node stores the
   pairing under the owner's subject, epoch and session digest, closes the owner's earlier unfinished pairing, and
   returns a single-use join token.
2. **Phone link.** The owner screen shows a QR of `https://<owner origin>/pair#j=<token>`. The token is in the URL
   fragment: the browser never sends it, so it reaches no log or Referer. The page removes it from the address bar.
3. **Join.** The phone opens `/pair` top level (no account, no cookie). It makes its own device key and calls
   `POST /api/pairing/join {join, deviceKey}`. The token works once. The node now knows both public keys, writes the
   pinned context, and gives the phone a bearer for this pairing only.
4. **Exchange.** Both screens run the portal engine (`portal/engine.ts`) with the node's context bytes as the
   exchange context. Both sign with their durable device keys. Frames rotate each second: FACE (nonce commitment),
   SEENYOU (reveal), HANDSHAKE (B signs the core), BLOOM (A signs; the receipt).
5. **Receipt.** The owner screen submits the receipt: `POST /api/pairing/receipt {pairing, receipt}`. The node checks
   the claimed context against everything it pinned, then `copresence::v1::verify_receipt` (both signatures over one
   core, the 10-second window between the timestamps and freshness, durable attempt journal), then that both
   timestamps fall in the pairing window. Nonce commitments and the transcript are the devices' checks (above).
6. **Spend and record.** In one SQLite transaction the node inserts the receipt digest into `spent_receipts`
   (primary key; no update or delete), marks the pairing spent and upserts both devices. Then it appends one Aura fact.
   It returns the verdict.
7. **Done.** The owner screen shows BLOOM only after the node's verdict (a local BLOOM is shown as HANDSHAKE while the
   node decides, so frames keep rotating for the phone). The phone polls `POST /api/pairing/phone {phone}` and shows
   "Verified by your node." when the pairing is spent.

## Frames: compact-v1 (the default) and json-v1

The four frames can travel in two wire forms; both screens of an exchange use the same (`BrowserEngineOptions.frames`,
default `"compact-v1"`). **The node never reads a frame.** It verifies the receipt only, and the receipt's `transcript`
is an opaque 32-byte digest to it, so the frame wire is a matter between the two browsers and `crates/copresence`'s
reference codec. A receipt is byte for byte the same either way; neither the receipt nor the node verifier changed.

- **json-v1** is the original canonical-JSON frame. It repeats the whole context (SEENYOU) and the whole core
  (HANDSHAKE), 0.7 to 1.5 KB, QR versions 19 to 27 (93 to 125 modules a side). It is kept for old vectors and tests.
- **compact-v1** is the same four frames in binary, 168 to 201 bytes (233 with an intent signature), QR versions 8 to
  10 (49 to 57 modules a side), the density portal-v0 used on the phone-tested page. Layout, big-endian, fixed width,
  `frame = body || signature`, `body = 0xC1 || type || fields`:

  | Frame | Fields after magic and type |
  |---|---|
  | FACE `01` | node 16, key 33 (SEC1 compressed), epoch u32, attempt u32, session 16, method u8, layers u8, nonce commitment 32, t u32, index u16 |
  | SEENYOU `02` | sender u8 (0 A, 1 B), context digest 32, face A hash 32, face B hash 32, nonce 32, t u32, index u16 |
  | HANDSHAKE `03` | core digest 32, `sig_b` 64, t u32, index u16 |
  | BLOOM `04` | flags u8 (bit 0 = intent signature), core digest 32, `sig_a` 64, [intent signature 64], t u32, index u16 |

  The signature is the raw 64-byte `r || s` (what WebCrypto ECDSA P-256 returns) over
  `SHA-256("copresence.compact-frame.v1" 0x00 || be32(len(body)) || body)`. Nothing is new cryptography: the same WebCrypto
  P-256 ECDSA signs and verifies; a key is stored compressed and expanded with standard SEC1 point decompression
  (`portal/p256.ts`, checked against WebCrypto on 300 fresh keys and against the Rust `p256` crate through the vectors),
  and WebCrypto's import rejects anything that is not a point on the curve.
- Where json-v1 repeated the context and the core, compact-v1 carries their digests: each device already holds both and
  compares the digest it computed itself, so a frame for another context or core is refused exactly as before.
- **Freshness is 30 s for compact-v1** (json-v1 keeps 5 s). A screen redraws its first frames (the face, the reveal) all through the
  exchange, and they cannot be re-signed because the transcript hashes their exact bytes, so a peer that reads one late must still
  accept it; with 5 s a slow reader hit `frame-stale` on a redrawn frame and the exchange failed. A frame that is too old is now
  ignored, never fatal. The receipt's own freshness (10 s from its second timestamp) is the node's and is unchanged.
- **Dwell.** Each frame stays on screen two seconds (`BrowserEngineOptions.dwell`, default 2): the face, the re-signed handshake or
  bloom, and the cycle all move on together, so a reader that decodes a few times a second sees every frame. While the other screen
  is being read the exchange may take up to 45 s (25 s until the first frame from the peer is read).
- **B rebuilds the receipt instead of reading it.** In json-v1 A also drew the whole receipt as a QR for B. In compact-v1
  A's BLOOM frame carries `sig_a` (and the intent signature when there is one); B already holds the core and its own
  `sig_b`, assembles the same canonical receipt, and verifies and spends it exactly as before. Both ends hold identical
  bytes (tested).
- A QR code carries a compact frame as **base45 text** (RFC 9285) in its alphanumeric mode, at 5.5 bits a character; a
  reader gets text back from jsQR and `portal/frame-text.ts` tells a compact frame (decodes to bytes starting `0xC1`)
  from a JSON one. The QR version is the smallest that holds the payload, except version 23, which jsQR 1.4.0 cannot read.
- Tests: `tests/copresence/compact-frames.mjs` (the shared vectors, point compression, base45, QR sizes read back with
  jsQR, and two real engines running a whole exchange on compact frames, with an intent acknowledgement, and on json-v1,
  ending in byte-identical receipts); `cargo test -p copresence compact` (the Rust reference codec decodes, re-encodes,
  verifies the WebCrypto signatures and recomputes the context, core and transcript digests from the same
  `vectors/compact-frames-v1.json`, written once by `tests/copresence/make-compact-vectors.mjs`). The Rust codec is the
  reference for the wire; it does not carry the exchange state machine, which `v1::exchange` keeps for json-v1 only.

## The pinned context (`aukora.copresence.pairing-context.v1`)

C1 canonical JSON (keys sorted by UTF-16 code unit, integers as plain decimals, no spaces), at most 4,096 bytes.
Both devices pass these exact bytes as the exchange context; the engine binds them as the v1 `purpose`, so both
device signatures over the receipt core commit to every field. Example, wrapped for reading:

```json
{"devices":{"initiator":"04…(65-byte SEC1 P-256, hex)","joiner":"04…"},
 "expiresAtMs":1800000300000,"issuedAtMs":1800000005000,"layers":"optical","method":"screen-to-screen",
 "node":"<node id, 32 hex>","origin":"https://owner.example.org",
 "owner":"aukora:1:<64 hex>","ownerEpoch":1,
 "ownerSession":"<SHA-256(\"aukora:copresence-owner-session:v1\" NUL session-token-digest)>",
 "pairing":"<pairing id, 32 hex>","purpose":"pair-own-device","schema":"aukora.copresence.pairing-context.v1"}
```

The receipt's two participants must both name this node, their two keys must be exactly `initiator` and `joiner`
(either order), the method screen-to-screen, no sound, motion or intent layer. Session ids and attempt counters in
the participants stay the devices' own. A change of meaning is a new schema.

## Reading codes

The decoder (`portal/node/decoder.ts`) never decodes a whole phone frame (1080 by 1920 cost 400 to 600 ms on an iPhone and read one
frame a second or two): it reads the centre 62% downscaled to 512 pixels first, then the whole picture at 640 on its longer side
on every other miss, and every fifth miss the whole picture at 1280, at a steady ten looks a second. When nothing reads, the small
picture is searched for the code's three corner squares (`portal/guide.ts`) and both pages show one calm hint under a small camera
preview with a framing square: "Hold steady", "Move back a little", "Move closer", "Tilt slightly to avoid glare". The phone page
shows the same completion as the computer: the Pentora comes forward, locks with the chime, and says "Co-presence complete."

Both pairing pages read the other screen with jsQR 1.4.0 (`portal/vendor/jsQR.min.js`, the exact file the
phone-tested portal-v0 used, Apache-2.0, licence in `portal/vendor/LICENSE-jsQR`; both pinned in `checks/pins.json`).
The phone page loads it with a plain `<script src>`; the owner's pairing port adds it on first `open()`. Nothing
else loads it and nothing comes from a CDN. Where it is missing, `BarcodeDetector` is the fallback.

## Device keys

Each device makes one P-256 ECDSA key in WebCrypto with a non-extractable private half and keeps it in IndexedDB on
the owner origin (`portal/node/device-key.ts`; stores `aukora.copresence.device.owner.v1` and `…phone.v1`). The node
learns only public halves: the computer's at start, the phone's at join, both then fixed in the context and proven by
the verified receipt. The device list names each key by SHA-256(`aukora:copresence-device-key:v1` NUL key).
Clearing site data forgets a key; the next pairing lists a new device.

## Endpoints (owner origin only)

| Route | Who | Body | Returns |
|---|---|---|---|
| `POST /api/pairing/start` | bound owner-frame session | `{deviceKey}` | `pairing-start.v1`: `pairing`, `join`, `joinPath`, `expiresAtMs`, `nodeTimeMs` |
| `POST /api/pairing/status` | same session | `{pairing}` | `pairing-status.v1`: `state` (open, joined, spent, closed, expired), `context`, `verdict` |
| `POST /api/pairing/receipt` | same session | `{pairing, receipt}` (base64url, at most 16 KiB) | `pairing-verdict.v1` |
| `GET /api/pairing/devices` | bound owner-frame session | — | `paired-devices.v1`: key id, public key, role, first/last pairing and time, count |
| `POST /api/pairing/join` | the phone, no session | `{join, deviceKey}` | `pairing-join.v1`: `phone` bearer, `status` |
| `POST /api/pairing/phone` | the phone, no session | `{phone}` | `pairing-status.v1` |
| `GET /pair` | anyone (top level) | — | `portal/phone/index.html` |

All POSTs pass the frontdoor's same-origin, `sec-fetch-site: same-origin` and JSON checks. A refusal is HTTP 400
`{"error":"copresence:<reason>"}`. Another session's pairing answers `pairing-unknown`, like an unknown id.

The verdict: `{schema, pairing, verdict: "UNDETERMINED", code: null, receipt, devices: {initiator, joiner},
personNostrKeys: null, recorded: {sequence, entry} | null, evidence}`. `recorded` is null while the Aura fact is
pending; the node records it later by itself (below).

## Serving and walls

- `portal/` ships in the release and is served on the **owner surface only** (`frontdoor::assets`); the shell, faces
  and the engine never resolve a portal path. `portal` alone still refuses.
- The owner frame's `Permissions-Policy` adds `camera=(self)`; the shell's iframe delegates `camera` to the owner
  origin only (`app/shell/owner-frame.ts`).
- `/pair` is the one top-level document on the owner origin. Its CSP: `default-src 'none'; script-src 'self'
  'wasm-unsafe-eval'; connect-src 'self'; frame-ancestors 'none'; form-action 'none'; base-uri 'none'` (plus style,
  image and media from self). Its `Permissions-Policy` allows the camera and denies passkeys, microphone,
  location and payment. `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, COOP same-origin.

## Storage, limits, expiry

- `state/copresence/pairing-v1.sqlite3`, `synchronous=FULL`: `pairings`, `attempts` (one row per verification
  attempt, never deleted), `spent_receipts` (never updated or deleted), `devices` (never deleted), all pinned to this
  node id.
- A pairing, its join token and context last 5 minutes. A receipt verifies only while the pairing lives, within 10 s
  of its second timestamp (a device clock up to 3 s ahead is tolerated), with both timestamps in [the pairing's creation second, its expiry second + 3 s], checked before verification.
- At most 8 receipt submissions per pairing; then it closes. **The owner is never locked out:** a new start always
  works (and closes the previous unfinished pairing). Join tokens and bearers are 256-bit; guessing gives nothing to
  limit. Unfinished pairings older than a day are forgotten at the next start; spent ones stay.

## The Aura fact

One nonauthorizing `boot.facts` row per spent receipt, actor `copresence` (the same pattern messaging uses), body
`aukora:copresence-pairing:v1`: `evidenceOnly`, `pairing`, `node`, `owner`, `ownerEpoch`, `context` (SHA-256 of the
context bytes), `receipt` (verified core digest), `receiptBytes` (SHA-256), `method`, `tA`, `tB`, `devices`.
The spend commits first, so a receipt can never be accepted twice; a crash between the spend and the fact leaves the
fact pending. Pending facts are swept, 64 at a time, at boot, on every pairing start and on every device-list read
(and on a status read of that pairing), so nothing waits for anyone to poll the old pairing id. The lookup reads only
copresence fact rows through an index (`aura::LedgerTxn::fact_sequences_after`), one per pairing, so there is no
record-count cap that could make a pending fact unrecordable as the ledger grows, and no current-owner check: the
fact names the owner it was verified under. The append is idempotent: before the first attempt the store
persists the Aura frontier (`aura_floor`), and each attempt, inside one Aura transaction, first looks for a
copresence fact with the same `receipt` after that sequence and returns it. A crash after the Aura commit and before
the store's acknowledgement therefore never yields a second fact (tests: `a_crash_after_the_aura_commit_never_appends_
the_fact_twice`, and `a_retried_append_returns_the_committed_fact` against a real ledger). This is a `boot.facts`
row for now; an own Aura kind with its migration is on the open list.

## Interface for `ui/owner/pairing-port.ts`

`portal/node/pairing-port.ts` exports `createNodePairingPort(options?)`. Its result is structurally the scene's
`PairingPort`; the release composes it with:

```ts
import { createNodePairingPort } from "../../portal/node/pairing-port.js";
export const pairingPort: PairingPort | null = createNodePairingPort();
```

- `phoneLink.draw(canvas)` starts the pairing (first call) and draws the phone link; it redraws a fresh link before
  the five minutes run out and after a pairing is spent. `phoneLink.url` is empty until the node answered.
- `open(canvases, signal)` returns the portal services. `engine.begin(request, signal)` waits until the phone has
  joined, then **replaces `request.contextBytes`** with the node's context. The scene's `CONTEXT` text can stay.
- Observations: BLOOM arrives only with the node's verdict (`UNDETERMINED`, `code: null`); a node refusal arrives
  as REFUSED with `copresence:<reason>`. `personNostrKeys` is null for now, so `showBloom` draws nothing (see below).
- Options: `decode` (frame decoder), `pentora` (bloom WASM), `onVerdict`, `pollMs`, `client`, `origin`.

## What ran

- `cargo test -p supervisor --bin sovereign pairing`: 16 tests (including crash-injection, post-spend failure and
  pending-fact sweep tests, and one against a real Aura ledger); with real P-256 receipts (spend once, replay, wrong context,
  wrong node, stranger key, stale and future frames, tampered signature, attempt bound, single-use and expiring join,
  session separation, pending fact settled once, reopen).
- `cargo test -p frontdoor --lib`: portal paths on the owner surface only; pairing routes; phone page headers.
- `node tests/copresence/port.mjs`: the owner port's renewal timer keeps a joined pairing, renews an unjoined one.
- `node tests/copresence/twin.mjs --runs=5`: two isolated headless-Chrome contexts against a local
  stand-in node running `supervisor::pairing` (`crates/supervisor/src/pairing/twin.rs`): 5 of 5 paired in about
  4.5 s, phone verified, one fact per run, replay refused, both devices listed, no CSP violation. Both pages read
  codes with the vendored jsQR. Cameras are canvas streams painted by the driver; TLS, the owner session check and Aura are stood in. Not the physical test.

## Open

- **Bloom keys for own-device pairing** (waiting on Peter). The relationship bloom needs two distinct row-113 person
  keys; an owner pairing their own phone has one person. The verdict carries `personNostrKeys: null`; onboarding
  shows "Verified" without a bloom.
- **Own Aura kind** for the pairing fact (C3 registry, schema migration, verifier) and **AUMLOK `add_device`** for
  making a paired phone an authority device with the passkey: both on the Kira open list.
- **Licence in the release.** `portal/vendor/LICENSE-jsQR` sits beside the script in the repository; the release
  build ships only code and data extensions, so the served release carries the script without its licence file.
- **Frame size.** With compact-v1 a frame is a QR of version 8 to 10 (49 to 57 modules), the size portal-v0 read on a
  phone. It has been read by jsQR from a simulated camera (blur, rotation, noise) and by the headless twin test; a real
  phone camera at arm's length has not been tried with this engine yet.
