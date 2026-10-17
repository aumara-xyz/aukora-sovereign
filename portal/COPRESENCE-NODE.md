# Co-presence on the node

The owner's first journey ends by pairing a second device, their phone, screen to screen. This page is the node
side: how the phone reaches the node, what the transcript binds, the endpoints, what is stored, and what a
verified pairing proves. Bricks 47, 76, 77, 78, 118, 132 (NORTH-STAR.md).

## What it proves, and what it does not

- **Proves:** two device keys, each held by a browser, exchanged signed rotating QR frames within the same few
  seconds, while both bound the same node-issued context (this node, this owner, this owner session, this pairing,
  this owner origin, these two keys, this five-minute window). The node checked both signatures, the nonce
  commitments and timestamps the receipt carries, and accepted that receipt once.
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
   the claimed context against everything it pinned, then `copresence::v1::verify_receipt` (both signatures, core,
   10-second freshness, durable attempt journal), then that both timestamps fall in the pairing window.
6. **Spend and record.** In one SQLite transaction the node inserts the receipt digest into `spent_receipts`
   (primary key; no update or delete), marks the pairing spent and upserts both devices. Then it appends one Aura fact.
   It returns the verdict.
7. **Done.** The owner screen shows BLOOM only after the node's verdict (a local BLOOM is shown as HANDSHAKE while the
   node decides, so frames keep rotating for the phone). The phone polls `POST /api/pairing/phone {phone}` and shows
   "Verified by your node." when the pairing is spent.

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
pending; the next status read retries it.

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
  of its second timestamp (a device clock up to 3 s ahead is tolerated), with both timestamps inside the window.
- At most 8 receipt submissions per pairing; then it closes. **The owner is never locked out:** a new start always
  works (and closes the previous unfinished pairing). Join tokens and bearers are 256-bit; guessing gives nothing to
  limit. Unfinished pairings older than a day are forgotten at the next start; spent ones stay.

## The Aura fact

One nonauthorizing `boot.facts` row per spent receipt, actor `copresence` (the same pattern messaging uses), body
`aukora:copresence-pairing:v1`: `evidenceOnly`, `pairing`, `node`, `owner`, `ownerEpoch`, `context` (SHA-256 of the
context bytes), `receipt` (verified core digest), `receiptBytes` (SHA-256), `method`, `tA`, `tB`, `devices`.
The spend commits first, so a receipt can never be accepted twice; a crash between the spend and the fact leaves the
fact pending and the next status read appends it.

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

- `cargo test -p supervisor --bin sovereign pairing`: 10 tests with real P-256 receipts (spend once, replay, wrong context,
  wrong node, stranger key, stale and future frames, tampered signature, attempt bound, single-use and expiring join,
  session separation, pending fact settled once, reopen).
- `cargo test -p frontdoor --lib`: portal paths on the owner surface only; pairing routes; phone page headers.
- `JSQR=<jsQR.min.js> node tests/copresence/twin.mjs --runs=5`: two isolated headless-Chrome contexts against a local
  stand-in node running `supervisor::pairing` (`crates/supervisor/src/pairing/twin.rs`): 5 of 5 paired in about
  4.5 s, phone verified, one fact per run, replay refused, both devices listed, no CSP violation. Cameras are canvas
  streams painted by the driver; TLS, the owner session check and Aura are stood in. Not the physical test.

## Open

- **Bloom keys for own-device pairing.** The relationship bloom needs two distinct row-113 person keys; an owner
  pairing their own phone has one person. The verdict carries `personNostrKeys: null` until a choice is made.
- **QR reading on iPhone and Safari.** They have no `BarcodeDetector`. `portal/node/decoder.ts` uses a page-loaded
  `jsQR` (the decoder portal-v0 was phone-tested with); the release does not ship it yet.
- **Frame size.** A FACE/SEENYOU frame is a version-40 QR (177 modules). The rehearsal needed about 8 px per module.
  A real phone camera at arm's length has not been tried with this engine.
