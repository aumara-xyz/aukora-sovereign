# Owner UI — build report (2026-10-14)

## Built
`ui/owner/` — plain HTML/CSS/ES modules, no build step, servable static:
- `index.html`, `app.js`: state-driven router — claim → enrol → bind → `#/approvals|aura|memory`.
- `styles.css`: Prime's thread-list glass panel and accent tokens copied verbatim, with source comments.
- Claim + passkey enrolment (`navigator.credentials.create`); the `?claim=` token is scrubbed from the URL.
- Binding: anchor ACROSS in gold boxes, words 2–7 DOWN per anchor letter, ROOT green / UNITE blue / RISE violet; two-line memory-palace guidance; honest server entropy number; no-paste type-back; refresh-phrase entry point disabled (501 `aumlok:refresh-unsupported`).
- Approvals: C6 cards via the injective escaped renderer (`card.js`), ROUTINE blue / CRITICAL red, facts + from→to on top, model note fenced last; one Approve button — the page re-checks the C5 digest and `display_sha256`, then `navigator.credentials.get`.
- Aura: head, recent rows, Pentora from the root (`pentora.js`, byte-verified port, passes Prime's vectors), IndexedDB head witness with red rollback/fork alarm (`consistency.js`, port of `verify.py`).
- Memory: recall with citations and tier labels, demote, honest found/empty/undetermined.
- `plan/OWNER-API.md`: the exact JSON API for the Rust front door.
- `dev/fake-server.mjs`: node built-ins only, fixtures for every screen (running on http://localhost:8787, claim token `dev-claim-token`).

## v1.1 (2026-10-14): sign-in, model, agent status, memory permission
- `route-state.js`: boot decision factored out and pinned by tests — sign-in only when the node is `bound`/`released` and `/api/state` reports `session: false`; claim stays for unclaimed nodes.
- Sign-in (`screens/signin.js`, §7): one "sign in with passkey" action — `/api/signin/start`, `navigator.credentials.get`, `/api/signin/finish`, then state reloads. Dev bypass honoured localhost-only, as before.
- Model (`screens/model.js`, §8, nav `#/model`): key fingerprint only, live grant as spent/cap dollars + expiry. "Set key": password input cleared at submit, sha256 over the exact key bytes via `crypto.subtle`, `/api/broker/key/propose`, then the approval card; the approvals screen POSTs `/api/broker/key` once when the proposal comes back `applied` and clears the held copy on every path (`keyflow.js`). "New grant": allowed-models select, dollar caps, max requests, hours 1–24; `grant.js` refuses zero/negative/over-24h client-side (`broker:invalid-grant`) before proposing.
- Agent status (§9): one icon in the approvals heading from `GET /api/release` (running green / starting gold / stopped muted / exited red, no strips); the supervisor's release proposal is an ordinary critical card.
- Memory (§10): one heading action proposes disclose-to-context, then the approval card.
- `dev/fake-server.mjs`: all v1.1 routes with the spec's validation and codes (`aumlok:not-enrolled`, `broker:invalid-key`, `broker:key-not-approved|key-mismatch|key-redeemed`, `broker:invalid-grant`), apply effects (grant install, agent start, permission), release proposed at bind, `/api/state` gains the honest `session` flag; `dev_bypass` semantics unchanged.

## Tests (`node --test ui/owner/test/*.test.mjs`)
`tests 50 · pass 50 · fail 0` — the v1.0 suites plus: key-flow fetch interception (the key rides only the one POST to `/api/broker/key`, hash is over the exact bytes, held copy cleared on applied/refused), client-side grant refusal, boot routing, and a spawned-server end-to-end (sign-in gating and fresh session, grant refusal and install, key lifecycle through approval to redeemed, release apply, permission propose).

## Not done
Real WebAuthn unexercised (no authenticator; dev bypass is localhost-only). Head `sig` not yet Ed25519-verified in JS. Untested in a real browser. The held key lives only in page memory: a reload between proposal and approval strands the proposal (re-propose to recover). The fake does not append the §7 `aumlok.signin` Aura row to its fixture log.

## Server must provide
Everything in `OWNER-API.md`, honestly: `entropy_bits` over the real lists; `display_sha256` = sha256 of the exact canonical card bytes; challenge = sha256(`aukora:owner-authorization:v1\0`‖canon(auth)); `proofFromPrevious` honouring `?since=`; Ed25519 `sig` over the entry hash; never `dev_bypass`.
