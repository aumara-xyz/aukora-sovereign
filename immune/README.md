# Immune corpus

Acquired immunity (issues #40/#41) has two inventories. `ANTIBODIES.tsv` registers source
regression tests; `crates/immune/corpus/*.json` contains scenarios that a running supervisor
replays against fresh, disposable Nodes and their real front door. A vector is data, not a
Rust test name. Source tests alone do not establish that replay passed.

Each vector is one canonical JSON object with exactly these fields:

```json
{"expected_refusal":"frontdoor:owner-required","guarded_issue":"#41","id":"example","organ":"frontdoor","scenario":{"steps":[]}}
```

Canonical encoding follows frozen contract C1, including UTF-16 key sorting, integer-only
numbers, no duplicate keys, no whitespace and no trailing newline. IDs are unique ASCII
tokens. The first 20 scenarios contain bounded HTTP requests plus setup steps, captured
values and deterministic software passkey fixtures. They never use production credentials,
provider calls or the owner's state. The replay implementation lives in `sovereign`, where
the Node and its transport are available; `immune` owns parsing, hashing and result comparison.

The corpus root, `antibody_corpus_sha256`, is a SHA-256 Merkle root over the exact vector
bytes in ascending ID order. Leaves hash `0x00 || vector_bytes`; parents hash
`0x01 || left_hash || right_hash`. Trees split at the largest power of two below their leaf
count, as in RFC 6962. Empty corpora, duplicate IDs and noncanonical vectors are refused.
The build embeds the vector files, so installed supervisors replay their own corpus without
needing a source checkout. This root is distinct from the source-test manifest's SHA-256.

Run `cargo run -p sovereign --offline -- immune-check` to print the root and `passed/total`;
any wrong refusal, runner error or exhausted time budget exits nonzero. The supervisor also
replays before proposing a runtime release and shows the root and pass count as review facts.
Immune results are evidence only. Passing the corpus never approves a release; the owner's
passkey remains required. Failed, missing, or unavailable evidence still produces a release
card. The normal approve button stays disabled. The owner selects **approve despite failing
antibodies**, reviews a fresh card stating that exception, confirms it, and completes a fresh
passkey assertion. The signed display hash binds that exception to the exact release; an
ordinary approval proof cannot approve the exception card. This uses C5's existing `release`
operation and adds no new authorization operation.

Release cards show the vector count and SHA-256 of the canonical, sorted ID array. Full IDs,
failed IDs, missing IDs, corpus root, supervisor binary hash, and proposal ID stay in signed
Aura evidence. Bounded previews show failed and missing IDs; the owner can inspect the full
list in Aura. Evidence belongs to one proposal and the running supervisor binary. A pending
proposal from a pre-immune binary gets a fresh replay after upgrading. Failed recovery
withdraws an unreviewed proposal visibly and raises a warning card. A previously reviewed
proposal retains its fence if withdrawal would require the owner's passkey: its unavailable
card and refusal say to retire it first. Old challenges never approve changed card bytes.

One unavailable card never hides other approvals. Gate refusals become visible Aura facts
and owner notices instead of terminating the supervisor. The floor retains every ID from
applied releases, including exceptional approvals. Applied pre-immune releases get an empty
`floor.advance` so their signed cards need not be walked repeatedly. The in-memory floor and
latest refusal caches invalidate when their relevant Aura facts change; signed verification
remains required for new evidence and independent cold floor verification.

Replay twins live in private `0700` directories beneath the system temporary directory,
outside live state files. The systemd unit's `PrivateTmp` isolates them. Setup and storage
failures use `immune:replay-unavailable`. Automatic retries start after ten seconds and double
to a maximum of five minutes. The owner can request another replay with **retry antibodies**;
a five-second minimum separates starts. Each automatic replay retains its 120-second budget, and
owner actions remain available during replay. Synchronous setup/KDF work is not preempted.

Owner API additions use the existing owner session, origin, binding, strict body, and passkey
checks:

- `POST /api/approvals/despite/challenge`, body `{"id":"<proposal>"}`, returns a fresh
  exception `card`, `display_sha256`, `auth`, and `public_key`.
- `POST /api/approvals/despite/decide`, body `{"id":"<proposal>","assertion":{...}}`,
  consumes that exception review once. The ordinary decide route refuses this review.
- `POST /api/release/retry`, body `{}`, schedules a bounded retry and returns
  `{"ok":true,"retry":"scheduled"}`. It grants no release authority.

Frozen contracts C5/C6 and the release record remain unchanged. Corpus evidence is additional
C6 display facts committed by the existing card hash. Refusals use an existing Aura kind
with `phase="fact"`; no new authoritative row kind is introduced. This slice does not add
Thymus, continuous MHC attestation or hypermutation (#42–#44).
FD 3 corpus replay, sandbox confinement and provider calls are not exercised by this slice.
Supervisor-only upgrades replay pending releases when their evidence binary differs.
An already applied release with unchanged runtime digests does not require a new proposal.
The deadline rejects late results; synchronous Node setup and KDF work are not
preempted mid-call. Installed-node and browser delivery remain the integrator's live checks.

Never delete or rewrite corpus files. Add a new vector for a correction or newly confirmed
fault. Retiring a vector would require a separate owner-approved proposal and is out of scope
for this slice. `ANTIBODIES.tsv` is also retained: `scripts/antibodies.py --check` fails when
a registered antibody is missing, unregistered or removed from the manifest. Register new
`antibody_` tests with `python3 -B scripts/antibodies.py --write` (append-only).

Initial vectors use `guarded_issue="#41"` for the replay migration. Their source protections
include existing security tests as well as registered antibodies; this corpus does not
claim to replay every test in the TSV. The source mapping is:

| Vector ids | Existing protection tests |
| --- | --- |
| `claim-single-use`, `claim-unknown` | frontdoor `claim_replay_race_expiry_and_wrong_guesses_are_separate` |
| `request-exact-host`, `request-proxy-https` | frontdoor `exact_host_and_proxy_transport_cannot_be_forged` |
| `request-origin`, `request-fetch-site`, `stranger-owner-action` | frontdoor `origin_and_fetch_fences_cover_posts_websockets_and_sse`, `antibody_owner_retire_reconcile_require_owner_session_origin_and_binding` |
| `request-path-alias`, `chat-owner-route`, `owner-before-binding` | frontdoor `bootstrap_allowlist_is_closed_and_chat_has_no_owner_routes` |
| `chat-owner-cookie` | frontdoor `sessions_have_flags_expiry_revocation_audience_and_no_cookie_shadowing` |
| `request-strict-json` | frontdoor `body_limit_strict_json_and_route_errors_fail_closed`, `antibody_binding_refresh_uses_json_limit_and_strict_parser` |
| `session-expired`, `session-revoked` | frontdoor `antibody_owner_session_stops_when_its_stored_row_is_revoked_or_expired`, sovereign HTTP expiry/signout antibodies |
| `binding-before-enrolment`, `enrolment-second-key` | sovereign owner `registration_needs_possession_and_resumes_without_second_key` |
| `binding-wrong-word` | sovereign owner `binding_words_cancel_root_wrapping_and_terminal_rows_hold` |
| `signin-counter-regression`, `signin-invalid-signature` | sovereign owner `signin_challenge_replay_counter_and_aura_transaction_hold`, counter antibodies for #33 |
| `refresh-without-passkey` | frontdoor `antibody_binding_refresh_requires_passkey_assertion`, sovereign `antibody_refresh_requires_live_session_fresh_passkey_and_supervisor_authorization` |

The frozen C5 document was not changed. The gate retains pre-existing authorization metadata
fields outside C5's exact schema; the cold floor parser still rejects those extra fields.
The duplicate-proposal compatibility fix is covered independently with exact C5 fixtures;
complete gate-to-cold-floor verification does not yet hold for the gate's existing layout.
Installed Linux/systemd operation, real passkeys, disk exhaustion and abrupt process death
require the integrator's live checks. Browser tests use mocks; transport fallback is reported.
