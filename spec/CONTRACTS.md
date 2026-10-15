> **Frozen input to [NORTH-STAR.md](../NORTH-STAR.md), the only plan.** Kept so nothing is lost; never edited, never a plan of its own.

# Contracts v1 (frozen; issue #1)

Every crate and the guest bridge code against this file. Changing it needs an issue and Claude's merge. **Version every format. Old records never gain authority under a new version.**

## C1. Canonical JSON (`canon`)
**Output:** the byte-exact equal of Prime's `canonicalJSON` (`plugins/aukora-kira/lib/memory-owner.mjs`, restated in `scripts/aura/verify-append-only.mjs`):
- Objects: keys sorted by UTF-16 code unit order (JavaScript's default sort), `{"k":v,...}`, no whitespace.
- Arrays: `[v,...]`.
- Strings: exactly what JavaScript `JSON.stringify` emits.
  - Escapes `"` and `\`, plus `\b \f \n \r \t`.
  - Other code points below 0x20 become `\u00xx` (lowercase hex).
  - Everything else is literal UTF-8, including U+2028, U+2029 and U+007F.
- Integers: in −(2^53−1)..(2^53−1), with no leading zeros, no `-0`, no exponent, no fraction.
- Literals: `true`, `false` and `null` only.

**Input (strict parse):** accept a value only if:
- it is UTF-8 with no BOM
- it has no duplicate keys
- every number is a canonical integer in range (no floats, exponents or `-0`)
- it has no lone surrogates (including escaped `\ud800`)
- it has nesting depth ≤ 64 and nothing trails the value

**Frames** must also be canonical: re-serialising the parsed value must equal the input bytes. Anything else is refused before interpretation.

**Golden vectors:** `crates/canon/vectors/*.json`, with byte outputs checked against Node's canonicalJSON. The JS bridge runs the same vectors.

## C2. Hashes and domains
- `sha256` is hex lowercase (64 characters) unless a field says bytes.
- **Aura entry hash:** `sha256(canon({prev, ...fields, domain: "aukora:aura-record:v1"}))`.
  - `prev` is the previous entry hash, or the string `"aukora:aura-record:v1"` for sequence 1.
  - This is the same rule as Prime `auraEntryHash`.
- **RFC 6962 leaf:** `sha256(0x00 || bytes(entry_hash))`. Node: `sha256(0x01 || left || right)`. Leaf convention name: `rfc6962-leaf-sha256-0x00-prefixed-v1`.
- **Node signature:** Ed25519 over the 32 raw bytes of `entry_hash`, stored base64 (standard, padded).
- **Other domain tags** (prefix + `\0` + canonical bytes):
  - `aukora:owner-authorization:v1` — what the passkey signs (C5).
  - `aukora:operation-content:v1` — the operation digest over the exact target bytes.
  - `aukora:kira-aead:v1` — Kira associated data (length-prefixed fields: `u32be(len)||bytes`).
  - `pentora.display.v1` — `sha256("pentora.display.v1" || 0x00 || root32)`.

## C3. Aura rows (one table, `aura`)
`seq INTEGER PRIMARY KEY` (1.., no gaps), `prev TEXT`, `hash TEXT UNIQUE`, `sig TEXT`, `at INTEGER` (ms since epoch, supervisor clock, informational only), `kind TEXT`, `actor TEXT`, `op TEXT` (operation id or empty), `phase TEXT` (`intent` | `settle` | `terminal` | `fact`), `body TEXT` (canonical JSON).

- `fields` for the entry hash = `{sequence: seq, at, kind, actor, op, phase, body: <parsed body>}`.
- Triggers forbid UPDATE and DELETE.
- Every operation has exactly one `terminal` row.

**Kinds (v1):**
- `boot.facts`
- `gate.propose`, `gate.review`, `gate.consume`, `gate.apply`, `gate.retire`, `gate.refuse`, `gate.expire`, `gate.recover`
- `floor.advance`
- `aumlok.enrol`, `aumlok.bind`, `aumlok.signin`
- `broker.grant`, `broker.reserve`, `broker.settle`, `broker.revoke`
- `kira.save`, `kira.demote`, `kira.permission`
- `sandbox.start`, `sandbox.exit`
- `nostr.bind` (#52: the node and agent Nostr identities bound to this ledger)

A new kind needs an issue.

**Export:**
- Retained head: `{"schema":"aukora-aura-retained-head-v1","leafConvention":...,"sequence":M,"hash":<entry hash M>,"treeSize":M,"root":<hex>}`.
- Presented head: `{"schema":"aukora-aura-presented-head-v1","leafConvention":...,"treeSize":N,"root":<hex>,"retainedTreeSize":M,"proofFromPrevious":[...]}`. The proof is RFC 6962 §2.1.2 SUBPROOF(M, D[N], true).
- `vendor/append-only/verify.py` must accept these unchanged. At a power-of-two retained size it can only say UNDETERMINED for a rewritten prefix (by design). Our verifier adds the arm-1 chain walk, which names the first rewritten entry.

## C4. FD 3 frames
**Transport (v1.1, 2026-10-14):** FD 3 is an AF_UNIX **SOCK_STREAM** socketpair. Node cannot read SEQPACKET (`net.Socket({fd})` accepts only pipes or TCP), so each frame is a 4-byte big-endian length followed by that many bytes of one canonical JSON object, 1..65,536 bytes.
- A zero length, a length over 65,536, or a short read is a fatal framing error, and the connection is closed.
- Only one write is in flight per side, and replies are matched by `id`.

Each frame is:

`{"v":1,"id":<string ≤64, [A-Za-z0-9_-]>,"kind":<string>,"body":<object>}`

Replies reuse the `id`. Unknown `v` or `kind` → refusal; the supervisor never guesses.

**Guest → supervisor:**
- `propose` `{target, base_sha256, new_bytes_b64, note}`. `note` is model text: untrusted, shown fenced. Optional `cell {module_sha256, input_sha256, effect_sha256}`.
  - `input_sha256 = sha256(canon({key, value}))`; `effect_sha256 = sha256(cellEffectBody bytes)` as Prime's `wasm-proposal.mjs` defines.
  - The supervisor re-runs the cell and compares; it never trusts guest digests.
- `read` `{target}` — the current bytes of an allowed target, so the guest can compute `base_sha256`.
- `model.call` `{grant_id, model, messages, tools, max_output_tokens}` — OpenAI chat-completions shape (what OpenRouter speaks).
  - `messages`: `[{role, content, tool_calls?, tool_call_id?}]`.
  - `tools`: `[{type:"function", function:{name, description, parameters}}]` or `[]`.
  - Non-streaming in v1. The supervisor never retries on its own; one call is one reservation.
- `memory.put` `{cell:{...}, statement, quote?, category}`
  - The cell's input is `value = {category, statement, quote?}` and `key = "memory:" + sha256(canon(value))`.
  - The effect bytes are the cell's canonical effect body plus one LF, as Prime's `wasm-proposal.mjs` produces.
  - The supervisor acknowledges with `accepted` and the eventual `outcome`. The guest reports only "pending" until then.
- `memory.recall` `{query, limit}`
- `memory.list` `{tier:"remembered"|"forgotten", before:<note_id>|null}` → `memory.list.reply {tier, items:[{note_id, category, at, cite_seq, text, demoted_seq, demoted_at}], next:<note_id>|null}` (#16, #58). Read-only, current principal only, newest save sequence first, at most 100 items and bounded by C4 bytes; `before` is the last returned note id in that tier. Remembered requires the same hosted-context permission as recall: active text carries no authority, demoted fields are null. Forgotten contains only retained metadata: text=null, demoted_seq>cite_seq, demoted_at is the demotion time; never cold plaintext, keys or demotion reason. `at` is the save time, `cite_seq` its Aura receipt. No per-note signing or pending note approval counterpart exists; the face receives empty Signed/Proposals sections. A separate OpenViking note store and reply manifests are unavailable; Forget remains unavailable until an owner fingerprint card path exists.
- `status` `{}` → `status.reply {ready, bound, grant_id|null, grant_remaining|null}`
- `organs` `{}` → `organs.reply {aumlok:{bound, passkeys, refresh_due}, kira:{notes, demoted}, aura:{sequence, root, sources:[{name, head|null, entries, absence|null}]}, nostr:{node_npub|null, agent_npub|null, witness_accepted}, wasm:{module_sha256}, owner_origin}` (#58); `aura.sources` (#17, #58) has exactly `gate-ledger`, `kira-chain`, `code-chain` in that order: verified latest matching Aura row hash and row count for gate.* (all eight C3 gate kinds), kira.save/demote/permission, floor.advance respectively; no rows means head=null, entries=0, absence=`gate-ledger-empty`/`kira-ledger-empty`/`code-record-missing`, otherwise absence=null. Read-only and non-secret: no key material, phrase, credential ids, session data or note text.

**Supervisor → guest:**
- `accepted` `{proposal_id}` (means queued for the owner, NOT applied)
- `outcome` `{proposal_id, state}`, where `state` ∈ `applied|refused|expired|retired|incomplete|failed|conflict|unknown`
- `model.reply` `{content, tool_calls, finish_reason, usage:{prompt_tokens, completion_tokens, cost_microusd}, receipt_seq}`
- `read.reply` `{target, sha256, bytes_b64}`
- `recall` `{result: "found"|"empty"|"undetermined", items:[{note_id, text, cite_seq}]}`
- `refusal` `{code, next}`

**Refusal codes** are stable strings `<organ>:<reason>` (e.g. `gate:stale-base`, `broker:grant-exhausted`, `frame:not-canonical`). The registry lives in `crates/canon/src/codes.rs`.

## C5. Owner authorization (what the passkey signs)
`auth = {"v":1,"node":<node id>,"subject":<aukora:1:hex64>,"op":"apply"|"retire"|"release"|"grant"|"permission","proposal":<id>,"target":<string>,"base_sha256":<hex|absent>,"new_sha256":<hex>,"cell":<object|null>,"display_sha256":<sha256 of the exact card bytes shown>,"challenge":<hex32 from the gate>,"expires_at":<ms>}`

- v1.1 (from the gate build): `auth` also carries `"epoch":<owner-state epoch>` and `"operation":<hex>`.
  - `operation = sha256("aukora:operation-content:v1\0" || canon({v:1, node, target, base_sha256, new_sha256, cell}))`.
  - Retirement uses this SAME object with `"op":"retire"`, including its own fresh `challenge`, `expires_at` and the `display_sha256` of the retirement card. There is one layout and one domain. The `op` field keeps an apply proof from retiring and a retire proof from applying.
  - `base_sha256` is the literal string `"absent"` when the target does not exist, never an omitted key. Rust and JS must produce identical bytes.
  - The proof must also name the credential that signed it. The gate compares it with the owner binding for the current `epoch`, so a key from an earlier epoch can never sign.
- WebAuthn challenge = `sha256("aukora:owner-authorization:v1\0" || canon(auth))`.
- The gate rebuilds `auth` from its own state and compares. It never takes it from the browser.

## C6. Card (what the owner sees, any surface)
`card = {"v":1,"risk":"routine"|"critical","says":<one line, gate-written>,"facts":[[label,value],...],"from_to":{...},"model_note":<string, shown fenced last>}`

- The browser renders it, and the gate hashes exactly those canonical bytes into `display_sha256`.
- Rendering must be injective: two different cards never look the same (the escape round-trip test).

## C7. Ids
- Node id: 16 random bytes, hex.
- Subject: `aukora:1:<hex64>`.
- Proposal, operation and request ids: 16 random bytes, hex.
- All times are ms integers. Clock is never authority; ordering is by `seq`.
