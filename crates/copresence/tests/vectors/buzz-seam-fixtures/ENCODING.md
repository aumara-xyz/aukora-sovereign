# Rehearsal receipts for the Buzz seam, and exactly what is signed

Made by `tests/make-seam-fixtures.mjs` with throwaway keys. No real ceremony, no location. `TEXT.txt` holds the text.

| File | `node ../verify-intent.mjs <file> --text "$(cat TEXT.txt)"` |
|---|---|
| `good.json` | exit 0 |
| `fail-wrong-text.json` | exit 1, `intent_mismatch` (a valid approval of a different text) |
| `fail-missing-ack.json` | exit 1, `no_owner_signature` |
| `fail-bad-ack-signature.json` | exit 1, `bad_owner_signature` |

`verify-intent.mjs` (beside the frozen `verify.mjs`) is a reference for the two extra checks; it is standalone Node.

## Encodings in the file

- `pk_A`, `pk_B`: P-256 public key, uncompressed SEC1, 65 bytes, as 130 lowercase hex characters starting `04`.
- `nonce_A`, `nonce_B`: 8 bytes, 16 lowercase hex.
- `t_A`, `t_B`: integer Unix seconds.
- `sig_A`, `sig_B`, `intent.ack.sig`: ECDSA P-256 with SHA-256, raw `r || s` (IEEE P1363), 64 bytes, 128 hex. Not DER.
- `core`: 32 bytes, 64 hex. `intent.digest`: 32 bytes, 64 hex. `intent.salt`: 16 bytes, 32 hex.
- `intent.side`: `"A"` or `"B"`, the side that ASKED (the computer). The approver is the other side.
  `intent.ack.by` names the approver's side.
- `intent.text`: the exact approved text, UTF-8, at most 280 characters, no control or bidi characters.

`X || Y` is byte concatenation; `0x00` is one zero byte; labels are ASCII; hex fields are decoded to bytes first.

## What each signature covers

1. **Core** (what `verify.mjs` checks):
   `core = SHA-256("copresence.v0" || 0x00 || pk_A(65) || pk_B(65) || nonce_A(8) || nonce_B(8) || BE64(t_B))`
   `sig_A` is A's signature over the 32 core bytes as the message (so ECDSA hashes them once more with SHA-256);
   `sig_B` likewise with B's key.
2. **Text binding** (asker's nonce commits to the text):
   `digest = SHA-256("copresence.intent.v1" || 0x00 || utf8(text))`
   `nonce_<side> == first 8 bytes of SHA-256("copresence.intent-nonce.v1" || 0x00 || digest(32) || salt(16))`
3. **Approver's signature over the text**:
   `m = SHA-256("copresence.intent-ack.v1" || 0x00 || digest(32) || pk_<side>(65) || nonce_<other>(8))`
   `intent.ack.sig` is the approver's (`pk_<other>`) ECDSA signature over the 32 bytes `m` as the message.

Refuse unless 1, 2 and 3 all hold and `intent.text` equals the string you asked for. Single use and freshness
(`t_B`) are the caller's to enforce. A pass is evidence that the approver device displayed that text and its key
signed it for this one session; it is not proof of a human, of who tapped, or that anything was then done.
