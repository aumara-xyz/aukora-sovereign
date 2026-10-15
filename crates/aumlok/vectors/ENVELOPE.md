# Envelope v1 interoperability vector

`envelope-v1.json` was generated locally by `generate-envelope.py` using the
installed Python cryptography 49.0.0 Argon2id and ChaCha20-Poly1305, with the
HChaCha20 subkey transformation written explicitly in the generator. The Rust
test must reproduce it byte for byte using RustCrypto. No network was used.

All input material is disposable: password bytes `envelope interoperability
fixture`, root 32 copies of byte `0x5a`, salt 16 copies of byte `0x12`, nonce 24
copies of byte `0x34`. These bytes are fixtures, not an owner identity.

The vector uses memory 32 KiB, time cost 1 and parallelism 1. Production defaults
remain memory 262144 KiB, time cost 3 and parallelism 1. Envelope version 1 uses
Argon2id version 19, a 32-byte wrapping key and XChaCha20-Poly1305. Associated
data is `aukora:aumlok-envelope:v1`, a zero byte, and the canonical JSON header
containing `kdf`, `nonce`, `salt` and `version`.

The exact envelope format is an issue #12 local format. Frozen CONTRACTS.md
does not specify its field names or domain tag; this format follows its C1
canonical JSON rules for the envelope's restricted ASCII/integer schema.

## Passkey-bound download v2 (issue #50)

The live node keeps its v1 envelope. The independent downloaded v2 backup seals
the same 32-byte root with fresh Argon2id salt and XChaCha20-Poly1305 nonce. Its
canonical fields are `ciphertext`, `kdf`, `nonce`, `prf`, `salt`, `version:2`.
`prf` contains `credential_id` (canonical unpadded base64url), `rp_id` (the
original WebAuthn relying-party DNS name), and `salt` (standard padded base64).
All other byte fields also use standard padded base64 as v1 does.

WebAuthn PRF `eval.first` always receives SHA-256 of the UTF-8 bytes
`aukora:aumlok-backup-prf:v2`. Its 32-byte result is concatenated after the
32-byte Argon2id phrase key. RFC 5869 HKDF-SHA256 extracts with salt
`aukora:aumlok-backup-hkdf:v2\0` and expands with info
`aukora:aumlok-backup-key:v2\0` to 32 bytes. The implementation uses the already
locked `ring` HKDF API. Associated data is `aukora:aumlok-backup-aead:v2\0`
followed by the canonical header (every field except `ciphertext`), including
the credential and relying-party metadata.

`backup-kdf-v2.json` independently pins the phrase key and combined HKDF key
using Node v24.11.1 `crypto.argon2Sync` and `crypto.hkdfSync`, with disposable
inputs and the small test KDF cost. No network was used.

Restore/verification requires the original phrase and the same credential's
PRF result for this salt, obtained under its original `rp_id`. Availability of
that credential and relying-party origin must be preserved; a credential on a
new RP cannot recover this copy. A separately requested v1 phrase-only recovery
copy remains guessable offline at the Argon2id cost.

Enrolment may request `prf:{}` without requiring support. The scoped
`verify_prf_registration` verifier permits only the client result
`prf:{enabled:<boolean>}` (or no result), plus an optional exact CBOR
`hmac-secret:<boolean>` after the complete COSE key. The existing ordinary
registration verifier keeps rejecting extensions. Existing keys are not
replaced or locked out when PRF is unavailable.

`verify_backup_assertion` shares the ordinary assertion checks and verifies the
complete signed authenticator data. Only that backup path permits ED with one
minimal CBOR `hmac-secret` byte string: 32 encrypted output bytes for CTAP PIN/UV
protocol 1, or 48 including protocol 2's IV, for the one requested `eval.first`.
Ordinary assertions keep their exact 37-byte/no-extension policy. These software
vectors do not establish interoperability with an installed browser and hardware
authenticator; both CTAP variants and platform PRF need live verification.
