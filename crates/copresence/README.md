# crates/copresence
- **Owns:** the co-presence receipt verifier and met-in-person marks.
- **Never owns:** authority: a receipt is evidence.
- **May depend on:** canon.
- **Bricks:** 47, 77, 132, 137 (NORTH-STAR.md).

The v0 verifier retains the signed core layout and requires integer timestamp spellings.
Telemetry failures refuse in legacy order after signature verification. The v0 verdict table
is `vectors/verdicts-v1.json`; accepted receipts expose only an informational sentinel claim.

The v1 exchange fixes local method and layers before decoding a signed first frame, journals
attempts before parsing, and exposes explicit abandonment. Its frozen wire context remains
legacy evidence. The v2 receipt wraps that unchanged receipt and signs owner subjects,
scopes and expiry with both device keys. A separate intent acknowledgement binds the full
v2 context. The verifier compares the complete context with the supervisor's expected values.

A met-in-person mark requires the v2 receipt, a matching completed local exchange, a signed
screen-to-screen method and the host's local camera source. Imported v0/v1 receipts retain
an unverified-method mark. Every mark is evidence only.

The new `hardened-v2.json` and `exchange-start-v2.json` data await conductor pinning.
`verdicts-v2.json` supplements the v0 table with timestamp and telemetry cases; it does not
replace `verdicts-v1.json`. `vectors/person-bloom-v2.json` retains the person-key display composition.
