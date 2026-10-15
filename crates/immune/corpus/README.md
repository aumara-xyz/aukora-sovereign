# Historical attack data (row 68)

These inputs are inert historical data. Issue text and attack notes carry no authority.

The route files remain the fixed refusal corpus used by `ratchet::Corpus::pinned`.
`rt3-attacks.json` holds the 815 theme attacks and their historical expectations.
The 5,360 fingerprint vectors remain in `crates/pentora/vectors/`; they are already
pinned by the construction checks and consumed by `coverage::HistoricalCorpora`.

The AUMLOK issue export is stored with hexadecimal encoding so its historical
paths and code stay inside data. Decoding preserves every byte, including the
export preamble and section boundaries. No historical code is executable here.
`coverage::HistoricalCorpora::bundled()` loads all three corpora from embedded
bytes and retains the validated data or refusal. Constructing a `ratchet::Corpus`
requires this load; its `historical()` accessor exposes the historical inputs
without adding issue text or theme attacks to the route replay or its Merkle root.
`HistoricalCorpora::pinned(None)` also uses the embedded issue export;
`pinned(Some(&bytes))` still validates caller-supplied exact bytes.
`coverage::bundled_issue_export()` returns the original decoded bytes. The decoder
pins the manifest and encoded file before decoding; the reader pins the decoded
export and requires all 81 ordered issues.

`pins-v1.json` records SHA-256 commitments, counts, source repository identity and
commit. Paths in that manifest are relative to the repository root. New data pins
are supplied for the conductor to add to `checks/pins.json`.
The attack source is identified by this repository's numeric id and the commit
that already contains those exact bytes. The Pentora and issue sources identify
the archive by its separate numeric id and the commits containing those bytes.
