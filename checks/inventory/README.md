# Inventory construction check

This directory owns the omission check for NORTH-STAR rows 127 and 41. Python's
standard library and local Git are its only dependencies. It neither changes
Git nor contacts a remote. NORTH-STAR remains the only plan.

Run `python3 -B checks/inventory/check.py` for the working tree, or append
`--ref FULL_COMMIT` to inspect committed bytes. The index is not substituted for
the working tree. Missing history refuses; a shallow clone works only when it
contains the pinned seed and all intervening history. Refusals use `inventory:`.

The checker retains every version of every numbered plan row, every carry-list
paragraph or bullet with its heading and list context, every coverage-audit
paragraph, and each stable old-tech row observed in Git since the seed.
Whitespace wrapping is immaterial. Changing a requirement under its old ID is
an omission of its former version. Adding a
row is permitted; later deleting that row is caught even after an intervening
commit. The initial old-tech document is pinned separately because it did not
exist at the seed. Its plan references are locators, not completion claims.
Fenced examples do not count as requirements, and raw HTML is refused so hiding
a row cannot preserve its inventory identity. Use committed mode after staging;
a working-tree result does not describe different bytes held only in the index.

Owner dispositions are never inferred from a Git author, a status, an accounting
mapping, or an agent's statement. The optional `--owner-records FULL_COMMIT`
argument is an **external trust anchor**: the caller must obtain it through the
existing owner approval route. The checker reads only the exact record blob in
that commit, never a candidate's editable replacement. It validates the record
structure and exact before/after digests; it does not verify a passkey or prove
who wrote a quote. Without a trusted anchor, omissions refuse. Workers must not
create records on Peter's behalf.
Successive recorded replacements may compose for the same ID; a removal ends
the chain, and a cycle never grants an unrecorded replacement.

`--release --ref FULL_COMMIT` additionally requires the actual 522-row packet,
and trusted rebuilt registrations for that exact commit or dated owner
dispositions for every retained item. The packet has not been supplied. No
source-provenance status (RAN, SOURCE, PORT, BUILD, LATER) establishes completion.
A successful static check never claims installed acceptance or authorizes a
release. The frozen coverage audit has 16 numbered gaps; all are retained.

Conductor integration is required: replace the presence/CSV heuristic in
`checks/run.py` with this command, pin these checker sources and policy through
the existing independent source-pin mechanism, and invoke release mode before
release proposal or signing. A source candidate must not choose either its own
checker pins or its own trusted owner-record revision. Existing row-41 registry
and Aura terminal checks remain required; this check preserves their plan row
but does not measure runtime terminal coverage.

The future `codex-carry-v1.json` adapter has exact keys `schema` and `rows`, with
schema `aukora-codex-carry-v1`. Each of its 522 rows has `id` (`C0001` through
`C0522`) and a nonempty `requirement`. It must be transcribed from Peter's saved
packet and reviewed; no placeholder packet is supplied here.

The trusted revision's `checks/inventory/owner-records-v1.json` has exact keys
`schema`, `dispositions`, and `completions`, with schema
`aukora-inventory-owner-records-v1`. Each disposition has `id`, `before_sha256`,
`after_sha256` (the exact replacement digest or null for removal), `author`,
`date`, `issue`, and `quote`. Each completion has `id`, `sha256`, `commit`,
`author`, `date`, `issue`, and `quote`. Author is `Peter`, date is a valid
`YYYY-MM-DD`, issue is a positive integer, and quote preserves his own words.
Completion means the trusted caller has recorded rebuilding at that exact
candidate commit. The checker does not derive it from the presence of a file.
No owner records are supplied by this worker.
