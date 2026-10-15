# Browser head witness

Row 53 implements `OwnerWitness.observeVisit`. The owner router already calls it
for initialization and browser restoration and displays its observations.

The trusted release must compose `createOwnerWitness` with a node-scoped
IndexedDB store, a read-only head source, and Rust-backed canonicalization and
SHA-256 primitives. There is no JavaScript cryptographic primitive or codec fallback.
The source receives only the retained tree size and cancellation signal. Its
response is the exact six-key C3 presented-head-v1 JSON, bounded to 65,536 bytes.
The source must request a fresh proof for that retained size, without caching.
Neither the source nor the scope comes from parent messages or a URL.

The browser stores a separate `aukora-owner-browser-head-v1` checkpoint with
exactly schema, leafConvention, treeSize and root. C3 presented heads do not
contain an entry hash, so this checkpoint does not claim one or extend C3 v1.
It records an observation, not an authenticated identity or complete history.
Initial retention leaves earlier history unchecked. Clearing browser data loses
the observation; a first visit cannot establish that no earlier head existed.
The local format and observation cases are in `vectors/checkpoints-v1.json`.

Only a connected consistency proof advances a retained checkpoint. An identical
head maps to the frozen interface's `extension` state. Rollback and conflicting
roots alarm; invalid or incomplete proofs remain undetermined. An alarm never
changes an owner's permission to act. Rollback, fork and undetermined findings
do not initiate checkpoint writes. The compare-and-set transaction prevents
concurrent tabs from replacing a newer observation.

The adapter bounds one visit and its single concurrency retry by a deadline.
Cancellation is checked before writes and aborts still-active transactions. A
commit can finish before cancellation is processed; that visit may report
unavailable despite retaining a verified checkpoint.
There are no fingerprint inputs or health-map outputs. No browser health-probe
transport is declared in the frozen owner contract.
