# Auma Lingwa

The local language course for stock app row 2. The face contains the 84-day Auma
curriculum, its 948-word dictionary, and six graded readers. All lessons and
readers remain browsable; reader labels show the vocabulary's lesson range.

`curriculum.json` contains linguistic data transformed into the face's own small
schema. `content.ts` validates that complete schema before exposing `CONTENT`.
`contract.json` records the source data digests, the generated curriculum digest,
and expected counts. No executable reference application code is included.

Vocabulary day `0` means the source assigned no lesson day: these 24 entries are
supplementary recognition vocabulary. Missing usage examples are represented by
paired empty strings. An empty category means the source had no category.
Teaching mode, stability, and protected/sacred flags preserve the dictionary's
source metadata. They describe language content and grant no authority.

The face uses static local data and plain TypeScript. Study progress is local
convenience state and never owner authorization.
