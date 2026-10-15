# Normalization oracle

Generated offline with Python 3.9.6, `unicodedata` Unicode 13.0.0.
The implementation uses the locked `icu_normalizer` 2.3.0 compiled NFKC data,
then Rust Unicode lowercase, then Unicode whitespace trim.

`unicode-13-assigned-ranges.txt` includes every scalar assigned in Unicode
13.0.0 (including private use), excluding surrogates: 281392 scalars.
Its SHA256 is `a5d9219f2edd09ce1396629d095b65d25cdaa7a68847ab145ef08fed48a6299f`.

For each scalar in ascending order, the oracle hashes its four-byte big-endian
code point, the four-byte big-endian length, then the UTF-8 bytes of
`unicodedata.normalize('NFKC', scalar).lower()` followed by trimming Unicode
White_Space characters (U+0009..000D, 0020, 0085, 00A0, 1680, 2000..200A,
2028..2029, 202F, 205F, 3000). The final SHA256 is
`ea88d0ef7ad48857ffebd85377fe2a3b2e57638707d3f9a593a28c25c20d3f55`. This checks all older assigned scalars independently
of ICU. New Unicode scalars and arbitrary multi-scalar strings are not
exhaustively compared with Python; targeted sequence tests cover ordering,
blocked composition, Hangul, ligatures, compatibility forms and case context.
