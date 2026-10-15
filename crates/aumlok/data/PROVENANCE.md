# Phrase list provenance

New phrases are drawn only from these curated lists. They were reviewed on 2026-10-14 to be
common everyday words that are positive or pleasant and on theme, after the earlier lists drew
morbid and obscure words. Each word was kept from the legacy (v1) lists or added from
`/usr/share/dict/words` (Webster's Second, public domain); a few modern space and technology
words absent from that 1934 dictionary are listed in `curated/README.md`. No spelling is invented.

- ROOT (words 2-3) = nature: plants, animals, land, water, weather, gems, natural light.
- UNITE (words 4-5) = people, connection and celebration.
- RISE (words 6-7) = spirit, space and technology.
- Anchors (word 1) are six-letter everyday words; words 2-7 start with its letters in order.

Rules (checked by `tools/build_curated.py`): lowercase a-z; theme words 3-12 letters, anchors
exactly 6; sorted and unique; no word is a prefix of another in its theme and first-letter
bucket; no word on the profanity or LDNOOBW lists. The legacy lists in `legacy/` are accepted
when an existing phrase is typed and are never drawn.

## Bucket sizes

| Letter | ROOT | UNITE | RISE |
| --- | ---: | ---: | ---: |
| a | 58 | 70 | 87 |
| b | 67 | 65 | 52 |
| c | 97 | 120 | 84 |
| d | 30 | 49 | 60 |
| e | 28 | 38 | 115 |
| f | 38 | 47 | 52 |
| g | 50 | 51 | 51 |
| h | 49 | 47 | 50 |
| i | 20 | 25 | 52 |
| j | 10 | 20 | 13 |
| k | 12 | 18 | 15 |
| l | 38 | 49 | 66 |
| m | 65 | 59 | 55 |
| n | 16 | 40 | 36 |
| o | 34 | 28 | 32 |
| p | 72 | 86 | 61 |
| q | 6 | 10 | 13 |
| r | 43 | 71 | 83 |
| s | 91 | 121 | 91 |
| t | 51 | 81 | 79 |
| u | 8 | 17 | 24 |
| v | 11 | 18 | 29 |
| w | 36 | 28 | 34 |
| x | 0 | 1 | 2 |
| y | 7 | 8 | 11 |
| z | 5 | 3 | 11 |

## Entropy

For anchor a, P(a) is the product of its six slot bucket sizes in ROOT, ROOT, UNITE, UNITE,
RISE, RISE order. Every phrase under a has probability 1/(N*P(a)), so the exact minimum
entropy is log2(N*min P(a)); the average is log2(N) + (1/N)*sum_a log2(P(a)). An anchor is
kept only if all six of its buckets reach the threshold T that maximizes N*min P(a).

Counts: ROOT=942, UNITE=1170, RISE=1258, anchor candidates=1190, anchors drawn=92 (T=39).
Weakest anchor: `branch`; slot buckets [67, 43, 70, 40, 84, 50].
Minimum: 41.503300625602697 bits. Average: 43.085708228442431 bits.

## Source hashes

| Curated source | SHA-256 |
| --- | --- |
| `curated/ANCHOR-CANDIDATES.txt` | `c60b6c5eaaa06291e6630c5c4fb05ce37544235d60ce5721c1b6361c0cc8e116` |
| `curated/RISE.txt` | `27fb304e872330a5119950044dd777745cd5da674a1cf2898ae0e5077ea7323e` |
| `curated/ROOT.txt` | `862e5b4ca633b73024e25443a91c4c6bf9967eadf552a87de92131e6298aa807` |
| `curated/UNITE.txt` | `3fd8124a12ee0d26153661d09512f46eb19df12e43559902ca784afc0125e1ec` |
