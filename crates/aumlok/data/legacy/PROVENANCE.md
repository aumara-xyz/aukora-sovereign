# Legacy (v1) phrase list provenance

These lists are accepted when an existing phrase is typed and are never drawn; new phrases
come from the curated lists (`../PROVENANCE.md`).

Generated offline by `tools/build_lists.py` from the complete named Prime source files.
No EFF membership or frequency requirement applies to theme or original anchor words.
No Zipf measurements, measuredBar metadata or wordfreq availability affect eligibility.
The five safety lists remove exact spellings: all proper-name fields, category lists plus
`hard`, and every pleasantness category. Words must be lowercase a-z and length 3..12.

ROOT = nature; UNITE = people; RISE = spirit plus EFF words starting with a reviewed seed root.
Seed roots and matched words are recorded in `RISE-SEED-COVERAGE.tsv`; expansions are only
existing EFF spellings. No word is invented. Prefix collisions are resolved within each
theme/initial bucket by retaining trie leaves (longest words). This maximizes cardinality:
each removed ancestor has at least one retained descendant, and retaining it instead cannot
add words. Single-descendant ties prefer the longest word. Lists are sorted and unique.

The anchor candidate union is the three unpruned theme sources, chosen EFF additions, and
`aumlok-anchors.json`, with the same safety/shape filters and exactly six letters. The anchor
slot is separate from theme slots; equal-length anchors have no prefix collisions. Original
anchors remain eligible even when absent from a theme. Theme pruning never hides an anchor.

## Filter counts

Inputs below are unique spellings. Source hits count each filter independently against that
input; removed/remaining counts apply filters sequentially in the stated order, so overlapping
safety denials are not double-counted. Prefix counts apply to the remaining safe words.

| Source | Unique words |
| --- | ---: |
| `theme-nature.json` | 8656 |
| `theme-people.json` | 19157 |
| `theme-spirit.json` | 9260 |
| `aumlok-anchors.json` | 150 |
| `safety/eff_large_words.txt` | 7773 |
| `safety/profanity-block.json` | 449 |
| `safety/ldnoobw-en.txt` | 403 |
| `safety/proper-names.json` | 1616 |
| `safety/category-drop.json` | 3496 |
| `safety/pleasant-drop.json` | 1093 |

### ROOT: 8656 input words

| Filter | Source hits | Removed at this step | Remaining |
| --- | ---: | ---: | ---: |
| `safety/profanity-block.json` | 22 | 22 | 8634 |
| `safety/ldnoobw-en.txt` | 8 | 0 | 8634 |
| `safety/proper-names.json` | 13 | 13 | 8621 |
| `safety/category-drop.json` | 192 | 169 | 8452 |
| `safety/pleasant-drop.json` | 67 | 31 | 8421 |
| `lowercase a-z` | 0 | 0 | 8421 |
| `length 3..12` | 0 | 0 | 8421 |
| `prefix collision (keep leaves)` | 670 | 670 | 7751 |

### UNITE: 19157 input words

| Filter | Source hits | Removed at this step | Remaining |
| --- | ---: | ---: | ---: |
| `safety/profanity-block.json` | 93 | 93 | 19064 |
| `safety/ldnoobw-en.txt` | 48 | 0 | 19064 |
| `safety/proper-names.json` | 52 | 52 | 19012 |
| `safety/category-drop.json` | 937 | 846 | 18166 |
| `safety/pleasant-drop.json` | 343 | 187 | 17979 |
| `lowercase a-z` | 0 | 0 | 17979 |
| `length 3..12` | 0 | 0 | 17979 |
| `prefix collision (keep leaves)` | 2523 | 2523 | 15456 |

### RISE: 9838 input words

| Filter | Source hits | Removed at this step | Remaining |
| --- | ---: | ---: | ---: |
| `safety/profanity-block.json` | 53 | 53 | 9785 |
| `safety/ldnoobw-en.txt` | 24 | 0 | 9785 |
| `safety/proper-names.json` | 12 | 12 | 9773 |
| `safety/category-drop.json` | 732 | 692 | 9081 |
| `safety/pleasant-drop.json` | 321 | 184 | 8897 |
| `lowercase a-z` | 0 | 0 | 8897 |
| `length 3..12` | 0 | 0 | 8897 |
| `prefix collision (keep leaves)` | 857 | 857 | 8040 |

### ANCHOR candidates: 30998 input words

| Filter | Source hits | Removed at this step | Remaining |
| --- | ---: | ---: | ---: |
| `safety/profanity-block.json` | 130 | 130 | 30868 |
| `safety/ldnoobw-en.txt` | 66 | 0 | 30868 |
| `safety/proper-names.json` | 59 | 59 | 30809 |
| `safety/category-drop.json` | 1399 | 1280 | 29529 |
| `safety/pleasant-drop.json` | 519 | 287 | 29242 |
| `lowercase a-z` | 0 | 0 | 29242 |
| `length 3..12` | 0 | 0 | 29242 |
| `anchor length exactly 6` | 24765 | 24765 | 4477 |

## Source hashes

| Local source (relative to Prime Aumlok data) | SHA-256 |
| --- | --- |
| `theme-nature.json` | `2e74cffd294a1edf504b54f9b84a888e77c221fedd8e8dd62c870ff0940860ac` |
| `theme-people.json` | `fd9da45b54c7465aea1d83981706e7501d590579100df16dd2f3430ef441359a` |
| `theme-spirit.json` | `c4559d39ad645bd8d54dcf1e4ad78aaa80d4bd306474aa94ddf267babcb0e200` |
| `aumlok-anchors.json` | `7a01ce1e0381c92b8b7b4ac7397523da9fc5fafb2c83279f76a3eb9eee333c3b` |
| `safety/eff_large_words.txt` | `e1eebc11e80b20e6a0850032778a9b3ac7a1c11f0a3864886857e8f8f71fb12b` |
| `safety/profanity-block.json` | `a180028e9f6515828bcef211a70f5f51db6ef1730731153548ab923ce4148204` |
| `safety/ldnoobw-en.txt` | `af851ecef1d5f212caba17339b12ac39cc2fef7d78c74876f67237644fcee8bd` |
| `safety/proper-names.json` | `ca034161ff82c0a156830b9c1c538d7cd7d58200c23b8e9365027202775819c6` |
| `safety/category-drop.json` | `56b55f6c6ccd0acf5a290d1fa0efc50c3b89bf2bcc05a48580fef0dbc32bcf98` |
| `safety/pleasant-drop.json` | `47d26c48987d8b47a587429035e19d57825ab4b6d43a7a92cd6e287c40988e99` |
| `RISE-SPACE-TECH-SEEDS.txt` (this crate) | `5ef14b4d9f166a9e039ff6aaf097b8063111ca3799dc39d6cf38ff272b6e94ea` |

EFF attribution: Electronic Frontier Foundation large diceware list, CC BY 3.0 US.
LDNOOBW attribution: List of Dirty, Naughty, Obscene, and Otherwise Bad Words, CC BY 4.0.
The curated filters and theme classification come from aukora-prime.

## Entropy and threshold curve

For anchor a, P(a) is the product of its six slot bucket sizes in ROOT, ROOT, UNITE, UNITE,
RISE, RISE order. Its bits are log2(N) + sum_slot log2(bucket size). Every phrase under a
has probability 1/(N*P(a)), so exact min-entropy is log2(N*min P(a)). Average (Shannon)
entropy is log2(N) + (1/N)*sum_a log2(P(a)), weighted by the uniform anchor draw.
Decimal displays are floored at 15 places with 110-digit arithmetic; binary constants round down.

An anchor survives T only if all six slot-specific buckets have at least T words. We examine
every positive integer T via intervals between membership changes. Compare N*min P(a) as an
exact integer, avoiding floating-point optimization. Equal maxima prefer more anchors, then
the smallest T. Each curve row covers every integer T in its inclusive interval; an empty
set has undefined entropy. Per-anchor bits/buckets are in `../../vectors/legacy/anchor-entropy.tsv`.

| T (inclusive) | Anchors | Minimum bits (floored) | Average bits (floored) |
| --- | ---: | ---: | ---: |
| 1..7 | 4477 | 53.508697642877842 | 63.418286211778537 |
| 8..16 | 4446 | 53.498673273001288 | 63.443988810197970 |
| 17..24 | 4122 | 55.257543761930772 | 63.656686271372104 |
| 25..42 | 4103 | 56.014276785880794 | 63.670161188560888 |
| 43..54 | 4072 | 56.003335193063954 | 63.687644744336771 |
| 55..64 | 3959 | 55.962733699018355 | 63.707248594700917 |
| 65..80 | 3920 | 55.948451285990829 | 63.715153548798664 |
| 81..85 | 3863 | 55.927319309220190 | 63.720854317183808 |
| 86..97 | 3772 | 55.892927307663355 | 63.740167152647629 |
| 98..102 | 3733 | 55.877933140291328 | 63.751259598129915 |
| 103..108 | 3292 | 56.660761245982038 | 63.723779237052074 |
| 109..120 | 3258 | 57.893757535544405 | 63.743685650408897 |
| 121..131 | 3007 | 57.778095799592891 | 63.713031348575309 |
| 132..138 | 2951 | 57.750974852450895 | 63.722951413017115 |
| 139 | 2480 | 57.500111052293125 | 63.697236217401709 |
| 140..143 | 2372 | 57.435874941564891 | 63.719025976390500 |
| 144 | 2319 | 57.403273751664891 | 63.729433461274919 |
| 145..164 | 2294 | 58.981593295967355 | 63.738125551724225 |
| 165..169 | 2274 | 58.968960158843778 | 63.736164890098099 |
| 170..177 | 1874 | 59.622940757923213 | 63.708486379796200 |
| 178..199 | 1847 | 60.228437525235996 | 63.712856220389676 |
| 200..202 | 1463 | 59.982400324014781 | 63.540920538643681 |
| 203..216 | 1460 | 59.979438923643673 | 63.542883199124688 |
| 217..229 | 951 | 59.972821481274758 | 63.268092956350463 |
| 230..252 | 822 | 59.930469995609584 | 63.079520175038956 |
| 253..291 | 790 | 59.873184254992367 | 63.064128976012320 |
| 292..297 | 641 | 59.971589562022579 | 62.914312734882100 |
| 298..304 | 528 | 59.691803134762291 | 62.817714344647914 |
| 305..307 | 499 | 59.610305020741099 | 62.721944167145482 |
| 308..311 | 483 | 59.563288394239611 | 62.687648184591051 |
| 312..323 | 462 | 59.675938799335512 | 62.672352782246165 |
| 324..326 | 459 | 59.666540101333263 | 62.672402458771573 |
| 327..329 | 139 | 58.817377759121739 | 61.718060976980288 |
| 330..332 | 93 | 58.911091952235458 | 61.447852504781564 |
| 333..338 | 92 | 58.895495097184439 | 61.448610443090107 |
| 339 | 86 | 58.798197895829524 | 61.414634169734178 |
| 340 | 85 | 58.781324077265128 | 61.415023542041329 |
| 341..361 | 72 | 59.143913012945187 | 61.545125086423299 |
| 362..383 | 58 | 58.917314561668233 | 61.331921397239971 |
| 384 | 18 | 59.060304734111214 | 59.884499975544597 |
| 385..390 | 14 | 58.697734654726506 | 59.593225915666422 |
| 391..397 | 13 | 58.590819450809994 | 59.495042801341164 |
| 398..415 | 10 | 58.275931314450144 | 59.292203049846702 |
| 416 | 4 | 57.330649911216701 | 58.481411703768362 |
| 417..450 | 2 | 57.774985786828138 | 58.206510073993055 |
| 451..577 | 1 | 57.638034361157972 | 57.638034361157972 |
| 578+ | 0 | undefined | undefined |

Chosen T=178, maximizing minimum entropy; threshold removes 2630 of 4477 eligible candidates.
Counts: ROOT=7751, UNITE=15456, RISE=8040, anchors=1847; eligible anchor candidates=4477.
Weakest anchor: `rookie`; slot buckets [291, 199, 499, 339, 229, 326].
Exact minimum: log2(1350722975157664362) bits.
Minimum display: 60.228437525235996 bits.
Average display: 63.712856220389676 bits.
55-bit target reached; margin (floored): 5.228437525235996 bits.

`WORD-SOURCES.tsv` identifies every source containing each output theme word or anchor.
`vectors/legacy/sources.json` preserves exact word projections and complete input hashes for independent
offline membership checks. Regeneration from Prime also checks complete source bytes; projected
snapshots alone do not authenticate the original files. Entropy assumes the existing uniform
random draw; it does not quantify owner-chosen phrases or establish installed supervisor/UI behavior.
