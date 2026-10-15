#!/usr/bin/env python3
"""Reproduce the legacy (v1) phrase lists from Prime sources: accepted when typed, never drawn.

The drawn lists are the curated ones; see build_curated.py."""
import argparse
from decimal import Decimal, localcontext, ROUND_FLOOR
import hashlib
import json
import math
import os
from pathlib import Path
import re

CRATE = Path(__file__).resolve().parents[1]
DEFAULT_PRIME = '/Users/peterviviani/aukora-prime'
FILES = ['theme-nature.json', 'theme-people.json', 'theme-spirit.json',
         'aumlok-anchors.json', 'safety/eff_large_words.txt',
         'safety/profanity-block.json', 'safety/ldnoobw-en.txt',
         'safety/proper-names.json', 'safety/category-drop.json',
         'safety/pleasant-drop.json']
THEME_FILES = dict(zip(['ROOT', 'UNITE', 'RISE'], FILES[:3]))
SAFETY_FILES = FILES[5:]
SHAPE = re.compile(r'[a-z]+\Z')
SLOTS = ['ROOT', 'ROOT', 'UNITE', 'UNITE', 'RISE', 'RISE']


def read_sources(directory):
    words, hashes, docs = {}, {}, {}
    for name in FILES:
        raw = (directory / name).read_bytes()
        hashes[name] = hashlib.sha256(raw).hexdigest()
        if name.endswith('.json'):
            docs[name] = json.loads(raw)
        else:
            words[name] = set(raw.decode('utf8').splitlines())
    for name in THEME_FILES.values():
        doc = docs[name].get('letters', docs[name])
        words[name] = {w for c, ws in doc.items() if len(c) == 1 for w in ws}
    words['aumlok-anchors.json'] = set(docs['aumlok-anchors.json']['anchors'])
    words['safety/profanity-block.json'] = set(docs['safety/profanity-block.json']['words'])
    names = docs['safety/proper-names.json']
    words['safety/proper-names.json'] = set(names['words'] + names['places'] + names['ambiguousNames'])
    drops = docs['safety/category-drop.json']
    words['safety/category-drop.json'] = set(drops['hard']) | {w for ws in drops['categories'].values() for w in ws}
    words['safety/pleasant-drop.json'] = {w for ws in docs['safety/pleasant-drop.json']['categories'].values() for w in ws}
    return words, hashes


def read_seeds(raw):
    seeds = {line.split('#', 1)[0].strip() for line in raw.decode('utf8').splitlines()}
    seeds.discard('')
    if not all(SHAPE.fullmatch(seed) for seed in seeds):
        raise ValueError('aumlok:invalid-seed-root')
    return seeds


def prefix_free(words):
    """Keep trie leaves: a maximum-cardinality prefix-free subset; prefer longer ties."""
    ordered = sorted(words)
    return {word for index, word in enumerate(ordered)
            if index + 1 == len(ordered) or not ordered[index + 1].startswith(word)}


def filter_words(candidates, words):
    current = set(candidates)
    rows = []
    filters = [(name, lambda word, name=name: word not in words[name]) for name in SAFETY_FILES]
    filters += [('lowercase a-z', lambda word: bool(SHAPE.fullmatch(word))),
                ('length 3..12', lambda word: 3 <= len(word) <= 12)]
    for name, keep in filters:
        independent = sum(not keep(word) for word in candidates)
        kept = {word for word in current if keep(word)}
        rows.append(dict(filter=name, source_hits=independent, removed=len(current) - len(kept), remaining=len(kept)))
        current = kept
    return current, rows


def compose(words, seeds):
    extras = {word for word in words['safety/eff_large_words.txt']
              if any(word.startswith(seed) for seed in seeds)}
    raw = {theme: set(words[name]) for theme, name in THEME_FILES.items()}
    raw['RISE'] |= extras
    themes, audit = {}, {}
    for theme, candidates in raw.items():
        safe, rows = filter_words(candidates, words)
        themes[theme] = prefix_free(safe)
        rows.append(dict(filter='prefix collision (keep leaves)', source_hits=len(safe) - len(themes[theme]),
                         removed=len(safe) - len(themes[theme]), remaining=len(themes[theme])))
        audit[theme] = dict(input_count=len(candidates), filters=rows)
    # The anchor slot is its own bucket: six-letter words cannot prefix one another.
    # Theme prefix pruning never hides an otherwise eligible six-letter anchor.
    candidates = set().union(*raw.values(), words['aumlok-anchors.json'])
    safe, rows = filter_words(candidates, words)
    anchors = {word for word in safe if len(word) == 6}
    rows.append(dict(filter='anchor length exactly 6', source_hits=len(safe) - len(anchors),
                     removed=len(safe) - len(anchors), remaining=len(anchors)))
    audit['ANCHOR candidates'] = dict(input_count=len(candidates), filters=rows)
    return themes, anchors, audit


def bucket_counts(themes):
    return {theme: {letter: sum(word.startswith(letter) for word in words) for letter in 'abcdefghijklmnopqrstuvwxyz'}
            for theme, words in themes.items()}


def anchor_profile(counts, anchor):
    sizes = [counts[theme][letter] for theme, letter in zip(SLOTS, anchor)]
    return min(sizes), math.prod(sizes)


def floor_bits(value):
    return str(value.quantize(Decimal('0.000000000000001'), rounding=ROUND_FLOOR))


def entropy(themes, anchors):
    if not anchors:
        raise ValueError('aumlok:no-supported-anchors')
    counts = bucket_counts(themes)
    products = {anchor: anchor_profile(counts, anchor)[1] for anchor in sorted(anchors)}
    weakest = min(products, key=lambda anchor: (products[anchor], anchor))
    denominator = len(anchors) * products[weakest]
    if denominator == 0:
        raise ValueError('aumlok:empty-anchor-bucket')
    with localcontext() as context:
        context.prec = 110
        ln2 = Decimal(2).ln()
        minimum = Decimal(denominator).ln() / ln2
        average = Decimal(len(anchors)).ln() / ln2 + sum(Decimal(p).ln() / ln2 for p in products.values()) / len(anchors)
        def lower_float(value):
            result = float(value)
            return math.nextafter(result, -math.inf) if Decimal(result) > value else result
        return dict(anchor_count=len(anchors), weakest_anchor=weakest,
                    weakest_buckets=[counts[theme][letter] for theme, letter in zip(SLOTS, weakest)],
                    min_probability_denominator=denominator, min_entropy_bits=floor_bits(minimum),
                    average_entropy_bits=floor_bits(average), min_entropy_float=lower_float(minimum),
                    average_entropy_float=lower_float(average), buckets=counts)


def optimize_anchors(themes, candidates):
    """Sweep every distinct anchor set; compare exact integer probability denominators."""
    counts = bucket_counts(themes)
    profiles = {anchor: anchor_profile(counts, anchor) for anchor in candidates}
    # Membership changes only just after a candidate's smallest slot bucket size.
    thresholds = sorted({1} | {smallest + 1 for smallest, _ in profiles.values() if smallest >= 1})
    curve, best_anchors, best_key, best_threshold = [], set(), (0, 0), None
    for index, threshold in enumerate(thresholds):
        anchors = {anchor for anchor, (smallest, _) in profiles.items() if smallest >= threshold}
        end = thresholds[index + 1] - 1 if index + 1 < len(thresholds) else None
        if not anchors:
            curve.append(dict(threshold=threshold, threshold_end=end, anchor_count=0,
                              min_probability_denominator=0, min_entropy_bits=None,
                              average_entropy_bits=None, weakest_anchor=None))
            continue
        measurement = entropy(themes, anchors)
        curve.append(dict(threshold=threshold, threshold_end=end, **{key: measurement[key] for key in
                          ('anchor_count', 'min_probability_denominator', 'min_entropy_bits',
                           'average_entropy_bits', 'weakest_anchor')}))
        key = (measurement['min_probability_denominator'], len(anchors))
        if key > best_key:
            best_key, best_anchors, best_threshold = key, anchors, threshold
    if best_threshold is None:
        raise ValueError('aumlok:no-supported-anchors')
    measurement = entropy(themes, best_anchors)
    measurement.update(anchor_threshold=best_threshold, candidate_anchor_count=len(candidates))
    return best_anchors, measurement, curve


def artifacts(directory):
    words, hashes = read_sources(directory)
    seed_raw = (CRATE / 'data/legacy/RISE-SPACE-TECH-SEEDS.txt').read_bytes()
    seeds = read_seeds(seed_raw)
    themes, candidates, audit = compose(words, seeds)
    anchors, measurement, curve = optimize_anchors(themes, candidates)
    outputs = {f'data/legacy/{theme}.txt': ''.join(word + '\n' for word in sorted(ws)) for theme, ws in themes.items()}
    outputs['data/legacy/ANCHORS.txt'] = ''.join(anchor + '\n' for anchor in sorted(anchors))
    outputs['vectors/legacy/sources.json'] = json.dumps(dict(words={name: sorted(ws) for name, ws in sorted(words.items())},
                                                    sha256=hashes), sort_keys=True, separators=(',', ':')) + '\n'
    outputs['vectors/legacy/entropy.json'] = json.dumps(measurement, sort_keys=True, separators=(',', ':')) + '\n'
    outputs['vectors/legacy/threshold-curve.json'] = json.dumps(curve, sort_keys=True, separators=(',', ':')) + '\n'
    outputs['vectors/legacy/filter-counts.json'] = json.dumps(audit, sort_keys=True, separators=(',', ':')) + '\n'
    outputs['vectors/legacy/entropy_constants.rs.txt'] = '\n'.join([
        '// Generated by tools/build_lists.py from the shipped lists.',
        f'pub const ANCHOR_THRESHOLD: usize = {measurement["anchor_threshold"]};',
        f'pub const ANCHOR_COUNT: usize = {measurement["anchor_count"]};',
        f'pub const WEAKEST_ANCHOR: &str = "{measurement["weakest_anchor"]}";',
        f'pub const MIN_PROBABILITY_DENOMINATOR: u128 = {measurement["min_probability_denominator"]};',
        f'pub const MIN_ENTROPY_BITS: f64 = {measurement["min_entropy_float"]!r};',
        f'pub const AVERAGE_ENTROPY_BITS: f64 = {measurement["average_entropy_float"]!r};',
        f'pub const MIN_ENTROPY_DISPLAY: &str = "{measurement["min_entropy_bits"]}";',
        f'pub const AVERAGE_ENTROPY_DISPLAY: &str = "{measurement["average_entropy_bits"]}";', ''])
    provenance = ['# Legacy (v1) phrase list provenance', '',
        'These lists are accepted when an existing phrase is typed and are never drawn; new phrases',
        'come from the curated lists (`../PROVENANCE.md`).', '',
        'Generated offline by `tools/build_lists.py` from the complete named Prime source files.',
        'No EFF membership or frequency requirement applies to theme or original anchor words.',
        'No Zipf measurements, measuredBar metadata or wordfreq availability affect eligibility.',
        'The five safety lists remove exact spellings: all proper-name fields, category lists plus',
        '`hard`, and every pleasantness category. Words must be lowercase a-z and length 3..12.', '',
        'ROOT = nature; UNITE = people; RISE = spirit plus EFF words starting with a reviewed seed root.',
        'Seed roots and matched words are recorded in `RISE-SEED-COVERAGE.tsv`; expansions are only',
        'existing EFF spellings. No word is invented. Prefix collisions are resolved within each',
        'theme/initial bucket by retaining trie leaves (longest words). This maximizes cardinality:',
        'each removed ancestor has at least one retained descendant, and retaining it instead cannot',
        'add words. Single-descendant ties prefer the longest word. Lists are sorted and unique.', '',
        'The anchor candidate union is the three unpruned theme sources, chosen EFF additions, and',
        '`aumlok-anchors.json`, with the same safety/shape filters and exactly six letters. The anchor',
        'slot is separate from theme slots; equal-length anchors have no prefix collisions. Original',
        'anchors remain eligible even when absent from a theme. Theme pruning never hides an anchor.', '',
        '## Filter counts', '',
        'Inputs below are unique spellings. Source hits count each filter independently against that',
        'input; removed/remaining counts apply filters sequentially in the stated order, so overlapping',
        'safety denials are not double-counted. Prefix counts apply to the remaining safe words.', '',
        '| Source | Unique words |', '| --- | ---: |']
    provenance += [f'| `{name}` | {len(words[name])} |' for name in FILES]
    for label, stats in audit.items():
        provenance += ['', f'### {label}: {stats["input_count"]} input words', '',
                       '| Filter | Source hits | Removed at this step | Remaining |', '| --- | ---: | ---: | ---: |']
        provenance += [f'| `{row["filter"]}` | {row["source_hits"]} | {row["removed"]} | {row["remaining"]} |' for row in stats['filters']]
    provenance += ['', '## Source hashes', '', '| Local source (relative to Prime Aumlok data) | SHA-256 |', '| --- | --- |']
    provenance += [f'| `{name}` | `{digest}` |' for name, digest in hashes.items()]
    provenance += [f'| `RISE-SPACE-TECH-SEEDS.txt` (this crate) | `{hashlib.sha256(seed_raw).hexdigest()}` |', '',
        'EFF attribution: Electronic Frontier Foundation large diceware list, CC BY 3.0 US.',
        'LDNOOBW attribution: List of Dirty, Naughty, Obscene, and Otherwise Bad Words, CC BY 4.0.',
        'The curated filters and theme classification come from aukora-prime.', '', '## Entropy and threshold curve', '',
        'For anchor a, P(a) is the product of its six slot bucket sizes in ROOT, ROOT, UNITE, UNITE,',
        'RISE, RISE order. Its bits are log2(N) + sum_slot log2(bucket size). Every phrase under a',
        'has probability 1/(N*P(a)), so exact min-entropy is log2(N*min P(a)). Average (Shannon)',
        'entropy is log2(N) + (1/N)*sum_a log2(P(a)), weighted by the uniform anchor draw.',
        'Decimal displays are floored at 15 places with 110-digit arithmetic; binary constants round down.', '',
        'An anchor survives T only if all six slot-specific buckets have at least T words. We examine',
        'every positive integer T via intervals between membership changes. Compare N*min P(a) as an',
        'exact integer, avoiding floating-point optimization. Equal maxima prefer more anchors, then',
        'the smallest T. Each curve row covers every integer T in its inclusive interval; an empty',
        'set has undefined entropy. Per-anchor bits/buckets are in `../../vectors/legacy/anchor-entropy.tsv`.', '',
        '| T (inclusive) | Anchors | Minimum bits (floored) | Average bits (floored) |', '| --- | ---: | ---: | ---: |']
    for row in curve:
        interval = str(row['threshold'])
        if row['threshold_end'] is None:
            interval += '+'
        elif row['threshold_end'] != row['threshold']:
            interval += '..' + str(row['threshold_end'])
        provenance.append(f'| {interval} | {row["anchor_count"]} | {row["min_entropy_bits"] or "undefined"} | {row["average_entropy_bits"] or "undefined"} |')
    with localcontext() as context:
        context.prec = 110
        exact_minimum = Decimal(measurement['min_probability_denominator']).ln() / Decimal(2).ln()
        target_text = ('55-bit target reached; margin (floored): ' + floor_bits(exact_minimum - 55) + ' bits.'
                       if exact_minimum >= 55 else
                       '55-bit target NOT reached; shortfall (floored): ' + floor_bits(55 - exact_minimum) + ' bits. '
                       'This is the best threshold on these complete filtered sources and reviewed EFF seed roots; '
                       'finite per-letter bucket sizes and loss of anchors at higher thresholds limit the result.')
    provenance += ['', f'Chosen T={measurement["anchor_threshold"]}, maximizing minimum entropy; threshold removes {len(candidates) - len(anchors)} of {len(candidates)} eligible candidates.',
        f'Counts: ROOT={len(themes["ROOT"])}, UNITE={len(themes["UNITE"])}, RISE={len(themes["RISE"])}, anchors={len(anchors)}; eligible anchor candidates={len(candidates)}.',
        f'Weakest anchor: `{measurement["weakest_anchor"]}`; slot buckets {measurement["weakest_buckets"]}.',
        f'Exact minimum: log2({measurement["min_probability_denominator"]}) bits.',
        f'Minimum display: {measurement["min_entropy_bits"]} bits.',
        f'Average display: {measurement["average_entropy_bits"]} bits.', target_text, '',
        '`WORD-SOURCES.tsv` identifies every source containing each output theme word or anchor.',
        '`vectors/legacy/sources.json` preserves exact word projections and complete input hashes for independent',
        'offline membership checks. Regeneration from Prime also checks complete source bytes; projected',
        'snapshots alone do not authenticate the original files. Entropy assumes the existing uniform',
        'random draw; it does not quantify owner-chosen phrases or establish installed supervisor/UI behavior.', '']
    outputs['data/legacy/PROVENANCE.md'] = '\n'.join(provenance)
    output_union = set().union(*themes.values(), anchors)
    outputs['data/legacy/WORD-SOURCES.tsv'] = 'word\tsources\n' + ''.join(word + '\t' + ','.join(
        name for name, ws in sorted(words.items()) if word in ws and (name not in SAFETY_FILES)) + '\n'
        for word in sorted(output_union))
    outputs['data/legacy/RISE-SEED-COVERAGE.tsv'] = 'root\tEFF matches (before filters)\n' + ''.join(
        root + '\t' + ','.join(sorted(word for word in words['safety/eff_large_words.txt'] if word.startswith(root))) + '\n'
        for root in sorted(seeds))
    with localcontext() as context:
        context.prec = 110
        ln2 = Decimal(2).ln()
        outputs['vectors/legacy/anchor-entropy.tsv'] = 'anchor\tROOT1\tROOT2\tUNITE1\tUNITE2\tRISE1\tRISE2\tbits (floored)\n' + ''.join(
            anchor + '\t' + '\t'.join(str(measurement['buckets'][theme][letter]) for theme, letter in zip(SLOTS, anchor)) + '\t' +
            floor_bits(Decimal(len(anchors) * anchor_profile(measurement['buckets'], anchor)[1]).ln() / ln2) + '\n'
            for anchor in sorted(anchors))
    return outputs, measurement


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.source is None:
        args.source = Path(os.environ.get('AUKORA_PRIME', DEFAULT_PRIME)) / 'plugins/aukora-aumlok/data'
    for name in FILES:
        if not (args.source / name).is_file():
            raise SystemExit(f'AUKORA_PRIME: reference file {args.source / name} is missing; set AUKORA_PRIME or --source')
    outputs, measurement = artifacts(args.source)
    for name, content in outputs.items():
        path = CRATE / name
        if args.check:
            if path.read_text() != content:
                raise SystemExit('aumlok:data-drift: ' + name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf8')
    print(json.dumps({key: value for key, value in measurement.items() if key != 'buckets'}, sort_keys=True))


if __name__ == '__main__':
    main()
