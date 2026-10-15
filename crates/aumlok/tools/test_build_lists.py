#!/usr/bin/env python3
import unittest
from decimal import Decimal, localcontext
import os
from pathlib import Path
import subprocess
import tempfile

from build_lists import (FILES, THEME_FILES, SAFETY_FILES, SLOTS, compose, entropy,
                         filter_words, optimize_anchors, prefix_free, read_seeds)


class ReferenceEnvironmentTests(unittest.TestCase):
    def test_missing_prime_fails_list_builder_with_variable_name(self):
        tool = Path(__file__).with_name('build_lists.py')
        with tempfile.TemporaryDirectory(dir=tool.parent) as directory:
            result = subprocess.run(['python3', '-B', str(tool), '--check'],
                                    env=dict(os.environ, AUKORA_PRIME=directory),
                                    text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('AUKORA_PRIME:', result.stderr)

    def test_incomplete_prime_fails_list_builder_with_variable_name(self):
        tool = Path(__file__).with_name('build_lists.py')
        with tempfile.TemporaryDirectory(dir=tool.parent) as directory:
            source = Path(directory) / 'plugins/aukora-aumlok/data'
            source.mkdir(parents=True)
            result = subprocess.run(['python3', '-B', str(tool), '--check'],
                                    env=dict(os.environ, AUKORA_PRIME=directory),
                                    text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('AUKORA_PRIME:', result.stderr)
        self.assertIn(FILES[0], result.stderr)

    def test_missing_prime_fails_webauthn_vectors_with_variable_name(self):
        crate = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=crate) as directory:
            node = os.environ.get('AUKORA_NODE', 'node')
            try:
                result = subprocess.run([node, str(crate / 'tests/prime_vectors.mjs')],
                                        env=dict(os.environ, AUKORA_PRIME=directory),
                                        text=True, capture_output=True)
            except OSError as error:
                self.fail(f'AUKORA_NODE: cannot execute {node}: {error}')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('AUKORA_PRIME:', result.stderr)


def counted_themes(counts):
    return {theme: {letter + str(index) for letter, count in letters.items() for index in range(count)}
            for theme, letters in counts.items()}


class ListProtectionTests(unittest.TestCase):
    def inputs(self):
        words = {name: set() for name in FILES}
        for name in THEME_FILES.values():
            words[name] = {'sample', 'memory', 'nature', 'united', 'rising'}
        return words

    def test_all_named_safety_files_remove_candidates_and_anchors_independently(self):
        for name in SAFETY_FILES:
            with self.subTest(name=name):
                words = self.inputs()
                words[name].add('sample')
                words['aumlok-anchors.json'].add('sample')
                themes, anchors, _ = compose(words, set())
                self.assertTrue(all('sample' not in ws for ws in themes.values()))
                self.assertNotIn('sample', anchors)

    def test_complete_themes_and_original_anchors_need_no_eff_or_frequency_evidence(self):
        words = self.inputs()
        self.assertFalse(words['safety/eff_large_words.txt'])
        words['aumlok-anchors.json'].add('absent')
        themes, anchors, _ = compose(words, set())
        self.assertTrue(all(ws == words['theme-nature.json'] for ws in themes.values()))
        self.assertIn('absent', anchors)
        self.assertEqual(anchors, words['theme-nature.json'] | {'absent'})

    def test_shape_requires_lowercase_ascii(self):
        words = self.inputs()
        invalid = {'UPPER', 'two words', 'dash-word', 'éclair', 'abc123', ''}
        for name in THEME_FILES.values():
            words[name] |= invalid
        words['aumlok-anchors.json'] |= invalid
        themes, anchors, _ = compose(words, set())
        self.assertTrue(all(not (ws & invalid) for ws in themes.values()))
        self.assertFalse(anchors & invalid)

    def test_length_is_inclusive_three_through_twelve(self):
        words = self.inputs()
        invalid = {'a', 'ab', 'q', 'zz', 'abcdefghijklm'}
        valid = {'xyz', 'abcdefghijkl'}
        for name in THEME_FILES.values():
            words[name] |= invalid | valid
        themes, _, _ = compose(words, set())
        self.assertTrue(all(not (ws & invalid) and valid <= ws for ws in themes.values()))

    def test_prefix_collision_removes_ancestors_and_keeps_all_branches_per_theme(self):
        words = self.inputs()
        words['theme-nature.json'] |= {'air', 'airfield', 'airflow', 'airflows', 'airship', 'candle', 'candles'}
        words['theme-people.json'].add('air')
        themes, anchors, _ = compose(words, set())
        self.assertTrue({'airfield', 'airflows', 'airship', 'candles'} <= themes['ROOT'])
        self.assertFalse({'air', 'airflow', 'candle'} & themes['ROOT'])
        self.assertIn('air', themes['UNITE'])
        self.assertIn('candle', anchors)  # Removed only in the different slot bucket.
        self.assertEqual(prefix_free({'air', 'airship', 'airships', 'airfield'}), {'airships', 'airfield'})

    def test_unsafe_extensions_do_not_suppress_safe_shorter_words(self):
        words = self.inputs()
        words['theme-nature.json'] |= {'candle', 'candles'}
        words['safety/category-drop.json'].add('candles')
        themes, _, _ = compose(words, set())
        self.assertIn('candle', themes['ROOT'])

    def test_seed_roots_select_only_existing_eff_prefixes_and_apply_filters(self):
        words = self.inputs()
        words['safety/eff_large_words.txt'] |= {'orbit', 'orbital', 'deorbit', 'circuit', 'circuitry'}
        words['safety/pleasant-drop.json'].add('circuitry')
        themes, _, _ = compose(words, {'orbit', 'circuit', 'invented'})
        self.assertIn('orbital', themes['RISE'])
        self.assertIn('circuit', themes['RISE'])
        for forbidden in ('orbit', 'deorbit', 'circuitry', 'invented'):
            self.assertNotIn(forbidden, themes['RISE'])

    def test_seeds_allow_comments_and_refuse_nonlowercase_roots(self):
        self.assertEqual(read_seeds(b'# sky\norbit # cosmos\n\nstar\n'), {'orbit', 'star'})
        for raw in (b'Orbit\n', b'two words\n', 'étoile'.encode()):
            with self.assertRaisesRegex(ValueError, 'invalid-seed-root'):
                read_seeds(raw)

    def test_anchor_candidates_are_exactly_safe_six_letter_source_union(self):
        words = self.inputs()
        words['aumlok-anchors.json'] |= {'absent', 'cat', 'toolong', 'Unsafe', 'denied'}
        words['safety/category-drop.json'].add('denied')
        words['safety/eff_large_words.txt'] |= {'galaxy', 'quasar', 'cosmic'}
        _, anchors, _ = compose(words, {'galaxy', 'quasar'})
        self.assertEqual(anchors, {'sample', 'memory', 'nature', 'united', 'rising', 'absent', 'galaxy', 'quasar'})

    def test_audit_counts_independent_hits_and_sequential_removals(self):
        words = self.inputs()
        words['safety/profanity-block.json'] |= {'sample', 'memory'}
        words['safety/pleasant-drop.json'] |= {'sample', 'nature'}
        kept, rows = filter_words(words['theme-nature.json'], words)
        self.assertEqual(kept, {'united', 'rising'})
        self.assertEqual(rows[0], dict(filter='safety/profanity-block.json', source_hits=2, removed=2, remaining=3))
        self.assertEqual(rows[4], dict(filter='safety/pleasant-drop.json', source_hits=2, removed=1, remaining=2))
        themes, _, audit = compose(words, set())
        for theme, ws in themes.items():
            self.assertEqual(sum(row['removed'] for row in audit[theme]['filters']) + len(ws), audit[theme]['input_count'])

    def test_threshold_uses_each_actual_slot_and_rejects_empty_buckets(self):
        themes = counted_themes({'ROOT': {'a': 2, 'b': 2}, 'UNITE': {'c': 3, 'd': 3}, 'RISE': {'e': 4, 'f': 4}})
        anchors, measured, curve = optimize_anchors(themes, {'abcdef', 'xbcdef'})
        self.assertEqual(anchors, {'abcdef'})
        self.assertEqual(measured['anchor_threshold'], 1)
        self.assertEqual(measured['weakest_buckets'], [2, 2, 3, 3, 4, 4])
        self.assertEqual(curve[0]['threshold_end'], 2)
        self.assertEqual(curve[-1]['anchor_count'], 0)
        self.assertEqual(curve[-1]['threshold'], 3)
        self.assertIsNone(curve[-1]['min_entropy_bits'])

    def test_threshold_requires_all_six_buckets(self):
        counts = {'ROOT': {'a': 2, 'b': 2}, 'UNITE': {'c': 2, 'd': 2}, 'RISE': {'e': 2, 'f': 2}}
        for slot, (theme, letter) in enumerate(zip(SLOTS, 'abcdef')):
            with self.subTest(slot=slot):
                altered = {name: dict(letters) for name, letters in counts.items()}
                altered[theme][letter] = 0
                with self.assertRaisesRegex(ValueError, 'no-supported-anchors'):
                    optimize_anchors(counted_themes(altered), {'abcdef'})

    def test_threshold_maximizes_minimum_entropy_not_bucket_threshold_or_anchor_count(self):
        themes = counted_themes({'ROOT': {'a': 1, 'b': 3, 'c': 4},
                                 'UNITE': {'a': 4, 'b': 4, 'c': 4}, 'RISE': {'a': 4, 'b': 4, 'c': 4}})
        candidates = {'aaaaaa', 'bbbbbb', 'cccccc'}
        anchors, measured, curve = optimize_anchors(themes, candidates)
        self.assertEqual(anchors, {'bbbbbb', 'cccccc'})
        self.assertEqual(measured['anchor_threshold'], 2)
        self.assertEqual(measured['min_probability_denominator'], 4608)
        self.assertEqual([(row['threshold'], row['threshold_end'], row['anchor_count']) for row in curve],
                         [(1, 1, 3), (2, 3, 2), (4, 4, 1), (5, None, 0)])
        # Independent brute force covers every integer, including interval interiors.
        for threshold in range(1, 6):
            expected = {anchor for anchor in candidates
                        if all(sum(word.startswith(letter) for word in themes[theme]) >= threshold
                               for theme, letter in zip(['ROOT', 'ROOT', 'UNITE', 'UNITE', 'RISE', 'RISE'], anchor))}
            row = next(row for row in curve if row['threshold'] <= threshold
                       and (row['threshold_end'] is None or threshold <= row['threshold_end']))
            self.assertEqual(row['anchor_count'], len(expected))
            if expected:
                exact = entropy(themes, expected)
                for field in ('min_probability_denominator', 'min_entropy_bits', 'average_entropy_bits'):
                    self.assertEqual(row[field], exact[field])

    def test_threshold_does_not_optimize_average_entropy(self):
        themes = counted_themes({'ROOT': {'a': 4, 'b': 3, 'c': 5, 'd': 2},
                                 'UNITE': {'a': 5, 'b': 2, 'c': 3, 'd': 2},
                                 'RISE': {'a': 7, 'b': 1, 'c': 5, 'd': 7}})
        anchors, measured, curve = optimize_anchors(themes, {letter * 6 for letter in 'abcd'})
        self.assertEqual(anchors, {'aaaaaa'})
        self.assertEqual(measured['anchor_threshold'], 4)
        self.assertEqual(measured['min_probability_denominator'], 19600)
        highest_average = max((row for row in curve if row['anchor_count']),
                              key=lambda row: Decimal(row['average_entropy_bits']))
        self.assertEqual(highest_average['threshold'], 3)

    def test_threshold_ties_prefer_more_anchors_then_smallest_threshold(self):
        themes = counted_themes({'ROOT': {'a': 1, 'd': 1, 'e': 1, 'b': 2},
                                 'UNITE': {'a': 2, 'd': 2, 'e': 2, 'b': 2},
                                 'RISE': {'a': 2, 'd': 2, 'e': 2, 'b': 2}})
        candidates = {'aaaaaa', 'dddddd', 'eeeeee', 'bbbbbb'}
        anchors, measured, _ = optimize_anchors(themes, candidates)
        self.assertEqual(anchors, candidates)
        self.assertEqual(measured['anchor_threshold'], 1)
        self.assertEqual(measured['min_probability_denominator'], 64)

    def test_no_supported_anchors_is_a_clear_error(self):
        for candidates in (set(), {'xxxxxx'}):
            with self.assertRaisesRegex(ValueError, 'no-supported-anchors'):
                optimize_anchors(counted_themes({theme: {'a': 1} for theme in THEME_FILES}), candidates)
        with self.assertRaisesRegex(ValueError, 'no-supported-anchors'):
            entropy({theme: set() for theme in THEME_FILES}, set())
        with self.assertRaisesRegex(ValueError, 'empty-anchor-bucket'):
            entropy({theme: {'a'} for theme in THEME_FILES}, {'xxxxxx'})

    def test_entropy_uses_minimum_phrase_probability_and_uniform_anchor_average(self):
        themes = {'ROOT': {'a', 'aa', 'b'}, 'UNITE': {'a', 'b'}, 'RISE': {'a', 'b'}}
        measured = entropy(themes, {'aaaaaa', 'bbbbbb'})
        self.assertEqual(measured['min_probability_denominator'], 2)
        self.assertEqual(measured['weakest_anchor'], 'bbbbbb')
        self.assertEqual(measured['min_entropy_bits'], '1.000000000000000')
        self.assertEqual(measured['average_entropy_bits'], '2.000000000000000')

    def test_entropy_never_rounds_up_in_binary_or_display(self):
        themes = {theme: set('abcdefghijklmnopqrstuvwxyz') for theme in THEME_FILES}
        for count in range(2, 48):
            anchors = {chr(97 + index // 26) + chr(97 + index % 26) + 'aaaa' for index in range(count)}
            measured = entropy(themes, anchors)
            with localcontext() as context:
                context.prec = 150
                exact = Decimal(count).ln() / Decimal(2).ln()
                for field in ('min_entropy_float', 'average_entropy_float'):
                    self.assertLessEqual(Decimal(measured[field]), exact)
                for field in ('min_entropy_bits', 'average_entropy_bits'):
                    self.assertLessEqual(Decimal(measured[field]), exact)
                    self.assertLessEqual(exact - Decimal(measured[field]), Decimal('0.000000000000001'))


if __name__ == '__main__':
    unittest.main()
