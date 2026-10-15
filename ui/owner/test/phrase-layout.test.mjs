/* Phrase layout logic: the acrostic structure (anchor across, words down,
   ROOT/UNITE/RISE bands) and the type-back check. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { layoutPhrase, firstMismatch, bandOf, BANDS } from '../phrase-layout.js';

const PHRASE = ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'];

test('anchor across, words down, bands grouped', () => {
  const { anchor, columns } = layoutPhrase(PHRASE);
  assert.equal(anchor.word, 'planet');
  assert.deepEqual(anchor.letters, ['P', 'L', 'A', 'N', 'E', 'T']);
  assert.equal(columns.length, 6);
  // column i sits under anchor letter i and holds word i+2, starting with that letter
  for (const [i, col] of columns.entries()) {
    assert.equal(col.letter, anchor.letters[i]);
    assert.equal(col.position, i + 2);
    assert.equal(col.word, PHRASE[i + 1]);
    assert.equal(col.word[0].toLowerCase(), anchor.letters[i].toLowerCase());
  }
  // ROOT (green, nature) words 2-3, UNITE (blue) 4-5, RISE (violet) 6-7
  assert.deepEqual(columns.map(c => c.band), ['root', 'root', 'unite', 'unite', 'rise', 'rise']);
  assert.deepEqual(BANDS.map(b => b.tone), ['green', 'blue', 'violet']);
});

test('band assignment by position', () => {
  assert.equal(bandOf(2).id, 'root');
  assert.equal(bandOf(3).id, 'root');
  assert.equal(bandOf(4).id, 'unite');
  assert.equal(bandOf(5).id, 'unite');
  assert.equal(bandOf(6).id, 'rise');
  assert.equal(bandOf(7).id, 'rise');
  assert.equal(bandOf(1), null); // the anchor has no band
});

test('rejects a broken acrostic, naming the position', () => {
  const bad = ['planet', 'pine', 'willow', 'accord', 'neighbor', 'eclipse', 'terraform'];
  assert.throws(() => layoutPhrase(bad), err => err.code === 'phrase:acrostic-broken' && err.position === 3);
});

test('rejects wrong word count and wrong anchor length', () => {
  assert.throws(() => layoutPhrase(PHRASE.slice(0, 6)), /phrase:word-count/);
  assert.throws(() => layoutPhrase(['sun', ...PHRASE.slice(1)]), /phrase:anchor-length/);
  assert.throws(() => layoutPhrase(['', ...PHRASE.slice(1)]), /phrase:empty-word/);
});

test('type-back: exact match wins, first mismatch is named', () => {
  assert.equal(firstMismatch(PHRASE, PHRASE), 0);
  assert.equal(firstMismatch(PHRASE, PHRASE.map(w => w.toUpperCase())), 0); // case-insensitive
  assert.equal(firstMismatch(PHRASE, ['planet', 'pine', 'linden', 'accord', 'x', 'eclipse', 'terraform']), 5);
  assert.equal(firstMismatch(PHRASE, PHRASE.slice(0, 6)), -1); // incomplete
  assert.equal(firstMismatch(PHRASE, [' planet', ...PHRASE.slice(1)]), 0); // trimmed
});
