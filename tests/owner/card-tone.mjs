// SPDX-License-Identifier: AGPL-3.0-or-later
// An approval card's colour follows its kind (Peter, 2026-10-18), never the gate's rating, which the pill still shows.
// Run: node --test tests/owner/card-tone.mjs
import assert from 'node:assert/strict';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const dir = mkdtempSync(path.join(tmpdir(), 'owner-card-tone-'));
after(() => rmSync(dir, { recursive: true, force: true }));
writeFileSync(path.join(dir, 'render.js'), stripTypeScriptTypes(readFileSync(path.join(root, 'ui/owner/cards/render.ts'), 'utf8')));
const { cardKind, cardPill, cardTone, splitSays } = await import(pathToFileURL(path.join(dir, 'render.js')).href);

test('the node-changing kinds are red and the people-facing kinds blue, whatever the gate rated them', () => {
  const tone = (target, op, risk) => cardTone(cardKind(target, op), risk);
  for (const risk of ['critical', 'routine']) {
    assert.equal(tone('release', 'release', risk), 'ak-tone-red');
    assert.equal(tone('engine/plugin-set.json', 'apply', risk), 'ak-tone-red');
    assert.equal(tone('engine/model-key.json', 'apply', risk), 'ak-tone-red');
    assert.equal(tone('engine/model-budget.json', 'apply', risk), 'ak-tone-red');
    assert.equal(tone('messaging/contacts.json', 'apply', risk), 'ak-tone-blue');
    assert.equal(tone('door/ask-01.json', 'apply', risk), 'ak-tone-blue');
    assert.equal(tone('door/standing-grants.json', 'grant', risk), 'ak-tone-blue');
  }
  // Any other change keeps the gate's own rating.
  assert.equal(tone('notes/today.md', 'apply', 'critical'), 'ak-tone-red');
  assert.equal(tone('notes/today.md', 'apply', 'routine'), 'ak-tone-blue');
});

test('the level pill matches the colour: red cards say CRITICAL, blue cards ROUTINE', () => {
  const pill = (target, op, risk) => cardPill(cardKind(target, op), risk);
  assert.deepEqual(pill('release', 'release', 'critical'), { text: 'CRITICAL', tone: 'ak-tone-red' });
  assert.deepEqual(pill('engine/model-key.json', 'apply', 'critical'), { text: 'CRITICAL', tone: 'ak-tone-red' });
  assert.deepEqual(pill('messaging/contacts.json', 'apply', 'critical'), { text: 'ROUTINE', tone: 'ak-tone-blue' });
  assert.deepEqual(pill('door/ask-01.json', 'apply', 'critical'), { text: 'ROUTINE', tone: 'ak-tone-blue' });
  assert.deepEqual(pill('notes/today.md', 'apply', 'critical'), { text: 'CRITICAL', tone: 'ak-tone-red' });
  assert.deepEqual(pill('notes/today.md', 'apply', 'routine'), { text: 'ROUTINE', tone: 'ak-tone-blue' });
});

test('the summary splits after its first sentence and loses nothing', () => {
  const says = 'Approve this exact Aukora ID as a contact: npub1abc. This approves the ID, not the person. Before you approve, compare it.';
  const [first, rest] = splitSays(says);
  assert.equal(first, 'Approve this exact Aukora ID as a contact: npub1abc.');
  assert.equal(`${first} ${rest}`, says);
  assert.deepEqual(splitSays('Upgrade this node to a new release: it becomes the floor.'), ['Upgrade this node to a new release: it becomes the floor.', '']);
});
