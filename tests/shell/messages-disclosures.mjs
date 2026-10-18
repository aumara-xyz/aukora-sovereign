// SPDX-License-Identifier: AGPL-3.0-or-later
// The Messages face tells the owner what a contact card approves, who can send, what relays see, and that both
// sides must add each other. It never claims the seven words
// recover the node's Nostr key.
// Run with: node --test tests/shell/messages-disclosures.mjs
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const face = join(root, 'app/faces/messages');
const built = mkdtempSync(join(tmpdir(), 'messages-copy-'));
writeFileSync(join(built, 'copy.js'), stripTypeScriptTypes(readFileSync(join(face, 'copy.ts'), 'utf8')));
const { COPY, sendOutcome } = await import(pathToFileURL(join(built, 'copy.js')).href);
after(() => rmSync(built, { recursive: true, force: true }));
const actions = readFileSync(join(face, 'actions.ts'), 'utf8');

test('a contact card approves an exact Aukora ID, not a person, and the owner is asked to compare it out of band', () => {
  for (const line of [COPY.contactKey, COPY.contactReview]) {
    assert.match(line, /exact Aukora ID, not the person/);
    assert.match(line, /compare it with them/);
  }
  assert.match(COPY.contactKey, /in person or on a call you trust/);
  assert.match(actions, /COPY\.contactKey\b/);
  assert.match(actions, /status\.textContent = COPY\.contactReview;/);
});

test('the composer says who can send and what relays see', () => {
  assert.match(COPY.sendSession, /^Anyone using your signed-in session can send messages as you\./);
  assert.match(COPY.sendSession, /recorded in Aura/);
  for (const seen of ['IP address', "recipient's key", 'message size', 'when your node connects']) assert.ok(COPY.relaysSee.includes(seen), seen);
  // The wrap's own timestamp is randomized (NIP-59), so the copy must not claim relays see the send time from it.
  assert.match(COPY.relaysSee, /randomized, not the send time/);
  assert.match(COPY.sendSession, /not its text/);
  assert.match(COPY.footnote, /never the text/);
  assert.match(actions + readFileSync(join(face, 'view.ts'), 'utf8'), /COPY\.footnote/);
  assert.match(COPY.relaysSee, /^Relays cannot read your text/);
  const composer = actions.slice(actions.indexOf('export function composer'));
  assert.match(composer, /COPY\.sendSession/);
  assert.match(composer, /COPY\.relaysSee/);
});

test('both owners are told to add each other', () => {
  assert.match(COPY.mutual, /add theirs, and ask them to add yours/);
  assert.equal(actions.match(/COPY\.mutual/g)?.length, 2);
});

test('nothing the face shows, and nothing the operator guide says, claims the seven words recover the Nostr key', () => {
  const sources = readdirSync(face).filter(name => /\.(ts|html|json)$/.test(name)).map(name => readFileSync(join(face, name), 'utf8'));
  for (const text of sources) assert.doesNotMatch(text, /seven|7[- ]word|phrase/i);
  const guide = readFileSync(join(root, 'deploy/MESSAGING.md'), 'utf8');
  assert.match(guide, /the seven-word phrase does not derive, back up or restore\s+it\./);
  // Every sentence of the guide that mentions the phrase must negate each recovery verb it uses, verb by verb: remove the
  // one negated list ("does not derive, back up or restore it") and no recovery verb may remain.
  const verbs = /deriv|back(?:s|ed|ing)?[\s-]*up|backup|restor|recover|regenerat|rebuild|retriev/i;
  for (const sentence of guide.split(/(?<=\.)\s/)) {
    if (!/seven|phrase|words/i.test(sentence) || !verbs.test(sentence)) continue;
    const rest = sentence.replace(/\bdoes not (?:(?:derive|back up|restore|recover)(?:,\s*|\s+or\s+|\s+and\s+)?)+(?:it\b)?/i, '');
    assert.doesNotMatch(rest, verbs, sentence);
  }
  // The check itself catches a claim hidden behind an unrelated negation.
  const claim = 'The seven-word phrase does not derive a password, and you can restore the key from it.';
  assert.match(claim.replace(/\bdoes not (?:(?:derive|back up|restore|recover)(?:,\s*|\s+or\s+|\s+and\s+)?)+(?:it\b)?/i, ''), verbs);
});

test('contact revocation failures explain why submission stopped', () => {
  assert.equal(sendOutcome({ state: 'failed', code: 'messaging:contact-removed' }),
    'Sending stopped because this contact was removed.');
  assert.equal(sendOutcome({ state: 'failed', code: 'messaging:contact-changed' }),
    'Sending stopped because this contact approval changed.');
  assert.equal(sendOutcome({ state: 'failed', code: 'messaging:transport-rejected' }), COPY.states.failed);
  assert.equal(sendOutcome({ state: 'published', code: null }), COPY.states.published);
  assert.equal(sendOutcome({ state: null, code: null }), null);
  assert.match(readFileSync(join(face, 'view.ts'), 'utf8'), /sendOutcome\(message\)/);
});
