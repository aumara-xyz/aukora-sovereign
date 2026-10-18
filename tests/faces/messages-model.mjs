#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The Messages list and thread use the same loaded rows; read marks belong only to the open face.
//   node --test tests/faces/messages-model.mjs
import assert from 'node:assert/strict';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

const source = await readFile(new URL('../../app/faces/messages/model.ts', import.meta.url), 'utf8');
const compiled = await mkdtemp(join(tmpdir(), 'messages-model-'));
const modulePath = join(compiled, 'model.mjs');
await writeFile(modulePath, stripTypeScriptTypes(source));
const { conversationList, readContactChange, readMarks, threadMessages } = await import(pathToFileURL(modulePath).href);
await rm(compiled, { recursive: true, force: true });
const contact = (npub, label) => Object.freeze({ npub, label, pairing: null });
const message = (id, contact, at, direction = 'in', text = id) => Object.freeze({
  id, contact, at, direction, text, state: direction === 'in' ? null : 'published', code: null,
});

test('conversation list includes approved contacts, latest activity first, and keeps empty contacts', () => {
  const contacts = [contact('old', 'Bea'), contact('empty-z', 'Zed'), contact('recent', 'Ari'), contact('empty-a', 'Ada')];
  const rows = [message('recent', 'recent', 30), message('oldest', 'old', 10), message('old', 'old', 20)];
  const list = conversationList(contacts, rows, new Set());
  assert.deepEqual(list.map(item => item.contact.npub), ['recent', 'old', 'empty-a', 'empty-z']);
  assert.equal(list[1].latest.id, 'old');
  assert.equal(list[2].latest, null);
  assert.equal(list[2].snippet, '');
  assert.equal(list[2].unread, false);
  assert.deepEqual(conversationList(contacts, [], new Set()).map(item => item.contact.npub), ['empty-a', 'recent', 'old', 'empty-z']);
});

test('thread filters a contact and orders messages chronologically without changing its inputs', () => {
  const rows = Object.freeze([
    message('b', 'friend', 20), message('other', 'someone-else', 5),
    message('first', 'friend', 10), message('a', 'friend', 20),
  ]);
  assert.deepEqual(threadMessages(rows, 'friend').map(row => row.id), ['first', 'a', 'b']);
  assert.deepEqual(rows.map(row => row.id), ['b', 'other', 'first', 'a']);
  assert.deepEqual(threadMessages(rows, 'absent'), []);
});

test('equal-time list ordering and latest rows are deterministic across service page order', () => {
  const contacts = Object.freeze([contact('b', 'Same'), contact('a', 'Same'), contact('z', 'Same')]);
  const rows = Object.freeze([message('a', 'a', 10), message('b', 'a', 10), message('c', 'b', 10)]);
  const forward = conversationList(contacts, rows, new Set());
  assert.deepEqual(forward, conversationList([...contacts].reverse(), [...rows].reverse(), new Set()));
  assert.deepEqual(forward.map(item => item.contact.npub), ['b', 'a', 'z']);
  assert.equal(forward[1].latest.id, 'b');
  assert.deepEqual(contacts.map(item => item.npub), ['b', 'a', 'z']);
});

test('only unseen incoming rows mark a conversation unread, including delayed and equal-time arrivals', () => {
  const contacts = [contact('friend', 'Friend')];
  const incoming = message('seen', 'friend', 20);
  const outgoing = message('sent', 'friend', 30, 'out');
  const read = new Set(['seen']);
  assert.equal(conversationList(contacts, [incoming, outgoing], read)[0].unread, false);
  assert.equal(conversationList(contacts, [incoming], new Set())[0].unread, true);
  for (const at of [10, 20]) {
    const delayed = message('delayed', 'friend', at);
    assert.equal(conversationList(contacts, [incoming, outgoing, delayed], read)[0].unread, true);
    assert.equal(conversationList(contacts, [incoming, outgoing, delayed], new Set(['seen', 'delayed']))[0].unread, false);
  }
  assert.deepEqual([...read], ['seen']);
});

test('preview is one short line and keeps Unicode characters intact', () => {
  const contacts = [contact('friend', 'Friend')];
  const preview = text => conversationList(contacts, [message('id', 'friend', 1, 'in', text)], new Set())[0].snippet;
  assert.equal(preview('  Hello\n\tthere  '), 'Hello there');
  assert.equal(preview('😀'.repeat(97)), `${'😀'.repeat(95)}…`);
  assert.equal(Array.from(preview('😀'.repeat(97))).length, 96);
  assert.equal(preview('a'.repeat(96)), 'a'.repeat(96));
});

test('messages for contacts outside the approved contact list do not make new conversations', () => {
  const contacts = [contact('approved', 'Friend')];
  const list = conversationList(contacts, [message('stranger', 'unknown', 20)], new Set());
  assert.equal(list.length, 1);
  assert.equal(list[0].latest, null);
  assert.equal(list[0].unread, false);
});

test('the owner marks read back exactly, and a row with neither mark or a repeated npub is refused', () => {
  const key = digit => `npub1${digit.repeat(58)}`;
  const marks = readMarks({ items: [{ npub: key('q'), pinned: true, archived: false }, { npub: key('p'), pinned: false, archived: true }] });
  assert.deepEqual([...marks], [[key('q'), { pinned: true, archived: false }], [key('p'), { pinned: false, archived: true }]]);
  for (const bad of [
    { items: [{ npub: key('q'), pinned: false, archived: false }] },
    { items: [{ npub: key('q'), pinned: true, archived: false }, { npub: key('q'), pinned: false, archived: true }] },
    { items: [{ npub: key('q'), pinned: 1, archived: false }] },
    { items: [{ npub: key('q'), pinned: true, archived: false, label: 'x' }] },
    { items: [], next: null },
    { items: [{ npub: 'npub1nope', pinned: true, archived: false }] },
  ]) assert.throws(() => readMarks(bad), /app:invalid-reply/);
});

test('contact changes distinguish applied actions from pending owner cards and refuse ambiguous replies', () => {
  assert.deepEqual(readContactChange({ state: 'applied' }), { state: 'applied' });
  assert.deepEqual(readContactChange({ state: 'pending', proposal_id: 'card' }), { state: 'pending', proposalId: 'card' });
  for (const bad of [
    {}, { proposal_id: 'card' }, { state: 'pending' }, { state: 'pending', proposal_id: '' },
    { state: 'applied', proposal_id: 'card' }, { state: 'rejected' }, { state: 'pending', proposal_id: 'card', extra: true },
  ]) assert.throws(() => readContactChange(bad), /app:invalid-reply/);
});
