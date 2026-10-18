// SPDX-License-Identifier: AGPL-3.0-or-later
// The real contact snapshot reader, supplied with a local fake paged service.
// Run with: node --test tests/shell/messages-paging.mjs
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const built = mkdtempSync(join(tmpdir(), 'messages-paging-'));
writeFileSync(join(built, 'paging.js'), stripTypeScriptTypes(readFileSync(join(root, 'app/faces/messages/paging.ts'), 'utf8')));
const { MAX_SNAPSHOT_PAGES, readAllPages } = await import(pathToFileURL(join(built, 'paging.js')).href);
after(() => rmSync(built, { recursive: true, force: true }));

function service(book, calls) {
  return async before => {
    calls.push(before);
    const start = before === null ? 0 : book.findIndex(contact => contact.npub === before) + 1;
    const items = book.slice(start, start + 50);
    return { items, next: start + 50 < book.length ? items.at(-1).npub : null };
  };
}
const key = contact => contact.npub;

test('refresh reads every contact page before replacing a retained book, including beyond the message display cap', async () => {
  const book = Array.from({ length: 1005 }, (_, n) => ({ npub: `contact-${n}` }));
  const firstCalls = [];
  let retained = await readAllPages(service(book, firstCalls), key);
  assert.deepEqual(retained, book);
  assert.equal(firstCalls.length, 21);
  const changed = book.filter(contact => contact.npub !== 'contact-20');
  const refreshCalls = [];
  retained = await readAllPages(service(changed, refreshCalls), key);
  assert.deepEqual(retained, changed);
  assert.equal(retained.at(-1).npub, 'contact-1004');
  assert.equal(refreshCalls[0], null);
  assert.equal(refreshCalls.length, 21);
});

test('a failed later page leaves the prior snapshot available and cursor cycles are refused', async () => {
  const retained = [{ npub: 'existing' }];
  let shown = retained;
  await assert.rejects(async () => {
    shown = await readAllPages(async before => {
      if (before !== null) throw new Error('app:service-unavailable');
      return { items: [{ npub: 'new' }], next: 'new' };
    }, key);
  }, /app:service-unavailable/);
  assert.equal(shown, retained);
  let calls = 0;
  await assert.rejects(readAllPages(async () => ({ items: [{ npub: String(calls++) }], next: 'stuck' }), key), /app:invalid-reply/);
  assert.equal(calls, 2);
});

test('an endless run of fresh cursors stops at the page bound instead of growing the book', async () => {
  let calls = 0;
  await assert.rejects(readAllPages(async () => {
    calls++;
    return { items: [{ npub: `contact-${calls}` }], next: `cursor-${calls}` };
  }, key), /app:invalid-reply/);
  assert.equal(calls, MAX_SNAPSHOT_PAGES);
});
