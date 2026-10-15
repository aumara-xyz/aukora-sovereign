// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('../../../ui/owner/claim-link.js', import.meta.url), 'utf8');
let reloads = 0;
globalThis.location = {
  pathname: '/', hash: '#claim=disposable-link-fixture', search: '',
  reload() { reloads += 1; },
};
let cleaned = false;
globalThis.history = {
  replaceState(_state, _title, path) {
    assert.equal(path, '/');
    location.hash = '';
    cleaned = true;
  },
};
const listeners = {};
globalThis.window = { addEventListener(type, listener) { listeners[type] = listener; } };
const link = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
assert.equal(cleaned, true);
assert.equal(location.hash, '');
assert.equal(link.takeLinkClaim(), 'disposable-link-fixture');
assert.equal(link.takeLinkClaim(), null);
// A new claim link pasted into the same tab changes only the hash: the page reloads.
location.hash = '#/approvals';
listeners.hashchange();
assert.equal(reloads, 0);
location.hash = '#claim=second-disposable-link';
listeners.hashchange();
assert.equal(reloads, 1);
console.log('claim link: 7 assertions passed');
