// SPDX-License-Identifier: AGPL-3.0-or-later
// Run: node --test tests/owner/passkey-codec.mjs
import assert from 'node:assert/strict';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const dir = mkdtempSync(path.join(tmpdir(), 'owner-passkey-'));
after(() => rmSync(dir, { recursive: true, force: true }));
for (const module of ['cards/codec', 'passkey/codec']) {
  const output = path.join(dir, `${module}.js`);
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(output, stripTypeScriptTypes(readFileSync(path.join(root, 'ui/owner', `${module}.ts`), 'utf8')));
}
const { canonical } = await import(pathToFileURL(path.join(dir, 'cards/codec.js')).href);
const { assertionBytes } = await import(pathToFileURL(path.join(dir, 'passkey/codec.js')).href);

// Deliberately use the material's declaration order, rather than C1 key order.
const assertion = {
  kind: 'passkey', credential_id: 'AQID', client_data_json: 'BAUG',
  authenticator_data: 'BwgJ', signature: 'CgsM', user_handle: null,
};

test('assertion bytes equal C1 canonical output regardless of material key order', () => {
  for (const user_handle of [null, 'DQ4P']) {
    const material = { ...assertion, user_handle };
    assert.deepEqual(assertionBytes(material), new TextEncoder().encode(canonical(material)));
  }
});

test('the existing assertion field set retains its exact wire bytes', () => {
  assert.deepEqual(assertionBytes(assertion), new TextEncoder().encode(
    '{"authenticator_data":"BwgJ","client_data_json":"BAUG","credential_id":"AQID","kind":"passkey","signature":"CgsM","user_handle":null}',
  ));
});
