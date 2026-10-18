// SPDX-License-Identifier: AGPL-3.0-or-later
// Run against a wasm test artifact: AUKORA_AUMLOK_TEST_WASM=<artifact> node --test tests/owner/write-kdf.mjs
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const artifact = process.env.AUKORA_AUMLOK_TEST_WASM;
test('seal and both backup write APIs reject weak KDFs before any browser or random import', {
  skip: artifact ? false : 'requires a wasm32 aumlok test artifact',
}, async () => {
  const module = await WebAssembly.compile(readFileSync(artifact));
  const imports = {};
  for (const entry of WebAssembly.Module.imports(module)) {
    assert.equal(entry.kind, 'function', `unexpected import ${entry.module}.${entry.name}`);
    imports[entry.module] ??= {};
    imports[entry.module][entry.name] = () => { throw new Error(`unexpected import ${entry.module}.${entry.name}`); };
  }
  const instance = await WebAssembly.instantiate(module, imports);
  const probes = Object.entries(instance.exports).filter(([name]) => /^write_kdf_floor_probe(?:_[a-f0-9]+)?$/.test(name));
  assert.equal(probes.length, 1);
  assert.equal(probes[0][1](), 1);
});
