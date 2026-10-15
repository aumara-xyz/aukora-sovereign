// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const helper = new URL('./prime.mjs', import.meta.url).href;

function fixture(t) {
  const root = mkdtempSync(fileURLToPath(new URL('./.prime-environment-', import.meta.url)));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function probe(root) {
  return spawnSync(process.execPath, ['--input-type=module', '-e',
    `import { primeFile } from ${JSON.stringify(helper)}; process.stdout.write(primeFile('reference.txt'));`],
  { env: { ...process.env, AUKORA_PRIME: root }, encoding: 'utf8' });
}

test('configured Prime checkout takes precedence and accepts spaces', t => {
  const root = join(fixture(t), 'configured prime');
  mkdirSync(root);
  const file = join(root, 'reference.txt');
  writeFileSync(file, 'reference');
  const result = probe(root);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, file);
});

test('missing Prime reference fails with the variable name', t => {
  const result = probe(fixture(t));
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /AUKORA_PRIME:/);
});

test('Prime reference directories cannot pass as files', t => {
  const root = fixture(t);
  mkdirSync(join(root, 'reference.txt'));
  const result = probe(root);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /AUKORA_PRIME:/);
});

test('empty configured Prime checkout fails with the variable name', () => {
  const result = probe('');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /AUKORA_PRIME:/);
});
