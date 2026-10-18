// SPDX-License-Identifier: AGPL-3.0-or-later
// Run: node --test tests/owner/card-state.mjs
import assert from 'node:assert/strict';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const built = mkdtempSync(join(tmpdir(), 'owner-card-state-'));
after(() => rmSync(built, { recursive: true, force: true }));
for (const name of ['ui/owner/cards/state', 'app/core/session-state', 'app/core/service-state']) {
  const output = join(built, `${name}.js`);
  mkdirSync(dirname(output), { recursive: true });
  writeFileSync(output, stripTypeScriptTypes(readFileSync(join(root, `${name}.ts`), 'utf8')));
}
const { closedState, retryTarget } = await import(pathToFileURL(join(built, 'ui/owner/cards/state.js')).href);
const { SESSION_REFUSALS, isEngineRefusal, signoutFailure } = await import(pathToFileURL(join(built, 'app/core/session-state.js')).href);
const { serviceState } = await import(pathToFileURL(join(built, 'app/core/service-state.js')).href);

test('only supervisor engine and release cards offer asking again after decline', () => {
  for (const target of ['engine/plugin-set.json', 'engine/model-budget.json', 'release']) assert.equal(retryTarget(target), true);
  for (const target of ['door/ask.json', 'build/request.json', 'sites/example', 'messaging/contacts.json']) assert.equal(retryTarget(target), false);
});

test('only a retriable terminal confirmed by the node offers Ask again', () => {
  assert.deepEqual(closedState(new Error('gate:declined-retryable')), { message: 'You declined this request.', again: true });
  assert.deepEqual(closedState(new Error('gate:expired-retryable')), { message: 'This request ran out of time.', again: true });
  const settled = closedState(new Error('gate:not-pending'));
  assert.equal(settled.again, false);
  assert.doesNotMatch(settled.message, /declined|ran out/);
  assert.equal(closedState(new Error('gate:stale-base')), null);
});

test('a sign-out cleanup failure says that the session is already ended', () => {
  assert.match(signoutFailure(false), /^Signed out\./);
  assert.doesNotMatch(signoutFailure(false), /Try again/);
  assert.equal(signoutFailure(true), 'Sign out did not finish. Try again.');
});

test('all shared session refusals show Sign in again in faces', () => {
  for (const code of SESSION_REFUSALS) assert.equal(serviceState(new Error(code)).kind, 'session-ended', code);
  assert.equal(serviceState(new Error('gate:refused')).kind, 'failure');
});

test('engine refusal codes with digits use the same validated connection notice', () => {
  assert.equal(isEngineRefusal('supervisor:authority-plugin-v2-missing'), true);
  assert.equal(isEngineRefusal('supervisor:profile-plugin-disabled'), true);
  for (const value of [null, {}, 'supervisor:running', 'supervisor:authority-missing\n']) assert.equal(isEngineRefusal(value), false);
});
