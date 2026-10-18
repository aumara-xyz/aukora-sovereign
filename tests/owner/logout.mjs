// SPDX-License-Identifier: AGPL-3.0-or-later
// Run: node --test tests/owner/logout.mjs
import assert from 'node:assert/strict';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const dir = mkdtempSync(path.join(tmpdir(), 'owner-logout-'));
after(() => rmSync(dir, { recursive: true, force: true }));
for (const module of ['ui/owner/session', 'ui/owner/transport', 'ui/owner/abort',
  'ui/owner/passkey/codec', 'ui/owner/cards/codec', 'app/shell/approvals', 'app/core/data']) {
  const output = path.join(dir, `${module}.js`);
  mkdirSync(path.dirname(output), { recursive: true });
  writeFileSync(output, stripTypeScriptTypes(readFileSync(path.join(root, `${module}.ts`), 'utf8')));
}
const { endOwnerSession } = await import(pathToFileURL(path.join(dir, 'ui/owner/session.js')).href);
const { ApprovalWatch } = await import(pathToFileURL(path.join(dir, 'app/shell/approvals.js')).href);
const { encodeData } = await import(pathToFileURL(path.join(dir, 'app/core/data.js')).href);
const json = (value, status = 200) => new Response(encodeData(value), {
  status, headers: { 'Content-Type': 'application/json; charset=utf-8' },
});

function context() {
  const controller = new AbortController();
  let completed = 0;
  return {
    controller,
    pane: { host: { textContent: '' }, route: { pane: 'signout' },
      signal: controller.signal, shellOrigin: 'https://shell.example', complete() { completed++; } },
    get completed() { return completed; },
  };
}

test('owner logout posts on its own host, completes, and cleans request scope', async t => {
  const owner = context();
  const added = t.mock.method(owner.pane.signal, 'addEventListener');
  const removed = t.mock.method(owner.pane.signal, 'removeEventListener');
  let requestSignal;
  t.mock.method(globalThis, 'fetch', async (route, options) => {
    assert.equal(route, '/api/session/end');
    assert.equal(options.method, 'POST');
    assert.equal(options.credentials, 'same-origin');
    assert.equal(options.mode, 'same-origin');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.body, '{}');
    requestSignal = options.signal;
    return json({ ended: true });
  });
  const dispose = await endOwnerSession(owner.pane);
  assert.equal(owner.pane.host.textContent, 'Signing out…');
  assert.equal(owner.completed, 1);
  assert.equal(requestSignal.aborted, true);
  assert.equal(added.mock.callCount(), 1);
  assert.equal(removed.mock.callCount(), 1);
  assert.equal(added.mock.calls[0].arguments[1], removed.mock.calls[0].arguments[1]);
  dispose();
  owner.controller.abort();
  assert.equal(owner.completed, 1);
});

for (const [reply, code] of [
  [{ ended: false }, 'owner:session-end-refused'],
  [{ ended: true, extra: true }, 'owner:response-invalid'],
]) {
  test(`owner logout refuses invalid confirmation (${code})`, async t => {
    const owner = context();
    t.mock.method(globalThis, 'fetch', async () => json(reply));
    await assert.rejects(endOwnerSession(owner.pane), { message: code });
    assert.equal(owner.completed, 0);
  });
}

test('owner logout propagates server refusal without completing', async t => {
  const owner = context();
  t.mock.method(globalThis, 'fetch', async () => json({ error: 'frontdoor:session-revoked' }, 403));
  await assert.rejects(endOwnerSession(owner.pane), { message: 'frontdoor:session-revoked' });
  assert.equal(owner.completed, 0);
});

test('closing the owner pane aborts pending logout and removes its parent listener', async t => {
  const owner = context();
  const removed = t.mock.method(owner.pane.signal, 'removeEventListener');
  let requestSignal;
  t.mock.method(globalThis, 'fetch', (_route, options) => {
    requestSignal = options.signal;
    return new Promise((_resolve, reject) => {
      requestSignal.addEventListener('abort', () => reject(requestSignal.reason), { once: true });
    });
  });
  const ending = endOwnerSession(owner.pane);
  const reason = new DOMException('Pane closed', 'AbortError');
  owner.controller.abort(reason);
  await assert.rejects(ending, reason);
  assert.equal(requestSignal.aborted, true);
  assert.equal(owner.completed, 0);
  assert.ok(removed.mock.callCount() > 0);
});

test('a response arriving after pane closure cannot complete logout', async t => {
  const owner = context();
  t.mock.method(globalThis, 'fetch', async () => {
    owner.controller.abort(new DOMException('Pane closed', 'AbortError'));
    return json({ ended: true });
  });
  await assert.rejects(endOwnerSession(owner.pane), { name: 'AbortError' });
  assert.equal(owner.completed, 0);
});

test('approval polling notices session revocation while an owner pane stays open', async t => {
  const previous = globalThis.window;
  const window = {};
  window.top = window.self = window;
  globalThis.window = window;
  t.after(() => { if (previous === undefined) delete globalThis.window; else globalThis.window = previous; });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const controller = new AbortController();
  const sessions = [], pending = [], declined = [], opened = [], refusals = [];
  const proposal = '1'.repeat(32);
  let calls = 0;
  t.mock.method(globalThis, 'fetch', async (route, options) => {
    assert.equal(route, '/api/approvals');
    assert.equal(options.credentials, 'same-origin');
    calls++;
    return calls === 1 ? json({ sequence: 1, proposals: [{ proposal, expires_at_ms: 1000 }], declined: [proposal] })
      : json({ error: 'frontdoor:session-revoked' }, 403);
  });
  const watch = new ApprovalWatch({ signal: controller.signal, ownerBusy: () => true,
    async openOwner(route) { opened.push(route); }, pending: value => pending.push(value),
    declined: value => declined.push(value), session: value => sessions.push(value),
    refusal: error => refusals.push(error),
  });
  t.after(() => controller.abort());
  watch.refresh();
  await setImmediate();
  assert.deepEqual(sessions, [true]);
  assert.deepEqual(opened, []);
  t.mock.timers.tick(1200);
  await setImmediate();
  assert.deepEqual(sessions, [true, false]);
  assert.deepEqual(pending, [1, 0]);
  assert.deepEqual(declined, [[proposal], []]);
  assert.deepEqual(refusals, []);
  assert.deepEqual(opened, []);
  t.mock.timers.tick(1200);
  await setImmediate();
  assert.equal(calls, 2);
});

test('disposed approval polling ignores a late response and schedules no further requests', async t => {
  const previous = globalThis.window;
  const window = {};
  window.top = window.self = window;
  globalThis.window = window;
  t.after(() => { if (previous === undefined) delete globalThis.window; else globalThis.window = previous; });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const controller = new AbortController();
  let respond;
  const fetch = t.mock.method(globalThis, 'fetch', () => new Promise(resolve => { respond = resolve; }));
  const events = [];
  const watch = new ApprovalWatch({ signal: controller.signal, ownerBusy: () => true,
    async openOwner(route) { events.push(route); }, pending: value => events.push(value),
    declined: value => events.push(value), session: value => events.push(value),
    refusal: error => events.push(error),
  });
  watch.refresh();
  controller.abort();
  respond(json({ sequence: 1, proposals: [], declined: [] }));
  await setImmediate();
  t.mock.timers.tick(1200);
  await setImmediate();
  assert.deepEqual(events, []);
  assert.equal(fetch.mock.callCount(), 1);
});
