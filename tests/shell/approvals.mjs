// SPDX-License-Identifier: AGPL-3.0-or-later
// The real shell poller and wire codec, with a same-origin fetch response and browser globals supplied by the test.
// Run with: node --test tests/shell/approvals.mjs
import assert from 'node:assert/strict';
import { after, test } from 'node:test';
import { stripTypeScriptTypes } from 'node:module';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '../..');
const built = mkdtempSync(join(tmpdir(), 'shell-approvals-'));
for (const name of ['core/data', 'core/session-state', 'shell/approvals']) {
  mkdirSync(dirname(join(built, name)), { recursive: true });
  writeFileSync(join(built, `${name}.js`), stripTypeScriptTypes(readFileSync(join(root, `app/${name}.ts`), 'utf8')));
}
const { ApprovalWatch } = await import(pathToFileURL(join(built, 'shell/approvals.js')).href);
const { encodeData } = await import(pathToFileURL(join(built, 'core/data.js')).href);
after(() => rmSync(built, { recursive: true, force: true }));

const proposal = '0123456789abcdef0123456789abcdef';
const declined = 'fedcba9876543210fedcba9876543210';
const snapshot = { sequence: 7, proposals: [{ proposal, expires_at_ms: 123 }], declined: [declined] };

async function poll(body) {
  const events = [];
  const previousFetch = globalThis.fetch;
  const previousWindow = globalThis.window;
  const frame = {};
  globalThis.window = { top: frame, self: frame };
  globalThis.fetch = async (path, init) => {
    assert.equal(path, '/api/approvals');
    assert.equal(init.credentials, 'same-origin');
    return new Response(encodeData(body), { headers: { 'content-type': 'application/json' } });
  };
  const watch = new ApprovalWatch({
    signal: new AbortController().signal,
    ownerBusy: () => false,
    openOwner: async route => { events.push(['open', route]); },
    pending: count => events.push(['pending', count]),
    declined: ids => events.push(['declined', ids]),
    session: bound => events.push(['session', bound]),
    refusal: error => events.push(['refusal', error.message]),
  });
  try {
    watch.refresh();
    await new Promise(resolve => setImmediate(resolve));
    return events;
  } finally {
    watch.dispose();
    globalThis.fetch = previousFetch;
    if (previousWindow === undefined) delete globalThis.window;
    else globalThis.window = previousWindow;
  }
}

const approvedEvents = [['pending', 1], ['declined', [declined]], ['open', `/approval/${proposal}`]];

test('an authority refusal is visible while the same response still opens an approval card', async () => {
  for (const code of ['supervisor:authority-plugin-missing', 'supervisor:authority-plugin-v2-missing', 'supervisor:profile-plugin-disabled']) {
    assert.deepEqual(await poll({ ...snapshot, engine_refusal: code }), [
      ['session', true], ['refusal', code], ...approvedEvents,
    ]);
  }
});

test('responses without an engine refusal keep the approval flow', async () => {
  for (const body of [snapshot, { ...snapshot, engine_refusal: null }]) {
    assert.deepEqual(await poll(body), [['session', true], ...approvedEvents]);
  }
});

test('a malformed engine refusal fails the response before it opens an approval card', async () => {
  for (const value of [false, {}, 'supervisor:running', 'supervisor:authority-plugin-missing\n']) {
    assert.deepEqual(await poll({ ...snapshot, engine_refusal: value }), [['refusal', 'shell:approval-response-invalid']]);
  }
});

test('a response missing the declined list is refused before opening a card', async () => {
  const { declined: _declined, ...body } = snapshot;
  assert.deepEqual(await poll(body), [['refusal', 'app:invalid-message']]);
});
