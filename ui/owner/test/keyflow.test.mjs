/* Key flow (OWNER-API §8): the key leaves the page exactly once, in the body
   of POST /api/broker/key; sha256 is computed over the exact key bytes; the
   held copy is cleared after delivery and on any non-applied outcome.
   fetch is intercepted and every request is inspected. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createKeyFlow } from '../keyflow.js';
import { api } from '../api.js';

const KEY = 'sk-or-v1-exact bytes ✓ — keep the trailing space ';
const KEY_SHA256 = createHash('sha256').update(KEY, 'utf8').digest('hex');

const jsonResponse = (status, body) =>
  new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

function intercept(t) {
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), body: init?.body ?? null });
    if (url === '/api/broker/key/propose') return jsonResponse(200, { id: 'prop-1' });
    if (url === '/api/broker/key') return jsonResponse(200, { ok: true, sha256_prefix: KEY_SHA256.slice(0, 8) });
    return jsonResponse(404, { error: 'frontdoor:unknown-route' });
  };
  t.after(() => { globalThis.fetch = realFetch; });
  return calls;
}

const flow = () => createKeyFlow({
  propose: key_sha256 => api.brokerKeyPropose(key_sha256),
  deliver: (id, key) => api.brokerKeyDeliver(id, key),
  sha256: bytes => globalThis.crypto.subtle.digest('SHA-256', bytes),
});

test('sha256 is computed over the exact key bytes', async t => {
  const calls = intercept(t);
  const f = flow();
  await f.proposeKey(KEY);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, '/api/broker/key/propose');
  assert.deepEqual(JSON.parse(calls[0].body), { key_sha256: KEY_SHA256 });
});

test('the key leaves only in the one POST to /api/broker/key, then is cleared', async t => {
  const calls = intercept(t);
  const f = flow();
  const id = await f.proposeKey(KEY);
  assert.equal(f.pendingId(), id);
  const res = await f.deliverIfApproved(id, 'applied');
  assert.deepEqual(res, { ok: true, sha256_prefix: KEY_SHA256.slice(0, 8) });

  const carrying = calls.filter(c => c.body?.includes(KEY) || c.url.includes(KEY));
  assert.equal(carrying.length, 1, 'exactly one request carries the key');
  assert.equal(carrying[0].url, '/api/broker/key');
  assert.deepEqual(JSON.parse(carrying[0].body), { id, key: KEY });
  // the proposal itself carried only the hash
  assert.ok(!calls[0].body.includes(KEY));
  assert.equal(f.pendingId(), null, 'held key cleared right after delivery');
});

test('a non-applied outcome delivers nothing and clears the key', async t => {
  const calls = intercept(t);
  const f = flow();
  const id = await f.proposeKey(KEY);
  const res = await f.deliverIfApproved(id, 'refused');
  assert.equal(res, null);
  assert.equal(calls.length, 1, 'no delivery POST');
  assert.equal(f.pendingId(), null);
});

test('an unknown proposal id neither delivers nor drops the held key', async t => {
  const calls = intercept(t);
  const f = flow();
  const id = await f.proposeKey(KEY);
  assert.equal(await f.deliverIfApproved('someone-else', 'applied'), null);
  assert.equal(calls.length, 1);
  assert.equal(f.pendingId(), id);
  f.discard(id);
  assert.equal(f.pendingId(), null);
});
