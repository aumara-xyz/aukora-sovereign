/* Against dev/fake-server.mjs (HTTP, or handlers when bind is denied): the v1.1
   routes with the same validation rules and error codes as OWNER-API.md —
   sign-in gating, grant refusal, the key lifecycle, release, permission. */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bootStage } from '../route-state.js';
import { startFakeServer } from './fake-server-fixture.mjs';

const PHRASE = ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'];
const MODEL = 'openai/gpt-5';

let server;
let cookie = null; // the bound session

const get = (path, withCookie = true) =>
  server.request(path, { headers: withCookie && cookie ? { cookie } : {} });
const post = (path, body, withCookie = true) => server.request(path, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...(withCookie && cookie ? { cookie } : {}) },
  body: JSON.stringify(body),
});

async function approve(id) {
  const ch = await post('/api/approvals/challenge', { id });
  assert.equal(ch.status, 200);
  const res = await post('/api/approvals/decide', { id, approve: true, assertion: { kind: 'dev-bypass' } });
  assert.equal(res.status, 200);
  return res.json();
}

test.before(async () => {
  server = await startFakeServer();
});
test.after(() => server?.close());

// Order matters: these tests share one node, driven through its lifecycle.

test('unclaimed node: no session, no sign-in', async () => {
  const state = await (await get('/api/state')).json();
  assert.equal(state.state, 'unclaimed');
  assert.equal(state.session, false);
  assert.equal(bootStage(state), 'claim');
  const res = await post('/api/signin/start', {}, false);
  assert.equal(res.status, 409);
  assert.equal((await res.json()).error, 'aumlok:not-enrolled');
});

test('bootstrap to bound; state then reports the session honestly', async () => {
  const claim = await post('/api/claim', { token: 'dev-claim-token' }, false);
  assert.equal(claim.status, 200);
  cookie = claim.headers.get('set-cookie').split(';')[0];
  await post('/api/enrol/start', {});
  await post('/api/enrol/finish', { enrolment_id: 'dev', attestation: { kind: 'dev-bypass' } });
  const prep = await (await post('/api/binding/prepare', {})).json();
  const bind = await post('/api/binding/confirm', { ceremony_id: prep.ceremony_id, words: PHRASE });
  assert.equal((await bind.json()).state, 'bound');

  const signed = await (await server.request('/api/state', { headers: { cookie } })).json();
  assert.equal(signed.state, 'bound');
  assert.equal(signed.session, true);
  assert.equal(bootStage(signed), 'owner');

  // the same node, this browser without a session: sign-in, not claim
  const anon = await (await get('/api/state', false)).json();
  assert.equal(anon.state, 'bound');
  assert.equal(anon.session, false);
  assert.equal(anon.subject, null);
  assert.equal(bootStage(anon), 'signin');
});

test('sign-in on a bound node issues a fresh session', async () => {
  const start = await post('/api/signin/start', {}, false);
  assert.equal(start.status, 200);
  const { ceremony_id, dev_bypass } = await start.json();
  assert.equal(dev_bypass, true);
  const finish = await post('/api/signin/finish', { ceremony_id, assertion: { kind: 'dev-bypass' } }, false);
  assert.equal(finish.status, 200);
  assert.equal((await finish.json()).state, 'bound');
  const fresh = finish.headers.get('set-cookie').split(';')[0];
  const approvals = await server.request('/api/approvals', { headers: { cookie: fresh } });
  assert.equal(approvals.status, 200);
});

test('a second sign-in start without finish is ceremony-unknown at finish', async () => {
  const res = await post('/api/signin/finish', { ceremony_id: 'deadbeef', assertion: {} }, false);
  assert.equal(res.status, 403);
  assert.equal((await res.json()).error, 'aumlok:ceremony-unknown');
});

test('release: stopped, supervisor proposal pending, apply starts the agent', async () => {
  const rel = await (await get('/api/release')).json();
  assert.equal(rel.agent, 'stopped');
  assert.equal(rel.approved_digest, null);

  const { pending } = await (await get('/api/approvals')).json();
  const release = pending.find(p => p.card.says === 'Start the agent runtime');
  assert.ok(release, 'a release proposal waits at boot when bound');
  assert.equal(release.card.risk, 'critical');

  const decided = await approve(release.id);
  assert.equal(decided.state, 'applied');
  const after = await (await get('/api/release')).json();
  assert.equal(after.approved_digest, after.current_digest);
  assert.ok(after.agent === 'starting' || after.agent === 'running');
});

test('grant: zero/negative/over-24h refused by the server', async () => {
  const base = { model: MODEL, cap_microusd: 5_000_000, per_request_cap_microusd: 100_000, max_requests: 10, hours: 4 };
  const cases = [
    { cap_microusd: 0 }, { cap_microusd: -5 }, { per_request_cap_microusd: 0 },
    { max_requests: 0 }, { max_requests: -1 }, { hours: 0 }, { hours: 25 }, { hours: -2 },
    { hours: 1.5 }, { model: 'not/allowed' },
  ];
  for (const patch of cases) {
    const res = await post('/api/broker/grant/propose', { ...base, ...patch });
    assert.equal(res.status, 422, JSON.stringify(patch));
    assert.equal((await res.json()).error, 'broker:invalid-grant');
  }
});

test('grant: a valid proposal becomes a card stating dollars and expiry', async () => {
  const res = await post('/api/broker/grant/propose',
    { model: MODEL, cap_microusd: 5_000_000, per_request_cap_microusd: 100_000, max_requests: 10, hours: 4 });
  assert.equal(res.status, 200);
  const { id } = await res.json();
  const { pending } = await (await get('/api/approvals')).json();
  const card = pending.find(p => p.id === id).card;
  assert.equal(card.says, 'Allow model spend');
  const facts = Object.fromEntries(card.facts);
  assert.equal(facts.cap, '$5.00');
  assert.equal(facts['per request'], '$0.10');
  assert.equal(facts['max requests'], '10');
  assert.ok(facts.expires);

  assert.equal((await approve(id)).state, 'applied');
  const broker = await (await get('/api/broker')).json();
  assert.equal(broker.grant.model, MODEL);
  assert.equal(broker.grant.spent_microusd, 0);
  assert.equal(broker.grant.remaining_microusd, 5_000_000);
});

test('key lifecycle: propose, gate on approval, deliver once', async () => {
  const KEY = 'sk-or-v1-server-side-check ✓';
  const digest = createHash('sha256').update(KEY, 'utf8').digest('hex');

  const propose = await post('/api/broker/key/propose', { key_sha256: digest });
  assert.equal(propose.status, 200);
  const { id } = await propose.json();

  // before approval the key cannot be delivered
  const early = await post('/api/broker/key', { id, key: KEY });
  assert.equal(early.status, 409);
  assert.equal((await early.json()).error, 'broker:key-not-approved');

  const { pending } = await (await get('/api/approvals')).json();
  const card = pending.find(p => p.id === id).card;
  assert.equal(card.says, 'Use this model provider key');
  assert.deepEqual(card.facts, [['Key fingerprint', digest.slice(0, 8)]]);
  assert.ok(!JSON.stringify(card).includes(KEY), 'the key never appears in a card');

  assert.equal((await approve(id)).state, 'applied');

  const wrong = await post('/api/broker/key', { id, key: 'not the key' });
  assert.equal(wrong.status, 422);
  assert.equal((await wrong.json()).error, 'broker:key-mismatch');

  const delivered = await post('/api/broker/key', { id, key: KEY });
  assert.equal(delivered.status, 200);
  assert.deepEqual(await delivered.json(), { ok: true, sha256_prefix: digest.slice(0, 8) });

  const again = await post('/api/broker/key', { id, key: KEY });
  assert.equal(again.status, 409);
  assert.equal((await again.json()).error, 'broker:key-redeemed');

  const broker = await (await get('/api/broker')).json();
  assert.equal(broker.key.present, true);
  assert.equal(broker.key.sha256_prefix, digest.slice(0, 8));
});

test('key propose refuses a non-digest', async () => {
  const res = await post('/api/broker/key/propose', { key_sha256: 'not-hex' });
  assert.equal(res.status, 422);
  assert.equal((await res.json()).error, 'broker:invalid-key');
});

test('memory permission proposes a card, then applies', async () => {
  const res = await post('/api/memory/permission/propose', {});
  assert.equal(res.status, 200);
  const { id } = await res.json();
  const { pending } = await (await get('/api/approvals')).json();
  const card = pending.find(p => p.id === id).card;
  assert.equal(card.says, 'Let memory recall enter the hosted model’s context');
  assert.equal((await approve(id)).state, 'applied');
});

test('v1.1 routes still refuse the unauthenticated', async () => {
  for (const [method, path, body] of [
    ['GET', '/api/broker'], ['GET', '/api/release'],
    ['POST', '/api/broker/key/propose', { key_sha256: 'ab'.repeat(32) }],
    ['POST', '/api/broker/key', {}],
    ['POST', '/api/broker/grant/propose', {}],
    ['POST', '/api/memory/permission/propose', {}],
  ]) {
    const res = await (method === 'GET' ? get(path, false) : post(path, body, false));
    assert.equal(res.status, 401, path);
    assert.equal((await res.json()).error, 'frontdoor:session-required');
  }
});
