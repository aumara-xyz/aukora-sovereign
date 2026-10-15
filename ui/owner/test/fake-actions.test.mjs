import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJSON } from '../canon.js';
import { startFakeServer } from './fake-server-fixture.mjs';

let server;
let cookie;
const assertion = { kind: 'dev-bypass' };
const get = path => server.request(path, { headers: { cookie } });
const post = (path, body, authed = true) => server.request(path, {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...(authed ? { cookie } : {}) },
  body: JSON.stringify(body),
});
const proposals = async () => (await (await get('/api/approvals')).json()).pending;

async function action(id, operation) {
  const ch = await post(`/api/approvals/${operation}/challenge`, { id });
  assert.equal(ch.status, 200);
  const challenge = await ch.json();
  assert.equal(challenge.auth.op, operation);
  const display = createHash('sha256').update(canonicalJSON(challenge.card)).digest('hex');
  assert.equal(display, challenge.display_sha256);
  assert.equal(display, challenge.auth.display_sha256);
  const digest = createHash('sha256').update('aukora:owner-authorization:v1\0' + canonicalJSON(challenge.auth)).digest('base64url');
  assert.equal(digest, challenge.public_key.challenge);
  const res = await post(`/api/approvals/${operation}`, { id, assertion });
  assert.equal(res.status, 200);
  return res.json();
}

test.before(async () => {
  server = await startFakeServer({ conflict: true });
  const claim = await post('/api/claim', { token: 'dev-claim-token' }, false);
  cookie = claim.headers.get('set-cookie').split(';')[0];
  await post('/api/enrol/start', {});
  await post('/api/enrol/finish', { enrolment_id: 'dev', attestation: assertion });
  const prep = await (await post('/api/binding/prepare', {})).json();
  await post('/api/binding/confirm', { ceremony_id: prep.ceremony_id,
    words: ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'] });
});
test.after(() => server?.close());

test('antibody_fake_conflict_is_listed_fenced_then_owner_reconciles', async () => {
  // gate:target-fenced blocks proposals until reconciliation, with no retry.
  const conflict = (await proposals()).find(item => item.state === 'conflict');
  assert.ok(conflict);
  assert.equal(conflict.operator_only, true);
  const fenced = await post('/api/broker/key/propose', { key_sha256: '11'.repeat(32) });
  assert.equal(fenced.status, 409);
  assert.equal((await fenced.json()).error, 'gate:target-fenced');
  const noApply = await post('/api/approvals/challenge', { id: conflict.id });
  assert.equal((await noApply.json()).error, 'gate:not-pending');
  const noRetire = await post('/api/approvals/retire/challenge', { id: conflict.id });
  assert.equal((await noRetire.json()).error, 'gate:not-retirable');
  const reconciled = await action(conflict.id, 'reconcile');
  assert.equal(reconciled.state, 'reconciled');
  assert.deepEqual(Object.keys(reconciled).sort(), ['ok', 'seq', 'state']);
  assert.equal(reconciled.ok, true);
  assert.equal((await proposals()).some(item => item.id === conflict.id), false);
  const newProposal = await post('/api/broker/key/propose', { key_sha256: '22'.repeat(32) });
  assert.equal(newProposal.status, 200);
  assert.equal((await action((await newProposal.json()).id, 'retire')).state, 'retired');
});

test('antibody_fake_reviewed_operator_can_retire_and_propose_immediately', async () => {
  // gate:owner-retirement-required keeps reviewed/operator proposals owner-controlled.
  const proposed = await post('/api/broker/key/propose', { key_sha256: '33'.repeat(32) });
  const { id } = await proposed.json();
  assert.equal(proposed.status, 200);
  const unreviewedReject = await post('/api/approvals/decide', { id, approve: false });
  assert.equal((await unreviewedReject.json()).error, 'gate:owner-retirement-required');
  assert.equal((await post('/api/approvals/challenge', { id })).status, 200);
  const listed = (await proposals()).find(item => item.id === id);
  assert.equal(listed.state, 'pending');
  assert.equal(listed.reviewed, true);
  assert.equal(listed.operator_only, true);
  const noReconcile = await post('/api/approvals/reconcile/challenge', { id });
  assert.equal((await noReconcile.json()).error, 'gate:not-reconcilable');
  const reject = await post('/api/approvals/decide', { id, approve: false });
  assert.equal((await reject.json()).error, 'gate:owner-retirement-required');
  const noChallenge = await post('/api/approvals/retire', { id, assertion });
  assert.equal((await noChallenge.json()).error, 'gate:challenge-expired');
  await post('/api/approvals/retire/challenge', { id });
  const invalid = await post('/api/approvals/retire', { id, assertion: {} });
  assert.equal((await invalid.json()).error, 'gate:proof-invalid');
  const retired = await action(id, 'retire');
  assert.equal(retired.state, 'retired');
  const repeated = await post('/api/approvals/retire', { id, assertion });
  assert.deepEqual(await repeated.json(), retired);
  const invalidRepeat = await post('/api/approvals/retire', { id, assertion: {} });
  assert.equal((await invalidRepeat.json()).error, 'gate:proof-invalid');
  const immediate = await post('/api/broker/key/propose', { key_sha256: '44'.repeat(32) });
  assert.equal(immediate.status, 200);
  await action((await immediate.json()).id, 'retire');
});

test('antibody_fake_incomplete_can_reconcile_without_claiming_apply', async () => {
  // gate:target-fenced lasts until owner reconciliation; incomplete never becomes applied.
  const incomplete = (await proposals()).find(item => item.state === 'incomplete');
  assert.ok(incomplete);
  const fenced = await post('/api/memory/permission/propose', {});
  assert.equal((await fenced.json()).error, 'gate:target-fenced');
  const result = await action(incomplete.id, 'reconcile');
  assert.equal(result.state, 'reconciled');
  assert.deepEqual(Object.keys(result).sort(), ['ok', 'seq', 'state']);
  assert.equal(result.ok, true);
  const next = await post('/api/memory/permission/propose', {});
  assert.equal(next.status, 200);
  await action((await next.json()).id, 'retire');
});

test('antibody_fake_reviewed_guest_requires_retirement', async () => {
  // gate:owner-retirement-required also applies after a guest challenge was fetched.
  const guest = (await proposals()).find(item => !item.operator_only && !item.reviewed);
  assert.ok(guest);
  await post('/api/approvals/challenge', { id: guest.id });
  const reject = await post('/api/approvals/decide', { id: guest.id, approve: false });
  assert.equal((await reject.json()).error, 'gate:owner-retirement-required');
  assert.equal((await action(guest.id, 'retire')).state, 'retired');
});

test('antibody_fake_owner_action_routes_require_owner_session', async () => {
  // frontdoor:session-required protects all four owner action routes.
  for (const operation of ['retire', 'reconcile']) {
    for (const suffix of ['', '/challenge']) {
      const res = await post(`/api/approvals/${operation}${suffix}`, { id: 'cf'.repeat(16), assertion }, false);
      assert.equal(res.status, 401);
      assert.equal((await res.json()).error, 'frontdoor:session-required');
    }
  }
});
