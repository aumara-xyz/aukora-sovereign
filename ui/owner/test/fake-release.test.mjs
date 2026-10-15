import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJSON } from '../canon.js';
import { fakeRequest, fakeMeasureRuntime } from '../dev/fake-server.mjs';

let cookie;
const assertion = { kind: 'dev-bypass' };
const get = path => fakeRequest(path, { headers: { cookie } });
const post = (path, body) => fakeRequest(path, { method: 'POST',
  headers: { cookie }, body: JSON.stringify(body) });
const releases = async () => (await (await get('/api/approvals')).json()).pending
  .filter(item => item.card.says === 'Start the agent runtime');

async function approve(id) {
  assert.equal((await post('/api/approvals/challenge', { id })).status, 200);
  const res = await post('/api/approvals/decide', { id, approve: true, assertion });
  assert.equal(res.status, 200);
  assert.equal((await res.json()).state, 'applied');
}

test.before(async () => {
  const claim = await post('/api/claim', { token: 'dev-claim-token' });
  cookie = claim.headers.get('set-cookie').split(';')[0];
  await post('/api/enrol/start', {});
  await post('/api/enrol/finish', { enrolment_id: 'dev', attestation: assertion });
  const prep = await (await post('/api/binding/prepare', {})).json();
  await post('/api/binding/confirm', { ceremony_id: prep.ceremony_id,
    words: ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'] });
});

test('antibody_fake_unreviewed_release_is_replaced_on_each_digest_change', async () => {
  const [initial] = await releases();
  fakeMeasureRuntime('12'.repeat(32));
  const first = await releases();
  assert.equal(first.length, 1);
  assert.notEqual(first[0].id, initial.id);
  fakeMeasureRuntime('34'.repeat(32));
  const second = await releases();
  assert.equal(second.length, 1);
  assert.notEqual(second[0].id, first[0].id);
  assert.equal(second[0].superseded, false);
  assert.equal(Object.fromEntries(second[0].card.facts)['runtime digest'], '34'.repeat(32));
  for (const id of [initial.id, first[0].id]) {
    const stale = await post('/api/approvals/challenge', { id });
    assert.equal(stale.status, 404);
    assert.equal((await stale.json()).error, 'gate:unknown-proposal');
  }
  await approve(second[0].id);
  const running = await (await get('/api/release')).json();
  assert.equal(running.approved_digest, running.current_digest);
  assert.equal(running.agent, 'starting');
});

test('antibody_fake_reviewed_release_waits_for_owner_retirement', async () => {
  fakeMeasureRuntime('56'.repeat(32));
  const [reviewed] = await releases();
  const originalCard = canonicalJSON(reviewed.card);
  assert.equal((await post('/api/approvals/challenge', { id: reviewed.id })).status, 200);
  fakeMeasureRuntime('78'.repeat(32));
  const stale = await releases();
  assert.equal(stale.length, 1);
  assert.equal(stale[0].id, reviewed.id);
  assert.equal(stale[0].reviewed, true);
  assert.equal(stale[0].superseded, true);
  assert.equal(canonicalJSON(stale[0].card), originalCard);
  assert.equal(stale[0].display_sha256, reviewed.display_sha256);
  assert.equal((await (await get('/api/release')).json()).agent, 'stopped');
  const rejected = await post('/api/approvals/decide', { id: reviewed.id, approve: false });
  assert.equal((await rejected.json()).error, 'gate:owner-retirement-required');
  const noChallenge = await post('/api/approvals/retire', { id: reviewed.id, assertion });
  assert.equal((await noChallenge.json()).error, 'gate:challenge-expired');
  const challenge = await (await post('/api/approvals/retire/challenge', { id: reviewed.id })).json();
  assert.equal(challenge.auth.op, 'retire');
  assert.notEqual(challenge.display_sha256, reviewed.display_sha256);
  const retired = await post('/api/approvals/retire', { id: reviewed.id, assertion });
  assert.equal((await retired.json()).state, 'retired');
  fakeMeasureRuntime('78'.repeat(32));
  const next = await releases();
  assert.equal(next.length, 1);
  assert.notEqual(next[0].id, reviewed.id);
  assert.equal(next[0].superseded, false);
  await approve(next[0].id);
  assert.equal((await (await get('/api/release')).json()).agent, 'starting');
});

test('antibody_fake_superseded_review_approval_cannot_start_old_runtime', async () => {
  fakeMeasureRuntime('9a'.repeat(32));
  const [old] = await releases();
  assert.equal((await post('/api/approvals/challenge', { id: old.id })).status, 200);
  fakeMeasureRuntime('bc'.repeat(32));
  const applied = await post('/api/approvals/decide', { id: old.id, approve: true, assertion });
  assert.equal((await applied.json()).state, 'applied');
  const stopped = await (await get('/api/release')).json();
  assert.equal(stopped.approved_digest, '9a'.repeat(32));
  assert.equal(stopped.current_digest, 'bc'.repeat(32));
  assert.equal(stopped.agent, 'stopped');
  fakeMeasureRuntime('bc'.repeat(32));
  const next = await releases();
  assert.equal(next.length, 1);
  assert.equal(next[0].superseded, false);
});

test('antibody_fake_release_retirement_challenge_prevents_withdrawal', async () => {
  fakeMeasureRuntime('de'.repeat(32));
  const [old] = await releases();
  assert.equal(old.reviewed, false);
  const issued = await post('/api/approvals/retire/challenge', { id: old.id });
  assert.equal(issued.status, 200);
  assert.equal((await issued.json()).auth.op, 'retire');
  fakeMeasureRuntime('ef'.repeat(32));
  const retained = await releases();
  assert.equal(retained.length, 1);
  assert.equal(retained[0].id, old.id);
  assert.equal(retained[0].reviewed, true);
  assert.equal(retained[0].superseded, true);
  assert.equal(canonicalJSON(retained[0].card), canonicalJSON(old.card));
  const retired = await post('/api/approvals/retire', { id: old.id, assertion });
  assert.equal(retired.status, 200);
  assert.equal((await retired.json()).state, 'retired');
  fakeMeasureRuntime('ef'.repeat(32));
  const next = await releases();
  assert.equal(next.length, 1);
  assert.notEqual(next[0].id, old.id);
  assert.equal(next[0].superseded, false);
});
