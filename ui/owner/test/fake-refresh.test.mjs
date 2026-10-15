// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJSON } from '../canon.js';
import { startFakeServer } from './fake-server-fixture.mjs';

const PHRASE = ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'];
let currentPhrase = PHRASE.join(' ');
let server;
let owner;
const post = (path, body, cookie = owner) => server.request(path, {
  method: 'POST', headers: { 'Content-Type': 'application/json', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body),
});
async function freshOwner() {
  const start = await (await post('/api/signin/start', {}, null)).json();
  const finish = await post('/api/signin/finish', { ceremony_id: start.ceremony_id, assertion: { kind: 'dev-bypass' } }, null);
  assert.equal(finish.status, 200);
  return finish.headers.get('set-cookie').split(';')[0];
}
async function challenge(cookie = owner) {
  const response = await post('/api/binding/refresh', {}, cookie);
  assert.equal(response.status, 200);
  return response.json();
}
const proof = ch => ({ kind: 'dev-bypass', challenge: ch.public_key.challenge });
const prepare = (ch, phrase = currentPhrase, cookie = owner) => post('/api/binding/refresh/prepare', {
  ceremony_id: ch.ceremony_id, current_phrase: phrase, assertion: proof(ch),
}, cookie);

test.before(async () => {
  server = await startFakeServer();
  const claim = await post('/api/claim', { token: 'dev-claim-token' }, null);
  owner = claim.headers.get('set-cookie').split(';')[0];
  await post('/api/enrol/finish', { enrolment_id: 'dev', attestation: { kind: 'dev-bypass' } });
  const binding = await (await post('/api/binding/prepare', {})).json();
  await post('/api/binding/confirm', { ceremony_id: binding.ceremony_id, words: PHRASE });
});
test.after(() => server?.close());

async function directFixture(name, bind = true) {
  const { fakeRequest } = await import(`../dev/fake-server.mjs?refresh_test=${name}`);
  let cookie;
  const request = (path, body) => fakeRequest(path, { method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const claim = await request('/api/claim', { token: 'dev-claim-token' });
  cookie = claim.headers.get('set-cookie').split(';')[0];
  await request('/api/enrol/finish', { enrolment_id: 'dev', attestation: { kind: 'dev-bypass' } });
  if (bind) {
    const prep = await (await request('/api/binding/prepare', {})).json();
    await request('/api/binding/confirm', { ceremony_id: prep.ceremony_id, words: PHRASE });
  }
  return request;
}

test('antibody_fake_refresh_routes_refuse_unbound_owner', async () => {
  const request = await directFixture('unbound', false);
  for (const suffix of ['', '/prepare', '/resume', '/confirm', '/cancel']) {
    const response = await request(`/api/binding/refresh${suffix}`, {});
    assert.equal(response.status, 403);
    assert.equal((await response.json()).error, 'aumlok:binding-required');
  }
});

test('antibody_fake_refresh_challenges_and_draws_expire', async () => {
  const request = await directFixture('expiry');
  const ch = await (await request('/api/binding/refresh', {})).json();
  const lateRequest = await directFixture('approval-expiry');
  const late = await (await lateRequest('/api/binding/refresh', {})).json();
  const draw = await (await request('/api/binding/refresh/prepare', { ceremony_id: ch.ceremony_id,
    current_phrase: currentPhrase, assertion: proof(ch) })).json();
  const now = Date.now;
  try {
    Date.now = () => Math.max(draw.expires_at, late.auth.expires_at) + 1;
    for (const suffix of ['/resume', '/confirm']) {
      const response = await request(`/api/binding/refresh${suffix}`, { ceremony_id: draw.ceremony_id,
        current_phrase: currentPhrase, ...(suffix === '/confirm' ? { words: draw.words } : {}) });
      assert.equal((await response.json()).error, 'aumlok:ceremony-expired');
    }
    const expiredChallenge = await lateRequest('/api/binding/refresh/prepare', { ceremony_id: late.ceremony_id,
      current_phrase: currentPhrase, assertion: proof(late) });
    assert.equal((await expiredChallenge.json()).error, 'aumlok:ceremony-expired');
  } finally { Date.now = now; }
});

test('antibody_fake_refresh_routes_require_owner_session', async () => {
  for (const suffix of ['', '/prepare', '/resume', '/confirm', '/cancel']) {
    const response = await post(`/api/binding/refresh${suffix}`, {}, null);
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error, 'frontdoor:session-required');
  }
});

test('antibody_fake_refresh_challenge_commits_card_and_c5_without_phrase', async () => {
  const ch = await challenge();
  const display = createHash('sha256').update(canonicalJSON(ch.card)).digest('hex');
  assert.equal(display, ch.display_sha256);
  assert.equal(display, ch.auth.display_sha256);
  assert.equal(ch.auth.op, 'permission');
  assert.equal(ch.auth.target, 'aumlok/binding/refresh');
  assert.equal(ch.auth.proposal, ch.ceremony_id);
  const content = { v: 1, node: ch.auth.node, target: ch.auth.target, base_sha256: ch.auth.base_sha256,
    new_sha256: ch.auth.new_sha256, cell: ch.auth.cell };
  assert.equal(createHash('sha256').update('aukora:operation-content:v1\0' + canonicalJSON(content)).digest('hex'), ch.auth.operation);
  assert.equal(createHash('sha256').update('aukora:owner-authorization:v1\0' + canonicalJSON(ch.auth)).digest('base64url'), ch.public_key.challenge);
  for (const word of PHRASE) assert.equal(JSON.stringify(ch).includes(word), false);
});

test('antibody_fake_refresh_rejects_browser_authorization_fields', async () => {
  for (const [suffix, body] of [
    ['', { auth: {} }], ['/prepare', { ceremony_id: '00'.repeat(16), current_phrase: currentPhrase, assertion: {}, auth: {} }],
    ['/resume', { ceremony_id: '00'.repeat(16), current_phrase: currentPhrase, auth: {} }],
    ['/confirm', { ceremony_id: '00'.repeat(16), current_phrase: currentPhrase, words: [], auth: {} }],
    ['/cancel', { ceremony_id: '00'.repeat(16), auth: {} }],
  ]) {
    const response = await post(`/api/binding/refresh${suffix}`, body);
    assert.equal(response.status, 400);
    assert.equal((await response.json()).error, 'frontdoor:body-invalid');
  }
});

test('antibody_fake_refresh_missing_or_replayed_assertion_is_refused', async () => {
  const missing = await challenge();
  const noProof = await post('/api/binding/refresh/prepare', { ceremony_id: missing.ceremony_id, current_phrase: currentPhrase });
  assert.equal((await noProof.json()).error, 'aumlok:assertion-refused');
  const burned = await prepare(missing);
  assert.equal((await burned.json()).error, 'aumlok:ceremony-spent');
  const other = await challenge();
  const replay = await post('/api/binding/refresh/prepare', { ceremony_id: other.ceremony_id,
    current_phrase: currentPhrase, assertion: proof(missing) });
  assert.equal((await replay.json()).error, 'aumlok:assertion-refused');
  const secondOwner = await freshOwner();
  const own = await challenge();
  const stranger = await prepare(own, currentPhrase, secondOwner);
  assert.equal((await stranger.json()).error, 'aumlok:ceremony-unknown');
});

test('antibody_fake_refresh_resume_preserves_words_and_confirm_requires_first_match', async () => {
  const ch = await challenge();
  const started = await prepare(ch);
  assert.equal(started.status, 200);
  const draw = await started.json();
  assert.notDeepEqual(draw.words, PHRASE);
  const again = await prepare(ch);
  assert.deepEqual(await again.json(), { ceremony_id: draw.ceremony_id, state: 'live', expires_at: draw.expires_at });
  const otherOwner = await freshOwner();
  const second = await post('/api/binding/refresh', {}, otherOwner);
  assert.equal((await second.json()).error, 'aumlok:refresh-live');
  const foreign = await post('/api/binding/refresh/resume', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase }, otherOwner);
  assert.equal((await foreign.json()).error, 'aumlok:ceremony-principal');
  const wrongCurrent = await post('/api/binding/refresh/resume', { ceremony_id: draw.ceremony_id, current_phrase: 'wrong current words' });
  assert.equal((await wrongCurrent.json()).error, 'aumlok:current-phrase');
  const resumed = await post('/api/binding/refresh/resume', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase });
  assert.deepEqual(await resumed.json(), draw);
  const wrong = [...draw.words]; wrong[1] = 'wrong'; wrong[4] = 'also wrong';
  const mismatch = await post('/api/binding/refresh/confirm', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase, words: wrong });
  assert.deepEqual(await mismatch.json(), { error: 'aumlok:word-mismatch', position: 2 });
  const tooMany = await post('/api/binding/refresh/confirm', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase, words: [...draw.words, 'extra'] });
  assert.equal((await tooMany.json()).error, 'aumlok:phrase-word-count');
  const finish = await post('/api/binding/refresh/confirm', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase, words: draw.words });
  assert.equal(finish.status, 200);
  assert.equal((await finish.json()).state, 'committed');
  const repeated = await post('/api/binding/refresh/confirm', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase, words: draw.words });
  assert.equal((await repeated.json()).state, 'committed');
  const oldPhrase = currentPhrase;
  currentPhrase = draw.words.join(' ');
  const oldRejected = await prepare(await challenge(otherOwner), oldPhrase, otherOwner);
  assert.equal((await oldRejected.json()).error, 'aumlok:current-phrase');
});

test('antibody_fake_refresh_lost_prepare_recovers_only_own_live_id_without_spend', async () => {
  const request = await directFixture('lost-prepare');
  const ch = await (await request('/api/binding/refresh', {})).json();
  const prepared = await request('/api/binding/refresh/prepare', { ceremony_id: ch.ceremony_id,
    current_phrase: PHRASE.join(' '), assertion: proof(ch) });
  const draw = await prepared.json();
  const start = await request('/api/binding/refresh', {});
  const live = { ceremony_id: draw.ceremony_id, state: 'live', expires_at: draw.expires_at };
  assert.deepEqual(await start.json(), live);
  const retry = await request('/api/binding/refresh/prepare', { ceremony_id: 'unknown', current_phrase: 'wrong', assertion: {} });
  assert.deepEqual(await retry.json(), live);
  const resume = await request('/api/binding/refresh/resume', { ceremony_id: draw.ceremony_id, current_phrase: PHRASE.join(' ') });
  assert.deepEqual(await resume.json(), draw);
});

test('antibody_fake_refresh_committed_confirm_and_resume_report_no_words', async () => {
  const request = await directFixture('lost-confirm');
  const ch = await (await request('/api/binding/refresh', {})).json();
  const draw = await (await request('/api/binding/refresh/prepare', { ceremony_id: ch.ceremony_id,
    current_phrase: PHRASE.join(' '), assertion: proof(ch) })).json();
  await request('/api/binding/refresh/confirm', { ceremony_id: draw.ceremony_id, current_phrase: PHRASE.join(' '), words: draw.words });
  for (const suffix of ['/confirm', '/resume', '/cancel']) {
    const result = await request(`/api/binding/refresh${suffix}`, { ceremony_id: draw.ceremony_id,
      ...(suffix !== '/cancel' ? { current_phrase: '' } : {}), ...(suffix === '/confirm' ? { words: [] } : {}) });
    assert.equal(result.status, 200);
    const committed = await result.json();
    assert.equal(committed.state, 'committed');
    assert.equal(committed.ok, true);
    assert.equal(Object.hasOwn(committed, 'words'), false);
    assert.equal(Object.hasOwn(committed, 'envelope'), false);
  }
  const next = await (await request('/api/binding/refresh', {})).json();
  assert.ok(next.public_key);
  assert.equal(Object.hasOwn(next, 'state'), false);
});

test('antibody_fake_refresh_cancel_is_own_live_ceremony_and_preserves_current_phrase', async () => {
  const ch = await challenge();
  const draw = await (await prepare(ch)).json();
  const stranger = await freshOwner();
  const foreign = await post('/api/binding/refresh/cancel', { ceremony_id: draw.ceremony_id }, stranger);
  assert.equal((await foreign.json()).error, 'aumlok:ceremony-principal');
  const stillLive = await post('/api/binding/refresh/resume', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase });
  assert.deepEqual(await stillLive.json(), draw);
  const cancelled = await post('/api/binding/refresh/cancel', { ceremony_id: draw.ceremony_id });
  assert.deepEqual(await cancelled.json(), { ok: true });
  const spent = await post('/api/binding/refresh/resume', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase });
  assert.equal((await spent.json()).error, 'aumlok:ceremony-spent');
  const repeatCancel = await post('/api/binding/refresh/cancel', { ceremony_id: draw.ceremony_id });
  assert.equal((await repeatCancel.json()).error, 'aumlok:ceremony-spent');
  const unknownCancel = await post('/api/binding/refresh/cancel', { ceremony_id: 'unknown' });
  assert.equal((await unknownCancel.json()).error, 'aumlok:ceremony-unknown');
  const next = await prepare(await challenge());
  assert.equal(next.status, 200);
  const nextDraw = await next.json();
  await post('/api/binding/refresh/cancel', { ceremony_id: nextDraw.ceremony_id });
});

test('antibody_fake_refresh_expired_ceremony_cannot_be_cancelled', async () => {
  const request = await directFixture('cancel-expiry');
  const ch = await (await request('/api/binding/refresh', {})).json();
  const draw = await (await request('/api/binding/refresh/prepare', { ceremony_id: ch.ceremony_id,
    current_phrase: PHRASE.join(' '), assertion: proof(ch) })).json();
  const now = Date.now;
  try {
    Date.now = () => draw.expires_at;
    const cancelled = await request('/api/binding/refresh/cancel', { ceremony_id: draw.ceremony_id });
    assert.equal((await cancelled.json()).error, 'aumlok:ceremony-expired');
  } finally { Date.now = now; }
});

test('antibody_fake_refresh_wrong_current_phrase_limits_only_its_session', async () => {
  const guessingOwner = await freshOwner();
  for (let i = 0; i < 5; i++) {
    const response = await prepare(await challenge(guessingOwner), 'wrong current words', guessingOwner);
    assert.equal((await response.json()).error, 'aumlok:current-phrase');
  }
  const blocked = await prepare(await challenge(guessingOwner), currentPhrase, guessingOwner);
  assert.equal(blocked.status, 429);
  assert.equal((await blocked.json()).error, 'aumlok:phrase-rate-limited');
  const cleanOwner = await freshOwner();
  const allowed = await prepare(await challenge(cleanOwner), currentPhrase, cleanOwner);
  assert.equal(allowed.status, 200);
  const draw = await allowed.json();
  const finished = await post('/api/binding/refresh/confirm', { ceremony_id: draw.ceremony_id, current_phrase: currentPhrase, words: draw.words }, cleanOwner);
  assert.equal(finished.status, 200);
  currentPhrase = draw.words.join(' ');
});
