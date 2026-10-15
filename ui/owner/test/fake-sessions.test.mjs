// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';

const PHRASE = ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'];
const proof = ch => ({ kind: 'dev-bypass', challenge: ch.public_key.challenge });

async function fixture(name, stage = 'bound') {
  const { fakeRequest } = await import(`../dev/fake-server.mjs?session_test=${name}`);
  let owner;
  const post = (path, body, cookie = owner) => fakeRequest(path, { method: 'POST',
    headers: { ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const session = async cookie => (await (await fakeRequest('/api/state', { headers: { cookie } })).json()).session;
  const claim = await post('/api/claim', { token: 'dev-claim-token' });
  owner = claim.headers.get('set-cookie').split(';')[0];
  if (stage !== 'claim-open') await post('/api/enrol/finish', {});
  if (stage === 'bound') {
    const draw = await (await post('/api/binding/prepare', {})).json();
    await post('/api/binding/confirm', { ceremony_id: draw.ceremony_id, words: PHRASE });
  }
  const signin = async () => {
    const ch = await (await post('/api/signin/start', {}, null)).json();
    const response = await post('/api/signin/finish', { ceremony_id: ch.ceremony_id, assertion: { kind: 'dev-bypass' } }, null);
    return response.headers.get('set-cookie').split(';')[0];
  };
  const refresh = async cookie => {
    const ch = await (await post('/api/binding/refresh', {}, cookie)).json();
    return (await post('/api/binding/refresh/prepare', { ceremony_id: ch.ceremony_id,
      current_phrase: PHRASE.join(' '), assertion: proof(ch) }, cookie)).json();
  };
  return { post, session, signin, refresh, owner };
}

test('antibody_fake_logout_works_in_each_session_state_and_only_revokes_presenter', async () => {
  for (const stage of ['claim-open', 'enrolled', 'bound']) {
    const node = await fixture(`logout-${stage}`, stage);
    const second = stage !== 'claim-open' ? await node.signin() : null;
    const response = await node.post('/api/logout', {});
    assert.equal(response.status, 200);
    assert.match(response.headers.get('set-cookie'), /Max-Age=0/);
    assert.equal(await node.session(node.owner), false);
    if (second) assert.equal(await node.session(second), true);
  }
});

test('antibody_fake_logout_cancels_presenting_sessions_live_refresh', async () => {
  const node = await fixture('logout-refresh');
  await node.refresh(node.owner);
  await node.post('/api/logout', {});
  const fresh = await node.signin();
  const start = await node.post('/api/binding/refresh', {}, fresh);
  assert.equal(start.status, 200);
  assert.ok((await start.json()).public_key);
});

test('antibody_fake_logout_everywhere_requires_own_unspent_passkey_and_cancels_all_sessions', async () => {
  const node = await fixture('everywhere');
  const second = await node.signin();
  await node.refresh(second);
  const ch = await (await node.post('/api/logout/everywhere', {})).json();
  const foreign = await node.post('/api/logout/everywhere/confirm', { ceremony_id: ch.ceremony_id, assertion: proof(ch) }, second);
  assert.equal(foreign.status, 403);
  assert.equal(await node.session(node.owner), true);
  assert.equal(await node.session(second), true);
  const noProof = await node.post('/api/logout/everywhere/confirm', { ceremony_id: ch.ceremony_id });
  assert.equal(noProof.status, 422);
  assert.equal(await node.session(node.owner), true);
  assert.equal(await node.session(second), true);
  const replay = await node.post('/api/logout/everywhere/confirm', { ceremony_id: ch.ceremony_id, assertion: proof(ch) });
  assert.equal((await replay.json()).error, 'aumlok:ceremony-spent');
  const valid = await (await node.post('/api/logout/everywhere', {})).json();
  const finished = await node.post('/api/logout/everywhere/confirm', { ceremony_id: valid.ceremony_id, assertion: proof(valid) });
  assert.equal(finished.status, 200);
  assert.match(finished.headers.get('set-cookie'), /Max-Age=0/);
  assert.equal(await node.session(node.owner), false);
  assert.equal(await node.session(second), false);
  const fresh = await node.signin();
  const next = await node.post('/api/binding/refresh', {}, fresh);
  assert.equal(next.status, 200);
  assert.ok((await next.json()).public_key);
});

test('antibody_fake_foreign_live_refresh_returns_expiry_before_challenge_or_assertion_spend', async () => {
  const node = await fixture('foreign-live');
  const second = await node.signin();
  const earlier = await (await node.post('/api/binding/refresh', {})).json();
  const draw = await node.refresh(second);
  const refusedStart = await node.post('/api/binding/refresh', {});
  assert.equal(refusedStart.status, 409);
  assert.deepEqual(await refusedStart.json(), { error: 'aumlok:refresh-live', expires_at: draw.expires_at });
  const refusedPrepare = await node.post('/api/binding/refresh/prepare', { ceremony_id: earlier.ceremony_id,
    current_phrase: PHRASE.join(' '), assertion: proof(earlier) });
  assert.equal(refusedPrepare.status, 409);
  await node.post('/api/binding/refresh/cancel', { ceremony_id: draw.ceremony_id }, second);
  const stillUnspent = await node.post('/api/binding/refresh/prepare', { ceremony_id: earlier.ceremony_id,
    current_phrase: PHRASE.join(' '), assertion: proof(earlier) });
  assert.equal(stillUnspent.status, 200);
  assert.ok((await stillUnspent.json()).words);
});

test('antibody_fake_committed_refresh_cancel_reports_success_without_words', async () => {
  const node = await fixture('committed-cancel');
  const draw = await node.refresh(node.owner);
  const commit = await node.post('/api/binding/refresh/confirm', { ceremony_id: draw.ceremony_id,
    current_phrase: PHRASE.join(' '), words: draw.words });
  const expected = await commit.json();
  const cancel = await node.post('/api/binding/refresh/cancel', { ceremony_id: draw.ceremony_id });
  assert.equal(cancel.status, 200);
  assert.deepEqual(await cancel.json(), expected);
  assert.equal(Object.hasOwn(expected, 'words'), false);
});

test('antibody_fake_refresh_reuses_live_approval_but_supersedes_near_expiry_with_full_draw_window', async () => {
  const node = await fixture('approval-bound');
  const ch = await (await node.post('/api/binding/refresh', {})).json();
  for (let i = 0; i < 20; i++) assert.deepEqual(await (await node.post('/api/binding/refresh', {})).json(), ch);
  const now = Date.now;
  try {
    Date.now = () => ch.auth.expires_at - 59000;
    const newCh = await (await node.post('/api/binding/refresh', {})).json();
    assert.notEqual(newCh.ceremony_id, ch.ceremony_id);
    assert.ok(newCh.auth.expires_at - Date.now() >= 60000);
    const superseded = await node.post('/api/binding/refresh/prepare', { ceremony_id: ch.ceremony_id,
      current_phrase: PHRASE.join(' '), assertion: proof(ch) });
    assert.equal((await superseded.json()).error, 'aumlok:ceremony-unknown');
    const draw = await (await node.post('/api/binding/refresh/prepare', { ceremony_id: newCh.ceremony_id,
      current_phrase: PHRASE.join(' '), assertion: proof(newCh) })).json();
    assert.equal(draw.expires_at - Date.now(), 300000);
  } finally { Date.now = now; }
});
