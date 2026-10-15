import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { api } from '../api.js';
import { canonicalJSON } from '../canon.js';
import { renderCardHtml } from '../card.js';
import { showApprovals } from '../screens/approvals.js';

const ID = 'ab'.repeat(16);
const hash = value => createHash('sha256').update(canonicalJSON(value)).digest('hex');
const card = says => ({ v: 1, risk: 'critical', says,
  facts: [['target', 'broker/key']], from_to: {}, model_note: '' });
const listCard = card('Use this model provider key');
const json = body => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.dataset = {}; }
  appendChild(child) { child.remove(); this.children.push(child); child.parent = this; return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren() { this.children.forEach(child => { child.parent = null; }); this.children = []; }
  set innerHTML(html) {
    this.html = html;
    this.replaceChildren();
    if (html.startsWith('<article')) this.appendChild(new Element('article'));
  }
  get innerHTML() { return this.html; }
  get firstElementChild() { return this.children[0]; }
  setAttribute(name, value) { this[name] = value; }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this);
    this.parent = null;
  }
}

const descendants = element => [element, ...element.children.flatMap(descendants)];
const button = (app, label) => descendants(app).find(el => el.tagName === 'button' && el.textContent === label);
const error = app => descendants(app).find(el => el.className === 'instruct warn' && el.hidden === false)?.textContent;

function ceremony(operation, actionCard = card(operation === 'apply' ? listCard.says : `${operation} without retrying or applying`)) {
  const display = hash(actionCard);
  const auth = { v: 1, proposal: ID, op: operation, display_sha256: display,
    challenge: 'cd'.repeat(32), expires_at: 2000000000000 };
  const challenge = createHash('sha256').update('aukora:owner-authorization:v1\0' + canonicalJSON(auth)).digest('base64url');
  return { id: ID, auth, card: actionCard, display_sha256: display,
    public_key: { challenge, allowCredentials: [] } };
}

function setup(t, { operation = 'retire', state = 'pending', reviewed = true,
  operator_only = false, superseded = false, listedCard = listCard,
  target = 'broker/key', override_required = false, retry_available = false,
  patchChallenge, retryError, nostrPreview, floorRefusal = null, listDigest = hash(listedCard), credential = true } = {}) {
  const globals = ['document', 'location', 'window', 'navigator', 'fetch'];
  const previous = globals.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  const requests = [];
  const passkeyOptions = [];
  let passkeys = 0;
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement: tag => new Element(tag) } });
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { hostname: 'owner.example' } });
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { PublicKeyCredential: {} } });
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: {
    credentials: { get: async options => {
      passkeys++;
      passkeyOptions.push(options);
      return credential ? { rawId: new Uint8Array([1]), response: {
        clientDataJSON: new Uint8Array([2]), authenticatorData: new Uint8Array([3]),
        signature: new Uint8Array([4]), userHandle: null } } : null;
    } },
  } });
  Object.defineProperty(globalThis, 'fetch', { configurable: true, value: async (url, init) => {
    requests.push({ url, body: init.body ? JSON.parse(init.body) : undefined });
    if (url === '/api/release') return json({ agent: 'stopped', floor_refusal: floorRefusal });
    if (url === '/api/approvals') return json({ pending: [{ id: ID, card: listedCard,
      display_sha256: listDigest, state, reviewed, operator_only, superseded,
      target, override_required, retry_available }] });
    if (url.startsWith('/api/nostr/send/preview?id=')) return json(nostrPreview ?? {});
    if (url.endsWith('/challenge')) {
      const ch = url === '/api/approvals/challenge'
        ? ceremony(target === 'release' ? 'release' : 'apply', listedCard)
        : url === '/api/approvals/despite/challenge'
          ? ceremony('release', card('Approve this release despite failing antibodies'))
          : ceremony(operation);
      if (patchChallenge) patchChallenge(ch);
      return json(ch);
    }
    if (url === '/api/release/retry' && retryError) {
      return new Response(JSON.stringify({ error: retryError }), { status: 503 });
    }
    return json({ ok: true, state: operation === 'retire' ? 'retired' : 'reconciled', seq: 101 });
  } });
  t.after(() => globals.forEach((name, i) => {
    if (previous[i]) Object.defineProperty(globalThis, name, previous[i]);
    else delete globalThis[name];
  }));
  return { app: new Element('div'), requests, passkeyOptions, passkeys: () => passkeys };
}

// Bounded by time, not event-loop turns: WebCrypto digests finish off-thread and take longer on a loaded host.
async function waitFor(check) {
  const until = performance.now() + 5000;
  while (performance.now() < until) {
    if (check()) return;
    await new Promise(resolve => setTimeout(resolve, 1));
  }
  assert.fail('screen did not reach the expected action');
}

const releaseCard = { v: 1, risk: 'critical', says: 'Start the agent runtime',
  facts: [['runtime digest', 'aa'.repeat(32)]], from_to: {}, model_note: '' };

test('antibody_ui_pre_a3_release_refusal_shows_reapproval_as_text_and_keeps_status', async t => {
  const refusal = 'floor:pre-a3-release-reapprove: approve the release again <img src=x onerror=alert(1)>';
  const before = canonicalJSON(releaseCard);
  const fixture = setup(t, { target: 'release', operator_only: true, listedCard: releaseCard, floorRefusal: refusal });
  await showApprovals(fixture.app);
  const warning = descendants(fixture.app).find(el => el.className === 'instruct warn' && el.textContent === refusal);
  assert.ok(warning);
  assert.equal(warning.innerHTML, undefined);
  const status = descendants(fixture.app).find(el => el.className === 'agent-status');
  assert.equal(status.dataset.agent, 'stopped');
  assert.equal(status['aria-label'], 'agent stopped');
  assert.equal(button(fixture.app, 'approve').disabled, false);
  assert.equal(fixture.passkeys(), 0);
  assert.equal(canonicalJSON(releaseCard), before);
});

test('antibody_ui_superseded_release_labels_without_changing_signed_card', async t => {
  const before = canonicalJSON(releaseCard);
  const fixture = setup(t, { superseded: true, operator_only: true, listedCard: releaseCard });
  await showApprovals(fixture.app);
  assert.ok(descendants(fixture.app).some(el => el.textContent === 'superseded: retire it'));
  assert.ok(descendants(fixture.app).some(el => el.innerHTML === renderCardHtml(releaseCard)));
  assert.equal(canonicalJSON(releaseCard), before);
});

test('antibody_ui_superseded_release_disables_approve', async t => {
  const fixture = setup(t, { superseded: true, operator_only: true, listedCard: releaseCard });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  assert.ok(button(fixture.app, 'retire'));
});

test('antibody_ui_superseded_release_never_requests_approval', async t => {
  const fixture = setup(t, { superseded: true, operator_only: true, listedCard: releaseCard });
  await showApprovals(fixture.app);
  await button(fixture.app, 'approve').onclick();
  assert.equal(fixture.passkeys(), 0);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/challenge'), false);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/decide'), false);
});

test('antibody_ui_superseded_release_retirement_stays_owner_controlled', async t => {
  const fixture = setup(t, { superseded: true, operator_only: true, listedCard: releaseCard });
  await showApprovals(fixture.app);
  let action = button(fixture.app, 'retire').onclick();
  await waitFor(() => button(fixture.app, 'confirm retire'));
  assert.equal(fixture.passkeys(), 0);
  button(fixture.app, 'cancel').onclick();
  await action;
  assert.equal(button(fixture.app, 'approve').disabled, true);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/retire'), false);
  action = button(fixture.app, 'retire').onclick();
  await waitFor(() => button(fixture.app, 'confirm retire'));
  assert.equal(fixture.passkeys(), 0);
  button(fixture.app, 'confirm retire').onclick();
  await action;
  assert.equal(fixture.passkeys(), 1);
  assert.equal(fixture.requests.find(r => r.url === '/api/approvals/retire').body.assertion.kind, 'passkey');
});

test('antibody_ui_owner_action_requests_never_supply_authorization', async t => {
  // The server builds authorization; request bodies contain only id and assertion.
  const { requests } = setup(t);
  const assertion = { kind: 'passkey', credential_id: 'AQ' };
  await api.approvalRetireChallenge(ID);
  await api.approvalRetire(ID, assertion);
  await api.approvalReconcileChallenge(ID);
  await api.approvalReconcile(ID, assertion);
  assert.deepEqual(requests, [
    { url: '/api/approvals/retire/challenge', body: { id: ID } },
    { url: '/api/approvals/retire', body: { id: ID, assertion } },
    { url: '/api/approvals/reconcile/challenge', body: { id: ID } },
    { url: '/api/approvals/reconcile', body: { id: ID, assertion } },
  ]);
});

for (const operation of ['retire', 'reconcile']) {
  test(`antibody_ui_${operation}_requires_displayed_action_confirmation`, async t => {
    // No passkey or action POST occurs before the owner confirms the action card.
    const state = operation === 'retire' ? 'pending' : 'conflict';
    const fixture = setup(t, { operation, state });
    await showApprovals(fixture.app);
    assert.ok(button(fixture.app, operation));
    if (operation === 'reconcile') assert.equal(button(fixture.app, 'approve'), undefined);
    const action = button(fixture.app, operation).onclick();
    await waitFor(() => button(fixture.app, `confirm ${operation}`));
    assert.ok(descendants(fixture.app).some(el => el.innerHTML?.includes(`${operation} without retrying or applying`)));
    assert.equal(fixture.passkeys(), 0);
    assert.equal(fixture.requests.filter(r => r.url === `/api/approvals/${operation}`).length, 0);
    button(fixture.app, `confirm ${operation}`).onclick();
    await action;
    assert.equal(fixture.passkeys(), 1);
    const sent = fixture.requests.find(r => r.url === `/api/approvals/${operation}`);
    assert.deepEqual(Object.keys(sent.body).sort(), ['assertion', 'id']);
    assert.equal(sent.body.assertion.kind, 'passkey');
  });
}

test('antibody_ui_retire_recovers_when_the_list_card_is_stale', async t => {
  // List display mismatch blocks apply but cannot block a fresh retirement card.
  const fixture = setup(t, { listDigest: '00'.repeat(32), operator_only: true, reviewed: false });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  assert.equal(button(fixture.app, 'retire').disabled, undefined);
  const action = button(fixture.app, 'retire').onclick();
  await waitFor(() => button(fixture.app, 'confirm retire'));
  button(fixture.app, 'confirm retire').onclick();
  await action;
  assert.equal(fixture.passkeys(), 1);
});

test('antibody_ui_cancelled_guest_review_exposes_retirement', async t => {
  // After challenge fetch the gate requires retirement, even if the passkey cancels.
  const fixture = setup(t, { reviewed: false, credential: false });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'retire'), undefined);
  await button(fixture.app, 'approve').onclick();
  assert.equal(error(fixture.app), 'aumlok:approval-cancelled');
  assert.ok(button(fixture.app, 'retire'));
  assert.equal(button(fixture.app, 'retire').disabled, false);
});

for (const [name, patchChallenge, code] of [
  ['action_card_tamper', ch => { ch.card.says = 'different displayed effect'; }, 'gate:card-changed'],
  ['authorization_digest_tamper', ch => { ch.auth.challenge = 'ef'.repeat(32); }, 'gate:challenge-mismatch'],
  ['action_operation_swap', ch => {
    const apply = ceremony('apply'); Object.assign(ch, apply);
  }, 'gate:challenge-mismatch'],
  ['authorization_display_swap', ch => {
    ch.card.says = 'different effect with a matching envelope';
    ch.display_sha256 = hash(ch.card);
  }, 'gate:card-changed'],
]) {
  test(`antibody_ui_${name}_refused_before_passkey`, async t => {
    // Expected refusal is the named gate code; no passkey prompt or action POST.
    const fixture = setup(t, { patchChallenge });
    await showApprovals(fixture.app);
    const action = button(fixture.app, 'retire').onclick();
    await waitFor(() => error(fixture.app) || button(fixture.app, 'confirm retire'));
    if (button(fixture.app, 'confirm retire')) button(fixture.app, 'cancel').onclick();
    await action;
    assert.equal(error(fixture.app), code);
    assert.equal(fixture.passkeys(), 0);
    assert.equal(button(fixture.app, 'confirm retire'), undefined);
    assert.equal(fixture.requests.some(r => r.url === '/api/approvals/retire'), false);
  });
}

test('antibody_ui_owner_action_cancel_sends_no_assertion', async t => {
  // Cancelling the displayed action keeps owner controls available.
  const fixture = setup(t);
  await showApprovals(fixture.app);
  const action = button(fixture.app, 'retire').onclick();
  await waitFor(() => button(fixture.app, 'cancel'));
  button(fixture.app, 'cancel').onclick();
  await action;
  assert.equal(fixture.passkeys(), 0);
  assert.equal(button(fixture.app, 'retire').disabled, false);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/retire'), false);
});

test('antibody_ui_remote_dev_bypass_still_requires_passkey', async t => {
  // A dev_bypass response cannot replace a passkey on the owner hostname.
  const fixture = setup(t, { patchChallenge: ch => { ch.dev_bypass = true; } });
  await showApprovals(fixture.app);
  const action = button(fixture.app, 'retire').onclick();
  await waitFor(() => button(fixture.app, 'confirm retire'));
  button(fixture.app, 'confirm retire').onclick();
  await action;
  assert.equal(fixture.passkeys(), 1);
  assert.equal(fixture.requests.find(r => r.url === '/api/approvals/retire').body.assertion.kind, 'passkey');
});


test('antibody_ui_failing_release_disables_and_refuses_normal_approval', async t => {
  const fixture = setup(t, { target: 'release', listedCard: releaseCard, override_required: true });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  await button(fixture.app, 'approve').onclick();
  assert.equal(fixture.passkeys(), 0);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/challenge'), false);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/decide'), false);
});

test('antibody_ui_normal_release_checks_release_authorization_operation', async t => {
  const fixture = setup(t, { target: 'release', listedCard: releaseCard });
  await showApprovals(fixture.app);
  await button(fixture.app, 'approve').onclick();
  assert.equal(error(fixture.app), undefined);
  assert.equal(fixture.passkeys(), 1);
  assert.equal(fixture.requests.find(r => r.url === '/api/approvals/decide').body.assertion.kind, 'passkey');
});

test('antibody_ui_failed_release_requires_second_card_confirmation_and_passkey', async t => {
  const fixture = setup(t, { target: 'release', listedCard: releaseCard, override_required: true,
    patchChallenge: ch => { ch.dev_bypass = true; } });
  location.hostname = 'localhost';
  await showApprovals(fixture.app);
  const label = 'approve despite failing antibodies';
  let action = button(fixture.app, label).onclick();
  await waitFor(() => button(fixture.app, `confirm ${label}`));
  assert.ok(descendants(fixture.app).some(el => el.innerHTML?.includes('Approve this release despite failing antibodies')));
  assert.equal(fixture.passkeys(), 0);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/despite/decide'), false);
  button(fixture.app, 'cancel').onclick();
  await action;
  assert.equal(fixture.passkeys(), 0);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/despite/decide'), false);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  action = button(fixture.app, label).onclick();
  await waitFor(() => button(fixture.app, `confirm ${label}`));
  button(fixture.app, `confirm ${label}`).onclick();
  await action;
  assert.equal(fixture.passkeys(), 1);
  assert.equal(fixture.passkeyOptions[0].publicKey.userVerification, 'required');
  const sent = fixture.requests.find(r => r.url === '/api/approvals/despite/decide');
  assert.deepEqual(Object.keys(sent.body).sort(), ['assertion', 'id']);
  assert.equal(sent.body.assertion.kind, 'passkey');
});

for (const [name, patchChallenge, code] of [
  ['card_bytes', ch => { ch.card.says = 'changed override'; }, 'gate:card-changed'],
  ['authorization', ch => { ch.auth.challenge = 'ef'.repeat(32); }, 'gate:challenge-mismatch'],
  ['operation', ch => { Object.assign(ch, ceremony('apply')); }, 'gate:challenge-mismatch'],
  ['proposal', ch => { ch.id = 'ef'.repeat(16); }, 'gate:challenge-mismatch'],
  ['authorization_display', ch => { ch.display_sha256 = hash(card('changed override')); }, 'gate:card-changed'],
]) {
  test(`antibody_ui_failed_release_${name}_checked_before_confirmation`, async t => {
    const fixture = setup(t, { target: 'release', listedCard: releaseCard,
      override_required: true, patchChallenge });
    await showApprovals(fixture.app);
    const action = button(fixture.app, 'approve despite failing antibodies').onclick();
    await waitFor(() => error(fixture.app) || button(fixture.app, 'confirm approve despite failing antibodies'));
    if (button(fixture.app, 'cancel')) button(fixture.app, 'cancel').onclick();
    await action;
    assert.equal(error(fixture.app), code);
    assert.equal(fixture.passkeys(), 0);
    assert.equal(fixture.requests.some(r => r.url === '/api/approvals/despite/decide'), false);
  });
}

test('antibody_ui_refused_release_retry_schedules_without_approval_and_refreshes', async t => {
  const fixture = setup(t, { target: 'release', listedCard: releaseCard,
    state: 'refused', override_required: true, retry_available: true });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve'), undefined);
  assert.equal(button(fixture.app, 'approve despite failing antibodies'), undefined);
  await button(fixture.app, 'retry antibodies').onclick();
  assert.deepEqual(fixture.requests.find(r => r.url === '/api/release/retry').body, {});
  assert.equal(fixture.requests.filter(r => r.url === '/api/approvals').length, 2);
  assert.equal(fixture.passkeys(), 0);
  assert.equal(fixture.requests.some(r => r.url === '/api/approvals/decide'), false);
});

test('antibody_ui_failed_release_retry_error_stays_visible_and_retryable', async t => {
  const fixture = setup(t, { target: 'release', listedCard: releaseCard,
    state: 'refused', retry_available: true, retryError: 'immune:replay-unavailable' });
  await showApprovals(fixture.app);
  await button(fixture.app, 'retry antibodies').onclick();
  assert.equal(error(fixture.app), 'immune:replay-unavailable');
  assert.equal(button(fixture.app, 'retry antibodies').disabled, false);
  assert.equal(fixture.requests.filter(r => r.url === '/api/approvals').length, 1);
});

test('antibody_ui_release_override_and_retry_requests_never_supply_authorization', async t => {
  const { requests } = setup(t);
  const assertion = { kind: 'passkey', credential_id: 'AQ' };
  await api.approvalDespiteChallenge(ID);
  await api.approvalDespiteDecide(ID, assertion);
  await api.releaseRetry();
  assert.deepEqual(requests, [
    { url: '/api/approvals/despite/challenge', body: { id: ID } },
    { url: '/api/approvals/despite/decide', body: { id: ID, assertion } },
    { url: '/api/release/retry', body: {} },
  ]);
});


const sendText = '<script>private exact message</script>\n雪';
const sendBlind = 'ab'.repeat(16);
const messageDigest = (content, blind = sendBlind) => createHash('sha256').update('nostr:message:v1\0').update(Buffer.from(blind, 'hex')).update(content).digest('hex');
const sendDigest = messageDigest(sendText);
const sendCard = { v: 1, risk: 'routine', says: 'Send this private Nostr message',
  facts: [['Message sha256', sendDigest], ['Message ciphertext', 'ciphertext-only'], ['Recipient npub', 'npub-public']], from_to: {}, model_note: '' };
const goodPreview = { id: ID, content: sendText, content_sha256: sendDigest, content_blind: sendBlind };

for (const reviewed of [false, true]) test(`antibody_ui_nostr_send_preview_is_safe_and_required_for_reviewed_${reviewed}`, async t => {
  const fixture = setup(t, { operation: 'apply', target: 'plugins/nostr/send.json', listedCard: sendCard, reviewed, nostrPreview: goodPreview });
  const before = canonicalJSON(sendCard);
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, false);
  assert.equal(fixture.passkeys(), 0);
  assert.ok(descendants(fixture.app).some(element => element.tagName === 'pre' && element.textContent === sendText));
  assert.ok(!descendants(fixture.app).some(element => element.innerHTML?.includes(sendText)));
  assert.ok(descendants(fixture.app).some(element => element.innerHTML === renderCardHtml(sendCard)));
  assert.equal(canonicalJSON(sendCard), before);
  await button(fixture.app, 'approve').onclick();
  assert.equal(fixture.passkeys(), 1);
  assert.ok(fixture.requests.some(request => request.url === '/api/approvals/decide'));
});

for (const [name, preview] of [
  ['wrong-id', { ...goodPreview, id: '00'.repeat(16) }],
  ['wrong-content', { ...goodPreview, content: 'changed bytes' }],
  ['wrong-digest', { ...goodPreview, content_sha256: '00'.repeat(32) }],
  ['wrong-blind', { ...goodPreview, content_blind: 'cd'.repeat(16) }],
  ['missing-blind', { ...goodPreview, content_blind: undefined }],
  ['uppercase-blind', { ...goodPreview, content_blind: sendBlind.toUpperCase() }],
  ['short-blind', { ...goodPreview, content_blind: 'ab'.repeat(15) }],
  ['invalid-blind', { ...goodPreview, content_blind: 'gh'.repeat(16) }],
  ['oversize', { ...goodPreview, content: 'é'.repeat(513) }],
  ['unavailable', undefined],
]) test(`antibody_ui_nostr_send_preview_${name}_disables_passkey_and_send`, async t => {
  const fixture = setup(t, { operation: 'apply', target: 'plugins/nostr/send.json', listedCard: sendCard, nostrPreview: preview });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  await button(fixture.app, 'approve').onclick();
  assert.equal(fixture.passkeys(), 0);
  assert.equal(fixture.requests.some(request => request.url === '/api/approvals/challenge'), false);
  assert.equal(fixture.requests.some(request => request.url === '/api/approvals/decide'), false);
});

for (const content of ['', 'é'.repeat(513)]) test(`antibody_ui_nostr_send_preview_enforces_byte_bound_${content.length}`, async t => {
  const digest = messageDigest(content);
  const listedCard = { ...sendCard, facts: sendCard.facts.map(row => row[0] === 'Message sha256' ? [row[0], digest] : row) };
  const fixture = setup(t, { operation: 'apply', target: 'plugins/nostr/send.json', listedCard, nostrPreview: { id: ID, content, content_sha256: digest, content_blind: sendBlind } });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  await button(fixture.app, 'approve').onclick();
  assert.equal(fixture.passkeys(), 0);
});

for (const facts of [sendCard.facts.filter(row => row[0] !== 'Message sha256'), [...sendCard.facts, ['Message sha256', sendDigest]]]) test(`antibody_ui_nostr_send_preview_requires_one_card_digest_${facts.length}`, async t => {
  const fixture = setup(t, { operation: 'apply', target: 'plugins/nostr/send.json', listedCard: { ...sendCard, facts }, nostrPreview: goodPreview });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  await button(fixture.app, 'approve').onclick();
  assert.equal(fixture.passkeys(), 0);
});


test('antibody_ui_nostr_send_preview_refuses_unblinded_dictionary_commitment', async t => {
  const digest = createHash('sha256').update(sendText).digest('hex');
  const listedCard = { ...sendCard, facts: sendCard.facts.map(row => row[0] === 'Message sha256' ? [row[0], digest] : row) };
  const fixture = setup(t, { operation: 'apply', target: 'plugins/nostr/send.json', listedCard, nostrPreview: { ...goodPreview, content_sha256: digest } });
  await showApprovals(fixture.app);
  assert.equal(button(fixture.app, 'approve').disabled, true);
  await button(fixture.app, 'approve').onclick();
  assert.equal(fixture.passkeys(), 0);
});
