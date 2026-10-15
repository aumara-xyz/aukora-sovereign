// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { EMBED_PANES, ownerRoute, configuredChatOrigin, postDecision } from '../embed.js';
import { renderCardHtml } from '../card.js';
import { canonicalJSON } from '../canon.js';

const CHAT = 'https://chat-fixture.example';
const STATE = { node: '01'.repeat(16), subject: 'aukora:1:' + '02'.repeat(32), state: 'bound', session: true };
const ID = 'ab'.repeat(16);
const card = { v: 1, risk: 'routine', says: 'Write the displayed bytes', facts: [['target', 'notes/test']], from_to: {}, model_note: '<script>untrusted</script>' };
const hash = value => createHash('sha256').update(canonicalJSON(value)).digest('hex');
const display = hash(card);
const auth = { v: 1, proposal: ID, op: 'apply', display_sha256: display, challenge: 'cd'.repeat(32), expires_at: 2000000000000 };
const challenge = { id: ID, auth, display_sha256: display, public_key: {
  challenge: createHash('sha256').update('aukora:owner-authorization:v1\0' + canonicalJSON(auth)).digest('base64url'),
  allowCredentials: [], userVerification: 'required',
} };
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });

class Element {
  constructor(tag) {
    this.tagName = tag; this.children = []; this.style = {}; this.dataset = {}; this.value = '';
    this.classes = new Set();
    this.classList = { add: (...names) => names.forEach(name => this.classes.add(name)),
      toggle: (name, value) => value ? this.classes.add(name) : this.classes.delete(name) };
  }
  appendChild(child) {
    if (typeof child === 'string') { const text = new Element('#text'); text.textContent = child; child = text; }
    child.remove(); this.children.push(child); child.parent = this; return child;
  }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren(...children) { this.children.forEach(child => { child.parent = null; }); this.children = []; this._text = ''; this.append(...children); }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get textContent() { return (this._text ?? '') + this.children.map(child => child.textContent).join(''); }
  set innerHTML(html) { this.replaceChildren(); this.html = html; if (html.startsWith('<article')) this.appendChild(new Element('article')); }
  get innerHTML() { return this.html; }
  get firstElementChild() { return this.children[0]; }
  setAttribute(name, value) { this[name] = String(value); }
  addEventListener() {}
  focus() {}
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
}
const descendants = el => [el, ...el.children.flatMap(descendants)];
const button = (app, label) => descendants(app).find(el => el.tagName === 'button' && el.textContent === label);

async function setup(t, { pane = 'approvals', session = true, origin = CHAT, listed = true, failDecision = false, cancel = false, reviewed = false, state = 'bound', handle, remaining = 0 } = {}) {
  const names = ['document', 'location', 'window', 'navigator', 'fetch', 'localStorage'];
  const previous = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  const app = new Element('div'), body = new Element('body'), events = {}, messages = [], requests = [], passkeys = [];
  const loc = { hash: `#/embed/${pane}`, hostname: 'owner-fixture.example' };
  let signedIn = session, decided = false;
  const values = {
    document: { createElement: tag => new Element(tag), getElementById: () => null, body }, location: loc,
    window: { PublicKeyCredential: {}, parent: { postMessage: (...args) => messages.push(args) }, addEventListener: (name, fn) => { events[name] = fn; } },
    navigator: { credentials: { get: async options => {
      passkeys.push(options);
      return cancel ? null : { rawId: new Uint8Array([1]), response: {
        clientDataJSON: new Uint8Array([2]), authenticatorData: new Uint8Array([3]), signature: new Uint8Array([4]), userHandle: null } };
    } } },
    localStorage: { getItem: () => null },
    fetch: async (url, init) => {
      const payload = init.body ? JSON.parse(init.body) : undefined;
      requests.push({ url, init, body: payload });
      if (url === '/') return new Response(null, { headers: origin == null ? {} : { 'aukora-chat-origin': origin } });
      if (url === '/api/state') return json({ ...STATE, state, session: signedIn, handle, words: ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'] });
      if (url === '/api/signin/start') return json({ ceremony_id: ID, public_key: { challenge: 'AQ', allowCredentials: [], userVerification: 'required' } });
      if (url === '/api/signin/finish') { signedIn = true; return json({ ok: true }); }
      if (url === '/api/release') return json({ agent: 'stopped' });
      if (url === '/api/approvals') return json({ pending: decided ? Array.from({ length: remaining }, () => ({ id: 'remaining' })) : listed ? [{ id: ID, target: 'notes/test', card, display_sha256: display, state: 'pending', reviewed }] : [] });
      if (url === '/api/approvals/challenge') return json(challenge);
      if (url === '/api/approvals/retire/challenge') {
        const retirementCard = { ...card, says: 'Retire without applying' };
        const retirementAuth = { ...auth, op: 'retire', display_sha256: hash(retirementCard) };
        return json({ id: ID, card: retirementCard, auth: retirementAuth, display_sha256: hash(retirementCard), public_key: {
          challenge: createHash('sha256').update('aukora:owner-authorization:v1\0' + canonicalJSON(retirementAuth)).digest('base64url'), allowCredentials: [],
        } });
      }
      if (url === '/api/approvals/retire') { decided = true; return json({ state: 'retired', seq: 42 }); }
      if (url === '/api/approvals/decide') {
        if (failDecision) return json({ error: 'gate:not-pending' }, 409);
        decided = true;
        return json({ state: payload.approve ? 'applied' : 'refused', seq: 42 });
      }
      if (url === '/api/broker') return json({ key: { present: false }, grant: null, models: [] });
      if (url === '/api/memory/permission/propose') return json({ id: ID });
      if (url === '/api/nostr') return json({ node: { npub: 'npub1' + 'q'.repeat(58) }, agent: { npub: 'npub1' + 'p'.repeat(58) }, witness: { relays: [], sequence: null, at: null, accepted: 0 } });
      throw new Error(`unexpected fixture request ${url}`);
    },
  };
  names.forEach(name => Object.defineProperty(globalThis, name, { configurable: true, value: values[name] }));
  t.after(() => names.forEach((name, i) => previous[i] ? Object.defineProperty(globalThis, name, previous[i]) : delete globalThis[name]));
  const { mountOwnerApp } = await import('../app.js');
  const mounted = mountOwnerApp(app);
  return { app, body, messages, requests, passkeys, loc, events, boot: mounted.boot };
}

for (const pane of EMBED_PANES) {
  test(`embed_${pane}_renders_only_panel_without_navigation_or_signout`, async t => {
    const f = await setup(t, { pane }); await f.boot();
    assert.equal(descendants(f.app).filter(el => el.tagName === 'main').length, 1);
    assert.equal(descendants(f.app).some(el => el.tagName === 'nav'), false);
    assert.equal(descendants(f.app).some(el => el.textContent.startsWith('Sign out') && el.tagName === 'button'), false);
    assert.equal(f.body.classes.has('owner-embed'), true);
    assert.deepEqual(f.messages, []);
    if (pane === 'nostr') assert.ok(f.app.textContent.includes('npub1' + 'q'.repeat(58)));
  });
  test(`embed_${pane}_missing_session_signs_in_inline_with_passkey`, async t => {
    const f = await setup(t, { pane, session: false }); await f.boot();
    assert.ok(button(f.app, 'sign in with passkey'));
    assert.deepEqual(f.messages, []);
    await button(f.app, 'sign in with passkey').onclick();
    assert.equal(f.passkeys.length, 1);
    assert.equal(f.passkeys[0].publicKey.userVerification, 'required');
    assert.equal(f.requests.find(r => r.url === '/api/signin/finish').body.assertion.kind, 'passkey');
    assert.equal(f.loc.hash, `#/embed/${pane}`);
    assert.equal(descendants(f.app).filter(el => el.tagName === 'main').length, 1);
    assert.equal(descendants(f.app).some(el => el.tagName === 'nav'), false);
    assert.deepEqual(f.messages, []);
  });
}

for (const action of ['approve', 'refuse']) test(`embed_approvals_${action}_posts_only_decision_and_authoritative_remaining_count_to_chat`, async t => {
  const f = await setup(t); await f.boot();
  assert.deepEqual(f.messages, []);
  assert.ok(descendants(f.app).some(el => el.innerHTML === renderCardHtml(card)));
  await button(f.app, action).onclick();
  assert.deepEqual(f.messages, [[{ kind: 'aukora-owner', event: 'decided', pending: 0 }, CHAT]]);
  assert.equal(f.passkeys.length, action === 'approve' ? 1 : 0);
  const sent = f.requests.find(r => r.url === '/api/approvals/decide').body;
  assert.deepEqual(Object.keys(sent).sort(), action === 'approve' ? ['approve', 'assertion', 'id'] : ['approve', 'id']);
  assert.equal(sent.approve, action === 'approve');
  if (action === 'approve') {
    assert.equal(sent.assertion.kind, 'passkey');
    assert.equal(f.passkeys[0].publicKey.userVerification, 'required');
  }
});

for (const options of [{ failDecision: true }, { cancel: true }]) test(`embed_failed_or_cancelled_approval_posts_nothing_${JSON.stringify(options)}`, async t => {
  const f = await setup(t, options); await f.boot();
  await button(f.app, 'approve').onclick();
  assert.deepEqual(f.messages, []);
  if (options.cancel) assert.equal(f.requests.some(r => r.url === '/api/approvals/decide'), false);
});

test('embed_empty_approvals_posts_nothing', async t => {
  const f = await setup(t, { listed: false }); await f.boot();
  assert.deepEqual(f.messages, []);
});

test('embed_reviewed_proposals_refuse_through_existing_passkey_retirement', async t => {
  const f = await setup(t, { reviewed: true }); await f.boot();
  const action = button(f.app, 'refuse').onclick();
  for (let i = 0; i < 100 && !button(f.app, 'confirm retire'); i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.passkeys.length, 0);
  assert.deepEqual(f.messages, []);
  button(f.app, 'confirm retire').onclick();
  await action;
  assert.equal(f.passkeys.length, 1);
  assert.equal(f.requests.some(r => r.url === '/api/approvals/decide'), false);
  assert.equal(f.requests.find(r => r.url === '/api/approvals/retire').body.assertion.kind, 'passkey');
  assert.deepEqual(f.messages, [[{ kind: 'aukora-owner', event: 'decided', pending: 0 }, CHAT]]);
});

test('embed_aumlok_sections_are_masked_and_identity_comes_from_owner_fixture', async t => {
  const f = await setup(t, { pane: 'aumlok', handle: 'fixture-owner' }); await f.boot();
  for (const text of ['SEVEN-WORD BINDING PHRASE', 'AUMLOK', 'BOUND', 'YOUR HANDLE', 'fixture-owner', 'Locked', 'WORD 1', 'ROOT', 'UNITE', 'RISE', STATE.subject, 'Passkeys']) assert.ok(f.app.textContent.includes(text), text);
  assert.equal(descendants(f.app).find(el => el.className === 'aumlok-badge').textContent, 'BOUND');
  const anchor = descendants(f.app).find(el => el.className === 'aumlok-anchor-boxes');
  assert.deepEqual(anchor.children.map(el => el.textContent), Array(6).fill('•'));
  for (const row of descendants(f.app).filter(el => el.className === 'aumlok-word')) assert.equal(row.children[1].textContent, '•  •  •  •  •');
  for (const secret of ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform']) assert.equal(f.app.textContent.includes(secret), false);
  assert.deepEqual(descendants(f.app).filter(el => el.dataset.word).map(el => el.dataset.word), ['2', '3', '4', '5', '6', '7']);
  assert.equal(descendants(f.app).filter(el => /^word \d masked$/.test(el['aria-label'] ?? '')).length, 7);
  assert.ok(button(f.app, 'Refresh phrase'));
  assert.ok(button(f.app, 'Download passkey-bound backup'));
  assert.equal(f.requests.some(r => r.url.includes('/binding/')), false);
  button(f.app, 'Refresh phrase').onclick();
  assert.ok(button(f.app, 'Continue'));
  await button(f.app, 'Back to Identity').onclick();
  assert.ok(button(f.app, 'Refresh phrase'));
  assert.equal(button(f.app, 'Sign out everywhere'), undefined);
});

test('embed_aumlok_does_not_invent_handle_when_owner_api_has_none', async t => {
  const f = await setup(t, { pane: 'aumlok' }); await f.boot();
  assert.ok(f.app.textContent.includes('Handle unavailable'));
  assert.ok(f.app.textContent.includes(STATE.subject));
});

for (const origin of [null, '*', 'https://chat-fixture.example/path', 'http://chat-fixture.example', 'https://evil.example', 'https://chat-fixture.example@evil.example']) {
  test(`embed_refuses_invalid_configured_chat_origin_${origin}`, async t => {
    const f = await setup(t, { origin });
    await assert.rejects(configuredChatOrigin(), { code: 'frontdoor:chat-origin-invalid' });
    await f.boot();
    assert.ok(f.app.textContent.includes('frontdoor:chat-origin-invalid'));
    assert.deepEqual(f.messages, []);
    assert.equal(button(f.app, 'approve'), undefined);
  });
}

test('embed_memory_permission_stays_inside_approvals_frame', async t => {
  const f = await setup(t, { pane: 'memory' }); await f.boot();
  const permit = descendants(f.app).find(el => el['aria-label'] === 'let recall enter the hosted model’s context');
  await permit.onclick();
  assert.equal(f.loc.hash, '#/embed/approvals');
});

test('embed_routes_refuse_unknown_panes', () => {
  for (const path of ['identity', 'approvals/other', '../approvals', 'approvals?origin=https://evil.example']) assert.deepEqual(ownerRoute(`#/embed/${path}`), { embedded: true, pane: null });
});

test('embed_canvas_is_transparent_and_sheet_width_is_bounded', async () => {
  const css = await readFile(new URL('../styles.css', import.meta.url), 'utf8');
  assert.match(css, /html:has\(body.owner-embed\), body.owner-embed \{ background: transparent;/);
  assert.match(css, /\.owner-embed #app \{[^}]*max-width: 760px;/);
});

test('embed_cancelled_signin_stays_in_frame_and_never_finishes_session', async t => {
  const f = await setup(t, { session: false, cancel: true }); await f.boot();
  await button(f.app, 'sign in with passkey').onclick();
  assert.ok(button(f.app, 'sign in with passkey'));
  assert.ok(f.app.textContent.includes('aumlok:signin-cancelled'));
  assert.equal(f.requests.some(r => r.url === '/api/signin/finish'), false);
  assert.deepEqual(f.messages, []);
});

for (const state of ['claim-open', 'enrolled']) test(`embed_boot_${state}_has_no_signout`, async t => {
  const f = await setup(t, { state }); await f.boot();
  assert.equal(descendants(f.app).some(el => el.tagName === 'button' && el.textContent.startsWith('Sign out')), false);
  assert.deepEqual(f.messages, []);
});

test('embed_decision_reports_remaining_count_from_fresh_server_list', async t => {
  const f = await setup(t, { remaining: 3 }); await f.boot();
  await button(f.app, 'refuse').onclick();
  assert.deepEqual(f.messages, [[{ kind: 'aukora-owner', event: 'decided', pending: 3 }, CHAT]]);
});

test('ordinary_owner_approvals_keeps_navigation_and_sends_no_parent_messages', async t => {
  const f = await setup(t); f.loc.hash = '#/approvals'; await f.boot();
  assert.ok(descendants(f.app).some(el => el.tagName === 'nav'));
  assert.ok(button(f.app, 'Sign out'));
  await button(f.app, 'approve').onclick();
  assert.deepEqual(f.messages, []);
});

test('embed_post_decision_refuses_invalid_counts_and_does_not_message_itself', async t => {
  const f = await setup(t);
  for (const count of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1]) postDecision(CHAT, count);
  assert.deepEqual(f.messages, []);
  window.postMessage = (...args) => f.messages.push(args);
  window.parent = window;
  postDecision(CHAT, 0);
  assert.deepEqual(f.messages, []);
});
