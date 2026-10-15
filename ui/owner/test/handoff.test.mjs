// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { addOwnerLinks, chatSessionUrl } from '../owner-links.js';

const CHAT = 'https://chat-fixture.example';
const TICKET = 'ab'.repeat(32);
const TARGET = `${CHAT}/__aukora/chat#ticket=${TICKET}`;
const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'Content-Type': 'application/json' },
});

class Element {
  constructor(tag) {
    this.tagName = tag; this.children = []; this.style = {}; this.dataset = {};
    this.classList = { toggle() {} };
  }
  appendChild(child) { child.remove(); this.children.push(child); child.parent = this; return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren(...children) {
    this.children.forEach(child => { child.parent = null; });
    this.children = []; this._text = ''; this.append(...children);
  }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get textContent() { return (this._text ?? '') + this.children.map(child => child.textContent).join(''); }
  setAttribute(name, value) { this[name] = String(value); }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this);
    this.parent = null;
  }
}
const all = element => [element, ...element.children.flatMap(all)];
const signInButton = app => all(app).find(element => element.tagName === 'button' && element.textContent === 'sign in with passkey');

async function setup(t, { session = true, origin = CHAT, target = TARGET, cancel = false,
  finishStatus = 200, finishSession = true, mintStatus = 200, stateStatus = 200,
  pathname = '/__aukora/handoff', search = '', hash = '', configStatus = 200, missingSession = false } = {}) {
  const names = ['document', 'location', 'window', 'navigator', 'fetch'];
  const previous = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  const app = new Element('div'), requests = [], passkeys = [], replaced = [], assigned = [];
  let signedIn = session;
  const loc = { pathname, search, hash, hostname: 'owner-fixture.example',
    replace: value => replaced.push(value), assign: value => assigned.push(value) };
  const values = {
    document: { createElement: tag => new Element(tag), getElementById: () => null, body: new Element('body') },
    location: loc,
    window: { PublicKeyCredential: {}, addEventListener() {} },
    navigator: { credentials: { get: async options => {
      passkeys.push(options);
      return cancel ? null : { rawId: new Uint8Array([1]), response: {
        clientDataJSON: new Uint8Array([2]), authenticatorData: new Uint8Array([3]),
        signature: new Uint8Array([4]), userHandle: null,
      } };
    } } },
    fetch: async (url, init) => {
      requests.push({ url, init, body: init.body && JSON.parse(init.body) });
      if (url === '/api/state') return json(stateStatus === 200
        ? { state: 'released', session: missingSession ? undefined : signedIn } : { error: 'frontdoor:backend-unavailable' }, stateStatus);
      if (url === '/') return new Response(null, {
        status: configStatus, headers: origin === null ? {} : { 'aukora-chat-origin': origin },
      });
      if (url === '/api/chat-session') return json(mintStatus === 200 ? { url: target } : { error: 'frontdoor:session-required' }, mintStatus);
      if (url === '/api/signin/start') return json({ ceremony_id: 'cd'.repeat(16), public_key: {
        challenge: 'AQ', allowCredentials: [], userVerification: 'required',
      } });
      if (url === '/api/signin/finish') {
        if (finishStatus === 200) signedIn = finishSession;
        return json(finishStatus === 200 ? { ok: true } : { error: 'aumlok:signin-invalid' }, finishStatus);
      }
      if (url === '/api/release') return json({ agent: 'stopped' });
      if (url === '/api/approvals') return json({ pending: [] });
      if (url === '/api/broker') return json({ key: { present: false }, grant: null, models: [] });
      throw new Error(`unexpected handoff request ${url}`);
    },
  };
  names.forEach(name => Object.defineProperty(globalThis, name, { configurable: true, value: values[name] }));
  t.after(() => names.forEach((name, i) => previous[i]
    ? Object.defineProperty(globalThis, name, previous[i]) : delete globalThis[name]));
  const { mountOwnerApp } = await import('../app.js');
  return { app, requests, passkeys, replaced, assigned, loc, boot: mountOwnerApp(app).boot };
}

test('antibody_ui_handoff_valid_owner_uses_existing_ticket_post_and_replaces_location_without_a_screen', async t => {
  const f = await setup(t, { search: '?next=https://chat-evil.example/', hash: '#/identity' });
  await f.boot();
  assert.deepEqual(f.requests.map(request => [request.url, request.init.method]), [
    ['/api/state', 'GET'], ['/', 'HEAD'], ['/api/chat-session', 'POST'],
  ]);
  assert.deepEqual(f.requests[2].body, {});
  for (const { init } of f.requests) {
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.redirect, 'error');
    assert.equal(init.cache, 'no-store');
  }
  assert.deepEqual(f.replaced, [TARGET]);
  assert.deepEqual(f.assigned, []);
  assert.deepEqual(f.passkeys, []);
  assert.equal(f.app.children.length, 0);
});

test('antibody_ui_handoff_requires_explicit_owner_session_then_rechecks_after_existing_passkey_signin', async t => {
  for (const session of [false, null, 0, 'true', undefined]) await t.test(String(session), async t => {
    const f = await setup(t, { session, missingSession: session === undefined });
    await f.boot();
    assert.ok(signInButton(f.app));
    assert.equal(f.requests.some(request => request.url === '/api/chat-session'), false);
    assert.deepEqual(f.replaced, []);
    if (session === undefined) return;
    await signInButton(f.app).onclick();
    assert.equal(f.passkeys.length, 1);
    assert.equal(f.passkeys[0].publicKey.userVerification, 'required');
    assert.equal(f.requests.find(request => request.url === '/api/signin/finish').body.assertion.kind, 'passkey');
    assert.equal(f.requests.filter(request => request.url === '/api/state').length, 2);
    assert.equal(f.requests.filter(request => request.url === '/api/chat-session').length, 1);
    assert.deepEqual(f.replaced, [TARGET]);
    assert.equal(all(f.app).some(element => element.tagName === 'nav'), false);
  });
});

test('antibody_ui_handoff_cancelled_failed_or_unconfirmed_signin_mints_no_ticket', async t => {
  for (const options of [{ cancel: true }, { finishStatus: 403 }, { finishSession: false }]) await t.test(JSON.stringify(options), async t => {
    const f = await setup(t, { session: false, ...options }); await f.boot();
    await signInButton(f.app).onclick();
    assert.equal(f.requests.some(request => request.url === '/api/chat-session'), false);
    assert.deepEqual(f.replaced, []);
    if (options.cancel) assert.equal(f.requests.some(request => request.url === '/api/signin/finish'), false);
    assert.ok(signInButton(f.app));
  });
});

test('antibody_ui_handoff_owner_session_expiry_or_state_failure_never_redirects', async t => {
  for (const options of [{ mintStatus: 401 }, { stateStatus: 503 }]) await t.test(JSON.stringify(options), async t => {
    const f = await setup(t, options); await f.boot();
    assert.deepEqual(f.replaced, []);
    assert.deepEqual(f.assigned, []);
    assert.ok(f.app.textContent.includes(options.mintStatus ? 'frontdoor:session-required' : 'frontdoor:backend-unavailable'));
    if (options.stateStatus) assert.equal(f.requests.some(request => request.url === '/api/chat-session'), false);
  });
});

test('antibody_ui_handoff_ticket_url_is_pinned_to_exact_node_chat_origin', async t => {
  for (const [i, target] of [
    `https://chat-evil.example/__aukora/chat#ticket=${TICKET}`,
    `http://chat-fixture.example/__aukora/chat#ticket=${TICKET}`,
    `${CHAT}:444/__aukora/chat#ticket=${TICKET}`,
    `https://chat-fixture.example@chat-evil.example/__aukora/chat#ticket=${TICKET}`,
    `https://user:password@chat-fixture.example/__aukora/chat#ticket=${TICKET}`,
    `https://user@chat-fixture.example/__aukora/chat#ticket=${TICKET}`,
    `https://:password@chat-fixture.example/__aukora/chat#ticket=${TICKET}`,
    '//chat-fixture.example/__aukora/chat', null, 'not a url',
  ].entries()) await t.test(`target ${i}`, async t => {
    const f = await setup(t, { target });
    await assert.rejects(chatSessionUrl(), { code: 'frontdoor:backend-invalid' });
    assert.deepEqual(f.replaced, []);
    assert.deepEqual(f.assigned, []);
  });
});

test('antibody_ui_handoff_ticket_stays_in_fragment_on_existing_chat_bootstrap_path', async t => {
  for (const [i, target] of [
    `${CHAT}/?ticket=${TICKET}`, `${CHAT}/__aukora/chat?ticket=${TICKET}#ticket=${TICKET}`,
    `${CHAT}/__aukora/chat?next=https://evil.example#ticket=${TICKET}`,
    `${CHAT}/other#ticket=${TICKET}`, `${CHAT}/__aukora/chat`,
    `${CHAT}/__aukora/chat#ticket=short`, `${CHAT}/__aukora/chat#ticket=${TICKET}&next=other`,
  ].entries()) await t.test(`target ${i}`, async t => {
    const f = await setup(t, { target }); await f.boot();
    assert.deepEqual(f.replaced, []);
    assert.ok(f.app.textContent.includes('frontdoor:backend-invalid'));
  });
});

test('antibody_ui_handoff_invalid_node_chat_configuration_mints_no_ticket', async t => {
  for (const options of [
    { origin: null }, { origin: '*' }, { origin: 'http://chat-fixture.example' },
    { origin: `${CHAT}/path` }, { origin: 'https://evil.example' }, { configStatus: 503 },
  ]) await t.test(JSON.stringify(options), async t => {
    const f = await setup(t, options); await f.boot();
    assert.equal(f.requests.some(request => request.url === '/api/chat-session'), false);
    assert.deepEqual(f.replaced, []);
    assert.ok(f.app.textContent.includes('frontdoor:chat-origin-invalid'));
  });
});

test('antibody_ui_handoff_and_speech_icon_share_one_chat_session_request_path', async t => {
  const f = await setup(t), nav = new Element('nav');
  addOwnerLinks(nav);
  const chat = all(nav).find(element => element['aria-label'] === 'open chat');
  let prevented = false;
  await chat.onclick({ preventDefault: () => { prevented = true; } });
  assert.equal(prevented, true);
  assert.deepEqual(f.requests.map(request => [request.url, request.init.method]), [
    ['/', 'HEAD'], ['/api/chat-session', 'POST'],
  ]);
  assert.deepEqual(f.assigned, [TARGET]);
});

test('antibody_ui_handoff_nested_route_loads_owner_assets_from_origin_root', async () => {
  const html = await readFile(new URL('../index.html', import.meta.url), 'utf8');
  assert.match(html, /href="\/styles\.css"/);
  assert.match(html, /src="\/app\.js"/);
});
