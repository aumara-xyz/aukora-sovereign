// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { api } from '../api.js';
import { canonicalJSON } from '../canon.js';
import { showIdentity } from '../screens/identity.js';
import { addSignOut, addSignOutEverywhere } from '../session-controls.js';
import { mountPhraseCeremony } from '../screens/binding.js';

const CURRENT = 'planet pine linden accord neighbor eclipse terraform';
const WORDS = ['silver', 'spruce', 'iris', 'laughter', 'village', 'enlighten', 'rocket'];
const ID = 'ab'.repeat(16);
const REFRESH = 'cd'.repeat(16);
const STATE = { node: '01'.repeat(16), subject: 'aukora:1:' + '02'.repeat(32), state: 'bound', session: true };
const KEY = `aukora.refresh.${STATE.node}.${STATE.subject}`;
const hash = text => createHash('sha256').update(text).digest('hex');
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
const seal = ch => {
  ch.public_key.challenge = createHash('sha256').update('aukora:owner-authorization:v1\0' + canonicalJSON(ch.auth)).digest('base64url');
};
const sign = ch => {
  const auth = ch.auth;
  auth.operation = hash('aukora:operation-content:v1\0' + canonicalJSON({
    v: 1, node: auth.node, target: auth.target, base_sha256: auth.base_sha256,
    new_sha256: auth.new_sha256, cell: auth.cell,
  }));
  seal(ch);
};
function ceremony() {
  const card = { v: 1, risk: 'critical', says: 'Replace your binding phrase', facts: [['identity', STATE.subject]], from_to: {}, model_note: '' };
  const display = hash(canonicalJSON(card));
  const content = { v: 1, node: STATE.node, target: 'aumlok/binding/refresh', base_sha256: '11'.repeat(32), new_sha256: '22'.repeat(32), cell: null };
  const ch = { ceremony_id: ID, card, display_sha256: display,
    auth: { ...content, subject: STATE.subject, epoch: 1, op: 'permission', proposal: ID,
      operation: hash('aukora:operation-content:v1\0' + canonicalJSON(content)),
      display_sha256: display, challenge: '33'.repeat(32), expires_at: Date.now() + 120000 },
    public_key: { challenge: '', allowCredentials: [], userVerification: 'required' } };
  seal(ch);
  return ch;
}

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.dataset = {}; this.style = {}; this.events = {}; this.value = ''; }
  appendChild(child) {
    if (typeof child === 'string') { const text = new Element('#text'); text.textContent = child; child = text; }
    child.remove(); this.children.push(child); child.parent = this; return child;
  }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren(...children) { this.children.forEach(child => { child.parent = null; }); this.children = []; this._text = ''; this.append(...children); }
  insertBefore(child, before) { child.remove(); this.children.splice(this.children.indexOf(before), 0, child); child.parent = this; }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get textContent() { return (this._text ?? '') + this.children.map(child => child.textContent).join(''); }
  set innerHTML(html) { this.replaceChildren(); this.html = html; if (html.startsWith('<article')) this.appendChild(new Element('article')); }
  get innerHTML() { return this.html; }
  get firstElementChild() { return this.children[0]; }
  setAttribute(name, value) { this[name] = value; }
  getAttribute(name) { return this[name] ?? null; }
  addEventListener(name, fn) { this.events[name] = fn; }
  focus() { this.focused = true; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
}
const descendants = el => [el, ...el.children.flatMap(descendants)];
const button = (app, label) => descendants(app).find(el => el.tagName === 'button' && el.textContent === label);
const current = app => descendants(app).find(el => el['aria-label'] === 'current phrase');
const error = app => descendants(app).find(el => el.className === 'instruct warn' && el.hidden === false)?.textContent;
const inputs = app => descendants(app).filter(el => el.tagName === 'input' && el.dataset.pos);

function setup(t, { patch, hostname = 'owner.example', credential = true, store = new Map(), failure, respond } = {}) {
  const names = ['document', 'location', 'window', 'navigator', 'fetch', 'localStorage'];
  const previous = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  const requests = [];
  const options = [];
  const value = {
    document: { createElement: tag => new Element(tag) }, location: { hostname }, window: { PublicKeyCredential: {} },
    navigator: { credentials: { get: async option => {
      options.push(option);
      return credential ? { rawId: new Uint8Array([1]), response: { clientDataJSON: new Uint8Array([2]),
        authenticatorData: new Uint8Array([3]), signature: new Uint8Array([4]), userHandle: null } } : null;
    } } },
    localStorage: { getItem: key => store.get(key) ?? null, setItem: (key, value) => store.set(key, value), removeItem: key => store.delete(key) },
    fetch: async (url, init) => {
      requests.push({ url, body: init.body ? JSON.parse(init.body) : undefined });
      const response = respond ? await respond(url, init) : undefined;
      if (response) return response;
      if (url === '/api/state') return json(STATE);
      if (url === '/api/binding/refresh') { const ch = ceremony(); if (patch) patch(ch); return json(ch); }
      if (url.endsWith('/prepare') || url.endsWith('/resume')) {
        if (failure) return json({ error: failure }, 422);
        return json({ ceremony_id: REFRESH, words: WORDS, entropy_bits: 69, expires_at: Date.now() + 300000 });
      }
      if (url.endsWith('/confirm')) return json({ ok: true, state: 'bound', subject: STATE.subject });
      return json({ ok: true });
    },
  };
  names.forEach(name => Object.defineProperty(globalThis, name, { configurable: true, value: value[name] }));
  t.after(() => names.forEach((name, i) => {
    if (previous[i]) Object.defineProperty(globalThis, name, previous[i]); else delete globalThis[name];
  }));
  return { app: new Element('div'), requests, options, store };
}
// Bounded by time, not event-loop turns: WebCrypto digests finish off-thread and take longer on a loaded host.
async function waitFor(check) {
  const until = performance.now() + 5000;
  while (performance.now() < until) { if (check()) return; await new Promise(resolve => setTimeout(resolve, 1)); }
  assert.fail('screen did not reach expected action');
}
async function reveal(fixture) {
  await showIdentity(fixture.app);
  button(fixture.app, 'Replace phrase').onclick();
  current(fixture.app).value = CURRENT;
  const action = button(fixture.app, 'Continue').onclick();
  await waitFor(() => button(fixture.app, 'Touch ID — replace phrase'));
  await button(fixture.app, 'Touch ID — replace phrase').onclick();
  await action;
}

test('antibody_ui_refresh_requests_never_supply_authorization', async t => {
  const fixture = setup(t);
  const assertion = { kind: 'passkey', credential_id: 'AQ' };
  await api.bindingRefresh();
  await api.bindingRefreshPrepare(ID, CURRENT, assertion);
  await api.bindingRefreshResume(REFRESH, CURRENT);
  await api.bindingRefreshConfirm(REFRESH, CURRENT, WORDS);
  await api.bindingRefreshCancel(REFRESH);
  assert.deepEqual(fixture.requests, [
    { url: '/api/binding/refresh', body: {} },
    { url: '/api/binding/refresh/prepare', body: { ceremony_id: ID, current_phrase: CURRENT, assertion } },
    { url: '/api/binding/refresh/resume', body: { ceremony_id: REFRESH, current_phrase: CURRENT } },
    { url: '/api/binding/refresh/confirm', body: { ceremony_id: REFRESH, current_phrase: CURRENT, words: WORDS } },
    { url: '/api/binding/refresh/cancel', body: { ceremony_id: REFRESH } },
  ]);
});

test('antibody_ui_phrase_inputs_are_plain_text_without_browser_retention', async t => {
  const fixture = setup(t);
  const check = field => {
    assert.equal(field.type, 'text');
    for (const name of ['autocomplete', 'autocorrect', 'autocapitalize']) assert.equal(field.getAttribute(name), 'off', name);
    assert.equal(field.getAttribute('spellcheck'), 'false');
  };
  await showIdentity(fixture.app);
  button(fixture.app, 'Replace phrase').onclick();
  check(current(fixture.app));
  await reveal(fixture);
  button(fixture.app, 'I have them — hide the words').onclick();
  assert.equal(inputs(fixture.app).length, 7);
  inputs(fixture.app).forEach(check);
  fixture.app.replaceChildren();
  mountPhraseCeremony(fixture.app, { words: WORDS, entropy_bits: 69 }, {
    label: 'bind', onDone: () => {}, doneText: 'done', confirm: () => {},
  });
  button(fixture.app, 'I have them — hide the words').onclick();
  inputs(fixture.app).forEach(check);
});

test('antibody_ui_refresh_lost_prepare_resumes_without_another_passkey', async t => {
  let prepared = false;
  const fixture = setup(t, { respond: url => {
    if (url.endsWith('/prepare')) {
      prepared = true;
      throw new Error('lost prepare response');
    }
    if (url === '/api/binding/refresh' && prepared) return json({ ceremony_id: REFRESH, state: 'live', expires_at: Date.now() + 300000 });
  } });
  await reveal(fixture);
  assert.ok(error(fixture.app).includes('lost prepare response'));
  assert.equal(fixture.options.length, 1);
  assert.deepEqual([...fixture.store], []);
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Continue').onclick();
  assert.equal(fixture.options.length, 1);
  assert.equal(fixture.requests.filter(r => r.url.endsWith('/prepare')).length, 1);
  assert.deepEqual(fixture.requests.at(-1), { url: '/api/binding/refresh/resume', body: { ceremony_id: REFRESH, current_phrase: CURRENT } });
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  assert.ok(button(fixture.app, 'I have them — hide the words'));
  assert.ok(button(fixture.app, 'Cancel replacement'));
});

test('antibody_ui_refresh_prepare_live_result_resumes_the_same_ceremony', async t => {
  const fixture = setup(t, { respond: url => url.endsWith('/prepare')
    ? json({ ceremony_id: REFRESH, state: 'live', expires_at: Date.now() + 300000 }) : undefined });
  await reveal(fixture);
  assert.deepEqual(fixture.requests.at(-1), { url: '/api/binding/refresh/resume', body: { ceremony_id: REFRESH, current_phrase: CURRENT } });
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  assert.ok(button(fixture.app, 'I have them — hide the words'));
});

test('antibody_ui_refresh_live_id_survives_phrase_refusal_for_owner_cancel', async t => {
  const fixture = setup(t, { failure: 'aumlok:current-phrase', respond: url => url === '/api/binding/refresh'
    ? json({ ceremony_id: REFRESH, state: 'live', expires_at: Date.now() + 300000 }) : undefined });
  await showIdentity(fixture.app);
  button(fixture.app, 'Replace phrase').onclick();
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Continue').onclick();
  assert.equal(error(fixture.app), 'aumlok:current-phrase');
  assert.equal(fixture.options.length, 0);
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  assert.ok(button(fixture.app, 'Cancel replacement'));
  await button(fixture.app, 'Cancel replacement').onclick();
  assert.deepEqual([...fixture.store], []);
  assert.ok(button(fixture.app, 'Replace phrase'));
});

test('antibody_ui_refresh_committed_resume_reports_success_without_words', async t => {
  const fixture = setup(t, { store: new Map([[KEY, REFRESH]]), respond: url => url.endsWith('/resume')
    ? json({ ok: true, state: 'committed', subject: STATE.subject }) : undefined });
  await showIdentity(fixture.app);
  button(fixture.app, 'Resume phrase replacement').onclick();
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Resume replacement').onclick();
  assert.ok(fixture.app.textContent.includes('Phrase replaced.'));
  assert.equal(fixture.options.length, 0);
  assert.equal(error(fixture.app), undefined);
  assert.equal(descendants(fixture.app).some(el => el.tagName === 'input'), false);
  assert.equal(button(fixture.app, 'I have them — hide the words'), undefined);
  assert.deepEqual([...fixture.store], []);
});

test('antibody_ui_refresh_lost_confirm_retry_reports_committed_success', async t => {
  let confirms = 0;
  const fixture = setup(t, { respond: url => {
    if (!url.endsWith('/confirm')) return;
    if (++confirms === 1) throw new Error('lost confirm response');
    return json({ ok: true, state: 'committed', subject: STATE.subject });
  } });
  await reveal(fixture);
  button(fixture.app, 'I have them — hide the words').onclick();
  inputs(fixture.app).forEach((input, i) => { input.value = WORDS[i]; });
  await button(fixture.app, 'Replace phrase').onclick();
  assert.ok(error(fixture.app).includes('lost confirm response'));
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  assert.equal(button(fixture.app, 'Replace phrase').disabled, false);
  await button(fixture.app, 'Replace phrase').onclick();
  assert.equal(confirms, 2);
  assert.ok(fixture.app.textContent.includes('Phrase replaced.'));
  assert.deepEqual([...fixture.store], []);
});

test('antibody_ui_refresh_owner_can_cancel_without_phrase_or_passkey', async t => {
  let attempts = 0;
  const fixture = setup(t, { store: new Map([[KEY, REFRESH]]), respond: url => {
    if (!url.endsWith('/cancel')) return;
    return ++attempts === 1 ? json({ error: 'frontdoor:backend-unavailable' }, 503) : json({ ok: true });
  } });
  await showIdentity(fixture.app);
  button(fixture.app, 'Resume phrase replacement').onclick();
  const cancel = button(fixture.app, 'Cancel replacement');
  await cancel.onclick();
  assert.match(error(fixture.app), /^frontdoor:backend-unavailable/);
  assert.equal(cancel.disabled, false);
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  await cancel.onclick();
  assert.ok(button(fixture.app, 'Replace phrase'));
  assert.equal(fixture.options.length, 0);
  assert.equal(fixture.requests.some(r => r.url.endsWith('/resume') || r.url.endsWith('/prepare')), false);
  assert.deepEqual(fixture.requests.filter(r => r.url.endsWith('/cancel')), [
    { url: '/api/binding/refresh/cancel', body: { ceremony_id: REFRESH } },
    { url: '/api/binding/refresh/cancel', body: { ceremony_id: REFRESH } },
  ]);
  assert.deepEqual([...fixture.store], []);
});

test('antibody_ui_refresh_cancel_stays_available_after_words_are_hidden', async t => {
  const fixture = setup(t);
  await reveal(fixture);
  assert.ok(button(fixture.app, 'Cancel replacement'));
  button(fixture.app, 'I have them — hide the words').onclick();
  await button(fixture.app, 'Cancel replacement').onclick();
  assert.ok(button(fixture.app, 'Replace phrase'));
  assert.deepEqual(fixture.requests.find(r => r.url.endsWith('/cancel')), { url: '/api/binding/refresh/cancel', body: { ceremony_id: REFRESH } });
  assert.deepEqual([...fixture.store], []);
  assert.equal(descendants(fixture.app).some(el => el.tagName === 'input'), false);
});

test('antibody_ui_refresh_active_cancel_failure_remains_owner_retryable', async t => {
  let attempts = 0;
  const fixture = setup(t, { respond: url => {
    if (!url.endsWith('/cancel')) return;
    return ++attempts === 1 ? json({ error: 'frontdoor:backend-unavailable' }, 503) : json({ ok: true });
  } });
  await reveal(fixture);
  const cancel = button(fixture.app, 'Cancel replacement');
  await cancel.onclick();
  assert.match(error(fixture.app), /^frontdoor:backend-unavailable/);
  assert.equal(cancel.disabled, false);
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  await cancel.onclick();
  assert.ok(button(fixture.app, 'Replace phrase'));
  assert.deepEqual([...fixture.store], []);
});

test('antibody_ui_refresh_success_links_new_backup_and_explains_old_backups', async t => {
  const fixture = setup(t);
  await reveal(fixture);
  button(fixture.app, 'I have them — hide the words').onclick();
  inputs(fixture.app).forEach((input, i) => { input.value = WORDS[i]; });
  await button(fixture.app, 'Replace phrase').onclick();
  assert.ok(fixture.app.textContent.includes('Download the new envelope backup.'));
  assert.ok(fixture.app.textContent.includes('Previously downloaded backups still open only with the old phrase.'));
  const backup = descendants(fixture.app).find(el => el.tagName === 'a');
  assert.equal(backup.href, '/api/binding/envelope');
  assert.equal(backup.download, 'aukora-envelope.json');
});

test('antibody_ui_refresh_is_reachable_after_binding', async () => {
  const source = await readFile(new URL('../app.js', import.meta.url), 'utf8');
  assert.match(source, /identity:\s*showIdentity/);
  assert.match(source, /\['identity',\s*ICONS\.key\]/);
});

test('antibody_ui_refresh_complete_flow_hides_words_and_limits_first_mismatch', async t => {
  const fixture = setup(t);
  await showIdentity(fixture.app);
  button(fixture.app, 'Replace phrase').onclick();
  const field = current(fixture.app);
  for (const kind of ['paste', 'drop']) { let prevented = false; field.events[kind]({ preventDefault: () => { prevented = true; } }); assert.equal(prevented, true); }
  field.value = CURRENT;
  const action = button(fixture.app, 'Continue').onclick();
  await waitFor(() => button(fixture.app, 'Touch ID — replace phrase'));
  assert.equal(fixture.options.length, 0);
  assert.equal(field.value, '');
  assert.equal(current(fixture.app), undefined);
  assert.ok(descendants(fixture.app).some(el => el.innerHTML?.includes('Replace your binding phrase')));
  assert.equal(fixture.requests.some(r => r.url.endsWith('/prepare')), false);
  await button(fixture.app, 'Touch ID — replace phrase').onclick();
  await action;
  assert.equal(fixture.options.length, 1);
  assert.equal(fixture.options[0].publicKey.userVerification, 'required');
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  assert.ok(fixture.app.textContent.includes('69 bits'));
  assert.ok(fixture.app.textContent.includes('Never type these words into an AI.'));
  assert.equal(descendants(fixture.app).filter(el => el.className === 'anchor-cell').length, 6);
  button(fixture.app, 'I have them — hide the words').onclick();
  assert.equal(button(fixture.app, 'I have them — hide the words'), undefined);
  for (const word of WORDS) assert.equal(fixture.app.textContent.includes(word), false);
  const typed = inputs(fixture.app);
  assert.equal(typed.length, 7);
  for (const input of typed) {
    for (const kind of ['paste', 'drop']) { let prevented = false; input.events[kind]({ preventDefault: () => { prevented = true; } }); assert.equal(prevented, true); }
  }
  typed.forEach((input, i) => { input.value = WORDS[i]; });
  typed[1].value = 'wrong'; typed[4].value = 'also wrong';
  await button(fixture.app, 'Replace phrase').onclick();
  assert.equal(error(fixture.app), 'word 2 does not match');
  assert.equal(typed[1].focused, true);
  assert.equal(fixture.requests.some(r => r.url.endsWith('/confirm')), false);
  typed.forEach((input, i) => { input.value = WORDS[i]; });
  await button(fixture.app, 'Replace phrase').onclick();
  assert.deepEqual(fixture.requests.find(r => r.url.endsWith('/confirm')).body, { ceremony_id: REFRESH, current_phrase: CURRENT, words: WORDS });
  assert.equal(typed.every(input => input.value === ''), true);
  assert.ok(fixture.app.textContent.includes('Phrase replaced.'));
  assert.deepEqual([...fixture.store], []);
});

test('antibody_ui_refresh_exact_typeback_refuses_case_and_padding', async t => {
  const fixture = setup(t);
  await reveal(fixture);
  button(fixture.app, 'I have them — hide the words').onclick();
  const typed = inputs(fixture.app);
  typed.forEach((input, i) => { input.value = WORDS[i]; });
  typed[1].value = WORDS[1].toUpperCase();
  typed[4].value = WORDS[4] + ' ';
  await button(fixture.app, 'Replace phrase').onclick();
  assert.equal(error(fixture.app), 'word 2 does not match');
  assert.equal(fixture.requests.some(r => r.url.endsWith('/confirm')), false);
  typed[1].value = WORDS[1];
  await button(fixture.app, 'Replace phrase').onclick();
  assert.equal(error(fixture.app), 'word 5 does not match');
  assert.equal(fixture.requests.some(r => r.url.endsWith('/confirm')), false);
  typed[4].value = WORDS[4];
  await button(fixture.app, 'Replace phrase').onclick();
  assert.deepEqual(fixture.requests.find(r => r.url.endsWith('/confirm')).body.words, WORDS);
  assert.ok(fixture.app.textContent.includes('Phrase replaced.'));
});

test('antibody_ui_refresh_exact_typeback_sends_raw_drawn_words', async t => {
  const fixture = setup(t);
  const drawn = WORDS.map(word => word[0].toUpperCase() + word.slice(1));
  let sent;
  mountPhraseCeremony(fixture.app, { words: drawn, entropy_bits: 69 }, {
    exact: true, label: 'confirm', onDone: () => {}, doneText: 'done',
    confirm: words => { sent = words; },
  });
  button(fixture.app, 'I have them — hide the words').onclick();
  inputs(fixture.app).forEach((input, i) => { input.value = drawn[i]; });
  await button(fixture.app, 'confirm').onclick();
  assert.deepEqual(sent, drawn);
});

test('initial_binding_typeback_retains_case_and_space_normalization', async t => {
  const fixture = setup(t);
  let sent;
  mountPhraseCeremony(fixture.app, { words: WORDS, entropy_bits: 69 }, {
    label: 'bind', onDone: () => {}, doneText: 'done', confirm: words => { sent = words; },
  });
  button(fixture.app, 'I have them — hide the words').onclick();
  inputs(fixture.app).forEach((input, i) => { input.value = ` ${WORDS[i].toUpperCase()} `; });
  await button(fixture.app, 'bind').onclick();
  assert.deepEqual(sent, WORDS);
});

test('antibody_ui_refresh_incomplete_current_phrase_never_prompts_passkey', async t => {
  const fixture = setup(t);
  await showIdentity(fixture.app);
  button(fixture.app, 'Replace phrase').onclick();
  current(fixture.app).value = 'only six typed current words here';
  await button(fixture.app, 'Continue').onclick();
  assert.equal(error(fixture.app), 'all seven current words are needed');
  assert.equal(fixture.options.length, 0);
  assert.equal(fixture.requests.some(r => r.url === '/api/binding/refresh'), false);
});

test('antibody_ui_refresh_tampered_c5_never_prompts_or_prepares', async t => {
  const mutations = [
    ch => { ch.card.says = 'another effect'; },
    ch => { ch.display_sha256 = '00'.repeat(32); },
    ch => { ch.auth.display_sha256 = '00'.repeat(32); seal(ch); },
    ch => { ch.auth.challenge = '44'.repeat(32); },
    ch => { ch.public_key.challenge = 'AA'; },
    ch => { ch.public_key.challenge = Buffer.concat([Buffer.from(ch.public_key.challenge, 'base64url'), Buffer.from([1])]).toString('base64url'); },
    ch => { ch.auth.op = 'apply'; seal(ch); },
    ch => { ch.auth.target = 'other/target'; sign(ch); },
    ch => { ch.auth.proposal = '55'.repeat(16); seal(ch); },
    ch => { ch.auth.node = '66'.repeat(16); sign(ch); },
    ch => { ch.auth.subject = 'aukora:1:' + '77'.repeat(32); seal(ch); },
    ch => { ch.auth.epoch = 0; seal(ch); },
    ch => { ch.auth.epoch = '1'; seal(ch); },
    ch => { ch.auth.v = 2; seal(ch); },
    ch => { ch.auth.expires_at = Date.now() - 1; seal(ch); },
    ch => { ch.auth.expires_at = String(Date.now() + 120000); seal(ch); },
    ch => { ch.auth.operation = '88'.repeat(32); seal(ch); },
  ];
  for (const [i, patch] of mutations.entries()) await t.test(`tamper ${i}`, async t => {
    const fixture = setup(t, { patch });
    await showIdentity(fixture.app);
    button(fixture.app, 'Replace phrase').onclick();
    current(fixture.app).value = CURRENT;
    const action = button(fixture.app, 'Continue').onclick();
    await waitFor(() => error(fixture.app) || button(fixture.app, 'Touch ID — replace phrase'));
    if (button(fixture.app, 'Touch ID — replace phrase')) await button(fixture.app, 'Touch ID — replace phrase').onclick();
    await action;
    assert.ok(['gate:card-changed', 'aumlok:refresh-challenge-mismatch'].includes(error(fixture.app)));
    assert.equal(fixture.options.length, 0);
    assert.equal(button(fixture.app, 'Touch ID — replace phrase'), undefined);
    assert.equal(fixture.requests.some(r => r.url.endsWith('/prepare')), false);
  });
});

test('antibody_ui_refresh_cancelled_passkey_never_prepares', async t => {
  const fixture = setup(t, { credential: false });
  await reveal(fixture);
  assert.equal(error(fixture.app), 'aumlok:approval-cancelled');
  assert.equal(fixture.requests.some(r => r.url.endsWith('/prepare')), false);
  assert.deepEqual([...fixture.store], []);
});

test('antibody_ui_refresh_without_webauthn_never_prepares', async t => {
  const fixture = setup(t);
  window.PublicKeyCredential = undefined;
  await reveal(fixture);
  assert.equal(error(fixture.app), 'aumlok:webauthn-unavailable');
  assert.equal(fixture.options.length, 0);
  assert.equal(fixture.requests.some(r => r.url.endsWith('/prepare')), false);
});

test('antibody_ui_refresh_remote_dev_bypass_requires_passkey', async t => {
  const fixture = setup(t, { patch: ch => { ch.dev_bypass = true; } });
  await reveal(fixture);
  assert.equal(fixture.options.length, 1);
  assert.equal(fixture.requests.find(r => r.url.endsWith('/prepare')).body.assertion.kind, 'passkey');
});

test('antibody_ui_refresh_local_fixture_assertion_is_challenge_bound', async t => {
  const fixture = setup(t, { hostname: 'localhost', patch: ch => { ch.dev_bypass = true; } });
  await reveal(fixture);
  assert.equal(fixture.options.length, 0);
  const sent = fixture.requests.find(r => r.url.endsWith('/prepare'));
  assert.equal(sent.body.assertion.kind, 'dev-bypass');
  assert.equal(typeof sent.body.assertion.challenge, 'string');
});

test('antibody_ui_refresh_restart_saves_only_id_and_asks_current_phrase_again', async t => {
  const fixture = setup(t);
  await reveal(fixture);
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
  const before = fixture.requests.length;
  await showIdentity(fixture.app);
  assert.ok(button(fixture.app, 'Resume phrase replacement'));
  button(fixture.app, 'Resume phrase replacement').onclick();
  assert.equal(current(fixture.app).value, '');
  assert.equal(fixture.app.textContent.includes(WORDS[0]), false);
  assert.equal(fixture.requests.length, before + 1);
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Resume replacement').onclick();
  const sent = fixture.requests.at(-1);
  assert.deepEqual(sent, { url: '/api/binding/refresh/resume', body: { ceremony_id: REFRESH, current_phrase: CURRENT } });
  assert.equal(fixture.options.length, 1);
  assert.ok(fixture.app.textContent.includes(WORDS[0]));
});

test('antibody_ui_refresh_resume_refusal_never_reveals_words', async t => {
  const fixture = setup(t, { store: new Map([[KEY, REFRESH]]), failure: 'aumlok:current-phrase' });
  await showIdentity(fixture.app);
  button(fixture.app, 'Resume phrase replacement').onclick();
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Resume replacement').onclick();
  assert.equal(error(fixture.app), 'aumlok:current-phrase');
  assert.equal(current(fixture.app).value, '');
  assert.equal(fixture.app.textContent.includes(WORDS[0]), false);
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
});

test('antibody_ui_refresh_stale_session_ceremony_is_cleared', async t => {
  const fixture = setup(t, { store: new Map([[KEY, REFRESH]]), failure: 'aumlok:ceremony-principal' });
  await showIdentity(fixture.app);
  button(fixture.app, 'Resume phrase replacement').onclick();
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Resume replacement').onclick();
  assert.equal(error(fixture.app), 'aumlok:ceremony-principal; the replacement may have completed: try your new phrase, else the old one');
  assert.deepEqual([...fixture.store], []);
  assert.ok(button(fixture.app, 'Continue'));
});


test('antibody_ui_signout_requests_never_supply_authorization', async t => {
  const fixture = setup(t);
  const assertion = { kind: 'passkey', credential_id: 'AQ' };
  await api.logout();
  await api.logoutEverywhere();
  await api.logoutEverywhereConfirm(ID, assertion);
  assert.deepEqual(fixture.requests, [
    { url: '/api/logout', body: {} },
    { url: '/api/logout/everywhere', body: {} },
    { url: '/api/logout/everywhere/confirm', body: { ceremony_id: ID, assertion } },
  ]);
});

test('antibody_ui_signout_revokes_presenting_session_without_passkey', async t => {
  const fixture = setup(t);
  let returned = 0;
  addSignOut(fixture.app, { onDone: () => returned++ });
  await button(fixture.app, 'Sign out').onclick();
  assert.deepEqual(fixture.requests, [{ url: '/api/logout', body: {} }]);
  assert.equal(fixture.options.length, 0);
  assert.equal(returned, 1);
});

test('antibody_ui_bootstrap_and_owner_navigation_keep_signout_reachable', async t => {
  for (const state of ['claim-open', 'enrolled', 'bound']) await t.test(state, async t => {
    const fixture = setup(t, { respond: url => url === '/api/state' ? json({ ...STATE, state }) : undefined });
    document.body = { classList: { toggle() {} } };
    document.getElementById = () => fixture.app;
    window.addEventListener = () => {};
    location.hash = '#/identity';
    let reloads = 0;
    location.reload = () => reloads++;
    await import(`../app.js?signout_state=${state}`);
    await waitFor(() => button(fixture.app, 'Sign out'));
    await button(fixture.app, 'Sign out').onclick();
    assert.equal(fixture.requests.at(-1).url, '/api/logout');
    assert.equal(reloads, 1);
  });
});

function logoutCeremony() {
  const ch = ceremony();
  ch.card.says = 'Sign out every owner session';
  ch.auth.target = 'aumlok/session/revoke-all';
  ch.display_sha256 = hash(canonicalJSON(ch.card));
  ch.auth.display_sha256 = ch.display_sha256;
  sign(ch);
  return ch;
}

test('antibody_ui_signout_everywhere_requires_review_and_passkey_before_dispatch', async t => {
  const fixture = setup(t, { respond: url => url === '/api/logout/everywhere' ? json(logoutCeremony()) : undefined });
  let returned = 0;
  addSignOutEverywhere(fixture.app, STATE, { onDone: () => returned++ });
  await button(fixture.app, 'Sign out everywhere').onclick();
  assert.equal(fixture.options.length, 0);
  assert.equal(fixture.requests.some(r => r.url.endsWith('/confirm')), false);
  assert.ok(descendants(fixture.app).some(el => el.innerHTML?.includes('Sign out every owner session')));
  await button(fixture.app, 'Touch ID — sign out everywhere').onclick();
  assert.equal(fixture.options.length, 1);
  assert.equal(fixture.options[0].publicKey.userVerification, 'required');
  assert.deepEqual(Object.keys(fixture.requests.at(-1).body).sort(), ['assertion', 'ceremony_id']);
  assert.equal(fixture.requests.at(-1).body.assertion.kind, 'passkey');
  assert.equal(returned, 1);
});

test('antibody_ui_signout_everywhere_refuses_wrong_target_subject_and_challenge_without_prompt', async t => {
  const changes = [
    ch => { ch.auth.target = 'aumlok/binding/refresh'; sign(ch); },
    ch => { ch.auth.subject = 'aukora:1:' + '88'.repeat(32); seal(ch); },
    ch => { ch.public_key.challenge = 'AA'; },
  ];
  for (const [index, change] of changes.entries()) await t.test(String(index), async t => {
    const fixture = setup(t, { respond: url => {
      if (url !== '/api/logout/everywhere') return;
      const ch = logoutCeremony(); change(ch); return json(ch);
    } });
    addSignOutEverywhere(fixture.app, STATE);
    await button(fixture.app, 'Sign out everywhere').onclick();
    assert.equal(error(fixture.app), 'aumlok:session-challenge-mismatch');
    assert.equal(fixture.options.length, 0);
    assert.equal(button(fixture.app, 'Touch ID — sign out everywhere'), undefined);
    assert.equal(fixture.requests.some(r => r.url.endsWith('/confirm')), false);
  });
});

test('antibody_ui_signout_everywhere_cancelled_passkey_cannot_revoke', async t => {
  const fixture = setup(t, { credential: false, respond: url => url === '/api/logout/everywhere' ? json(logoutCeremony()) : undefined });
  addSignOutEverywhere(fixture.app, STATE);
  await button(fixture.app, 'Sign out everywhere').onclick();
  await button(fixture.app, 'Touch ID — sign out everywhere').onclick();
  assert.equal(error(fixture.app), 'aumlok:approval-cancelled');
  assert.equal(fixture.requests.some(r => r.url.endsWith('/confirm')), false);
});

test('antibody_ui_foreign_refresh_live_reports_retry_time_without_passkey', async t => {
  const expires = Date.now() + 300000;
  const fixture = setup(t, { respond: url => url === '/api/binding/refresh'
    ? json({ error: 'aumlok:refresh-live', expires_at: expires }, 409) : undefined });
  await showIdentity(fixture.app);
  button(fixture.app, 'Replace phrase').onclick();
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Continue').onclick();
  assert.ok(error(fixture.app).includes(new Date(expires).toLocaleString()));
  assert.ok(error(fixture.app).includes('Sign out everywhere'));
  assert.equal(fixture.options.length, 0);
  assert.equal(fixture.requests.some(r => r.url.endsWith('/prepare')), false);
  assert.ok(button(fixture.app, 'Back to Identity'));
  await button(fixture.app, 'Back to Identity').onclick();
  assert.ok(button(fixture.app, 'Sign out everywhere'));
});

test('antibody_ui_committed_refresh_cancel_reports_completion_in_resumed_and_drawn_views', async t => {
  for (const resumed of [true, false]) await t.test(String(resumed), async t => {
    const fixture = setup(t, { store: resumed ? new Map([[KEY, REFRESH]]) : new Map(), respond: url => url.endsWith('/cancel')
      ? json({ ok: true, state: 'committed', subject: STATE.subject }) : undefined });
    if (resumed) { await showIdentity(fixture.app); button(fixture.app, 'Resume phrase replacement').onclick(); }
    else await reveal(fixture);
    await button(fixture.app, 'Cancel replacement').onclick();
    assert.ok(fixture.app.textContent.includes('Phrase replaced.'));
    assert.ok(fixture.app.textContent.includes('Download the new envelope backup.'));
    assert.deepEqual([...fixture.store], []);
  });
});

test('antibody_ui_lost_confirm_response_explains_uncertain_phrase_outcome', async t => {
  const fixture = setup(t, { respond: url => {
    if (url.endsWith('/confirm')) throw new Error('lost confirm response');
  } });
  await reveal(fixture);
  button(fixture.app, 'I have them — hide the words').onclick();
  inputs(fixture.app).forEach((input, i) => { input.value = WORDS[i]; });
  await button(fixture.app, 'Replace phrase').onclick();
  assert.ok(error(fixture.app).includes('the replacement may have completed: try your new phrase, else the old one'));
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
});

test('antibody_ui_other_session_refresh_resume_explains_uncertain_phrase_outcome', async t => {
  const fixture = setup(t, { store: new Map([[KEY, REFRESH]]), failure: 'aumlok:ceremony-principal' });
  await showIdentity(fixture.app);
  button(fixture.app, 'Resume phrase replacement').onclick();
  current(fixture.app).value = CURRENT;
  await button(fixture.app, 'Resume replacement').onclick();
  assert.ok(error(fixture.app).includes('the replacement may have completed: try your new phrase, else the old one'));
  assert.equal(fixture.options.length, 0);
  assert.equal(fixture.app.textContent.includes(WORDS[0]), false);
});


test('antibody_ui_refresh_session_refusal_explains_uncertain_phrase_outcome', async t => {
  const fixture = setup(t, { respond: url => url.endsWith('/confirm')
    ? json({ error: 'frontdoor:session-required' }, 401) : undefined });
  await reveal(fixture);
  button(fixture.app, 'I have them — hide the words').onclick();
  inputs(fixture.app).forEach((input, i) => { input.value = WORDS[i]; });
  await button(fixture.app, 'Replace phrase').onclick();
  assert.ok(error(fixture.app).includes('the replacement may have completed: try your new phrase, else the old one'));
  assert.deepEqual([...fixture.store], [[KEY, REFRESH]]);
});
