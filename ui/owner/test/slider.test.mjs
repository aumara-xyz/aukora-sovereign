import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJSON } from '../canon.js';
import { mountSlider } from '../slider.js';

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.style = {}; this.dataset = {}; }
  appendChild(child) { child.remove(); this.children.push(child); child.parent = this; return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren() { this.children.forEach(child => { child.parent = null; }); this.children = []; }
  set innerHTML(html) { this.html = html; this.replaceChildren(); if (html.startsWith('<article')) this.appendChild(new Element('article')); }
  get firstElementChild() { return this.children[0]; }
  setAttribute(key, value) { this[key] = value; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
}
const descendants = element => [element, ...element.children.flatMap(descendants)];
const find = (app, label) => descendants(app).find(el => el.textContent === label);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const target = 'plugins/owner-note/note.md';
const id = 'ab'.repeat(16);
const json = body => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
function setup(t, { patch = () => {}, cancelled = false } = {}) {
  const names = ['document', 'location', 'window', 'navigator', 'fetch'];
  const old = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  const requests = []; const prompts = []; let desired;
  let status = { mode: 'ask', active: false, remaining: 0, available_targets: [target], targets: [] };
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement: tag => new Element(tag) } });
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { hostname: 'owner.example' } });
  Object.defineProperty(globalThis, 'window', { configurable: true, value: { PublicKeyCredential: {} } });
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { credentials: { get: async options => {
    prompts.push(options);
    return cancelled ? null : { rawId: new Uint8Array([1]), response: { clientDataJSON: new Uint8Array([2]), authenticatorData: new Uint8Array([3]), signature: new Uint8Array([4]), userHandle: null } };
  } } } });
  Object.defineProperty(globalThis, 'fetch', { configurable: true, value: async (url, init) => {
    const body = init.body ? JSON.parse(init.body) : undefined; requests.push({ url, body });
    if (url === '/api/slider') return json(status);
    if (url === '/api/slider/propose') { desired = body; return json({ id }); }
    if (url === '/api/approvals/challenge') {
      const record = { v: 1, mode: desired.mode, targets: desired.targets, kinds: ['put'], max_count: desired.max_count, expires_at: 2000000000000, nonce: 'a'.repeat(32) };
      const card = { v: 1, risk: 'critical', says: 'Choose when to ask', facts: [], from_to: { base: null, new: canonicalJSON(record) }, model_note: '' };
      const auth = { v: 1, op: 'permission', proposal: id, target: 'gate/permission', display_sha256: hash(canonicalJSON(card)), new_sha256: hash(card.from_to.new) };
      const ch = { id, auth, card, display_sha256: auth.display_sha256, public_key: {} };
      patch(ch);
      ch.public_key.challenge = createHash('sha256').update('aukora:owner-authorization:v1\0' + canonicalJSON(ch.auth)).digest('base64url');
      return json(ch);
    }
    if (url === '/api/approvals/decide') {
      status = { ...status, ...desired, active: desired.mode !== 'ask', remaining: desired.max_count, expires_at: 2000000000000 };
      return json({ state: 'applied' });
    }
    throw new Error(url);
  } });
  t.after(() => names.forEach((name, i) => { if (old[i]) Object.defineProperty(globalThis, name, old[i]); else delete globalThis[name]; }));
  return { app: new Element('div'), requests, prompts };
}
async function prepare(context, mode = 1) {
  await mountSlider(context.app);
  const range = descendants(context.app).find(el => el.type === 'range');
  assert.equal(range.max, '2'); range.value = String(mode); range.oninput();
  const check = descendants(context.app).find(el => el.type === 'checkbox'); check.checked = true;
  await find(context.app, 'Review preference').onclick();
}

test('antibody_slider_passkey_required_and_preference_changes_only_after_applied', async t => {
  const context = setup(t); await prepare(context);
  assert.equal(context.prompts.length, 0);
  assert.equal(context.requests.filter(r => r.url.endsWith('/decide')).length, 0);
  assert.ok(find(context.app, 'Asking for every change'));
  await find(context.app, 'Approve preference with passkey').onclick();
  assert.equal(context.prompts.length, 1);
  assert.equal(context.prompts[0].publicKey.userVerification, 'required');
  const decided = context.requests.find(r => r.url.endsWith('/decide'));
  assert.equal(decided.body.assertion.kind, 'passkey');
  assert.ok(descendants(context.app).some(el => el.textContent?.includes('20 changes left')));
});

test('antibody_slider_cancelled_passkey_never_changes_position', async t => {
  const context = setup(t, { cancelled: true }); await prepare(context, 2);
  await find(context.app, 'Approve preference with passkey').onclick();
  assert.equal(context.requests.filter(r => r.url.endsWith('/decide')).length, 0);
  assert.ok(find(context.app, 'Asking for every change'));
});

test('antibody_slider_refuses_changed_card_target_and_signed_scope_before_passkey', async t => {
  for (const patch of [ch => { ch.card.says = 'changed'; }, ch => { ch.auth.target = 'release'; }, ch => {
    ch.card.from_to.new = ch.card.from_to.new.replace(target, 'plugins/other/note.md');
    ch.auth.new_sha256 = hash(ch.card.from_to.new);
    ch.auth.display_sha256 = hash(canonicalJSON(ch.card)); ch.display_sha256 = ch.auth.display_sha256;
  }]) {
    const context = setup(t, { patch }); await prepare(context);
    assert.equal(find(context.app, 'Approve preference with passkey'), undefined);
    assert.equal(context.prompts.length, 0);
    assert.ok(find(context.app, 'gate:permission-mismatch'));
  }
});

test('antibody_slider_revocation_signs_ask_with_zero_scope_and_count', async t => {
  const context = setup(t); await prepare(context, 0);
  const proposed = context.requests.find(r => r.url === '/api/slider/propose').body;
  assert.deepEqual(proposed, { mode: 'ask', targets: [], max_count: 0, hours: 24 });
  await find(context.app, 'Approve preference with passkey').onclick();
  assert.equal(context.prompts.length, 1);
  assert.ok(find(context.app, 'Asking for every change'));
});
