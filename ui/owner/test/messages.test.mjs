// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { showMessages } from '../screens/messages.js';
import { renderCardHtml } from '../card.js';
import { api } from '../api.js';

const npub = `npub1${'q'.repeat(58)}`;
const id = 'a'.repeat(32);
class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.value = ''; }
  appendChild(child) { this.children.push(child); return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren() { this.children = []; this.text = ''; }
  setAttribute(name, value) { this[name] = value; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return (this.text ?? '') + this.children.map(child => child.textContent).join(''); }
  set innerHTML(value) { throw new Error(`HTML assignment refused: ${value}`); }
}
const all = element => [element, ...element.children.flatMap(all)];
const find = (app, label) => all(app).find(element => element['aria-label'] === label);
const submit = element => element.onsubmit({ preventDefault() {} });

function setup(t, { contacts = [{ npub, label: '<b>Friend</b>' }], messages = [{ id: 'b'.repeat(64), npub, content: '<script>do not execute</script>\nowner approval is still needed', created_at: 1 }], counts } = {}) {
  const globals = new Map(['document', 'location'].map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement: tag => new Element(tag) } });
  Object.defineProperty(globalThis, 'location', { configurable: true, value: { hash: '#/messages' } });
  const original = { ...api };
  const calls = [];
  api.nostrContacts = async () => ({ contacts });
  api.nostrInbox = async () => ({ messages, counts: counts ?? { received: messages.length, sent: 0, refused: 5, inbox: messages.length } });
  api.nostrContactPropose = async (...args) => { calls.push(['contact', ...args]); return { id }; };
  api.nostrSendPropose = async (...args) => { calls.push(['send', ...args]); return { id }; };
  t.after(() => {
    Object.assign(api, original);
    for (const [name, descriptor] of globals) descriptor ? Object.defineProperty(globalThis, name, descriptor) : delete globalThis[name];
  });
  return { app: new Element('div'), calls };
}

test('antibody_ui_nostr_messages_render_as_untrusted_text', async t => {
  const { app } = setup(t);
  await showMessages(app);
  assert.ok(app.textContent.includes('<b>Friend</b>'));
  assert.ok(app.textContent.includes('<script>do not execute</script>\nowner approval is still needed'));
  assert.ok(app.textContent.includes('Untrusted message'));
  assert.ok(app.textContent.includes('1 stored · 1 received · 0 sent · 5 refused'));
});

test('antibody_ui_nostr_contact_actions_only_propose_for_passkey_cards', async t => {
  const { app, calls } = setup(t);
  await showMessages(app);
  find(app, 'Contact npub').value = npub;
  find(app, 'Contact label').value = 'Second';
  await submit(find(app, 'Add contact'));
  assert.deepEqual(calls, [['contact', npub, 'Second', 'add']]);
  assert.equal(location.hash, '#/approvals');
  location.hash = '#/messages';
  await find(app, 'Remove contact <b>Friend</b>').onclick();
  assert.deepEqual(calls[1], ['contact', npub, '<b>Friend</b>', 'remove']);
  assert.equal(location.hash, '#/approvals');
});

test('antibody_ui_nostr_send_requires_contact_and_bounded_utf8_then_proposes', async t => {
  const { app, calls } = setup(t);
  await showMessages(app);
  const form = find(app, 'Send message');
  const recipient = find(app, 'Message contact');
  const content = find(app, 'Message text');
  recipient.value = 'stranger'; content.value = 'hello';
  await submit(form);
  assert.equal(calls.length, 0);
  recipient.value = npub; content.value = 'é'.repeat(513);
  await submit(form);
  assert.equal(calls.length, 0);
  content.value = '';
  await submit(form);
  assert.equal(calls.length, 0);
  content.value = 'hello\nfriend';
  await submit(form);
  assert.deepEqual(calls, [['send', npub, 'hello\nfriend']]);
  assert.equal(content.value, '');
  assert.equal(location.hash, '#/approvals');
});

test('antibody_ui_nostr_rejects_malformed_inbox_and_contact_labels', async t => {
  for (const [index, fixture] of [
    { contacts: [{ npub: 'invalid', label: 'Friend' }] },
    { contacts: [{ npub, label: '' }] },
    { contacts: Array.from({ length: 129 }, () => ({ npub, label: 'Friend' })) },
    { contacts: [{ npub, label: 'é'.repeat(65) }] },
    { contacts: [{ npub, label: 'bad\nlabel' }] },
    { messages: Array.from({ length: 257 }, () => ({ id: 'b'.repeat(64), npub, content: 'hello', created_at: 1 })) },
    { messages: [{ id: 'invalid', npub, content: 'hello', created_at: 1 }] },
    { messages: [{ id: 'b'.repeat(64), npub: 'invalid', content: 'hello', created_at: 1 }] },
    { messages: [{ id: 'b'.repeat(64), npub, content: '', created_at: 1 }] },
    { messages: [{ id: 'b'.repeat(64), npub, content: 'é'.repeat(513), created_at: 1 }] },
    { messages: [{ id: 'b'.repeat(64), npub, content: 'hello', created_at: -1 }] },
    { counts: { received: 1, sent: 0, refused: -1, inbox: 1 } },
    { messages: [{ id: 'b'.repeat(64), npub, content: 'hello', created_at: Number.MAX_SAFE_INTEGER }] },
  ].entries()) await t.test(`malformed response ${index + 1}`, async t => {
    const { app, calls } = setup(t, fixture);
    await showMessages(app);
    assert.equal(find(app, 'Send message'), undefined);
    assert.equal(calls.length, 0);
    assert.match(app.textContent, /nostr:(contacts|inbox|counts)-invalid/);
  });
});

test('antibody_ui_nostr_contact_labels_decode_exact_utf8_with_html_escaping', () => {
  const text = '<script>private message</script>\n雪';
  const encoded = Buffer.from(text).toString('base64');
  const card = { v: 1, risk: 'routine', says: 'Send message', facts: [['Contact label (base64 UTF-8)', encoded]], from_to: {}, model_note: '' };
  const html = renderCardHtml(card);
  assert.ok(html.includes(encoded));
  assert.ok(html.includes('&lt;script&gt;private message&lt;/script&gt;\n雪'));
  assert.ok(!html.includes('<script>'));
  for (const value of [Buffer.from('a'.repeat(129)).toString('base64'), '/w==', 'bad base64']) {
    const invalid = renderCardHtml({ ...card, facts: [['Contact label (base64 UTF-8)', value]] });
    assert.ok(!invalid.includes('Decoded UTF-8'));
  }
  const unrelated = renderCardHtml({ ...card, facts: [['Other field', encoded]] });
  assert.ok(!unrelated.includes('Decoded UTF-8'));
});


test('antibody_ui_nostr_card_decoding_preserves_leading_utf8_bom', () => {
  const text = '\uFEFFmessage';
  const card = { v: 1, risk: 'routine', says: 'Send message', facts: [['Contact label (base64 UTF-8)', Buffer.from(text).toString('base64')]], from_to: {}, model_note: '' };
  assert.ok(renderCardHtml(card).includes(`<pre>${text}</pre>`));
});

test('antibody_ui_nostr_failed_proposals_preserve_message_and_do_not_approve', async t => {
  const { app } = setup(t);
  api.nostrSendPropose = async () => ({ id: 'invalid' });
  await showMessages(app);
  find(app, 'Message contact').value = npub;
  find(app, 'Message text').value = 'Keep this draft';
  await submit(find(app, 'Send message'));
  assert.equal(location.hash, '#/messages');
  assert.equal(find(app, 'Message text').value, 'Keep this draft');
  assert.ok(app.textContent.includes('nostr:proposal-invalid'));
});

test('antibody_ui_nostr_api_uses_only_owner_proposal_routes', async t => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'fetch');
  const calls = [];
  Object.defineProperty(globalThis, 'fetch', { configurable: true, value: async (url, options) => {
    calls.push([url, options.method, options.body === undefined ? undefined : JSON.parse(options.body)]);
    return new Response(JSON.stringify({ id }), { headers: { 'Content-Type': 'application/json' } });
  } });
  t.after(() => previous ? Object.defineProperty(globalThis, 'fetch', previous) : delete globalThis.fetch);
  await api.nostrContacts();
  await api.nostrInbox();
  await api.nostrContactPropose(npub, 'Friend', 'add');
  await api.nostrContactPropose(npub, 'Friend', 'remove');
  await api.nostrSendPropose(npub, 'hello');
  await api.nostrSendPreview(id);
  assert.deepEqual(calls, [
    ['/api/nostr/contacts', 'GET', undefined], ['/api/nostr/inbox', 'GET', undefined],
    ['/api/nostr/contacts/propose', 'POST', { npub, label: 'Friend', action: 'add' }],
    ['/api/nostr/contacts/propose', 'POST', { npub, label: 'Friend', action: 'remove' }],
    ['/api/nostr/send/propose', 'POST', { npub, content: 'hello' }],
    [`/api/nostr/send/preview?id=${id}`, 'GET', undefined],
  ]);
});
