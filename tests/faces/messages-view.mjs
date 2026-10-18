// SPDX-License-Identifier: AGPL-3.0-or-later
// Run the real face against a small DOM and owner-service fixture, without a browser or server.
//   node --test tests/faces/messages-view.mjs
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

const compiled = await mkdtemp(join(tmpdir(), 'messages-view-'));
let mountMessages;
try {
  await writeFile(join(compiled, 'package.json'), '{"type":"module"}');
  for (const path of [
    'faces/messages/view', 'faces/messages/actions', 'faces/messages/portal', 'faces/messages/dom',
    'faces/messages/copy', 'faces/messages/model', 'faces/identity/card', 'faces/identity/qr', 'faces/threads/time', 'core/service-state',
    'core/session-state',
    'faces/threads/spatial-icons', 'faces/threads/dom',
  ]) {
    const destination = join(compiled, `${path}.js`);
    await mkdir(dirname(destination), { recursive: true });
    const source = await readFile(new URL(`../../app/${path}.ts`, import.meta.url), 'utf8');
    await writeFile(destination, stripTypeScriptTypes(source));
  }
  // The thread list's glyphs, which the filters and row actions share.
  await mkdir(join(compiled, 'design/spatial'), { recursive: true });
  await writeFile(join(compiled, 'design/spatial/glyphs.json'), await readFile(new URL('../../app/design/spatial/glyphs.json', import.meta.url)));
  ({ mountMessages } = await import(pathToFileURL(join(compiled, 'faces/messages/view.js')).href));
} finally { await rm(compiled, { recursive: true, force: true }); }

class Text {
  nodeType = 3;
  parentNode = null;
  constructor(value) { this.textContent = value; }
  remove() {
    if (!this.parentNode) return;
    this.parentNode.childNodes.splice(this.parentNode.childNodes.indexOf(this), 1);
    this.parentNode = null;
  }
}

class Element extends Text {
  nodeType = 1;
  childNodes = [];
  attributes = {};
  dataset = {};
  listeners = new Map();
  hidden = false;
  disabled = false;
  required = false;
  value = '';
  scrollTop = 0;
  clientHeight = 100;
  drawing = [];
  constructor(tagName, document) { super(''); this.tagName = tagName; this.ownerDocument = document; }
  get children() { return this.childNodes.filter(child => child.nodeType === 1); }
  get parentElement() { return this.parentNode; }
  get textContent() { return (this.childNodes ?? []).map(child => child.textContent).join(''); }
  set textContent(value) {
    for (const child of this.childNodes ?? []) child.parentNode = null;
    this.childNodes = [];
    if (value) this.append(String(value));
  }
  get scrollHeight() { return 100 + descendants(this).length * 10; }
  get isConnected() { return this === this.ownerDocument.body || this.parentNode?.isConnected === true; }
  append(...children) {
    for (const child of children) {
      const node = typeof child === 'string' ? new Text(child) : child;
      node.remove(); node.parentNode = this; this.childNodes.push(node);
    }
  }
  replaceChildren(...children) { this.textContent = ''; this.append(...children); }
  insertBefore(child, reference) {
    child.remove();
    const at = reference === null ? this.childNodes.length : this.childNodes.indexOf(reference);
    assert.ok(at >= 0, 'reference belongs to the parent');
    child.parentNode = this; this.childNodes.splice(at, 0, child);
  }
  setAttribute(key, value) {
    this.attributes[key] = value;
    if (key.startsWith('data-')) this.dataset[key.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
    if (key === 'class') this.className = value;
    if (['name', 'pattern', 'type'].includes(key)) this[key] = value;
    if (['hidden', 'disabled', 'required'].includes(key)) this[key] = true;
  }
  getAttribute(key) { return this.attributes[key] ?? null; }
  removeAttribute(key) { delete this.attributes[key]; if (['hidden', 'disabled', 'required'].includes(key)) this[key] = false; }
  addEventListener(type, handler, options = {}) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push({ handler, signal: options.signal }); this.listeners.set(type, listeners);
  }
  dispatch(type) {
    const event = { type, target: this, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
    for (const listener of this.listeners.get(type) ?? []) if (!listener.signal?.aborted) listener.handler(event);
    return event;
  }
  click() { if (!this.disabled) this.dispatch('click'); }
  focus() { this.ownerDocument.activeElement = this; }
  reportValidity() {
    return descendants(this).every(field => !['input', 'textarea'].includes(field.tagName)
      || ((!field.required || field.value.length > 0) && (!field.pattern || new RegExp(`^(?:${field.pattern})$`).test(field.value))));
  }
  reset() { for (const field of descendants(this)) if (['input', 'textarea'].includes(field.tagName)) field.value = ''; }
  getClientRects() {
    for (let node = this; node; node = node.parentNode) if (node.hidden) return [];
    return this.isConnected ? [{}] : [];
  }
  getContext() { return { fillRect: (...args) => this.drawing.push(args) }; }
}

function descendants(element) { return element.children.flatMap(child => [child, ...descendants(child)]); }
function all(element, match) { return descendants(element).filter(match); }
function find(element, match) {
  const result = all(element, match)[0];
  assert.ok(result, 'expected element exists'); return result;
}
const hasClass = (element, name) => element.className?.split(' ').includes(name);
const byClass = (element, name) => find(element, item => hasClass(item, name));
const button = (element, text) => find(element, item => item.tagName === 'button' && item.textContent === text);
const settle = () => new Promise(resolve => setImmediate(resolve));
const key = digit => `npub1${digit.repeat(58)}`;
const maya = key('q');
const sam = key('p');
const owner = key('z');
const identity = {
  label: 'Peter', subject: `aukora:1:${'1'.repeat(64)}`, node_npub: owner, node_key_bound: true,
  agent_npub: null, contact_code: null, safety: [],
};
const message = (id, contact, at, direction, text = id) => ({
  id, contact, at, direction, text, transport: 'nostr-relays', state: direction === 'in' ? null : 'published', code: null,
});

function mount(t, options = {}) {
  const document = {
    hidden: false, activeElement: null, selected: null, copied: false,
    createElement(tagName) { return new Element(tagName, this); },
    createElementNS(_namespace, tagName) { return this.createElement(tagName); },
    createRange() { return { selectNodeContents: element => { document.selected = element; } }; },
    getSelection() { return { removeAllRanges() {}, addRange() {} }; },
    execCommand(command) { assert.equal(command, 'copy'); return this.copied; },
  };
  document.body = document.createElement('body');
  const root = document.createElement('main');
  document.body.append(root);
  globalThis.document = document;
  const controller = new AbortController();
  const calls = [];
  const contacts = options.contacts ?? [{ npub: maya, label: 'Maya', pairing: null }, { npub: sam, label: 'Sam', pairing: null }];
  const messages = [
    message('new', maya, 30, 'in', 'See you at five?'), message('middle', maya, 20, 'out', 'A walk sounds lovely.'),
    message('old', maya, 10, 'in', 'Are you free later?'), message('sam', sam, 5, 'in', 'I found the book.'),
  ];
  const client = {
    async call(service, method, params, callOptions) {
      assert.equal(callOptions.signal, controller.signal, 'all reads and owner actions share the face lifetime');
      calls.push({ service, method, params: structuredClone(params) });
      if (service === 'aumlok' && method === 'identity') return identity;
      assert.equal(service, 'network');
      if (method === 'contacts.list') return { items: contacts, next: null };
      if (method === 'messages.list') {
        if (options.page && params.npub === maya && params.limit !== 1) return options.page(params);
        const scoped = messages.filter(item => !params.npub || item.contact === params.npub);
        return { items: scoped.slice(0, params.limit), next: null };
      }
      if (method === 'send') return options.send ? options.send(params) : {};
      if (method === 'contact.propose') return {};
      if (method === 'conversations.marks') return { items: options.marks ?? [] };
      if (method === 'conversation.mark') return options.mark ? options.mark(params) : {};
      if (method === 'refusals.counts') return { envelope: 0, signature: 0, recipient: 0, stranger: 0, replay: 0, payload: 0, stale_contact: 0, total: 0, last_aura_sequence: 0 };
      assert.fail(`unexpected method: ${method}`);
    },
  };
  // The face re-reads on its own every few seconds; the tests move that clock by hand.
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const live = async () => { t.mock.timers.tick(6_000); for (let turn = 0; turn < 6; turn++) await settle(); };
  mountMessages(root, client, controller.signal, new Set(options.granted ?? ['contacts.list', 'messages.list', 'refusals.counts', 'conversations.marks', 'contact.propose', 'send', 'conversation.mark']));
  t.after(() => { controller.abort(); assert.equal(root.children.length, 0, 'face removes its canvas on dispose'); });
  return { root, document, calls, contacts, messages, live };
}

function conversation(root, contact = maya) { return find(root, element => element.dataset.contact === contact); }

test('the same conversation portal opens a chronological thread and returns to the centre list', async t => {
  const { root } = mount(t);
  await settle();
  const card = conversation(root);
  const holder = card.parentElement;
  const head = byClass(card, 'ak-portal__head');
  const back = byClass(card, 'thread-back');
  const mark = byClass(card, 'unreadMarker');
  const list = byClass(root, 'list-scene');
  const stage = byClass(root, 'thread-stage');
  assert.equal(root.dataset.view, 'list');
  assert.equal(mark.hidden, false);
  assert.equal(byClass(card, 'conversation-snippet').textContent, 'See you at five?');
  // The standard portal button (icon, title, summary, then the time and the expander), the back button hidden until
  // the thread is open, and the thread list's row actions beside it.
  assert.deepEqual(byClass(card, 'conversation-line').children.map(child => child.className), ['thread-back', 'ak-portal__head', 'row-actions']);
  assert.equal(back.hidden, true);
  assert.ok(byClass(byClass(head, 'ak-portal__end'), 'conversation-time'));
  assert.deepEqual(byClass(card, 'row-actions').children.map(child => child.getAttribute('aria-label')), ['Pin conversation', 'Archive conversation', 'Mark as read']);
  head.click();
  await settle();
  assert.equal(root.dataset.view, 'thread');
  assert.equal(card.parentElement, stage);
  assert.equal(list.hidden, true);
  assert.equal(stage.hidden, false);
  assert.equal(head.getAttribute('aria-expanded'), 'true');
  assert.equal(head.getAttribute('aria-label'), 'Maya. Back to conversations');
  assert.equal(byClass(card, 'conversation-snippet').textContent, `Aukora ID ${maya.slice(0, 10)}…${maya.slice(-4)}`);
  assert.equal(back.hidden, false, 'an open thread has a clear back button');
  assert.ok(all(root, item => hasClass(item, 'drawer')).every(drawer => drawer.dataset.open === 'no'), 'opening a thread closes any panel');
  const rows = byClass(card, 'transcript').children;
  assert.deepEqual(rows.map(row => row.dataset.message), ['old', 'middle', 'new']);
  assert.deepEqual(rows.map(row => row.dataset.direction), ['in', 'out', 'in']);
  assert.deepEqual(rows.map(row => byClass(row, 'who').textContent), ['MayaContact', 'You', 'MayaContact']);
  back.click();
  assert.equal(root.dataset.view, 'list');
  assert.equal(card.parentElement, holder);
  assert.equal(byClass(card, 'ak-portal__head'), head);
  assert.equal(list.hidden, false);
  assert.equal(stage.hidden, true);
  assert.equal(head.getAttribute('aria-expanded'), 'false');
  assert.equal(mark.hidden, true, 'opening the thread clears the loaded incoming marks');
  assert.equal(byClass(conversation(root, sam), 'unreadMarker').hidden, false, 'another contact stays unread');
  assert.equal(back.hidden, true);
  assert.equal(root.children.length, 1, 'navigation keeps the same centre canvas');
});

test('drafts survive close, reopen and a live re-read; Send uses the owner network API', async t => {
  let finish;
  const sent = new Promise(resolve => { finish = resolve; });
  const { root, calls, live } = mount(t, { send: () => sent });
  await settle();
  const card = conversation(root);
  const head = byClass(card, 'ak-portal__head');
  head.click(); await settle();
  const form = byClass(card, 'composer');
  const draft = find(form, element => element.tagName === 'textarea');
  draft.value = 'A draft for Maya';
  head.click(); head.click(); await settle();
  await live();
  assert.equal(find(form, element => element.tagName === 'textarea'), draft);
  assert.equal(draft.value, 'A draft for Maya');
  draft.value = '  Meet by the water.\nSee you soon.';
  form.dispatch('submit');
  assert.equal(draft.disabled, true);
  assert.equal(button(form, 'Send').disabled, true);
  assert.deepEqual(calls.filter(call => call.method === 'send'), [{
    service: 'network', method: 'send', params: { npub: maya, text: '  Meet by the water.\nSee you soon.' },
  }]);
  finish({}); await settle();
  assert.equal(draft.value, '');
  assert.equal(draft.disabled, false);
  assert.equal(button(form, 'Send').disabled, false);
  assert.match(form.textContent, /Queued for the relays\./);
  draft.value = ' \n ';
  form.dispatch('submit');
  assert.equal(calls.filter(call => call.method === 'send').length, 1);
  assert.match(form.textContent, /Write a message first\./);
});

test('a refused send keeps the draft and an explicit refusal', async t => {
  const { root } = mount(t, { send: () => { throw new Error('network:contact-unapproved'); } });
  await settle();
  const card = conversation(root);
  byClass(card, 'ak-portal__head').click(); await settle();
  const form = byClass(card, 'composer');
  const draft = find(form, element => element.tagName === 'textarea');
  draft.value = 'Keep this draft'; form.dispatch('submit'); await settle();
  assert.equal(draft.value, 'Keep this draft');
  assert.equal(draft.disabled, false);
  assert.match(form.textContent, /Request refused/);
  assert.doesNotMatch(form.textContent, /Queued for the relays/);
});

test('the own ID reuses QR and copy; contact approval names the exact ID and relay visibility', async t => {
  const { root, document, calls } = mount(t);
  await settle();
  const own = find(root, element => element.getAttribute('aria-label') === 'Your Aukora ID' && element.tagName === 'section');
  const qr = find(own, element => element.tagName === 'canvas');
  assert.equal(qr.hidden, false);
  assert.ok(qr.drawing.length > 1, 'the existing QR encoder supplies actual dark modules');
  button(own, 'Copy Aukora ID').click();
  assert.equal(document.selected.textContent, owner);
  assert.match(own.textContent, /Aukora ID selected\. Copy it with your keyboard or selection menu\./);
  document.copied = true;
  button(own, 'Copy Aukora ID').click();
  assert.match(own.textContent, /Aukora ID copied\./);
  const head = button(byClass(root, 'panel-row'), 'Add a contact+');
  head.click();
  assert.equal(head.getAttribute('aria-expanded'), 'true');
  assert.equal(byClass(root, 'drawer--contact').dataset.open, 'yes');
  const form = byClass(root, 'contact-form');
  assert.match(form.textContent, /The card approves this exact Aukora ID, not the person\./);
  assert.match(form.textContent, /compare it with them in person or on a call you trust\./);
  find(form, element => element.name === 'npub').value = key('r');
  find(form, element => element.name === 'label').value = '  Lee  ';
  form.dispatch('submit'); await settle();
  assert.deepEqual(calls.filter(call => call.method === 'contact.propose'), [{
    service: 'network', method: 'contact.propose', params: { npub: key('r'), label: 'Lee' },
  }]);
  assert.match(form.textContent, /Review the Add contact card with your passkey/);
  assert.equal(find(form, element => element.name === 'npub').value, '');
  assert.equal(all(root, element => element.dataset.contact !== undefined).length, 2, 'no contact is inserted before approval');
  assert.match(root.textContent, /they see your node's IP address, the recipient's key, the message size, and when your node connects to them\./);
  assert.doesNotMatch(root.textContent, /Nostr ID|Copy npub|Your npub/);
});

test('an exhausted older cursor stays exhausted when an overlapping newest page refreshes', async t => {
  let refreshed = false;
  const { root, calls, live } = mount(t, { page(params) {
    if (params.before === 'older') return { items: [message('earliest', maya, 1, 'in')], next: null };
    return {
      items: refreshed ? [message('arrival', maya, 4, 'in'), message('top', maya, 3, 'out')]
        : [message('top', maya, 3, 'out'), message('previous', maya, 2, 'in')],
      next: 'older',
    };
  } });
  await settle();
  const card = conversation(root);
  byClass(card, 'ak-portal__head').click(); await settle();
  const earlier = button(card, 'Load earlier messages');
  assert.equal(earlier.hidden, false);
  earlier.click(); await settle();
  assert.equal(earlier.hidden, true);
  refreshed = true;
  await live();
  assert.equal(earlier.hidden, true, 'refresh does not revive a consumed history cursor');
  assert.deepEqual(byClass(card, 'transcript').children.map(row => row.dataset.message), ['earliest', 'previous', 'top', 'arrival']);
  assert.equal(calls.filter(call => call.method === 'messages.list' && call.params.before === 'older').length, 1);
});

test('a burst with no page overlap resets the history window and follows the new older cursor', async t => {
  let burst = false;
  const range = (from, count) => Array.from({ length: count }, (_, at) => message(`burst-${from - at}`, maya, from - at, 'in'));
  const { root, calls, live } = mount(t, { page(params) {
    if (params.before === 'old-history') return { items: [message('oldest', maya, 1, 'in')], next: null };
    if (params.before === 'burst-history') return { items: range(101, 50), next: 'more-burst-history' };
    assert.equal(params.before, null);
    return burst ? { items: range(151, 50), next: 'burst-history' }
      : { items: [message('old-top', maya, 3, 'in'), message('old-middle', maya, 2, 'out')], next: 'old-history' };
  } });
  await settle();
  const card = conversation(root);
  byClass(card, 'ak-portal__head').click(); await settle();
  const earlier = button(card, 'Load earlier messages');
  earlier.click(); await settle();
  assert.equal(earlier.hidden, true);
  const draft = find(byClass(card, 'composer'), element => element.tagName === 'textarea');
  draft.value = 'Keep this while new messages arrive';
  burst = true;
  await live();
  assert.equal(earlier.hidden, false);
  assert.equal(byClass(card, 'transcript').children.length, 50);
  assert.match(card.textContent, /Showing the latest messages\. Load earlier messages to continue this conversation\./);
  assert.equal(draft.value, 'Keep this while new messages arrive');
  earlier.click(); await settle();
  assert.deepEqual(byClass(card, 'transcript').children.map(row => row.dataset.message), range(151, 100).reverse().map(row => row.id));
  assert.equal(calls.filter(call => call.method === 'messages.list' && call.params.before === 'burst-history').length, 1);
  assert.equal(calls.filter(call => call.method === 'messages.list' && call.params.before === 'old-history').length, 1);
});

test('a capped thread still accepts new arrivals and retains a thousand newest rows', async t => {
  let refreshed = false;
  const range = (from, count) => Array.from({ length: count }, (_, at) => message(`message-${from - at}`, maya, from - at, 'in'));
  const { root, live } = mount(t, { page(params) {
    const from = params.before === null ? (refreshed ? 1001 : 1000) : Number(params.before);
    return { items: range(from, 50), next: String(from - 50) };
  } });
  await settle();
  const card = conversation(root);
  byClass(card, 'ak-portal__head').click(); await settle();
  const earlier = button(card, 'Load earlier messages');
  for (let page = 1; page < 20; page++) { earlier.click(); await settle(); }
  assert.equal(byClass(card, 'transcript').children.length, 1000);
  assert.equal(earlier.hidden, true);
  refreshed = true;
  await live();
  const rows = byClass(card, 'transcript').children;
  assert.equal(rows.length, 1000);
  assert.equal(rows[0].dataset.message, 'message-2');
  assert.equal(rows.at(-1).dataset.message, 'message-1001');
  assert.equal(earlier.hidden, true);
});

const visibleRows = root => byClass(root, 'conversations').children.map(item => item.children[0].dataset.contact);
const filterButton = (root, label) => find(root, item => item.tagName === 'button' && item.getAttribute('aria-label') === label);

test('the filters, search and the owner marks choose which conversations show', async t => {
  const writes = [];
  const { root, calls } = mount(t, { marks: [{ npub: sam, pinned: true, archived: false }], mark: params => { writes.push(params); return {}; } });
  await settle();
  // A pinned conversation leads the list.
  assert.deepEqual(visibleRows(root), [sam, maya]);
  assert.equal(byClass(conversation(root, sam), 'pinMarker').hidden, false);
  filterButton(root, 'Show only pinned conversations').click();
  assert.deepEqual(visibleRows(root), [sam]);
  assert.equal(filterButton(root, 'Show only pinned conversations').getAttribute('aria-pressed'), 'true');
  // Tapping the selected filter again clears it: no filter is all conversations.
  filterButton(root, 'Show only pinned conversations').click();
  assert.equal(filterButton(root, 'Show only pinned conversations').getAttribute('aria-pressed'), 'false');
  assert.deepEqual(visibleRows(root), [sam, maya]);
  // Archiving writes both marks for that one npub and moves it to the Archived filter.
  find(conversation(root, maya), item => item.getAttribute('aria-label') === 'Archive conversation').click();
  await settle();
  assert.deepEqual(writes, [{ npub: maya, pinned: false, archived: true }]);
  assert.deepEqual(visibleRows(root), [sam]);
  filterButton(root, 'Show only archived conversations').click();
  assert.deepEqual(visibleRows(root), [maya]);
  assert.equal(byClass(conversation(root, maya), 'archiveMarker').hidden, false);
  filterButton(root, 'Show only archived conversations').click();
  // Search reads names and the loaded message text.
  const query = byClass(root, 'msg-search__input');
  query.value = 'book'; query.dispatch('input');
  assert.deepEqual(visibleRows(root), [sam]);
  query.value = 'nobody'; query.dispatch('input');
  assert.deepEqual(visibleRows(root), []);
  assert.match(byClass(root, 'msg-list').textContent, /No conversation matches “nobody”/);
  query.value = ''; query.dispatch('input');
  assert.ok(calls.some(call => call.method === 'conversations.marks'));
});

test('a refused mark is put back; mark as unread and read stay in this view', async t => {
  const { root } = mount(t, { mark: () => { throw new Error('network:owner-shell-session-required'); } });
  await settle();
  const card = conversation(root, maya);
  find(card, item => item.getAttribute('aria-label') === 'Pin conversation').click();
  assert.equal(byClass(card, 'pinMarker').hidden, false, 'the mark shows at once');
  await settle();
  assert.equal(byClass(card, 'pinMarker').hidden, true, 'and is put back when the node refuses it');
  assert.equal(byClass(root, 'msg-list').children.find(item => item.className === 'problem').hidden, false);
  const unread = find(card, item => item.getAttribute('aria-label') === 'Mark as read');
  unread.click();
  assert.equal(byClass(card, 'unreadMarker').hidden, true);
  assert.equal(unread.getAttribute('aria-label'), 'Mark as unread');
  unread.click();
  assert.equal(byClass(card, 'unreadMarker').hidden, false);
});

test('without the mark grant there is no pin or archive; the row-two panels open one at a time', async t => {
  const { root, calls } = mount(t, { granted: ['contacts.list', 'messages.list', 'send'] });
  await settle();
  assert.deepEqual(byClass(conversation(root, maya), 'row-actions').children.map(child => child.getAttribute('aria-label')), ['Mark as read']);
  assert.ok(!calls.some(call => call.method === 'conversations.marks'));
  assert.deepEqual(byClass(root, 'panel-row').children.map(child => child.textContent), ['Aukora ID+', 'More+'], 'no Add a contact without its grant');
  const id = button(byClass(root, 'panel-row'), 'Aukora ID+');
  const drawer = name => byClass(root, `drawer--${name}`);
  assert.equal(drawer('id').dataset.open, 'no');
  assert.equal(drawer('id').getAttribute('inert'), '', 'a closed panel cannot take focus');
  id.click();
  assert.equal(drawer('id').dataset.open, 'yes');
  assert.equal(drawer('id').getAttribute('inert'), null);
  assert.match(drawer('id').textContent, new RegExp(owner));
  button(byClass(root, 'panel-row'), 'More+').click();
  assert.equal(drawer('id').dataset.open, 'no', 'one panel at a time');
  assert.equal(drawer('more').dataset.open, 'yes');
  assert.match(drawer('more').textContent, /Your Aukora ID is a Nostr public key\./);
  root.dispatch('keydown');
  assert.equal(drawer('more').dataset.open, 'yes', 'only Escape closes');
  const escape = { type: 'keydown', key: 'Escape', defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
  for (const listener of root.listeners.get('keydown')) listener.handler(escape);
  assert.equal(drawer('more').dataset.open, 'no');
});

test('New message picks a contact, or starts with Add a contact when there is none', async t => {
  const { root } = mount(t);
  await settle();
  const plus = filterButton(root, 'New message');
  plus.click();
  const picker = byClass(root, 'drawer--pick');
  assert.equal(picker.dataset.open, 'yes');
  const choices = all(picker, item => item.className === 'picker__choice');
  assert.deepEqual(choices.map(choice => choice.textContent), ['Maya', 'Sam']);
  choices[1].click(); await settle();
  assert.equal(root.dataset.view, 'thread');
  assert.equal(byClass(root, 'thread-stage').children[0].dataset.contact, sam);
  assert.equal(picker.dataset.open, 'no');
});

test('with no contacts yet, New message opens Add a contact', async t => {
  const { root } = mount(t, { contacts: [] });
  await settle();
  filterButton(root, 'New message').click();
  assert.equal(byClass(root, 'drawer--contact').dataset.open, 'yes');
  assert.match(byClass(root, 'msg-list').textContent, /No contacts yet\. Share your Aukora ID/);
});

test('new messages arrive live in the list and in the open thread, keeping the draft', async t => {
  const { root, messages, live, calls } = mount(t);
  await settle();
  messages.unshift(message('fresh', sam, 40, 'in', 'Are you coming?'));
  await live();
  assert.equal(byClass(conversation(root, sam), 'conversation-snippet').textContent, 'Are you coming?');
  assert.deepEqual(visibleRows(root), [sam, maya], 'the newest conversation moves up');
  const card = conversation(root, maya);
  byClass(card, 'ak-portal__head').click(); await settle();
  const draft = find(byClass(card, 'composer'), element => element.tagName === 'textarea');
  draft.value = 'Half a thought';
  messages.unshift(message('later', maya, 50, 'in', 'On my way.'));
  const before = calls.length;
  await live();
  assert.deepEqual(byClass(card, 'transcript').children.map(row => row.dataset.message), ['old', 'middle', 'new', 'later']);
  assert.equal(draft.value, 'Half a thought');
  assert.ok(calls.slice(before).every(call => call.params.npub === maya), 'an open thread re-reads only itself');
  assert.equal(byClass(card, 'thread-panel').children[0].textContent.includes('Reading'), false, 'no Reading flicker');
});
