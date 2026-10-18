// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import test from 'node:test';

const moduleUrl = source => `data:text/javascript;base64,${Buffer.from(stripTypeScriptTypes(source)).toString('base64')}`;
const read = path => readFile(new URL(`../../app/${path}`, import.meta.url), 'utf8');
const session = moduleUrl(await read('core/session-state.ts'));
const state = moduleUrl((await read('core/service-state.ts')).replace('./session-state.js', session));
const qr = moduleUrl(await read('faces/identity/qr.ts'));
const source = (await read('faces/identity/view.ts'))
  .replace('../../core/service-state.js', state).replace('./qr.js', qr);
const { createIdentityView } = await import(moduleUrl(source));

class Element {
  constructor(tagName) {
    this.tagName = tagName;
    this.children = [];
    this.dataset = {};
    this.attributes = {};
    this.hidden = false;
    this.text = '';
  }
  set textContent(value) { this.text = value; this.children = []; }
  get textContent() { return this.text + this.children.map(child => child.textContent).join(''); }
  setAttribute(key, value) { this.attributes[key] = value; }
  append(...children) {
    for (const child of children) { child.parent = this; this.children.push(child); }
  }
  replaceChildren(...children) { this.text = ''; this.children = []; this.append(...children); }
  remove() { this.parent.children = this.parent.children.filter(child => child !== this); }
}

function mount() {
  globalThis.document = { createElement: tag => new Element(tag) };
  const root = new Element('main');
  return { root, view: createIdentityView(root) };
}

function descendants(element, tagName) {
  return element.children.flatMap(child => [
    ...(child.tagName === tagName ? [child] : []), ...descendants(child, tagName),
  ]);
}

const card = {
  label: 'Peter', subject: `aukora:1:${'1'.repeat(64)}`, nodeNpub: `npub1${'a'.repeat(58)}`,
  nodeKeyBound: true, agentNpub: `npub1${'b'.repeat(58)}`, contact: null, safety: [],
};

test('Identity shows one Aukora ID and describes AUMLOK as seven-word security', () => {
  const { root, view } = mount();
  view.show(card, 0);
  assert.deepEqual(descendants(root, 'dt').map(item => item.textContent), ['Aukora ID', 'AUMLOK']);
  assert.deepEqual(descendants(root, 'dd').map(item => item.textContent), [card.nodeNpub, 'secured by your seven words']);
  assert.equal(root.textContent.includes(card.subject), false);
  assert.equal(root.textContent.includes(card.agentNpub), false);
  assert.doesNotMatch(root.textContent, /Aumlok ID|Node address|Agent address|Nostr ID/);
  view.dispose();
  assert.equal(root.children.length, 0);
});

test('Identity keeps binding status honest and clears stale values after a refused read', () => {
  const { root, view } = mount();
  view.show({ ...card, subject: null, nodeKeyBound: false }, 0);
  assert.match(root.textContent, /Not secured yet\. Set your seven words in AUMLOK\./);
  assert.match(root.textContent, /Your Aukora ID is waiting for an owner-approved binding\./);
  view.unavailable(new Error('frontdoor:session-required'));
  assert.equal(root.textContent.includes(card.nodeNpub), false);
  assert.equal(descendants(root, 'dl')[0].hidden, true);
  assert.match(root.textContent, /Sign in again/);
});
