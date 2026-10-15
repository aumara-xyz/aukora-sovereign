// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { mountNostrIdentity } from '../nostr-identity.js';
import { api } from '../api.js';

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; }
  appendChild(child) { this.children.push(child); return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  setAttribute(name, value) { this[name] = value; }
  set textContent(value) { this.text = value; this.children = []; }
  get textContent() { return (this.text ?? '') + this.children.map(child => child.textContent).join(''); }
}
const all = element => [element, ...element.children.flatMap(all)];

test('antibody_nostr_owner_displays_and_copies_both_public_identities', async t => {
  const originals = new Map(['document', 'navigator'].map(name => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  const copied = [];
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement: tag => new Element(tag) } });
  Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { clipboard: { writeText: async value => copied.push(value) } } });
  const original = api.nostr;
  t.after(() => {
    api.nostr = original;
    for (const [name, descriptor] of originals) descriptor ? Object.defineProperty(globalThis, name, descriptor) : delete globalThis[name];
  });
  const identities = { node: { npub: `npub1${'q'.repeat(58)}` }, agent: { npub: `npub1${'p'.repeat(58)}` }, bound_seq: 7 };
  api.nostr = async () => identities;
  const target = new Element('main');
  await mountNostrIdentity(target);
  assert.ok(target.textContent.includes(identities.node.npub));
  assert.ok(target.textContent.includes(identities.agent.npub));
  const buttons = all(target).filter(element => element.tagName === 'button');
  assert.deepEqual(buttons.map(button => button['aria-label']), ['Copy node npub', 'Copy agent npub']);
  for (const button of buttons) await button.onclick();
  assert.deepEqual(copied, [identities.node.npub, identities.agent.npub]);
  for (const invalid of ['not-an-npub', '<script>secret</script>', null]) {
    api.nostr = async () => ({ ...identities, agent: { npub: invalid } });
    const malformed = new Element('main');
    await mountNostrIdentity(malformed);
    assert.equal(malformed.textContent, 'Nostr identities unavailable');
    assert.equal(all(malformed).filter(element => element.tagName === 'button').length, 0);
  }
  api.nostr = async () => { throw new Error('frontdoor:session-required'); };
  const unavailable = new Element('main');
  await mountNostrIdentity(unavailable);
  assert.equal(unavailable.textContent, 'Nostr identities unavailable');
  assert.equal(all(unavailable).filter(element => element.tagName === 'button').length, 0);
});
