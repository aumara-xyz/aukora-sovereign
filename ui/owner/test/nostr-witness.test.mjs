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
  set innerHTML(_) { assert.fail('relay witness data must be text'); }
}
const all = element => [element, ...element.children.flatMap(all)];
const identity = { node: { npub: `npub1${'q'.repeat(58)}` }, agent: { npub: `npub1${'p'.repeat(58)}` } };
const pending = { relays: ['wss://relay.example'], accepted: 0, sequence: null, at: null };
const attempted = { relays: ['wss://relay.example', 'wss://other.example'], accepted: 1, sequence: 42, at: 1728000000000 };

function setup(t) {
  const original = Object.getOwnPropertyDescriptor(globalThis, 'document');
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement: tag => new Element(tag) } });
  const originalNostr = api.nostr;
  t.after(() => {
    api.nostr = originalNostr;
    original ? Object.defineProperty(globalThis, 'document', original) : delete globalThis.document;
  });
  return async witness => {
    api.nostr = async () => ({ ...identity, witness });
    const target = new Element('main');
    await mountNostrIdentity(target);
    assert.ok(target.textContent.includes(identity.node.npub));
    assert.ok(target.textContent.includes(identity.agent.npub));
    return all(target).find(element => element.className === 'nostr-witness');
  };
}

test('antibody_nostr_owner_witness_distinguishes_off_pending_and_attempts', async t => {
  const render = setup(t);
  assert.equal((await render({ relays: [], accepted: 0, sequence: null, at: null })).textContent, 'Relay head witnessOff');
  const waiting = await render(pending);
  assert.equal(waiting.textContent, 'Relay head witnessWaiting for first publishwss://relay.example');
  const accepted = await render(attempted);
  assert.equal(accepted.textContent, 'Relay head witness1 of 2 relays accepted head #42Last attempt 2024-10-04T00:00:00.000Zwss://relay.examplewss://other.example');
  const refused = await render({ ...attempted, accepted: 0 });
  assert.ok(refused.textContent.includes('0 of 2 relays accepted head #42'));
  assert.ok(refused.textContent.includes('Last attempt 2024-10-04T00:00:00.000Z'));
});

test('antibody_nostr_owner_witness_rejects_invalid_or_unbounded_status', async t => {
  const render = setup(t);
  const invalid = [undefined, null, {},
    { ...attempted, relays: 'wss://relay.example' },
    { ...attempted, relays: Array(9).fill('wss://relay.example') },
    { ...attempted, relays: ['wss://relay.example/' + 'a'.repeat(2049 - 'wss://relay.example/'.length)] },
    ...['https://relay.example', 'ws://relay.example', 'wss://owner:secret@relay.example', 'wss://relay.example/#fragment', 'wss://relay.example/\ntext', '<script>bad</script>', null].map(relay => ({ ...attempted, accepted: 0, relays: [relay] })),
    ...[-1, 3, 0.5, '1', NaN].map(accepted => ({ ...attempted, accepted })),
    ...[-1, 0.5, '42', Number.MAX_SAFE_INTEGER + 1].map(sequence => ({ ...attempted, sequence })),
    ...[-1, 0.5, '1728000000000', 8640000000000001].map(at => ({ ...attempted, at })),
    { ...attempted, sequence: null }, { ...attempted, at: null },
    { ...pending, accepted: 1 }, { ...attempted, relays: [], accepted: 0 },
  ];
  for (const witness of invalid) {
    assert.equal((await render(witness)).textContent, 'Relay head witness unavailable', JSON.stringify(witness));
  }
});

test('antibody_nostr_owner_witness_renders_relay_urls_as_bounded_text', async t => {
  const render = setup(t);
  const hostile = 'wss://relay.example/<img/src=x/onerror=alert(1)>';
  const rendered = await render({ ...pending, relays: [hostile] });
  assert.ok(rendered.textContent.includes(hostile));
  assert.equal(all(rendered).filter(element => element.tagName === 'a').length, 0);
  for (const relay of ['ws://127.0.0.1:1234', 'ws://[::1]:1234', 'wss://relay.example/' + 'a'.repeat(2048 - 'wss://relay.example/'.length)]) {
    const block = await render({ ...pending, relays: [relay] });
    assert.ok(block.textContent.includes(relay));
    assert.ok(block.textContent.includes('Waiting for first publish'));
  }
});
