// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { showModel } from '../screens/model.js';

class Element {
  constructor(tag) {
    this.tagName = tag;
    this.children = [];
    this.classList = { add: name => { this.className += ` ${name}`; } };
  }
  appendChild(child) { this.children.push(child); return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  replaceChildren() { this.children = []; }
  setAttribute(name, value) { this[name] = value; }
  set textContent(value) { this.replaceChildren(); this._text = String(value); }
  get textContent() { return (this._text ?? '') + this.children.map(child => child.textContent).join(''); }
}

function setup(t, last_refusal) {
  const names = ['document', 'fetch'];
  const previous = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  Object.defineProperty(globalThis, 'document', {
    configurable: true, value: { createElement: tag => new Element(tag) },
  });
  Object.defineProperty(globalThis, 'fetch', {
    configurable: true,
    value: async url => {
      assert.equal(url, '/api/broker');
      return new Response(JSON.stringify({ key: { present: false }, grant: null, models: [], last_refusal }), {
        headers: { 'Content-Type': 'application/json' },
      });
    },
  });
  t.after(() => names.forEach((name, i) => {
    if (previous[i]) Object.defineProperty(globalThis, name, previous[i]);
    else delete globalThis[name];
  }));
  return new Element('div');
}

test('antibody_ui_model_last_refusal_maps_each_provider_code', async t => {
  const cases = [
    ['broker:provider-key-rejected', 'the provider rejected the model key: replace it on the owner page'],
    ['broker:provider-no-credit', 'the provider account has no credit'],
    ['broker:provider-rate-limited', 'the provider is rate limiting: try again shortly'],
    ['broker:provider-request-rejected', 'the provider rejected the request: model name or parameters'],
    ['broker:provider-unavailable', 'the provider is unavailable'],
    ['broker:provider-refused', 'the provider refused the call'],
  ];
  for (const [code, message] of cases) {
    await t.test(code, async t => {
      const app = setup(t, { code });
      await showModel(app);
      assert.ok(app.textContent.includes(`last model refusal: ${message}`));
      assert.ok(!app.textContent.includes(code));
    });
  }
});

test('antibody_ui_model_last_refusal_ignores_provider_body_and_next', async t => {
  const poison = 'sk-fake-provider-body-KEY-12345 <script>prompt bytes</script>';
  const app = setup(t, {
    code: 'broker:provider-no-credit', next: poison, body: poison, message: poison, provider_status: 402,
  });
  await showModel(app);
  assert.ok(app.textContent.includes('last model refusal: the provider account has no credit'));
  assert.ok(!app.textContent.includes(poison));
  assert.ok(!app.textContent.includes('402'));
});

test('antibody_ui_model_last_refusal_unknown_codes_never_echo', async t => {
  const poison = 'sk-fake-unknown-code-KEY-67890';
  for (const code of [poison, '__proto__', 'constructor', null, 402]) {
    await t.test(String(code), async t => {
      const app = setup(t, { code, next: poison });
      await showModel(app);
      assert.ok(app.textContent.includes('last model refusal: the model call was refused'));
      assert.ok(!app.textContent.includes(poison));
      assert.ok(!app.textContent.includes(String(code)));
    });
  }
});

test('antibody_ui_model_without_last_refusal_omits_warning', async t => {
  for (const last_refusal of [null, undefined]) {
    await t.test(String(last_refusal), async t => {
      const app = setup(t, last_refusal);
      await showModel(app);
      assert.ok(!app.textContent.includes('last model refusal:'));
      assert.ok(app.textContent.includes('no key set'));
      assert.ok(app.textContent.includes('no active grant'));
    });
  }
});
