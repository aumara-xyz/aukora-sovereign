// SPDX-License-Identifier: AGPL-3.0-or-later
// Exercise the real Settings control against owner-service responses, including pending approval and stale reads.
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { stripTypeScriptTypes } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';
import { pathToFileURL } from 'node:url';

const compiled = await mkdtemp(join(tmpdir(), 'slider-view-'));
let mountSlider, readSlider, readSliderChange;
try {
  await writeFile(join(compiled, 'package.json'), '{"type":"module"}');
  for (const path of ['faces/general/slider', 'faces/general/data', 'faces/messages/dom', 'faces/messages/portal', 'core/service-state', 'core/session-state']) {
    const output = join(compiled, `${path}.js`);
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, stripTypeScriptTypes(await readFile(new URL(`../../app/${path}.ts`, import.meta.url), 'utf8')));
  }
  ({ mountSlider, readSlider, readSliderChange } = await import(pathToFileURL(join(compiled, 'faces/general/slider.js')).href));
} finally { await rm(compiled, { recursive: true, force: true }); }

class Element {
  children = [];
  attributes = {};
  dataset = {};
  listeners = new Map();
  disabled = false;
  hidden = false;
  ownText = '';
  constructor(tagName) { this.tagName = tagName; }
  append(...nodes) { this.children.push(...nodes.filter(node => node !== null && node !== undefined)); }
  set textContent(value) { this.ownText = value; this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => typeof child === 'string' ? child : child.textContent).join(''); }
  setAttribute(name, value) {
    this.attributes[name] = value;
    if (name === 'class') this.className = value;
    if (name === 'disabled' || name === 'hidden') this[name] = true;
    if (name.startsWith('data-')) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = value;
  }
  getAttribute(name) { return this.attributes[name] ?? null; }
  get classList() { return { add: name => { this.className = `${this.className ?? ''} ${name}`.trim(); } }; }
  querySelector(selector) { return descendants(this).find(child => child.className?.split(' ').includes(selector.slice(1))) ?? null; }
  addEventListener(type, handler, options = {}) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push({ handler, signal: options.signal }); this.listeners.set(type, listeners);
  }
  click() { if (!this.disabled) for (const listener of this.listeners.get('click') ?? []) if (!listener.signal?.aborted) listener.handler(); }
  focus() { document.activeElement = this; }
  keydown(key) { for (const listener of this.listeners.get('keydown') ?? []) listener.handler({ key, preventDefault() {} }); }
}
function descendants(root) { return root.children.filter(child => typeof child !== 'string').flatMap(child => [child, ...descendants(child)]); }
const settle = () => new Promise(resolve => setImmediate(resolve));

function mount(t, options = {}) {
  const original = { document: globalThis.document, setInterval: globalThis.setInterval, clearInterval: globalThis.clearInterval };
  const controller = new AbortController();
  let tick;
  globalThis.document = { hidden: false, createElement: tag => new Element(tag), createElementNS: (_ns, tag) => new Element(tag) };
  globalThis.setInterval = callback => { tick = callback; return 1; };
  globalThis.clearInterval = () => {};
  let setting = options.setting ?? 'risky';
  const calls = [];
  const client = {
    async call(service, method, params, { signal }) {
      assert.equal(service, 'body'); assert.equal(signal, controller.signal);
      calls.push({ method, params });
      if (method === 'slider.get') return options.get ? options.get() : { setting };
      assert.equal(method, 'slider.set');
      if (options.set) return options.set(params.setting);
      if (['ask', 'risky', 'limits', 'trusted'].indexOf(params.setting) > ['ask', 'risky', 'limits', 'trusted'].indexOf(setting)) {
        return { state: 'pending', setting, proposal_id: 'a'.repeat(32) };
      }
      setting = params.setting;
      return { state: 'applied', setting };
    },
  };
  const root = new Element('main');
  mountSlider(root, client, controller.signal);
  t.after(() => { controller.abort(); Object.assign(globalThis, original); });
  const radio = value => descendants(root).find(node => node.dataset.sliderSetting === value).children[0];
  const selected = () => descendants(root).filter(node => node.getAttribute('aria-checked') === 'true');
  const status = () => root.querySelector('.slider-status').textContent;
  return { root, calls, radio, selected, status, tick: () => tick(), approve: next => { setting = next; } };
}

test('slider readers reject unknown levels and incomplete or extra approval fields', () => {
  assert.equal(readSlider({ setting: 'trusted' }), 'trusted');
  for (const bad of [{ setting: 'other' }, {}, { setting: 'ask', extra: true }]) assert.throws(() => readSlider(bad));
  for (const bad of [
    { state: 'pending', setting: 'risky' }, { state: 'pending', setting: 'risky', proposal_id: 'bad' },
    { state: 'applied', setting: 'ask', proposal_id: 'a'.repeat(32) }, { state: 'failed', setting: 'ask' },
  ]) assert.throws(() => readSliderChange(bad));
});

test('current setting selects one of four levels; only How it works carries the details', async t => {
  const ui = mount(t); await settle();
  assert.equal(ui.selected().length, 1);
  assert.equal(ui.radio('risky').getAttribute('aria-checked'), 'true');
  assert.equal(descendants(ui.root).filter(node => node.getAttribute('role') === 'radio').length, 4);
  const help = descendants(ui.root).find(node => node.tagName === 'details');
  assert.match(help.textContent, /How it works.*passkey.*Auma cannot add contacts/s);
  assert.equal(ui.root.children[0].getAttribute('data-open'), 'no');
});

test('tightening applies immediately, while loosening keeps the current selection until approval', async t => {
  const ui = mount(t); await settle();
  ui.radio('ask').click(); await settle();
  assert.equal(ui.radio('ask').getAttribute('aria-checked'), 'true');
  assert.equal(ui.status(), 'Slider updated.');
  ui.radio('trusted').click(); await settle();
  assert.equal(ui.radio('ask').getAttribute('aria-checked'), 'true');
  assert.equal(ui.radio('trusted').getAttribute('aria-checked'), 'false');
  assert.match(ui.status(), /Review.*passkey/);
  ui.approve('trusted'); ui.tick(); await settle();
  assert.equal(ui.radio('trusted').getAttribute('aria-checked'), 'true');
  assert.equal(ui.status(), 'Slider updated.');
});

test('failed reads clear the selected level and disable changes', async t => {
  let fail = false;
  const ui = mount(t, { get: () => { if (fail) throw new Error('frontdoor:session-required'); return { setting: 'risky' }; } });
  await settle(); fail = true; ui.tick(); await settle();
  assert.equal(ui.selected().length, 0);
  assert.equal(ui.radio('trusted').disabled, true);
  assert.match(ui.status(), /Sign in again/);
  const before = ui.calls.length; ui.radio('ask').click(); assert.equal(ui.calls.length, before);
  fail = false; ui.tick(); await settle();
  assert.equal(ui.status(), '');
  assert.equal(ui.radio('risky').getAttribute('aria-checked'), 'true');
});

test('radio keyboard navigation moves focus and requests the selected level', async t => {
  const ui = mount(t); await settle();
  assert.equal(ui.radio('risky').tabIndex, 0);
  assert.equal(ui.radio('ask').tabIndex, -1);
  ui.radio('risky').keydown('ArrowLeft'); await settle();
  assert.equal(document.activeElement, ui.radio('ask'));
  assert.equal(ui.radio('ask').getAttribute('aria-checked'), 'true');
  ui.radio('ask').keydown('End'); await settle();
  assert.equal(document.activeElement, ui.radio('trusted'));
  assert.match(ui.status(), /passkey/);
});

test('a request in flight blocks duplicate changes and a rejected loosening never changes the level', async t => {
  let reject;
  const ui = mount(t, { set: () => new Promise((_resolve, no) => { reject = no; }) });
  await settle(); ui.radio('trusted').click(); ui.radio('limits').click();
  assert.equal(ui.calls.filter(call => call.method === 'slider.set').length, 1);
  reject(new Error('gate:proposal-refused')); await settle();
  assert.equal(ui.radio('risky').getAttribute('aria-checked'), 'true');
  assert.match(ui.status(), /Request refused/);
});
