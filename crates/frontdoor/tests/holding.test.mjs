// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const template = readFileSync(new URL('../src/holding.html', import.meta.url), 'utf8')
const html = template.replaceAll('__OWNER_ORIGIN__', 'https://owner.example')
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1]
const shell = readFileSync(new URL('../../../guest/faces/organs/lib/client.js', import.meta.url), 'utf8')
const flush = async () => { for (let i = 0; i < 15; i++) await Promise.resolve() }

function element() {
  const events = new Map()
  return { events, addEventListener(name, listener) { events.set(name, listener) } }
}

function holding(load = async () => ({ agent: 'stopped' })) {
  const sheet = { ...element(), open: false, showModal() { this.open = true }, close() { this.open = false } }
  const frame = { contentWindow: {} }
  const button = element()
  const events = new Map()
  const timers = new Map()
  const requests = []
  let timerId = 0
  let reloads = 0
  const context = {
    document: { getElementById(id) { return { 'owner-sheet': sheet, 'owner-frame': frame, 'owner-close': button }[id] } },
    window: { location: { reload() { reloads++ } }, addEventListener(name, listener) { events.set(name, listener) } },
    async fetch(path, options) { requests.push([path, options]); return load(requests.length) },
    setTimeout(fn, ms) { const id = ++timerId; timers.set(id, { fn, ms }); return id },
    clearTimeout(id) { timers.delete(id) },
  }
  vm.runInNewContext(script, context)
  return {
    sheet, frame, button, timers, requests, reloads: () => reloads,
    message(data = { kind: 'aukora-owner', event: 'decided', pending: 0 }, overrides = {}) {
      events.get('message')({ origin: 'https://owner.example', source: frame.contentWindow, data, ...overrides })
    },
    async tick() {
      assert.equal(timers.size, 1)
      const [id, timer] = [...timers][0]
      assert.equal(timer.ms, 5000)
      timers.delete(id)
      timer.fn()
      await flush()
    },
  }
}

function response(state, ok = true) { return { ok, async json() { return state } } }

test('antibody_holding_frame_matches_shell_and_contains_no_other_origin_or_controls', () => {
  let api
  vm.runInNewContext(shell, { URL, window: { __ModuleLoader__: { load(module) {
    api = module.factory(() => ({ createElement(type, props, ...children) { return { type, props, children } },
      useRef() { return {} }, useState() { return [false] }, useEffect() {} }))
  } } } })
  const tree = api.OwnerSheet({ state: { data: { owner_origin: 'https://owner.example' }, pane: 'approvals' }, controller: {}, frameRef: {} })
  const nodes = value => value && typeof value === 'object' ? [value, ...(value.children ?? []).flatMap(nodes)] : []
  const shellFrame = nodes(tree).find(node => node.type === 'iframe')
  const frame = Object.fromEntries([...html.match(/<iframe\b([^>]+)>/)[1].matchAll(/([\w-]+)="([^"]*)"/g)].map(match => [match[1], match[2]]))
  for (const attribute of ['title', 'src', 'allow', 'sandbox', 'referrerPolicy']) assert.equal(frame[attribute], shellFrame.props[attribute])
  assert.deepEqual([...new Set(html.match(/https?:\/\/[^/'"\s<>]+/g))], ['https://owner.example'])
  assert.equal((html.match(/<iframe\b/g) ?? []).length, 1)
  assert.equal((html.match(/<button\b/g) ?? []).length, 1)
  assert.match(html, /class="JS6p6q_close" aria-label="Close owner panel">×<\/button>/)
  assert.doesNotMatch(html, /<a\b|role="status"|\/api\/sovereign\/organs/)
  for (const name of ['panel', 'header', 'title', 'close']) assert.match(html, new RegExp(`JS6p6q_${name}`))
  for (const name of ['--dsw-alias-bg-layer-2', '--dsw-alias-border-l1', '--dsw-alias-label-primary', '--dsw-shadow-lv1']) assert.ok(html.includes(`var(${name})`))
})

test('antibody_holding_reload_requires_running_release_and_same_origin_poll', async () => {
  const states = [response({ agent: 'stopped' }), response({ agent: 'starting' }), response({ agent: 'exited' }),
    response({ agent: 'running' }, false), response(null), response({ agent: true }), response({ agent: 'RUNNING' }), new Error('offline'), response({ agent: 'running' })]
  const view = holding(async () => { const state = states.shift(); if (state instanceof Error) throw state; return state })
  await flush()
  assert.equal(view.sheet.open, true)
  while (states.length > 1) { assert.equal(view.reloads(), 0); await view.tick() }
  assert.equal(view.reloads(), 0)
  await view.tick()
  assert.equal(view.reloads(), 1)
  for (const [path, options] of view.requests) {
    assert.equal(path, '/__aukora/release')
    assert.equal(options.credentials, 'same-origin')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
  }
})

test('antibody_holding_decision_requires_exact_owner_frame_and_message', async () => {
  const view = holding(async () => response({ agent: 'stopped' }))
  await flush()
  const good = { kind: 'aukora-owner', event: 'decided', pending: 0 }
  const badData = [null, {}, [], Object.assign([], good), Object.assign(() => {}, good), { ...good, extra: true },
    { ...good, kind: 'other' }, { ...good, event: 'ready' }, { kind: 'aukora-owner', event: 'decided' },
    ...[-1, 0.5, Number.MAX_SAFE_INTEGER + 1, '0', null, false, NaN, Infinity].map(pending => ({ ...good, pending }))]
  for (const data of badData) { view.message(data); assert.equal(view.sheet.open, true) }
  for (const origin of ['https://evil.example', 'https://owner.example.evil', 'https://owner.example/', 'http://owner.example', 'null', undefined]) {
    view.message(good, { origin }); assert.equal(view.sheet.open, true)
  }
  for (const source of [{}, null]) { view.message(good, { source }); assert.equal(view.sheet.open, true) }
  const frameWindow = view.frame.contentWindow
  view.frame.contentWindow = null
  view.message(good, { source: null })
  assert.equal(view.sheet.open, true)
  view.frame.contentWindow = frameWindow
  assert.equal(view.requests.length, 1)
  view.message({ ...good, pending: 2 })
  assert.equal(view.sheet.open, true)
  view.message(good)
  assert.equal(view.sheet.open, false)
  await flush()
  assert.equal(view.requests.length, 2)
  assert.equal(view.reloads(), 0)
  view.message(good)
  await flush()
  assert.equal(view.requests.length, 2)
})

test('antibody_holding_decision_fences_stale_poll_and_rechecks_immediately', async () => {
  const resolve = []
  const view = holding(() => new Promise(done => { resolve.push(done) }))
  assert.equal(view.requests.length, 1)
  view.message()
  assert.equal(view.sheet.open, false)
  assert.equal(view.requests.length, 1)
  resolve.shift()(response({ agent: 'running' }))
  await flush()
  assert.equal(view.reloads(), 0)
  assert.equal(view.requests.length, 2)
  assert.equal(view.timers.size, 0)
  resolve.shift()(response({ agent: 'stopped' }))
  await flush()
  assert.equal(view.reloads(), 0)
  await view.tick()
  assert.equal(view.requests.length, 3)
  resolve.shift()(response({ agent: 'running' }))
  await flush()
  assert.equal(view.reloads(), 1)
})

test('antibody_holding_invalid_counts_cannot_invalidate_release_poll', async () => {
  for (const pending of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, '0', null, false, NaN, Infinity]) {
    let resolve
    const view = holding(() => new Promise(done => { resolve = done }))
    view.message({ kind: 'aukora-owner', event: 'decided', pending })
    resolve(response({ agent: 'running' }))
    await flush()
    assert.equal(view.reloads(), 1, `invalid count ${pending} changed the decision state`)
  }
})

test('antibody_holding_keeps_shell_close_cancel_and_backdrop_behaviour', async () => {
  for (const action of ['close', 'cancel', 'backdrop']) {
    const view = holding(async () => response({ agent: 'stopped' }))
    await flush()
    view.sheet.events.get('click')({ target: {}, currentTarget: {} })
    assert.equal(view.sheet.open, true)
    if (action === 'close') view.button.events.get('click')()
    if (action === 'cancel') {
      let prevented = false
      view.sheet.events.get('cancel')({ preventDefault() { prevented = true } })
      assert.equal(prevented, true)
    }
    if (action === 'backdrop') view.sheet.events.get('click')({ target: view.sheet, currentTarget: view.sheet })
    assert.equal(view.sheet.open, false)
    await view.tick()
    assert.equal(view.reloads(), 0)
  }
})
