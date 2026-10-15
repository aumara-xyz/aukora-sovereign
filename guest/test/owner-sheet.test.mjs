// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

const source = readFileSync(new URL('../faces/organs/lib/client.js', import.meta.url), 'utf8')
const fixture = (count = 0) => ({
  ...JSON.parse(JSON.parse(readFileSync(new URL('../../crates/canon/vectors/organs.json', import.meta.url)))[0].input).body,
  approvals_pending: count,
})
const flush = async () => { for (let i = 0; i < 10; i++) await Promise.resolve() }

function timers() {
  const pending = new Map()
  let id = 0
  return {
    pending,
    schedule(fn, ms) { const key = ++id; pending.set(key, { fn, ms }); return key },
    cancel(key) { pending.delete(key) },
    async tick() {
      assert.equal(pending.size, 1)
      const [key, { fn, ms }] = [...pending][0]
      assert.equal(ms, 5000)
      pending.delete(key)
      fn()
      await flush()
    },
  }
}

function client() {
  let api
  let current
  const events = new Map()
  const time = timers()
  const hooks = {
    createElement(type, props, ...children) { return { type, props: props ?? {}, children } },
    useState(initial) {
      const i = current.cursor++
      if (!(i in current.values)) current.values[i] = typeof initial === 'function' ? initial() : initial
      const host = current
      return [host.values[i], value => { host.values[i] = typeof value === 'function' ? value(host.values[i]) : value }]
    },
    useRef(initial) {
      const i = current.cursor++
      return current.values[i] ??= { current: initial }
    },
    useEffect(effect, deps) {
      const i = current.cursor++
      const host = current
      const old = host.effects[i]
      if (!old || !deps || deps.some((value, index) => !Object.is(value, old.deps[index]))) {
        host.work.push(() => {
          old?.cleanup?.()
          host.effects[i] = { deps, cleanup: effect() }
        })
      }
    },
  }
  vm.runInNewContext(source, {
    URL, setTimeout: time.schedule, clearTimeout: time.cancel,
    window: {
      location: { origin: 'https://attacker.example', hash: '#/embed/evil' },
      addEventListener(name, fn) { events.set(name, fn) },
      removeEventListener(name, fn) { if (events.get(name) === fn) events.delete(name) },
      __ModuleLoader__: { load(module) { api = module.factory(() => hooks) } },
    },
  })
  function host(component) {
    const state = { cursor: 0, values: [], effects: [], work: [] }
    return {
      state,
      render(props) { state.cursor = 0; current = state; return component(props) },
      effects() { const work = state.work.splice(0); work.forEach(fn => fn()) },
      unmount() { state.effects.forEach(effect => effect?.cleanup?.()) },
    }
  }
  return { api, host, events, time }
}

function nodes(tree) {
  if (Array.isArray(tree)) return tree.flatMap(nodes)
  return tree && typeof tree === 'object' ? [tree, ...tree.children.flatMap(nodes)] : []
}

function message(frame, pending = 0) {
  return { origin: 'https://owner.example', source: frame, data: { kind: 'aukora-owner', event: 'decided', pending } }
}

async function running(count = 0) {
  const view = client()
  const clock = timers()
  let countValue = count
  let fail = false
  let calls = 0
  const controller = view.api.createOwnerController({ ...clock, async load() {
    calls++
    if (fail) throw new Error('fixture unavailable')
    return fixture(countValue)
  } })
  const stop = controller.start()
  await flush()
  return { ...view, clock, controller, stop, calls: () => calls,
    count(value) { countValue = value }, fail(value) { fail = value } }
}

test('antibody_owner_sheet_src_and_frame_policy', () => {
  const { api, host } = client()
  const controller = api.createOwnerController()
  assert.deepEqual(Array.from(api.PANES), ['approvals', 'aumlok', 'aura', 'memory', 'model', 'nostr'])
  for (const pane of api.PANES) {
    const sheet = host(api.OwnerSheet).render({ state: { data: fixture(), pane }, controller, frameRef: {} })
    const frame = nodes(sheet).find(node => node.type === 'iframe')
    assert.equal(frame.props.src, `https://owner.example/#/embed/${pane}`)
    assert.equal(frame.props.allow, 'publickey-credentials-get; publickey-credentials-create')
    assert.equal(frame.props.sandbox, 'allow-scripts allow-same-origin allow-forms allow-popups')
    assert.equal(frame.props.referrerPolicy, 'no-referrer')
    assert.equal(frame.props.title, sheet.props['aria-label'])
    assert.ok(nodes(sheet).some(node => node.props.className === 'JS6p6q_panel'))
    assert.ok(nodes(sheet).some(node => node.props.className === 'JS6p6q_header'))
    assert.equal(nodes(sheet).some(node => node.type === 'a'), false)
  }
  for (const pane of ['../approvals', 'aura?token=x', 'https://evil.example', '', null, 'constructor', 'toString']) {
    assert.equal(api.ownerFrameSrc(fixture(), pane), null)
    controller.open(pane)
    assert.equal(controller.getSnapshot().pane, null)
  }
  assert.equal(api.ownerFrameSrc({ origin: 'https://attacker.example' }, 'approvals'), null)
})

test('antibody_owner_sheet_message_requires_origin_shape_and_frame', async () => {
  const { controller, stop } = await running(3)
  const frame = {}
  const good = message(frame)
  const bad = [
    ...['https://evil.example', 'https://owner.example.evil', 'https://owner.example/', 'http://owner.example', 'null', undefined].map(origin => ({ ...good, origin })),
    ...[null, {}, [], Object.assign([], good.data), { kind: 'aukora-owner', event: 'decided' }, { ...good.data, extra: true },
      { ...good.data, kind: 'other' }, { ...good.data, event: 'ready' },
      ...[-1, 0.5, Number.MAX_SAFE_INTEGER + 1, '0', null, false, NaN, Infinity].map(pending => ({ ...good.data, pending }))].map(data => ({ ...good, data })),
    { ...good, source: {} }, { ...good, source: null },
  ]
  for (const event of bad) {
    controller.handleMessage(event, frame)
    assert.equal(controller.getSnapshot().pane, 'approvals')
    assert.equal(controller.getSnapshot().data.approvals_pending, 3)
  }
  controller.handleMessage({ ...good, source: null }, null)
  assert.equal(controller.getSnapshot().pane, 'approvals')
  controller.handleMessage(message(frame, 2), frame)
  assert.equal(controller.getSnapshot().pane, 'approvals')
  assert.equal(controller.getSnapshot().data.approvals_pending, 2)
  controller.handleMessage(good, frame)
  assert.equal(controller.getSnapshot().pane, null)
  assert.equal(controller.getSnapshot().data.approvals_pending, 0)
  stop()
})

test('antibody_owner_sheet_popup_once_per_rise_and_one_poll_in_flight', async () => {
  const view = await running()
  const { controller, clock, stop } = view
  const observed = []
  controller.subscribe(state => { if (state.pane === 'approvals') observed.push(state.data.approvals_pending) })
  for (const count of [0, 1, 1, 2, 2, 1, 1, 2, 0, 0, 1]) {
    view.count(count)
    await clock.tick()
    controller.close()
  }
  assert.deepEqual(observed, [1, 2, 2, 1])
  view.fail(true)
  await clock.tick()
  view.fail(false)
  await clock.tick()
  assert.equal(controller.getSnapshot().pane, null)
  assert.equal(controller.getSnapshot().data.approvals_pending, 1)
  const calls = view.calls()
  controller.start()()
  assert.equal(view.calls(), calls)
  stop()
  assert.equal(clock.pending.size, 0)

  let resolve
  const otherClock = timers()
  let loads = 0
  const other = view.api.createOwnerController({ ...otherClock, load() { loads++; return new Promise(done => { resolve = done }) } })
  const cancel = other.start()
  other.start()
  assert.equal(loads, 1)
  assert.equal(otherClock.pending.size, 0)
  cancel()
  resolve(fixture(1))
  await flush()
  assert.equal(other.getSnapshot().pane, null)
  assert.equal(otherClock.pending.size, 0)
})

test('antibody_owner_sheet_decision_does_not_reopen_from_inflight_read', async () => {
  const { api } = client()
  const clock = timers()
  let resolve
  let first = true
  const controller = api.createOwnerController({ ...clock, load() {
    if (first) { first = false; return fixture(1) }
    return new Promise(done => { resolve = done })
  } })
  const stop = controller.start()
  await flush()
  await clock.tick()
  const frame = {}
  controller.handleMessage(message(frame), frame)
  resolve(fixture(1))
  await flush()
  assert.equal(controller.getSnapshot().pane, null)
  assert.equal(controller.getSnapshot().data.approvals_pending, 0)
  stop()
})

test('antibody_owner_sheet_modal_close_and_fallback_only_after_failure', () => {
  const { api, host, time } = client()
  const controller = api.createOwnerController()
  const sheetHost = host(api.OwnerSheet)
  const props = { state: { data: fixture(1), pane: 'approvals' }, controller, frameRef: {} }
  controller.open('approvals')
  let sheet = sheetHost.render(props)
  let opened = 0
  let closed = 0
  sheet.props.ref.current = { showModal() { opened++ }, close() { closed++ } }
  sheetHost.effects()
  assert.equal(opened, 1)
  assert.equal(time.pending.size, 1)
  assert.equal([...time.pending.values()][0].ms, 15000)
  const iframe = nodes(sheet).find(node => node.type === 'iframe')
  iframe.props.onLoad()
  assert.equal(time.pending.size, 0)
  let prevented = false
  sheet.props.onCancel({ preventDefault() { prevented = true } })
  assert.equal(prevented, true)
  assert.equal(controller.getSnapshot().pane, null)
  controller.open('approvals')
  sheet.props.onClick({ target: {}, currentTarget: {} })
  assert.equal(controller.getSnapshot().pane, 'approvals')
  const backdrop = {}
  sheet.props.onClick({ target: backdrop, currentTarget: backdrop })
  assert.equal(controller.getSnapshot().pane, null)
  controller.open('approvals')
  nodes(sheet).find(node => node.props['aria-label'] === 'Close owner panel').props.onClick()
  assert.equal(controller.getSnapshot().pane, null)
  assert.equal(nodes(sheet).some(node => node.type === 'a'), false)
  iframe.props.onError()
  sheet = sheetHost.render(props)
  const link = nodes(sheet).find(node => node.type === 'a')
  assert.equal(link.props.href, 'https://owner.example/#/embed/approvals')
  assert.equal(link.props.target, '_blank')
  assert.equal(link.props.rel, 'noopener noreferrer')
  assert.equal(link.props.referrerPolicy, 'no-referrer')
  sheetHost.unmount()
  assert.equal(closed, 1)
})

test('antibody_owner_sheet_root_wires_messages_and_badge', async () => {
  const view = await running(2)
  view.stop()
  const { api, host, events, controller } = view
  const root = host(api.OwnerRoot)
  root.render({ controller })
  root.effects()
  await flush()
  const rendered = root.render({ controller })
  assert.equal(rendered.type, api.OwnerSheet)
  const beforeMenu = host(api.OrganMenu).render({ controller, organ: ['approvals', 'Approvals', 'Pending owner decisions'] })
  assert.equal(nodes(beforeMenu).find(node => node.props['data-approvals-badge']).children[0], 2)
  const frame = {}
  rendered.props.frameRef.current = { contentWindow: frame }
  events.get('message')(message(frame))
  assert.equal(root.render({ controller }), null)
  const menu = host(api.OrganMenu).render({ controller, organ: ['approvals', 'Approvals', 'Pending owner decisions'] })
  assert.equal(nodes(menu).find(node => node.props['data-approvals-badge']).children[0], 0)
  menu.props.onClick()
  assert.equal(controller.getSnapshot().pane, 'approvals')
  root.unmount()
  assert.equal(events.size, 0)
  assert.equal(view.clock.pending.size, 0)
})

test('antibody_owner_sheet_timeout_and_manual_failure_offer_fallback', () => {
  for (const failure of ['timeout', 'manual']) {
    const { api, host, time } = client()
    const sheetHost = host(api.OwnerSheet)
    const props = { state: { data: fixture(), pane: 'aura' }, controller: api.createOwnerController(), frameRef: {} }
    let sheet = sheetHost.render(props)
    sheet.props.ref.current = { showModal() {}, close() {} }
    sheetHost.effects()
    if (failure === 'timeout') [...time.pending.values()][0].fn()
    // The always-visible 'Panel did not load' button is gone (Peter, 2026-10-15); a frame error is the manual path now.
    else nodes(sheet).find(node => node.type === 'iframe').props.onError()
    sheet = sheetHost.render(props)
    assert.equal(nodes(sheet).find(node => node.type === 'a').props.href, 'https://owner.example/#/embed/aura')
    sheetHost.unmount()
    assert.equal(time.pending.size, 0)
  }
})

test('antibody_owner_sheet_bad_count_does_not_open_or_replace_snapshot', async () => {
  for (const count of [-1, 1.5, Number.MAX_SAFE_INTEGER + 1, '1', null, false]) {
    const view = await running()
    view.count(count)
    await view.clock.tick()
    assert.equal(view.controller.getSnapshot().pane, null)
    assert.equal(view.controller.getSnapshot().data.approvals_pending, 0)
    assert.equal(view.controller.getSnapshot().error, true)
    view.stop()
  }
})
