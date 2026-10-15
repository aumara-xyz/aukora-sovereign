// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { Duplex } from 'node:stream'
import test from 'node:test'
import vm from 'node:vm'
import { decodeFrame, encodeFrame } from '../canon.mjs'
import { Fd3Link } from '../fd3.mjs'
import { organsHandler, ORGANS_PATH, AURA_SNAPSHOT_PATH, registerOrgansRoute } from '../organs.mjs'

const source = readFileSync(new URL('../faces/organs/lib/client.js', import.meta.url), 'utf8')
const auraSources = JSON.parse(JSON.parse(readFileSync(new URL('../../crates/canon/vectors/organs.json', import.meta.url)))[0].input).body.aura.sources
const fixture = () => ({
  approvals_pending: 2,
  aumlok: { bound: true, passkeys: 2, refresh_due: false },
  kira: { notes: 23, demoted: 4 }, aura: { sequence: 42, root: 'a'.repeat(64), sources: structuredClone(auraSources) },
  nostr: { node_npub: 'npub1node', agent_npub: 'npub1agent', witness_accepted: 7 },
  wasm: { module_sha256: '34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438' },
  owner_origin: 'https://owner.example',
})
const frame = body => ({ v: 1, id: 'organs-test', kind: 'organs.reply', body })
const allow = { requestRejection: () => undefined }
const response = () => ({
  status: 0, headers: {}, body: '',
  writeHead(status, headers = {}) { this.status = status; this.headers = headers },
  end(body = '') { this.body = body },
})

function client({ fetch, state, effect = () => {} } = {}) {
  let result
  vm.runInNewContext(source, {
    URL, fetch, setTimeout, clearTimeout, window: { __ModuleLoader__: { load(module) {
      assert.equal(module.id, '@aukora/face-organs')
      result = module.factory(id => {
        assert.equal(id, 'react')
        return {
          createElement(type, props, ...children) { return { type, props: props ?? {}, children } },
          useState(initial) { return [state ?? (typeof initial === 'function' ? initial() : initial), () => {}] }, useEffect: effect, useRef(initial) { return { current: initial } },
        }
      })
    } } },
  })
  return result
}

function nodes(tree) {
  if (tree === null || tree === undefined || tree === false) return []
  if (Array.isArray(tree)) return tree.flatMap(nodes)
  if (typeof tree !== 'object') return []
  return [tree, ...tree.children.flatMap(nodes)]
}

function text(tree) {
  if (tree === null || tree === undefined || tree === false) return ''
  if (Array.isArray(tree)) return tree.map(text).join(' ')
  if (typeof tree !== 'object') return String(tree)
  return tree.children.map(text).join(' ')
}

test('antibody_organs_six_entries_and_state_surfaces', () => {
  const api = client()
  const rows = []
  api.apply({
    slots: { inject(_name, callback) { callback() }, register(options, component) { rows.push({ options, component }); return () => {} } },
    remote: { pluginInventory: { list() {} } },
  })
  const menus = rows.filter(row => row.options.name === 'shell.menu.system').sort((a, b) => a.options.order - b.options.order)
  assert.deepEqual(menus.map(row => row.options.id), ['organ-approvals', 'organ-aura', 'organ-kira', 'organ-aumlok', 'organ-nostr', 'organ-verifier', 'organ-wasm'])
  assert.equal(rows.filter(row => row.options.name === 'shell.overlay').length, 1)
  assert.equal(rows.filter(row => row.options.name === 'shell.surface').length, 0)
  const controller = menus[0].options.inject().controller
  const expected = ['approvals', 'aura', 'memory', 'aumlok', 'nostr', 'aura', 'aura']
  for (const [index, row] of menus.entries()) {
    assert.equal(row.options.inject().controller, controller)
    const tree = row.component(row.options.inject())
    assert.equal(nodes(tree).some(node => node.type === 'a'), false)
    tree.props.onClick()
    assert.equal(controller.getSnapshot().pane, expected[index])
  }
  const settings = readFileSync(new URL('../faces/settings/lib/client.js', import.meta.url))
  assert.equal(createHash('sha256').update(settings).digest('hex'), 'ae74e4b5ece33cf08125ef80e57fed6c7d1cc18afa5ac3edc62baaaf378142e1')
  assert.ok(settings.toString().includes('function AuraCoherenceSurface'))
  assert.ok(settings.toString().includes('pentora.display.v1'))
})

test('antibody_organs_no_ceremony_inputs_or_sensitive_wording', () => {
  const api = client()
  for (const data of [fixture(), null]) for (const pane of api.PANES) {
    const tree = api.OwnerSheet({ state: { pane, data, error: !data }, controller: api.createOwnerController(), frameRef: {} })
    assert.equal(nodes(tree).some(node => ['input', 'textarea', 'select', 'form'].includes(node.type) || node.props.contentEditable), false)
    assert.doesNotMatch(text(tree), /phrase|passkey|seven words/i)
    assert.equal(nodes(tree).some(node => node.props.dangerouslySetInnerHTML), false)
  }
  const overlay = JSON.parse(readFileSync(new URL('../sovereign.patch.yml', import.meta.url)))
  assert.equal(overlay.some(row => /aumlok/.test(row.module ?? row.path ?? row.id ?? '')), false)
  assert.doesNotMatch(source, /navigator\.credentials|<input|type:\s*['"]password['"]|autocomplete:\s*['"]webauthn['"]/i)
})

test('antibody_organs_owner_link_is_only_the_configured_origin', () => {
  const api = client()
  for (const pane of api.PANES) {
    const tree = api.OwnerSheet({ state: { pane, data: fixture() }, controller: api.createOwnerController(), frameRef: {} })
    const frames = nodes(tree).filter(node => node.type === 'iframe')
    assert.equal(frames.length, 1)
    assert.equal(frames[0].props.src, fixture().owner_origin + '/#/embed/' + pane)
    assert.equal(nodes(tree).some(node => node.type === 'a'), false)
  }
  for (const origin of ['', '/owner', 'https://owner.example/', 'https://owner.example/path',
    'https://owner.example?token=secret', 'https://owner.example#secret', 'https://user:password@owner.example',
    'http://owner.example', 'javascript:alert(1)', 'https://' + 'a'.repeat(2049)]) {
    assert.equal(api.ownerOrigin(origin), null, origin)
    assert.equal(api.ownerFrameSrc({ owner_origin: origin }, 'approvals'), null)
  }
})

test('antibody_organs_route_authenticates_before_reading_and_is_read_only', async () => {
  const calls = []
  const link = { async call(...args) { calls.push(args); return frame(fixture()) } }
  const routes = []
  registerOrgansRoute({ inject(names, callback) {
    assert.deepEqual(names, ['webServer', 'connection'])
    callback({ connection: allow, effect(callback) { callback() }, webServer: { register(route) { routes.push(route); return () => {} } } })
  } }, link)
  assert.deepEqual(routes.map(route => [route.kind, route.path]), [['exact', ORGANS_PATH], ['exact', AURA_SNAPSHOT_PATH]])
  for (const connection of [undefined, {}, { requestRejection: () => 401 }, { requestRejection: () => 403 }]) {
    const res = response()
    await organsHandler(connection, link)({ method: 'GET', url: ORGANS_PATH }, res)
    assert.ok([401, 403].includes(res.status))
    assert.equal(res.body, '')
  }
  for (const method of ['POST', 'PUT', 'DELETE', 'HEAD']) {
    const res = response()
    await organsHandler(allow, link)({ method, url: ORGANS_PATH }, res)
    assert.equal(res.status, 405)
  }
  for (const url of [ORGANS_PATH + '?x=1', ORGANS_PATH + '/alias']) {
    const res = response()
    await organsHandler(allow, link)({ method: 'GET', url }, res)
    assert.equal(res.status, 404)
  }
  assert.deepEqual(calls, [])
  const res = response()
  await routes[0].handler({ method: 'GET', url: ORGANS_PATH }, res)
  assert.equal(res.status, 200)
  assert.equal(res.headers['cache-control'], 'no-store')
  assert.deepEqual(calls, [['organs', {}]])
  assert.deepEqual(JSON.parse(res.body), fixture())
})

test('antibody_organs_http_fd3_browser_roundtrip', async () => {
  const socket = new Duplex({ read() {}, write(bytes, _encoding, callback) {
    const request = decodeFrame(bytes.subarray(4), 'guest')
    assert.equal(request.kind, 'organs')
    assert.deepEqual(Object.keys(request.body), [])
    const payload = encodeFrame({ ...frame(fixture()), id: request.id }, 'supervisor')
    const header = Buffer.alloc(4)
    header.writeUInt32BE(payload.length)
    this.push(Buffer.concat([header, payload]))
    callback()
  } })
  const link = new Fd3Link({ socket, timeoutMs: 100 })
  try {
    const api = client({ async fetch(url, options) {
      assert.equal(url, ORGANS_PATH)
      assert.equal(options.credentials, 'same-origin')
      assert.equal(options.cache, 'no-store')
      assert.equal(options.redirect, 'error')
      const res = response()
      await organsHandler(allow, link)({ method: 'GET', url }, res)
      return { ok: res.status === 200, async json() { return JSON.parse(res.body) } }
    } })
    const data = await api.loadOrgans()
    assert.deepEqual(data, fixture())
    for (const organ of api.ORGANS) {
      assert.ok(api.ownerFrameSrc(data, api.SYSTEM_PANES[organ[0]]).startsWith(data.owner_origin + '/#/embed/'))
    }
    assert.equal(link.pending.size, 0)
    assert.equal(link.closed, false)
  } finally { link.close() }
})

test('antibody_organs_route_refuses_unknown_and_secret_fields', async () => {
  for (const reply of [{ state: 'unknown' }, { kind: 'refusal', body: { code: 'frame:rate-limited' } },
    frame({ ...fixture(), secret: 'fixture-owner-secret' }), frame({ ...fixture(), aumlok: { ...fixture().aumlok, credential_ids: ['fixture-credential'] } })]) {
    const res = response()
    await organsHandler(allow, { async call() { return reply } })({ method: 'GET', url: ORGANS_PATH }, res)
    assert.equal(res.status, 503)
    assert.doesNotMatch(res.body, /fixture-owner-secret|fixture-credential/)
  }
})

test('antibody_organs_disabled_plugins_are_absent_from_rendered_inventory', () => {
  const overlay = JSON.parse(readFileSync(new URL('../sovereign.patch.yml', import.meta.url)))
  const disabled = overlay.filter(row => row.disabled === true).map(row => row.id)
  for (const id of ['llm-deepseek', 'llm-pi-ai', 'web-search-deepseek', 'web-fetch-http', 'session-telemetry-otel',
    'deepseek-llm-api-extensions', 'web', 'ui-settings-plugins', 'ui-settings-plugin-inventory']) {
    assert.ok(disabled.includes(id), id)
  }
  const entries = [...disabled.map(entryId => ({ entryId, moduleName: `@disabled/${entryId}`, enabled: false })),
    ...['llm', 'session-controller', 'plugin-inventory', 'sovereign-bridge'].map(entryId => ({ entryId, moduleName: `@active/${entryId}`, enabled: true }))]
  const api = client()
  const rows = api.enabledPlugins({ entries, agentPresets: [{ rows: [{ name: 'Kimi' }] }] })
  assert.deepEqual(Array.from(rows, row => row.entryId), ['llm', 'session-controller', 'plugin-inventory', 'sovereign-bridge'])
  const view = client({ state: { rows, error: false } }).PluginsSection({ list() {} })
  assert.equal(nodes(view).filter(node => node.type === 'li').length, 4)
  assert.doesNotMatch(text(view), /disabled|Kimi|pi-ai|web-search|web-fetch|telemetry/)
  assert.match(text(view), /sovereign-bridge/)
})
