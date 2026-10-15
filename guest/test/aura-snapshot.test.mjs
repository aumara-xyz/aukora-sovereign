// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import * as crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'
import { Duplex } from 'node:stream'
import test from 'node:test'
import vm from 'node:vm'
import { canonicalJSON, decodeFrame } from '../canon.mjs'
import { Fd3Link } from '../fd3.mjs'
import { AURA_SNAPSHOT_PATH, organsHandler, registerOrgansRoute } from '../organs.mjs'
import { apply as unavailable } from '../faces/unavailable.mjs'
import { primeFile } from '../../tests/support/prime.mjs'

const face = readFileSync(new URL('../faces/settings/lib/client.js', import.meta.url), 'utf8')
const start = face.indexOf('//#region src/client/aura-snapshot.ts')
const stop = face.indexOf('function advanceSourceEntries', start)
assert.ok(start >= 0 && stop > start)
const parseSnapshot = vm.runInNewContext(face.slice(start, stop) + '\nparseAuraSnapshot')
const fixture = () => ({
  ...JSON.parse(JSON.parse(readFileSync(new URL('../../crates/canon/vectors/organs.json', import.meta.url)))[0].input).body,
  aura: {
    sequence: 42, root: 'a'.repeat(64), sources: [
      { name: 'gate-ledger', head: 'b'.repeat(64), entries: 3, absence: null },
      { name: 'kira-chain', head: null, entries: 0, absence: 'kira-ledger-empty' },
      { name: 'code-chain', head: 'c'.repeat(64), entries: 1, absence: null },
    ],
  },
})
const frame = body => ({ v: 1, id: 'snapshot', kind: 'organs.reply', body })
const allow = { requestRejection: () => undefined }
const response = () => ({
  status: 0, headers: {}, body: '',
  writeHead(status, headers = {}) { this.status = status; this.headers = headers },
  end(body = '') { this.body = body },
})
const request = { method: 'GET', url: AURA_SNAPSHOT_PATH }
const handler = (connection, link) => organsHandler(connection, link, AURA_SNAPSHOT_PATH)

function linkFor(transform = value => canonicalJSON(value)) {
  const socket = new Duplex({ read() {}, write(bytes, _encoding, callback) {
    const request = decodeFrame(bytes.subarray(4), 'guest')
    assert.equal(request.kind, 'organs')
    assert.deepEqual(Object.keys(request.body), [])
    const payload = Buffer.from(transform({ ...frame(fixture()), id: request.id }))
    const header = Buffer.alloc(4)
    header.writeUInt32BE(payload.length)
    this.push(Buffer.concat([header, payload]))
    callback()
  } })
  return new Fd3Link({ socket, timeoutMs: 100 })
}

// Execute the pinned harness's own Host/Origin and signed browser-cookie checks.
function reference(relative, bindings, result) {
  const source = readFileSync(primeFile('vendor/dsh/packages/' + relative), 'utf8')
  const code = stripTypeScriptTypes(source.replace(/^import[\s\S]*?from [^\n]+\n/gm, ''), { mode: 'transform' })
    .replace(/^export /gm, '')
  return new Function(...Object.keys(bindings), code + '\nreturn ' + result)(...Object.values(bindings))
}
async function browserConnection() {
  const isLoopbackHostname = reference('client/connection/src/loopback-hostname.ts', {}, 'isLoopbackHostname')
  const isTrustedApiRequest = reference('client/connection/src/api-request-trust.ts', { isLoopbackHostname }, 'isTrustedApiRequest')
  const BrowserAuth = reference('client/connection/src/browser-auth.ts', {
    createHash: crypto.createHash, createHmac: crypto.createHmac,
    randomBytes: crypto.randomBytes, timingSafeEqual: crypto.timingSafeEqual,
    isLoopbackHostname, credentialKey: (...parts) => parts.join(':'),
  }, 'BrowserAuth')
  let record
  const browserAuth = await BrowserAuth.create({}, { async modifyRecord(_key, change) {
    record = await change(record) ?? record
    return record
  } }, 1)
  const host = readFileSync(primeFile('vendor/dsh/packages/client/connection/src/rpc-host.ts'), 'utf8')
  const start = host.indexOf('  requestRejection(request:')
  const stop = host.indexOf('\n  }', start) + 4
  assert.ok(start >= 0 && stop > start)
  const method = stripTypeScriptTypes('({' + host.slice(start, stop) + '})')
  const connection = Object.assign(new Function('isTrustedApiRequest', 'return ' + method)(isTrustedApiRequest), {
    trustedHosts: ['chat.example'], browserAuth,
  })
  const res = response()
  browserAuth.authorizeIndex({ method: 'GET', url: browserAuth.authenticatedUrl('https://chat.example'), headers: { host: 'chat.example' } }, res)
  assert.equal(res.status, 303)
  return { connection, cookie: res.headers['set-cookie'].split(';')[0] }
}

test('antibody_pentora_snapshot_runs_unchanged_face_parser_and_keeps_supervisor_head', async () => {
  const link = linkFor()
  try {
    const res = response()
    await handler(allow, link)(request, res)
    assert.equal(res.status, 200)
    assert.equal(res.headers['cache-control'], 'no-store')
    assert.equal(res.headers['content-type'], 'application/json')
    const snapshot = JSON.parse(res.body)
    let parsed
    assert.doesNotThrow(() => { parsed = JSON.parse(JSON.stringify(parseSnapshot(snapshot))) })
    assert.deepEqual(parsed, snapshot)
    assert.equal(snapshot.head, fixture().aura.root)
    assert.deepEqual(snapshot.sources.map(source => source.name), ['gate-ledger', 'kira-chain', 'code-chain'])
    assert.deepEqual(snapshot.sources[0], fixture().aura.sources[0])
    assert.deepEqual(snapshot.sources[2], fixture().aura.sources[2])
    assert.deepEqual(snapshot.sources[1].browserMemory, { active: false, reason: 'kira.memory:browser-overlay-unavailable' })
    assert.deepEqual(Object.keys(snapshot).sort(), ['head', 'schema', 'sources'])
  } finally { link.close() }
})

test('antibody_pentora_guest_empty_sources_are_explicit_absences', async () => {
  const body = fixture()
  body.aura.sources = ['gate-ledger-empty', 'kira-ledger-empty', 'code-record-missing'].map((absence, index) => ({
    name: ['gate-ledger', 'kira-chain', 'code-chain'][index], head: null, entries: 0, absence,
  }))
  const res = response()
  await handler(allow, { async call() { return frame(body) } })(request, res)
  assert.equal(res.status, 200)
  const snapshot = JSON.parse(res.body)
  assert.doesNotThrow(() => parseSnapshot(snapshot))
  for (const [index, source] of snapshot.sources.entries()) {
    assert.equal(source.head, null)
    assert.equal(source.entries, 0)
    assert.equal(source.absence, body.aura.sources[index].absence)
  }
})

test('antibody_pentora_session_host_origin_and_read_only_checks_precede_c4', async () => {
  const { connection, cookie } = await browserConnection()
  let calls = 0
  const link = { async call() { calls++; return frame(fixture()) } }
  for (const [headers, status] of [
    [{ host: 'chat.example' }, 401],
    [{ host: 'chat.example', cookie: 'unrelated=value' }, 401],
    [{ host: 'evil.example', cookie }, 403],
    [{ host: 'chat.example', origin: 'https://evil.example', cookie }, 403],
    [{ host: 'chat.example', 'sec-fetch-site': 'cross-site', cookie }, 403],
  ]) {
    const res = response()
    await handler(connection, link)({ ...request, headers }, res)
    assert.equal(res.status, status)
    assert.equal(res.body, '')
  }
  for (const missing of [undefined, {}]) {
    const res = response()
    await handler(missing, link)(request, res)
    assert.equal(res.status, 403)
  }
  for (const method of ['POST', 'PUT', 'DELETE', 'HEAD']) {
    const res = response()
    await handler(allow, link)({ ...request, method }, res)
    assert.equal(res.status, 405)
  }
  for (const url of [AURA_SNAPSHOT_PATH + '?x=1', AURA_SNAPSHOT_PATH + '/alias']) {
    const res = response()
    await handler(allow, link)({ ...request, url }, res)
    assert.equal(res.status, 404)
  }
  assert.equal(calls, 0)
  const res = response()
  await handler(connection, link)({ ...request, headers: { host: 'chat.example', origin: 'https://chat.example', cookie } }, res)
  assert.equal(res.status, 200)
  assert.equal(calls, 1)
})

test('antibody_pentora_exact_route_wins_and_other_aukora_routes_stay_503', async () => {
  const routes = []
  const ctx = { inject(_names, callback) { callback({ connection: allow,
    webServer: { register(route) { routes.push(route); return () => {} } }, effect(effect) { effect() },
  }) } }
  unavailable(ctx)
  registerOrgansRoute(ctx, { async call() { return frame(fixture()) } })
  const source = readFileSync(primeFile('vendor/dsh/packages/host/webserver/src/index.ts'), 'utf8')
  const start = source.indexOf('  private match(')
  const stop = source.indexOf('\n  }', start) + 4
  assert.ok(start >= 0 && stop > start)
  const code = stripTypeScriptTypes('class Router {' + source.slice(start, stop) + '}')
  const Router = new Function(code + '\nreturn Router')()
  const router = Object.assign(new Router(), { exact: new Map(), prefixes: new Map() })
  for (const route of routes) router[route.kind === 'exact' ? 'exact' : 'prefixes'].set(route.path, route)
  const res = response()
  await router.match(AURA_SNAPSHOT_PATH).handler(request, res)
  assert.equal(res.status, 200)
  for (const url of ['/api/aukora', '/api/aukora/theme', '/api/aukora/aumlok-control', AURA_SNAPSHOT_PATH + '/alias']) {
    const res = response()
    await router.match(url).handler({ method: 'GET', url }, res)
    assert.equal(res.status, 503, url)
    assert.equal(JSON.parse(res.body).error_code, 'UNAVAILABLE')
  }
})

test('antibody_pentora_tampered_c4_objects_are_refused_before_projection', async () => {
  const good = frame(fixture())
  const bad = [
    { state: 'unknown' }, { ...good, kind: 'status.reply' },
    { ...good, body: { ...good.body, secret: 'fixture-secret' } },
    { ...good, body: { ...good.body, aura: { ...good.body.aura, secret: 'fixture-secret' } } },
  ]
  for (const change of [
    source => { source.secret = 'fixture-secret' }, source => { source.head = 'INVALID' },
    source => { source.entries = 0 }, source => { source.absence = 'invented' },
    source => { source.name = 'code-chain' },
  ]) {
    const value = frame(fixture())
    change(value.body.aura.sources[0])
    bad.push(value)
  }
  for (const extra of [fixture().aura.sources[0], { secret: 'fixture-secret' }]) {
    const value = frame(fixture())
    value.body.aura.sources.push(extra)
    bad.push(value)
  }
  for (const value of bad) {
    const res = response()
    await handler(allow, { async call() { return value } })(request, res)
    assert.equal(res.status, 503)
    assert.doesNotMatch(res.body, /fixture-secret|INVALID/)
  }
})

test('antibody_pentora_noncanonical_c4_wire_reply_is_refused', async () => {
  for (const transform of [
    value => ' ' + canonicalJSON(value),
    value => canonicalJSON(value).replace('"body":', '"body":{},"body":'),
    value => canonicalJSON(value).replace('"root":"' + 'a'.repeat(64) + '"', '"root":"tampered"'),
  ]) {
    const link = linkFor(transform)
    try {
      const res = response()
      await handler(allow, link)(request, res)
      assert.equal(res.status, 503)
      assert.equal(link.closed, true)
      assert.ok(['frame:not-canonical', 'canon:duplicate-key', 'frame:invalid-field'].includes(link.error.code))
    } finally { link.close() }
  }
})
