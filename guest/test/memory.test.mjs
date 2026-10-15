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
import { MEMORY_PATHS, memoryHandler, registerMemoryRoutes } from '../memory.mjs'
import { apply as unavailable } from '../faces/unavailable.mjs'
import { primeFile } from '../../tests/support/prime.mjs'

const face = readFileSync(new URL('../faces/memory/lib/client.js', import.meta.url), 'utf8')
const start = face.indexOf('const KINDS = ')
const stop = face.indexOf('//#region src/client/MemorySurface.tsx', start)
assert.ok(start >= 0 && stop > start)
const { httpMemorySource, itemsOf, citedIdsOf } = vm.runInNewContext(face.slice(start, stop)
  + '\n({ httpMemorySource, itemsOf, citedIdsOf })', { URLSearchParams })
const at = 1_792_000_000_000
const item = (tier = 'remembered') => ({
  note_id: tier === 'remembered' ? 'active-note' : 'demoted-note',
  category: 'preference', at, cite_seq: 12,
  text: tier === 'remembered' ? '{"category":"preference","statement":"Tea with breakfast."}' : null,
  demoted_seq: tier === 'forgotten' ? 15 : null,
  demoted_at: tier === 'forgotten' ? at + 1000 : null,
})
const body = tier => ({ tier, items: [item(tier)], next: null })
const frame = (tier = 'remembered') => ({ v: 1, id: 'memory', kind: 'memory.list.reply', body: body(tier) })
const allow = { requestRejection: () => undefined }
const response = () => ({
  status: 0, headers: {}, body: '',
  writeHead(status, headers = {}) { this.status = status; this.headers = headers },
  end(body = '') { this.body = body },
})
const link = { async call(kind, request) {
  assert.equal(kind, 'memory.list')
  assert.deepEqual(request, { tier: request.tier, before: null })
  return frame(request.tier)
} }
const handler = (connection = allow, channel = link, path = MEMORY_PATHS[0]) => memoryHandler(connection, channel, path)

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
function router(channel = link, connection = allow) {
  const routes = []
  const ctx = { inject(_names, callback) { callback({ connection,
    webServer: { register(route) { routes.push(route); return () => {} } }, effect(effect) { effect() },
  }) } }
  unavailable(ctx)
  registerMemoryRoutes(ctx, channel)
  const source = readFileSync(primeFile('vendor/dsh/packages/host/webserver/src/index.ts'), 'utf8')
  const start = source.indexOf('  private match(')
  const stop = source.indexOf('\n  }', start) + 4
  assert.ok(start >= 0 && stop > start)
  const code = stripTypeScriptTypes('class Router {' + source.slice(start, stop) + '}')
  const Router = new Function(code + '\nreturn Router')()
  const router = Object.assign(new Router(), { exact: new Map(), prefixes: new Map() })
  for (const route of routes) router[route.kind === 'exact' ? 'exact' : 'prefixes'].set(route.path, route)
  return async (url, init = {}) => {
    const res = response()
    const route = router.match(url.split('?')[0])
    assert.ok(route, url)
    await route.handler({ method: init.method ?? 'GET', url, headers: init.headers ?? {} }, res)
    return { ok: res.status >= 200 && res.status < 300, status: res.status, headers: res.headers,
      async json() { return JSON.parse(res.body) }, text: res.body }
  }
}

test('antibody_memory_unchanged_face_parser_accepts_all_sections_and_receipt_sequences', async () => {
  const fetchImpl = router()
  const source = httpMemorySource({ fetchImpl })
  for (const tier of ['remembered', 'signed', 'proposal', 'forgotten']) {
    const answer = await source.list({ tier, q: '' })
    const parsed = itemsOf(answer, { tier, kind: 'all', query: '', citedIds: null })
    assert.equal(parsed.skipped, 0)
    assert.equal(answer.next, null)
    assert.equal(answer.issues.length, 0)
    assert.equal(parsed.items.length, ['remembered', 'forgotten'].includes(tier) ? 1 : 0)
    if (tier === 'remembered') {
      assert.equal(parsed.items[0].text, 'Tea with breakfast.')
      assert.equal(parsed.items[0].notInEffect, true)
      assert.equal(parsed.items[0].createdAt, at)
      assert.equal(answer.items[0].aura.index, 12)
    }
    if (tier === 'forgotten') {
      assert.equal(answer.items[0].text, '')
      assert.equal(parsed.items[0].text, '')
      assert.equal(parsed.items[0].forgottenAt, at + 1000)
      assert.equal(answer.items[0].aura.index, 15)
      assert.equal(answer.items[0].aura.prior_seq, 12)
      assert.match(parsed.items[0].forgottenReason, /retained/)
    }
  }
  for (const path of MEMORY_PATHS) {
    const res = await fetchImpl(path + '?q=')
    assert.equal(res.headers['content-type'], 'application/json')
    assert.equal(res.headers['cache-control'], 'no-store')
  }
  assert.equal(citedIdsOf({ manifest: null }), null)
})

test('antibody_memory_session_host_origin_and_read_only_checks_precede_c4', async () => {
  const { connection, cookie } = await browserConnection()
  let calls = 0
  const channel = { async call() { calls++; return frame() } }
  for (const path of MEMORY_PATHS) {
    for (const [headers, status] of [
      [{ host: 'chat.example' }, 401],
      [{ host: 'chat.example', cookie: 'unrelated=value' }, 401],
      [{ host: 'evil.example', cookie }, 403],
      [{ host: 'chat.example', origin: 'https://evil.example', cookie }, 403],
      [{ host: 'chat.example', 'sec-fetch-site': 'cross-site', cookie }, 403],
    ]) {
      const res = response()
      await handler(connection, channel, path)({ method: 'GET', url: path, headers }, res)
      assert.equal(res.status, status)
      assert.equal(res.body, '')
    }
    for (const method of ['POST', 'PUT', 'DELETE', 'HEAD']) {
      const res = response()
      await handler(allow, channel, path)({ method, url: path }, res)
      assert.equal(res.status, 405)
    }
    for (const connection of [null, {}]) {
      const res = response()
      await handler(connection, channel, path)({ method: 'GET', url: path }, res)
      assert.equal(res.status, 403)
    }
    const res = response()
    await handler(allow, channel, path)({ method: 'GET', url: path + '/alias' }, res)
    assert.equal(res.status, 404)
  }
  const invalid = response()
  await handler(allow, channel)({ method: 'GET', url: MEMORY_PATHS[0] + '?tier=rule' }, invalid)
  assert.equal(invalid.status, 400)
  assert.equal(calls, 0)
  const res = response()
  await handler(connection, channel)({ method: 'GET', url: MEMORY_PATHS[0], headers: { host: 'chat.example', cookie } }, res)
  assert.equal(res.status, 200)
  assert.equal(calls, 1)
})

test('antibody_memory_only_exact_list_routes_are_live_and_forget_stays_unavailable', async () => {
  const fetchImpl = router()
  for (const path of MEMORY_PATHS) assert.equal((await fetchImpl(path)).status, 200)
  for (const url of [
    '/api/aukora', '/api/aukora/theme', '/api/aukora/aumlok-control', '/api/aukora/why?replyId=reply',
    '/api/aukora/memory/remembered/alias', '/api/aukora/memory/openviking/forget',
    '/api/kira/memories/forget', '/api/kira/memories/verify', '/api/kira/trust', '/api/kira/pending',
  ]) {
    const res = await fetchImpl(url, { method: url.includes('forget') ? 'POST' : 'GET' })
    assert.equal(res.status, 503, url)
    assert.equal((await res.json()).error_code, 'UNAVAILABLE')
  }
  await assert.rejects(httpMemorySource({ fetchImpl }).forget('active-note'), error => error.status === 503)
})

test('antibody_memory_paging_search_and_unavailable_sections_do_not_invent_records', async () => {
  let calls = 0
  const channel = { async call(kind, request) {
    calls++
    assert.equal(kind, 'memory.list')
    assert.equal(request.before, 'cursor-note')
    return { ...frame(), body: { ...body('remembered'), next: 'active-note' } }
  } }
  const fetchImpl = router(channel)
  const answer = await (await fetchImpl(MEMORY_PATHS[1] + '?tier=remembered&before=cursor-note&q=TEA')).json()
  assert.equal(answer.next, 'active-note')
  assert.equal(answer.items.length, 1)
  assert.equal((await (await fetchImpl(MEMORY_PATHS[1] + '?before=cursor-note&q=coffee')).json()).items.length, 0)
  for (const tier of ['signed', 'proposal']) {
    assert.deepEqual(await (await fetchImpl(MEMORY_PATHS[0] + '?tier=' + tier)).json(), { items: [], next: null })
  }
  assert.deepEqual(await (await fetchImpl(MEMORY_PATHS[2])).json(), { items: [], next: null })
  assert.equal(calls, 2)
  const denied = router({ async call() { return { v: 1, id: 'a', kind: 'refusal', body: { code: 'kira:disclosure-not-permitted', next: '' } } } })
  assert.equal((await denied(MEMORY_PATHS[1])).status, 503)
})

test('antibody_memory_tampered_c4_and_demoted_plaintext_are_refused', async () => {
  const good = frame('forgotten')
  const bad = [
    { state: 'unknown' }, { ...good, kind: 'recall' },
    { ...good, body: { ...good.body, secret: 'fixture-secret' } },
    { ...good, body: { ...good.body, tier: 'remembered' } },
  ]
  for (const patch of [
    { text: 'erased-private-text' }, { demoted_seq: null }, { demoted_at: null },
    { secret: 'fixture-secret' }, { cite_seq: -1 }, { category: '' },
  ]) bad.push({ ...good, body: { ...good.body, items: [{ ...good.body.items[0], ...patch }] } })
  for (const value of bad) {
    const res = response()
    await handler(allow, { async call() { return value } })({ method: 'GET', url: MEMORY_PATHS[0] + '?tier=forgotten' }, res)
    assert.equal(res.status, 503)
    assert.doesNotMatch(res.body, /erased-private-text|fixture-secret/)
  }
  const res = response()
  await handler(allow, { async call() { return { ...frame(), body: { ...body('remembered'), items: [] } } } })
    ({ method: 'GET', url: MEMORY_PATHS[0] + '?tier=forgotten' }, res)
  assert.equal(res.status, 503)
})

function wireLink(transform) {
  const socket = new Duplex({ read() {}, write(bytes, _encoding, callback) {
    const request = decodeFrame(bytes.subarray(4), 'guest')
    assert.equal(request.kind, 'memory.list')
    const payload = Buffer.from(transform({ ...frame('forgotten'), id: request.id }))
    const header = Buffer.alloc(4)
    header.writeUInt32BE(payload.length)
    this.push(Buffer.concat([header, payload]))
    callback()
  } })
  return new Fd3Link({ socket, timeoutMs: 100 })
}

test('antibody_memory_fd3_round_trip_matches_the_request_kind_and_id', async () => {
  const channel = wireLink(canonicalJSON)
  try {
    const res = response()
    await handler(allow, channel)({ method: 'GET', url: MEMORY_PATHS[0] + '?tier=forgotten' }, res)
    assert.equal(res.status, 200)
    assert.equal(JSON.parse(res.body).items[0].id, 'demoted-note')
    assert.equal(channel.closed, false)
    assert.equal(channel.pending.size, 0)
  } finally { channel.close() }
})

test('antibody_memory_noncanonical_c4_wire_is_refused', async () => {
  for (const transform of [
    value => ' ' + canonicalJSON(value),
    value => canonicalJSON(value).replace('"body":', '"body":{},"body":'),
    value => canonicalJSON(value).replace('"text":null', '"text":"erased-private-text"'),
  ]) {
    const channel = wireLink(transform)
    try {
      const res = response()
      await handler(allow, channel)({ method: 'GET', url: MEMORY_PATHS[0] + '?tier=forgotten' }, res)
      assert.equal(res.status, 503)
      assert.equal(channel.closed, true)
      assert.ok(['frame:not-canonical', 'canon:duplicate-key', 'frame:invalid-field'].includes(channel.error.code))
      assert.doesNotMatch(res.body, /erased-private-text/)
    } finally { channel.close() }
  }
})
