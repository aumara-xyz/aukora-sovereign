// SPDX-License-Identifier: AGPL-3.0-or-later
import { strict as assert } from 'node:assert'
import { test } from 'node:test'
import { AumlokControlStatusLoader } from '../src/client/control-status-loader.ts'
import type { AumlokControlProjectionService } from '../src/client/control-projection.ts'

function projection(ceremonyAvailable: boolean) {
  const received: unknown[] = []
  let disconnected = 0
  const service = {
    ceremonyAvailable,
    connect(value: unknown) { received.push(value) },
    disconnect() { disconnected += 1 },
  } as unknown as AumlokControlProjectionService
  return { service, received, disconnected: () => disconnected }
}

test('the Sovereign browser has no legacy controller read without a desktop bridge', async () => {
  const state = projection(false)
  let reads = 0
  const loader = new AumlokControlStatusLoader(state.service, { isLoopback: true }, async () => {
    reads += 1
    return Response.json({})
  })
  await loader.refresh()
  await loader.refresh()
  assert.equal(reads, 0)
  assert.equal(state.disconnected(), 2)
  assert.deepEqual(state.received, [])
})

test('a desktop bridge retains the authenticated same-origin projection read', async () => {
  const state = projection(true)
  const body = { status: 'connected', control: { public: 'projection' } }
  const loader = new AumlokControlStatusLoader(state.service, { isLoopback: true }, async (path, init) => {
    assert.equal(path, '/api/aukora/aumlok-control')
    assert.equal(init.method, 'GET')
    assert.equal(init.credentials, 'same-origin')
    assert.equal(init.cache, 'no-store')
    return Response.json(body)
  })
  await loader.refresh()
  assert.deepEqual(state.received, [body])
})

test('a desktop bridge never enables a non-loopback controller read', async () => {
  const state = projection(true)
  const loader = new AumlokControlStatusLoader(state.service, { isLoopback: false }, async () => {
    assert.fail('non-loopback read')
  })
  await loader.refresh()
  assert.deepEqual(state.received, [])
})
