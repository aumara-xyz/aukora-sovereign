// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { apply, inject, name } from '../src/index.ts'
import { resolveConfig } from '../src/door.ts'

function fakeContext() {
  const log: Array<{ what: string; options?: unknown }> = []
  const ctx = {
    on(event: string, _listener: unknown, options?: unknown) {
      log.push({ what: `on:${event}`, options })
      return () => true
    },
    tools: {
      guard(_guard: unknown) {
        log.push({ what: 'guard' })
        return () => {}
      },
    },
  }
  return { ctx, log }
}

test('apply registers the three hooks ahead of every other listener, plus the result cleanup', () => {
  const { ctx, log } = fakeContext()
  apply(ctx as never, { socketPath: '/tmp/aukora-door-test.sock', workspaceRoots: ['/sandbox'] })
  assert.deepEqual(log.map(entry => entry.what), ['on:tools/pre-execute', 'guard', 'on:tools/execute', 'on:tools/result'])
  assert.deepEqual(log[0]?.options, { prepend: true, global: true })
  assert.deepEqual(log[2]?.options, { prepend: true, global: true })
})

test('the plugin declares its name and the service it needs', () => {
  assert.equal(name, 'aukora-door')
  assert.deepEqual(inject, ['tools'])
})

test('a bad configuration stops the engine at load time instead of leaving the door half open', () => {
  const { ctx, log } = fakeContext()
  assert.throws(() => apply(ctx as never, { socketPath: 'relative.sock', workspaceRoots: [] }), /socketPath/)
  assert.throws(() => apply(ctx as never, { socketPath: `/${'x'.repeat(120)}`, workspaceRoots: [] }), /socketPath/)
  assert.throws(() => apply(ctx as never, { socketPath: '/tmp/x.sock', workspaceRoots: ['relative'] }), /workspaceRoots/)
  assert.throws(() => apply(ctx as never, undefined as never), /config/)
  assert.equal(log.length, 0)
})

test('configuration defaults and bounds', () => {
  const config = resolveConfig({ socketPath: '/tmp/x.sock', workspaceRoots: ['/sandbox/', '/'] })
  assert.deepEqual(config.workspaceRoots, ['/sandbox', '/'])
  assert.equal(config.connectTimeoutMs, 2_000)
  assert.equal(config.responseTimeoutMs, 120_000)
  assert.equal(config.maxFrameBytes, 1_048_576)
  assert.throws(() => resolveConfig({ socketPath: '/tmp/x.sock', workspaceRoots: [], connectTimeoutMs: 0 }), /connectTimeoutMs/)
  assert.throws(() => resolveConfig({ socketPath: '/tmp/x.sock', workspaceRoots: [], maxFrameBytes: 10 }), /maxFrameBytes/)
})
