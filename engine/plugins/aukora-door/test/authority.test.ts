// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import test from 'node:test'
import { watchAuthority } from '../src/authority.ts'
import type { AuthorityMessage } from '../src/authority.ts'

const names = ['@aukora/door', '@aukora/kira', '@owner/authority']
const active = (name: string) => ({ options: { name }, disabled: false, fiber: { state: 2 } })

function setup() {
  const messages: AuthorityMessage[] = []
  let entries = names.map(active)
  let tick = () => {}
  let dispose = () => {}
  let cancelled = false
  const ctx = {
    loader: { entries: () => entries },
    effect: (effect: () => () => void) => { dispose = effect() },
  }
  const parent = { env: { AUKORA_AUTHORITY_PLUGINS: JSON.stringify(names) }, send: (message: AuthorityMessage) => messages.push(message) }
  const every = (check: () => void) => { tick = check; return () => { cancelled = true } }
  return { ctx, parent, every, messages, tick: () => tick(), dispose: () => dispose(), cancelled: () => cancelled,
    change: (next: typeof entries) => { entries = next } }
}

test('standalone plugins do not demand node IPC or a loader', () => {
  watchAuthority({} as never, { env: {} })
})

test('the node requires a valid full authority set and launcher IPC', () => {
  for (const encoded of ['{', '[]', '["@aukora/door"]', '["@aukora/door","@aukora/kira","@aukora/kira"]', '["@aukora/door","@aukora/kira","bad name"]']) {
    assert.throws(() => watchAuthority({} as never, { env: { AUKORA_AUTHORITY_PLUGINS: encoded }, send: () => {} }), /authority-runtime-check/)
  }
  assert.throws(() => watchAuthority({} as never, { env: { AUKORA_AUTHORITY_PLUGINS: JSON.stringify(names) } }), /launcher IPC/)
})

test('positive activation covers every authority package and repeats while all remain active', () => {
  const s = setup()
  watchAuthority(s.ctx, s.parent, s.every)
  s.tick()
  assert.equal(s.messages.length, 2)
  for (const message of s.messages) {
    assert.deepEqual(message, { type: 'aukora-authority', v: 1, state: 'ready', plugins: [...names].sort() })
  }
})

test('a skipped, disabled, failed or waiting authority plugin never produces readiness', () => {
  const cases = [
    names.slice(0, 2).map(active),
    names.map(name => ({ ...active(name), disabled: name === '@owner/authority' })),
    ...[0, 1, 3, 4].map(state => names.map(name => ({ ...active(name), fiber: { state: name === '@owner/authority' ? state : 2 } }))),
  ]
  for (const entries of cases) {
    const s = setup()
    s.change(entries)
    watchAuthority(s.ctx, s.parent, s.every)
    s.tick()
    assert.deepEqual(s.messages, [])
    s.change(names.map(active))
    s.tick()
    assert.equal(s.messages[0]?.state, 'ready')
  }
})

test('losing any previously active authority package refuses once and cannot recover in the same process', () => {
  for (const name of names) {
    const s = setup()
    watchAuthority(s.ctx, s.parent, s.every)
    s.change(names.filter(candidate => candidate !== name).map(active))
    s.tick()
    s.change(names.map(active))
    s.tick()
    assert.deepEqual(s.messages.map(message => [message.state, message.reason]), [['ready', undefined], ['refused', 'authority-plugin-inactive']])
  }
})

test('door disposal cancels its timer and says stopping once, never a terminal refusal (the crash path retries)', () => {
  for (const beforeReady of [false, true]) {
    const s = setup()
    if (beforeReady) s.change([])
    watchAuthority(s.ctx, s.parent, s.every)
    s.dispose()
    s.tick()
    s.dispose()
    assert.equal(s.cancelled(), true)
    assert.equal(s.messages.at(-1)?.state, 'stopping')
    assert.equal(s.messages.filter(message => message.state === 'stopping').length, 1)
    assert.equal(s.messages.filter(message => message.state === 'refused').length, 0)
  }
})

test('disposal after a refusal adds nothing', () => {
  const s = setup()
  watchAuthority(s.ctx, s.parent, s.every)
  s.change([])
  s.tick()
  s.dispose()
  assert.deepEqual(s.messages.map(message => message.state), ['ready', 'refused'])
})

test('an unreadable loader refuses and stops heartbeat', () => {
  const s = setup()
  s.ctx.loader.entries = () => { throw new Error('loader gone') }
  watchAuthority(s.ctx, s.parent, s.every)
  s.tick()
  assert.deepEqual(s.messages.map(message => [message.state, message.reason]), [['refused', 'authority-runtime-check']])
})

test('a lost IPC channel cannot resume a heartbeat in the same process', () => {
  const s = setup()
  let sends = 0
  s.parent.send = () => { sends += 1; throw new Error('IPC disconnected') }
  watchAuthority(s.ctx, s.parent, s.every)
  s.tick()
  assert.equal(sends, 1, 'the parent will stop the engine when no further heartbeat arrives')
})
