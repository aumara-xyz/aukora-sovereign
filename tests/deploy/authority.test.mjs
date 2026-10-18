// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict'
import test from 'node:test'
import { AuthorityWatch, priorRefusal, STARTUP_MS, HEARTBEAT_MS } from '../../deploy/engine/authority.mjs'

const plugins = ['@aukora/door', '@aukora/kira', '@owner/guard']
test('a terminal refusal survives a restart until different set or release bytes are approved', () => {
  const previous = { set_hash: 'set', release: 'release', reason: 'profile-plugin-disabled' }
  assert.equal(priorRefusal({ set_hash: 'set', release: 'release' }, previous), 'profile-plugin-disabled')
  assert.equal(priorRefusal({ set_hash: 'new', release: 'release' }, previous), undefined)
  assert.equal(priorRefusal({ set_hash: 'set', release: 'new' }, previous), undefined)
})
function rig() {
  let time = 0
  const refusals = []
  let ready = 0
  let paused = 0
  const watch = new AuthorityWatch(plugins, { now: () => time, ready: () => ready++, refuse: code => refusals.push(code), pause: () => paused++ })
  return { watch, refusals, ready: () => ready, paused: () => paused, at: value => { time = value; watch.tick() } }
}
test('no positive activation by the deadline stops the engine, even if DSH boots successfully', () => {
  const r = rig()
  r.at(STARTUP_MS - 1)
  assert.deepEqual(r.refusals, [])
  assert.equal(r.ready(), 0)
  r.at(STARTUP_MS)
  assert.deepEqual(r.refusals, ['authority-plugin-missing'])
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(r.ready(), 0)
})
test('all authority plugins must stay alive; a heartbeat extends liveness, silence stops it', () => {
  const r = rig()
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(r.ready(), 1)
  r.at(HEARTBEAT_MS - 1)
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  r.at(2 * HEARTBEAT_MS - 2)
  assert.deepEqual(r.refusals, [])
  r.at(2 * HEARTBEAT_MS - 1)
  assert.deepEqual(r.refusals, ['authority-plugin-timeout'])
})
test('an omitted extra authority, a disabled profile row or runtime deactivation refuses immediately', () => {
  const missing = rig()
  missing.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins: plugins.slice(0, 2) })
  assert.deepEqual(missing.refusals, ['authority-runtime-check'])
  const disabled = rig()
  disabled.watch.diagnostic('dsh: disabling profile plugin row "aukora-door": incompatible peers')
  assert.deepEqual(disabled.refusals, ['profile-plugin-disabled'])
  const lost = rig()
  lost.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  lost.watch.message({ type: 'aukora-authority', v: 1, state: 'refused', plugins, reason: 'authority-plugin-inactive' })
  assert.deepEqual(lost.refusals, ['authority-plugin-inactive'])
})
test('an intentional supervisor stop does not latch the expected disposal as a runtime failure', () => {
  const r = rig()
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  r.watch.close()
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'refused', plugins, reason: 'authority-plugin-inactive' })
  r.at(STARTUP_MS)
  assert.deepEqual(r.refusals, [])
})
test('a disposing plugin stops service at once without a terminal refusal; staying alive without it still latches', () => {
  const r = rig()
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  r.at(1)
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'stopping', plugins })
  assert.equal(r.paused(), 1)
  assert.deepEqual(r.refusals, [])
  // A late ready after stopping never re-admits the same process.
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(r.ready(), 1)
  r.at(HEARTBEAT_MS - 1)
  assert.deepEqual(r.refusals, [])
  r.at(HEARTBEAT_MS)
  assert.deepEqual(r.refusals, ['authority-plugin-timeout'])
})
