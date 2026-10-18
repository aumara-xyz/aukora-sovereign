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
  for (const reason of ['authority-runtime-check', 'authority-plugin-inactive']) {
    assert.equal(priorRefusal({ set_hash: 'set', release: 'release' }, { ...previous, reason }), reason)
  }
})
test('a legacy silence refusal permits a clean restart of the same composition', () => {
  for (const reason of ['authority-plugin-missing', 'authority-plugin-timeout']) {
    assert.equal(priorRefusal({ set_hash: 'set', release: 'release' }, { set_hash: 'set', release: 'release', reason }), undefined)
  }
})
function rig() {
  let time = 0
  const refusals = []
  const stops = []
  let ready = 0
  let paused = 0
  const watch = new AuthorityWatch(plugins, { now: () => time, ready: () => ready++, refuse: (code, terminal) => {
    stops.push(code)
    if (terminal) refusals.push(code)
  }, pause: () => paused++ })
  return { watch, refusals, stops, ready: () => ready, paused: () => paused,
    at: value => { time = value; watch.tick() }, time: value => { time = value } }
}
test('startup silence stops the engine without latching; a fresh process must prove liveness', () => {
  const r = rig()
  r.at(STARTUP_MS - 1)
  assert.deepEqual(r.refusals, [])
  assert.equal(r.ready(), 0)
  r.at(STARTUP_MS)
  assert.deepEqual(r.stops, ['authority-plugin-missing'])
  assert.deepEqual(r.refusals, [])
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(r.ready(), 0)
  const restarted = rig()
  assert.equal(restarted.ready(), 0)
  restarted.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(restarted.ready(), 1)
})
test('a heartbeat extends liveness; silence stops without latching and only a fresh process can recover', () => {
  const r = rig()
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(r.ready(), 1)
  r.at(HEARTBEAT_MS - 1)
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  r.at(2 * HEARTBEAT_MS - 2)
  assert.deepEqual(r.refusals, [])
  r.at(2 * HEARTBEAT_MS - 1)
  assert.deepEqual(r.stops, ['authority-plugin-timeout'])
  assert.deepEqual(r.refusals, [])
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(r.ready(), 2)
  const restarted = rig()
  assert.equal(restarted.ready(), 0)
  restarted.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(restarted.ready(), 1)
})
test('overdue readiness cannot beat a delayed watchdog tick and revive the same process', () => {
  const startup = rig()
  startup.time(STARTUP_MS)
  startup.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(startup.ready(), 0)
  assert.deepEqual(startup.stops, ['authority-plugin-missing'])
  assert.deepEqual(startup.refusals, [])
  const active = rig()
  active.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  active.time(HEARTBEAT_MS)
  active.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(active.ready(), 1)
  assert.deepEqual(active.stops, ['authority-plugin-timeout'])
  assert.deepEqual(active.refusals, [])
})
test('an omitted extra authority, a disabled profile row or runtime deactivation refuses immediately', () => {
  const missing = rig()
  missing.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins: plugins.slice(0, 2) })
  assert.deepEqual(missing.refusals, ['authority-runtime-check'])
  const disabled = rig()
  disabled.watch.diagnostic('dsh: disabling profile plugin row "aukora-door": incompatible peers')
  assert.deepEqual(disabled.refusals, ['profile-plugin-disabled'])
  const extraDisabled = rig()
  extraDisabled.watch.diagnostic('dsh: disabling profile plugin row "@owner/guard": incompatible peers')
  assert.deepEqual(extraDisabled.refusals, ['profile-plugin-disabled'])
  const lost = rig()
  lost.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  lost.watch.message({ type: 'aukora-authority', v: 1, state: 'refused', plugins, reason: 'authority-plugin-inactive' })
  assert.deepEqual(lost.refusals, ['authority-plugin-inactive'])
  const removed = rig()
  removed.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  removed.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins: plugins.slice(0, 2) })
  assert.deepEqual(removed.refusals, ['authority-runtime-check'])
})
test('a non-authority profile row being disabled does not poison the approved composition', () => {
  const r = rig()
  r.watch.diagnostic('dsh: disabling profile plugin row "ui-settings-models": incompatible peers')
  assert.deepEqual(r.stops, [])
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  assert.equal(r.ready(), 1)
})
test('an intentional supervisor stop does not latch the expected disposal as a runtime failure', () => {
  const r = rig()
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'ready', plugins })
  r.watch.close()
  r.watch.message({ type: 'aukora-authority', v: 1, state: 'refused', plugins, reason: 'authority-plugin-inactive' })
  r.at(STARTUP_MS)
  assert.deepEqual(r.refusals, [])
})
test('a disposing plugin stops service at once; its silent process is killed without a terminal refusal', () => {
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
  assert.deepEqual(r.stops, ['authority-plugin-timeout'])
  assert.deepEqual(r.refusals, [])
})
