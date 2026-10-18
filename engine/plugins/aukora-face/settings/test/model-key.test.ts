// SPDX-License-Identifier: AGPL-3.0-or-later
// The Models row's reading of the broker's standing and its hand-off to the shell origin (settings/src/client/models).
//   node --test engine/plugins/aukora-face/settings/test/*.test.ts      (Node 24: types are stripped)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { keyPageHref, parseStanding, rowView, shellOrigin } from '../src/client/models/model-key.ts'

test('the broker standing is read strictly: state only, never a character of the key', () => {
  assert.deepEqual(parseStanding(200, { state: 'none' }), { state: 'none' })
  assert.deepEqual(parseStanding(200, { state: 'awaiting-approval' }), { state: 'awaiting-approval' })
  assert.deepEqual(parseStanding(200, { state: 'not-approved' }), { state: 'not-approved' })
  assert.deepEqual(parseStanding(200, { state: 'approved' }), { state: 'approved' })
  assert.deepEqual(parseStanding(404, undefined), { state: 'unavailable' })
  for (const [status, body] of [
    [503, { state: 'none' }],
    [200, { state: 'approved', last4: 'wxyz' }],
    [200, { state: 'none', last4: 'wxyz' }],
    [200, { state: 'approved', last4: 'wxyz', key: 'sk-test-0000' }],
    [200, { state: 'approved', last4: 'wxyz', fingerprint: '0123456789ab' }],
    [200, { state: 'active' }],
    [200, ['none']],
    [200, null],
    [200, 'none'],
  ] as const) {
    assert.deepEqual(parseStanding(status, body), { state: 'unknown' }, JSON.stringify([status, body]))
  }
})

test('Edit opens the shell origin, never the engine origin it runs on', () => {
  const engine = { protocol: 'https:', host: 'engine.n1.example.net' }
  assert.equal(shellOrigin(engine), 'https://n1.example.net')
  assert.equal(keyPageHref(engine), 'https://n1.example.net/engine/model-key#from=models')
  // Not a node (the local preview, or a host that is not engine.<shell>): a name that cannot resolve, not this origin.
  for (const place of [{ protocol: 'http:', host: '127.0.0.1:3099' }, { protocol: 'https:', host: 'engine.' }, undefined]) {
    assert.equal(shellOrigin(place), 'https://node.invalid')
  }
})

test('the row is honest about each standing and shows no part of the key', () => {
  assert.equal(rowView({ state: 'none' }).action, 'Add your DeepSeek key')
  assert.equal(rowView({ state: 'awaiting-approval' }).pill, 'Waiting for you')
  assert.equal(rowView({ state: 'awaiting-approval' }).tone, 'gold')
  const approved = rowView({ state: 'approved' })
  assert.equal(approved.tone, 'mint')
  assert.equal(approved.pill, 'Approved')
  assert.equal(approved.summary, 'Held by your node, outside the engine')
  assert.equal(rowView({ state: 'not-approved' }).tone, 'red')
  assert.equal(approved.action, 'Edit')
  assert.equal(rowView({ state: 'unavailable' }).actionable, false)
  assert.notEqual(rowView({ state: 'unknown' }).tone, 'mint', 'nothing read is never shown as approved')
})
