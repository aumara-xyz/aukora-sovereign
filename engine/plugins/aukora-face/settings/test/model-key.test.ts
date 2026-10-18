// SPDX-License-Identifier: AGPL-3.0-or-later
// The Models row's reading of the broker's standing and its hand-off to the shell origin (settings/src/client/models).
//   node --test engine/plugins/aukora-face/settings/test/*.test.ts      (Node 24: types are stripped)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { keyPageHref, NOT_APPROVED_NOTE, parseStanding, rowView, shellOrigin, WAITING_NOTE } from '../src/client/models/model-key.ts'

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
  // A key waiting for approval, or declined, means refused calls (not a queue), and the old key does not come back.
  assert.equal(rowView({ state: 'awaiting-approval' }).note, WAITING_NOTE)
  assert.match(WAITING_NOTE, /can't reach the model/)
  assert.match(WAITING_NOTE, /If you decline it, enter a key again/)
  assert.equal(rowView({ state: 'not-approved' }).note, NOT_APPROVED_NOTE)
  assert.match(NOT_APPROVED_NOTE, /doesn't come back by itself/)
  for (const state of ['none', 'awaiting-approval', 'not-approved', 'approved', 'unknown'] as const) {
    assert.doesNotMatch(rowView({ state }, 'n1.example.net').note + rowView({ state }).summary, /\bwait for your passkey\b|never enters the engine/)
  }
  assert.match(rowView({ state: 'none' }, 'n1.example.net').note, /n1\.example\.net/, 'the exact key-page host is named')
})

test('a failed read does not keep saying it is still reading', () => {
  assert.equal(rowView({ state: 'reading' }).pill, 'Reading…')
  const failed = rowView(parseStanding(503, undefined))
  assert.equal(failed.pill, 'Could not read')
  assert.match(failed.note, /try again/)
  assert.notEqual(failed.tone, 'mint')
})
