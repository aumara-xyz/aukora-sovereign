// SPDX-License-Identifier: AGPL-3.0-or-later
// The owner origin a face links to (layout/src/client/composition.ts).
//   node --test engine/plugins/aukora-face/layout/test/*.test.ts      (Node >= 22.18: types are stripped)
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { ownerOrigin } from '../src/client/composition.ts'

test('on the engine origin the owner origin is owner.<shell>, never owner.engine.<shell>', () => {
  assert.equal(ownerOrigin({ protocol: 'https:', host: 'engine.n1.example.net' }), 'https://owner.n1.example.net')
  assert.equal(ownerOrigin({ protocol: 'https:', host: 'n1.example.net' }), 'https://owner.n1.example.net', 'the shell itself')
  assert.equal(ownerOrigin({ protocol: 'http:', host: '127.0.0.1:3099' }), 'http://owner.127.0.0.1:3099', 'the preview, unchanged')
  assert.equal(ownerOrigin({ protocol: 'https:', host: 'engine.' }), 'https://owner.invalid')
  assert.equal(ownerOrigin(undefined), 'https://owner.invalid')
})
