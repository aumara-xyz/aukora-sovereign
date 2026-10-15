// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { canonicalJSON, decodeFrame, encodeFrame } from './canon.mjs'

const vectors = JSON.parse(readFileSync(new URL('../crates/canon/vectors/memory.json', import.meta.url)))

test('memory shared vectors and direction round trip', () => {
  for (const vector of vectors) {
    if (vector.frame_refusal) assert.throws(() => decodeFrame(vector.input, vector.frame_direction), error => error.code === vector.frame_refusal, vector.name)
    else assert.equal(Buffer.from(encodeFrame(decodeFrame(vector.input, vector.frame_direction), vector.frame_direction)).toString(), vector.canonical, vector.name)
  }
})

test('memory encoder refuses demoted plaintext and noncanonical bytes', () => {
  const frame = JSON.parse(vectors.find(vector => vector.name === 'memory forgotten reply').input)
  frame.body.items[0].text = 'erased text'
  assert.throws(() => encodeFrame(frame, 'supervisor'), error => error.code === 'frame:invalid-field')
  frame.body.items[0].text = null
  assert.doesNotThrow(() => encodeFrame(frame, 'supervisor'))
  assert.throws(() => decodeFrame(JSON.stringify(frame, null, 2), 'supervisor'), error => error.code === 'frame:not-canonical')
  frame.body.items[0].demoted_seq = frame.body.items[0].cite_seq
  assert.throws(() => decodeFrame(canonicalJSON(frame), 'supervisor'), error => error.code === 'frame:invalid-field')
})
