// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { canonicalJSON, decodeFrame, encodeFrame, MAX_ORGAN_NPUB_BYTES, MAX_OWNER_ORIGIN_BYTES } from './canon.mjs'

const vectors = JSON.parse(readFileSync(new URL('../crates/canon/vectors/organs.json', import.meta.url)))
const fixture = () => JSON.parse(vectors[0].input)
const reject = (frame, code = 'frame:invalid-field', direction = 'supervisor') => assert.throws(() => encodeFrame(frame, direction), error => error.code === code)
const change = (path, value) => {
  const frame = fixture()
  let parent = frame
  for (const key of path.slice(0, -1)) parent = parent[key]
  parent[path.at(-1)] = value
  return frame
}
const sourceNames = [
  ['gate-ledger', 'gate-ledger-empty'],
  ['kira-chain', 'kira-ledger-empty'],
  ['code-chain', 'code-record-missing'],
]
const sourceFrame = (index, present) => {
  const frame = fixture()
  const [name, absence] = sourceNames[index]
  frame.body.aura.sources[index] = { name, head: present ? 'd'.repeat(64) : null, entries: present ? 1 : 0, absence: present ? null : absence }
  return frame
}
const rejectSource = (frame, code = 'frame:invalid-field') => {
  reject(frame, code)
  assert.throws(() => decodeFrame(canonicalJSON(frame), 'supervisor'), error => error.code === code)
}

test('organs shared vectors and directions round trip', () => {
  for (const vector of vectors) {
    if (vector.frame_refusal) assert.throws(() => decodeFrame(vector.input, vector.frame_direction), error => error.code === vector.frame_refusal, vector.name)
    else assert.equal(Buffer.from(encodeFrame(decodeFrame(vector.input, vector.frame_direction), vector.frame_direction)).toString(), vector.canonical, vector.name)
  }
})

test('organs reply has exact public fields', () => {
  for (const path of [['body'], ...['aumlok', 'aura', 'kira', 'nostr', 'wasm'].map(organ => ['body', organ])]) {
    const frame = fixture()
    let object = frame
    for (const key of path) object = object[key]
    const keys = Object.keys(object)
    object.secret = 'private'
    reject(frame, 'frame:unknown-field')
    for (const key of keys) {
      const frame = fixture()
      let object = frame
      for (const key of path) object = object[key]
      delete object[key]
      reject(frame, 'frame:missing-field')
    }
  }
  reject({ v: 1, id: 'a', kind: 'organs', body: { secret: 'private' } }, 'frame:unknown-field', 'guest')
  reject({ v: 1, id: 'a', kind: 'organs', body: [] }, 'frame:not-object', 'guest')
})

test('organs counts are nonnegative safe integers', () => {
  for (const path of [['body', 'approvals_pending'], ['body', 'aumlok', 'passkeys'], ['body', 'aura', 'sequence'], ['body', 'kira', 'notes'], ['body', 'kira', 'demoted'], ['body', 'nostr', 'witness_accepted']]) {
    for (const bad of [-1, null, false, '1']) reject(change(path, bad))
    for (const good of [0, Number.MAX_SAFE_INTEGER]) assert.doesNotThrow(() => encodeFrame(change(path, good), 'supervisor'))
    const text = canonicalJSON(change(path, Number.MAX_SAFE_INTEGER)).replace('9007199254740991', '9007199254740992')
    assert.throws(() => decodeFrame(text, 'supervisor'), error => error.code === 'canon:integer-range')
  }
})

test('organs reply field types are checked', () => {
  for (const field of ['bound', 'refresh_due']) {
    for (const bad of [null, 0, 'false']) reject(change(['body', 'aumlok', field], bad))
    for (const good of [false, true]) assert.doesNotThrow(() => encodeFrame(change(['body', 'aumlok', field], good), 'supervisor'))
  }
  for (const field of ['aumlok', 'aura', 'kira', 'nostr', 'wasm']) {
    for (const bad of [null, [], false]) reject(change(['body', field], bad), 'frame:not-object')
  }
})

test('organs digests require lowercase hex64', () => {
  for (const [organ, field] of [['aura', 'root'], ['wasm', 'module_sha256']]) {
    for (const bad of ['', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), 'é'.repeat(32), 0]) reject(change(['body', organ, field], bad))
  }
})

test('organs strings are bounded by UTF-8 bytes', () => {
  for (const [path, maximum, nullable] of [[['body', 'owner_origin'], MAX_OWNER_ORIGIN_BYTES, false], [['body', 'nostr', 'node_npub'], MAX_ORGAN_NPUB_BYTES, true], [['body', 'nostr', 'agent_npub'], MAX_ORGAN_NPUB_BYTES, true]]) {
    for (const bad of ['', 'x'.repeat(maximum + 1), '😀'.repeat(maximum / 4 + 1), 0]) reject(change(path, bad))
    for (const good of ['x'.repeat(maximum), '😀'.repeat(maximum / 4)]) assert.doesNotThrow(() => encodeFrame(change(path, good), 'supervisor'))
    if (nullable) assert.doesNotThrow(() => encodeFrame(change(path, null), 'supervisor'))
    else reject(change(path, null))
  }
})

test('organs aura sources require exactly three ordered source objects', () => {
  const sources = fixture().body.aura.sources
  for (const bad of [null, {}, false, 'sources', [], sources.slice(0, 2), [...sources, structuredClone(sources[0])]]) {
    rejectSource(change(['body', 'aura', 'sources'], bad))
  }
  for (const order of [[1, 0, 2], [0, 2, 1], [2, 1, 0], [0, 0, 2], [0, 1, 1]]) {
    rejectSource(change(['body', 'aura', 'sources'], order.map(index => structuredClone(sources[index]))))
  }
  for (let index = 0; index < sources.length; index++) {
    for (const bad of [null, [], false, 0, 'source']) rejectSource(change(['body', 'aura', 'sources', index], bad), 'frame:not-object')
    for (const bad of [null, false, 1, '', sourceNames[index][0].toUpperCase(), `${sourceNames[index][0]}-extra`]) {
      rejectSource(change(['body', 'aura', 'sources', index, 'name'], bad))
    }
    for (const field of ['absence', 'entries', 'head', 'name']) {
      const frame = fixture()
      delete frame.body.aura.sources[index][field]
      rejectSource(frame, 'frame:missing-field')
    }
    const frame = fixture()
    frame.body.aura.sources[index].extra = 'must-not-cross'
    rejectSource(frame, 'frame:unknown-field')
  }
})

test('organs aura source counts and absence states match Rust', () => {
  for (let index = 0; index < sourceNames.length; index++) {
    for (const present of [false, true]) {
      const frame = sourceFrame(index, present)
      const bytes = encodeFrame(frame, 'supervisor')
      assert.equal(canonicalJSON(decodeFrame(bytes, 'supervisor')), canonicalJSON(frame))
      for (const bad of [-1, null, false, '1']) {
        const invalid = structuredClone(frame)
        invalid.body.aura.sources[index].entries = bad
        rejectSource(invalid)
      }
      for (const [bad, code] of [[-0, 'canon:invalid-number'], [1.5, 'canon:integer-range'], [Number.MAX_SAFE_INTEGER + 1, 'canon:integer-range'], [Infinity, 'canon:invalid-json']]) {
        const invalid = structuredClone(frame)
        invalid.body.aura.sources[index].entries = bad
        reject(invalid, code)
      }
    }
    for (const entries of [1, Number.MAX_SAFE_INTEGER]) {
      const frame = sourceFrame(index, true)
      frame.body.aura.sources[index].entries = entries
      assert.doesNotThrow(() => encodeFrame(frame, 'supervisor'))
      assert.doesNotThrow(() => decodeFrame(canonicalJSON(frame), 'supervisor'))
    }
    const presentWithoutEntries = sourceFrame(index, true)
    presentWithoutEntries.body.aura.sources[index].entries = 0
    rejectSource(presentWithoutEntries)
    for (const entries of [1, Number.MAX_SAFE_INTEGER]) {
      const absentWithEntries = sourceFrame(index, false)
      absentWithEntries.body.aura.sources[index].entries = entries
      rejectSource(absentWithEntries)
    }
    for (const absence of ['', sourceNames[index][1], 'null', 0, false, {}, []]) {
      const present = sourceFrame(index, true)
      present.body.aura.sources[index].absence = absence
      rejectSource(present)
    }
    const wrongAbsences = [null, '', `${sourceNames[index][1]}-extra`, 0, false, {}, [], ...sourceNames.filter((_, other) => other !== index).map(([, absence]) => absence)]
    for (const absence of wrongAbsences) {
      const absent = sourceFrame(index, false)
      absent.body.aura.sources[index].absence = absence
      rejectSource(absent)
    }
    const oversized = sourceFrame(index, true)
    oversized.body.aura.sources[index].entries = Number.MAX_SAFE_INTEGER
    const wire = canonicalJSON(oversized).replace('9007199254740991', '9007199254740992')
    assert.throws(() => decodeFrame(wire, 'supervisor'), error => error.code === 'canon:integer-range')
  }
})

test('organs aura source heads require lowercase hex64 or a valid absence', () => {
  for (let index = 0; index < sourceNames.length; index++) {
    for (const head of [null, '', 'a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), 'é'.repeat(32), `${'a'.repeat(64)}\n`, `${'a'.repeat(64)}\r`, `${'a'.repeat(64)}\r\n`, 0, false, {}, []]) {
      const frame = sourceFrame(index, true)
      frame.body.aura.sources[index].head = head
      rejectSource(frame)
    }
  }
})
