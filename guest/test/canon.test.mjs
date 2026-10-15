// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { Readable } from 'node:stream'
import { fileURLToPath } from 'node:url'
import {
  CanonError, canonicalJSON, decodeBase64, decodeFrame, encodeFrame, FrameReader, parse,
} from '../canon.mjs'
import * as codes from '../../bridge/codes.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const vectors = join(root, 'crates/canon/vectors')
const corpus = join(root, 'crates/canon/corpus')
const rejectsCode = (operation, code, label) => assert.throws(operation, error => error instanceof CanonError && error.code === code, label)

test('guest codec is only a re-export of the shared bridge codec', () => {
  assert.equal(readFileSync(join(root, 'guest/canon.mjs'), 'utf8'), "// SPDX-License-Identifier: AGPL-3.0-or-later\n\nexport * from '../bridge/canon.mjs'\n")
})

test('shared golden vectors run through the guest codec import', () => {
  let valid = 0
  let refused = 0
  for (const file of readdirSync(vectors).filter(file => file.endsWith('.json')).sort()) {
    const document = JSON.parse(readFileSync(join(vectors, file), 'utf8'))
    for (const vector of Array.isArray(document) ? document : [document]) {
      const label = `${file}: ${vector.name ?? ''}`
      if (vector.canonical !== undefined) {
        assert.equal(canonicalJSON(parse(Buffer.from(vector.input))), vector.canonical, label)
        valid++
      } else {
        rejectsCode(() => parse(Buffer.from(vector.input)), vector.refusal, label)
        refused++
      }
    }
  }
  console.log(`GUEST SHARED VECTORS PASS ${valid} valid ${refused} refused`)
})

async function checkCorpus(item, bytes) {
  const operation = async () => {
    if (item.mode === 'transport-io') {
      return new FrameReader(Readable.from((async function* () { throw new Error('injected read failure') })())).read()
    }
    if (item.mode === 'base64') return decodeBase64(bytes.toString('utf8')).toString('hex')
    const payload = item.mode === 'transport' ? await new FrameReader(Readable.from([bytes])).read() : bytes
    if (item.mode === 'parse') {
      const value = parse(payload)
      return item.code !== undefined ? '' : canonicalJSON(value)
    }
    const frame = decodeFrame(payload, item.direction)
    assert.deepEqual(Buffer.from(encodeFrame(frame, item.direction)), payload, item.name)
    return canonicalJSON(frame)
  }
  if (item.output_hex !== undefined) assert.equal(await operation(), item.output_hex, item.name)
  else if (item.canonical !== undefined) assert.equal(await operation(), item.canonical, item.name)
  else await assert.rejects(operation, error => error instanceof CanonError && error.code === item.code, item.name)
}

test('shared hostile corpus runs through guest framing and directions', async () => {
  const cases = JSON.parse(readFileSync(join(corpus, 'manifest.json'), 'utf8'))
  const generated = JSON.parse(readFileSync(join(corpus, 'generated.json'), 'utf8'))
  for (const item of cases) await checkCorpus(item, readFileSync(join(corpus, item.file)))
  for (const item of generated) await checkCorpus(item, Buffer.from(item.input_hex, 'hex'))
  assert.ok(cases.length + generated.length >= 300)
  console.log(`GUEST SHARED CORPUS PASS ${cases.length + generated.length}`)
})

test('guest framing requires an explicit direction and shared refusal codes', () => {
  const frame = { body: {}, id: 'test', kind: 'status', v: 1 }
  const bytes = encodeFrame(frame, 'guest')
  assert.equal(canonicalJSON(decodeFrame(bytes, 'guest')), canonicalJSON(frame))
  for (const direction of [undefined, '', 'both']) {
    rejectsCode(() => encodeFrame(frame, direction), 'frame:invalid-field')
    rejectsCode(() => decodeFrame(bytes, direction), 'frame:invalid-field')
  }
  rejectsCode(() => decodeFrame(bytes, 'supervisor'), 'frame:unknown-kind')
})

test('antibody_provider_refusal_codes_cross_c4_registered', () => {
  for (const code of [
    'broker:provider-key-rejected', 'broker:provider-no-credit', 'broker:provider-rate-limited',
    'broker:provider-request-rejected', 'broker:provider-unavailable', 'broker:provider-refused',
  ]) {
    assert.ok(codes.ALL.includes(code), code)
    const frame = { body: { code, next: '' }, id: 'provider_refusal', kind: 'refusal', v: 1 }
    const bytes = encodeFrame(frame, 'supervisor')
    assert.equal(canonicalJSON(decodeFrame(bytes, 'supervisor')), canonicalJSON(frame))
  }
})
