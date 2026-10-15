// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { Readable, Writable } from 'node:stream'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { canonicalJSON, decodeBase64, decodeFrame, decodeGuestFrame, decodeSupervisorFrame, encodeFrame, FrameReader, parse, writeFrame } from './canon.mjs'
import { generatedCodes } from './gen-codes.mjs'
import * as codes from './codes.mjs'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const vectors = join(root, 'crates/canon/vectors')
const corpus = join(root, 'crates/canon/corpus')
const digest = 'a'.repeat(64)
const auraSources = [
  { name: 'gate-ledger', head: digest, entries: 1, absence: null },
  { name: 'kira-chain', head: null, entries: 0, absence: 'kira-ledger-empty' },
  { name: 'code-chain', head: null, entries: 0, absence: 'code-record-missing' },
]
const cell = { module_sha256: digest, input_sha256: digest, effect_sha256: digest }
const toolCall = { id: 'call_1', type: 'function', function: { name: 'read', arguments: '{"target":"note.md"}' } }
const frames = [
  ['guest', { v: 1, id: 'a', kind: 'propose', body: { target: 't', base_sha256: digest, new_bytes_b64: 'bg==', note: 'n', cell } }],
  ['guest', { v: 1, id: 'b', kind: 'read', body: { target: 't' } }],
  ['guest', { v: 1, id: 'c', kind: 'model.call', body: { grant_id: 'g', model: 'm', messages: [{ role: 'assistant', content: null, tool_calls: [toolCall] }, { role: 'tool', content: 'c', tool_call_id: 'call_1' }], tools: [{ type: 'function', function: { name: 'read', description: 'Read a target', parameters: { type: 'object', properties: { target: { type: 'string' } } } } }], max_output_tokens: 3 } }],
  ['guest', { v: 1, id: 'd', kind: 'memory.put', body: { cell, statement: 's', quote: 'q', category: 'fact' } }],
  ['guest', { v: 1, id: 'e', kind: 'memory.recall', body: { query: 'q', limit: 2 } }],
  ['guest', { v: 1, id: 'memory', kind: 'memory.list', body: { tier: 'remembered', before: null } }],
  ['supervisor', { v: 1, id: 'memory', kind: 'memory.list.reply', body: { tier: 'remembered', items: [], next: null } }],
  ['guest', { v: 1, id: 'f', kind: 'status', body: {} }],
  ['guest', { v: 1, id: 'organs', kind: 'organs', body: {} }],
  ['supervisor', { v: 1, id: 'organs', kind: 'organs.reply', body: { approvals_pending: 2, aumlok: { bound: true, passkeys: 1, refresh_due: false }, aura: { sequence: 7, root: digest, sources: auraSources }, kira: { notes: 2, demoted: 3 }, nostr: { node_npub: 'npub1node', agent_npub: null, witness_accepted: 4 }, wasm: { module_sha256: digest }, owner_origin: 'https://owner.example' } }],
  ['supervisor', { v: 1, id: 'g', kind: 'accepted', body: { proposal_id: 'p' } }],
  ['supervisor', { v: 1, id: 'h', kind: 'outcome', body: { proposal_id: 'p', state: 'unknown' } }],
  ['supervisor', { v: 1, id: 'i', kind: 'model.reply', body: { content: null, tool_calls: [toolCall], finish_reason: 'tool_calls', usage: { prompt_tokens: 3, completion_tokens: 2, cost_microusd: 1 }, receipt_seq: 2 } }],
  ['supervisor', { v: 1, id: 'j', kind: 'read.reply', body: { target: 't', sha256: digest, bytes_b64: 'bg==' } }],
  ['supervisor', { v: 1, id: 'k', kind: 'status.reply', body: { ready: true, bound: false, grant_id: null, grant_remaining: null } }],
  ['supervisor', { v: 1, id: 'l', kind: 'recall', body: { result: 'found', items: [{ note_id: 'n', text: 't', cite_seq: 1 }] } }],
  ['supervisor', { v: 1, id: 'm', kind: 'refusal', body: { code: 'gate:stale-base', next: 'review' } }]
]
const frameOf = kind => structuredClone(frames.find(([, frame]) => frame.kind === kind)[1])
const rejectsCode = (operation, code, label) => assert.throws(operation, error => error.code === code, label)
const wire = bytes => { const header = Buffer.alloc(4); header.writeUInt32BE(bytes.length); return Buffer.concat([header, bytes]) }

test('one generated refusal-code registry', () => {
  assert.equal(readFileSync(join(root, 'bridge/codes.mjs'), 'utf8'), generatedCodes())
  const source = readFileSync(join(root, 'crates/canon/src/codes.rs'), 'utf8')
  // Split Rust constant declarations independently of the generator regex.
  const declarations = source.split('\n').filter(line => line.startsWith('pub const ') && line.includes(': &str = '))
  const expectedNames = declarations.map(line => line.split(' ')[2].split(':')[0]).sort()
  assert.deepEqual(Object.keys(codes).filter(name => name !== 'ALL').sort(), expectedNames)
  for (const line of declarations) {
    const name = line.split(' ')[2].split(':')[0]
    assert.equal(codes[name], JSON.parse(line.split(' = ')[1].slice(0, -1)))
  }
  assert.equal(codes.CANON_INVALID_UTF8, 'canon:invalid-utf8')
  const namesInAll = source.split('pub const ALL:')[1].split('[').at(-1).split(']')[0].split(',').map(name => name.trim()).filter(Boolean)
  assert.deepEqual(codes.ALL, namesInAll.map(name => codes[name]).sort())
})

test('Prime-generated golden vectors', () => {
  execFileSync(process.execPath, [join(vectors, 'gen.mjs')], { stdio: 'pipe' })
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
  console.log(`JS GOLDEN VECTORS PASS ${valid} valid ${refused} refused`)
})

async function checkShared(item, bytes) {
  const operation = async () => {
    if (item.mode === 'transport-io') return new FrameReader(Readable.from((async function* () { throw new Error('injected read failure') })())).read()
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
  else await assert.rejects(operation, error => error.code === item.code, item.name)
}

test('shared hostile corpus and generated differential cases', async () => {
  execFileSync(process.execPath, [join(corpus, 'gen.mjs')], { stdio: 'pipe' })
  const cases = JSON.parse(readFileSync(join(corpus, 'manifest.json'), 'utf8'))
  for (const item of cases) await checkShared(item, readFileSync(join(corpus, item.file)))
  const generated = JSON.parse(readFileSync(join(corpus, 'generated.json'), 'utf8'))
  for (const item of generated) await checkShared(item, Buffer.from(item.input_hex, 'hex'))
  assert.ok(cases.length + generated.length >= 300, 'shared corpus must have at least 300 cases')
  console.log(`JS HOSTILE CORPUS PASS ${cases.length + generated.length}`)
})

test('all frame kinds and both directions', () => {
  for (const [direction, frame] of frames) {
    const bytes = encodeFrame(frame, direction)
    assert.equal(canonicalJSON(decodeFrame(bytes, direction)), canonicalJSON(frame))
    rejectsCode(() => decodeFrame(bytes, direction === 'guest' ? 'supervisor' : 'guest'), 'frame:unknown-kind', frame.kind)
  }
  assert.doesNotThrow(() => decodeGuestFrame(encodeFrame(frameOf('status'), 'guest')))
  assert.doesNotThrow(() => decodeSupervisorFrame(encodeFrame(frameOf('accepted'), 'supervisor')))
})

test('explicit direction is mandatory for decoding and encoding', () => {
  const frame = frameOf('status')
  const bytes = encodeFrame(frame, 'guest')
  for (const direction of [undefined, 'any', '', null, 'guest-to-nobody']) {
    rejectsCode(() => decodeFrame(bytes, direction), 'frame:invalid-field')
    rejectsCode(() => encodeFrame(frame, direction), 'frame:invalid-field')
  }
})

test('non JSON values and sparse arrays never serialize', () => {
  const sparse = new Array(2)
  sparse[1] = 1
  const inherited = [, 1]
  const inheritedPrototype = Object.create(Array.prototype)
  inheritedPrototype[0] = 0
  Object.setPrototypeOf(inherited, inheritedPrototype)
  for (const value of [sparse, inherited, [1, , 2], [undefined], [() => 1], [1n], [NaN], [Infinity], [-Infinity], undefined, () => 1, 1n, NaN, Infinity, -Infinity, { x: undefined }, { x: () => 1 }, { x: 1n }, { x: NaN }, new Date(), { [Symbol('x')]: 1 }, { get x() { return 1 } }]) {
    rejectsCode(() => canonicalJSON(value), 'canon:invalid-json')
  }
  assert.equal(canonicalJSON([null, 1, 'x']), '[null,1,"x"]')
})

test('arrays and objects never discard hidden properties or invoke accessors', () => {
  const property = [0]; property.bad = undefined
  const symbol = [0]; symbol[Symbol('bad')] = () => {}
  const negative = [0]; negative[-1] = 7
  const nonfinite = [0]; nonfinite.NaN = 7
  const accessor = [0]
  let invoked = false
  Object.defineProperty(accessor, '0', { get() { invoked = true; return 7 }, enumerable: true })
  const hiddenUndefined = Object.defineProperty({}, 'hidden', { value: undefined })
  const hiddenValid = Object.defineProperty({}, 'hidden', { value: 7 })
  for (const value of [property, symbol, negative, nonfinite, accessor, hiddenUndefined, hiddenValid]) rejectsCode(() => canonicalJSON(value), 'canon:invalid-json')
  assert.equal(invoked, false)
})

for (const [name, value] of [['undefined', undefined], ['function', () => 1], ['BigInt', 1n], ['NaN', NaN]]) {
  test(`non JSON ${name} is refused`, () => {
    rejectsCode(() => canonicalJSON(value), 'canon:invalid-json')
    rejectsCode(() => canonicalJSON({ value }), 'canon:invalid-json')
    rejectsCode(() => canonicalJSON([value]), 'canon:invalid-json')
  })
}

test('i64 MIN is refused in every JSON position', () => {
  for (const input of ['-9223372036854775808', '[-9223372036854775808]', '{"v":-9223372036854775808}']) {
    rejectsCode(() => parse(input), 'canon:integer-range')
  }
})

test('C1 strict parsing and serialization guards', () => {
  const cases = [
    [Buffer.from([0xef, 0xbb, 0xbf, 0x7b, 0x7d]), 'canon:bom'],
    [Buffer.from([0xff]), 'canon:invalid-utf8'],
    ['{"a":1,"a":2}', 'canon:duplicate-key'],
    ['01', 'canon:invalid-number'], ['-0', 'canon:invalid-number'], ['1.0', 'canon:invalid-number'], ['1e0', 'canon:invalid-number'],
    ['"\ud800"', 'canon:lone-surrogate'],
    ['9007199254740992', 'canon:integer-range'], ['-9007199254740992', 'canon:integer-range'],
    ['"\\ud800"', 'canon:lone-surrogate'], ['"\\udc00"', 'canon:lone-surrogate'], ['"\\ud800\\u0000"', 'canon:lone-surrogate'],
    ['"\\uZZZZ"', 'canon:invalid-json'], ['"\\z0000"', 'canon:invalid-json'],
    [Buffer.from([0x22, 0, 0x22]), 'canon:invalid-json'],
    ['truX', 'canon:invalid-json'], ['[1x2]', 'canon:invalid-json'], ['{"a":1x"b":2}', 'canon:invalid-json'], ['{"a"x1}', 'canon:invalid-json'], ['{x":1}', 'canon:invalid-json'],
    ['{}x', 'canon:trailing-bytes']
  ]
  for (const [input, code] of cases) rejectsCode(() => parse(input), code, String(input))
  for (const value of [9007199254740992, 1.5]) rejectsCode(() => canonicalJSON(value), 'canon:integer-range')
  rejectsCode(() => canonicalJSON(-0), 'canon:invalid-number')
  for (const value of ['\ud800', '\udc00']) rejectsCode(() => canonicalJSON(value), 'canon:lone-surrogate')
  rejectsCode(() => canonicalJSON({ [String.fromCharCode(0xd800)]: 1 }), 'canon:lone-surrogate')
  assert.equal(canonicalJSON({ '\ue000': 3, '𐀀': 2, '\ud7ff': 1 }), '{"퟿":1,"𐀀":2,"":3}')
  const controls = String.fromCharCode(...Array.from({ length: 32 }, (_, index) => index)) + '"\\\u2028\u2029𐀀'
  assert.equal(canonicalJSON(controls), JSON.stringify(controls))
  assert.equal(parse('"\\b\\f\\n\\r\\t\\/\\\\\\\""'), '\b\f\n\r\t/\\"')
  let nested = 0
  for (let index = 0; index < 65; index++) nested = [nested]
  rejectsCode(() => canonicalJSON(nested), 'canon:nesting-too-deep')
})

test('envelope and scalar-before-nested refusal order', () => {
  const cases = [
    ['guest', { body: null, id: 1, kind: false, v: '1' }, 'frame:invalid-field'],
    ['guest', { body: null, id: 1, kind: false, v: 2 }, 'frame:unsupported-version'],
    ['guest', { body: null, id: 1, kind: false, v: 1 }, 'frame:invalid-field'],
    ['guest', { body: {}, id: 1, kind: 'status', v: 1 }, 'frame:invalid-field'],
    ['guest', { body: null, id: '!', kind: false, v: 1 }, 'frame:invalid-id'],
    ['guest', { body: null, id: 'x', kind: false, v: 1 }, 'frame:invalid-field'],
    ['guest', { body: null, id: 'x', kind: 'accepted', v: 1 }, 'frame:unknown-kind'],
    ['guest', { body: { grant_id: 1, max_output_tokens: 1, messages: [1], model: 'm', tools: [] }, id: 'x', kind: 'model.call', v: 1 }, 'frame:invalid-field'],
    ['guest', { body: { category: 'c', cell: {}, statement: 1 }, id: 'x', kind: 'memory.put', v: 1 }, 'frame:invalid-field'],
    ['supervisor', { body: { items: [{}], result: 'bogus' }, id: 'x', kind: 'recall', v: 1 }, 'frame:invalid-field']
  ]
  for (const [direction, frame, code] of cases) rejectsCode(() => decodeFrame(canonicalJSON(frame), direction), code)
})

test('standard padded base64 and lowercase SHA256 guards', () => {
  for (const value of ['', 'AQ==', 'AAE=', 'AAAA', '/w==']) {
    const frame = frameOf('propose'); frame.body.new_bytes_b64 = value
    assert.doesNotThrow(() => encodeFrame(frame, 'guest'))
  }
  for (const value of ['AQ', 'AQ=', 'AQ===', 'AR==', 'AAF=', 'AA-A', 'AA_A', 'AQ==\n', '?===', 1]) {
    for (const [kind, direction, field] of [['propose', 'guest', 'new_bytes_b64'], ['read.reply', 'supervisor', 'bytes_b64']]) {
      const frame = frameOf(kind); frame.body[field] = value
      rejectsCode(() => encodeFrame(frame, direction), 'frame:invalid-field', `${kind} ${value}`)
    }
  }
  for (const bad of ['a'.repeat(63), 'a'.repeat(65), 'A'.repeat(64), 'g'.repeat(64), '', 1]) {
    const proposal = frameOf('propose'); proposal.body.base_sha256 = bad
    rejectsCode(() => encodeFrame(proposal, 'guest'), 'frame:invalid-field')
    const reply = frameOf('read.reply'); reply.body.sha256 = bad
    rejectsCode(() => encodeFrame(reply, 'supervisor'), 'frame:invalid-field')
    for (const field of ['module_sha256', 'input_sha256', 'effect_sha256']) {
      for (const kind of ['propose', 'memory.put']) {
        const frame = frameOf(kind); frame.body.cell[field] = bad
        rejectsCode(() => encodeFrame(frame, 'guest'), 'frame:invalid-field', `${kind} ${field}`)
      }
    }
  }
})

test('decoded base64 budget is inclusive', () => {
  for (const size of [0, 1, 65535, 65536]) {
    const bytes = Buffer.alloc(size, 0xff)
    assert.deepEqual(decodeBase64(bytes.toString('base64')), bytes)
  }
  rejectsCode(() => decodeBase64(Buffer.alloc(65537).toString('base64')), 'frame:invalid-field')
})

test('every count has an inclusive nonnegative bound', () => {
  const cases = [
    ['model.call', 'guest', ['max_output_tokens'], 1, 32768],
    ['memory.recall', 'guest', ['limit'], 1, 100],
    ['model.reply', 'supervisor', ['receipt_seq'], 1, 9007199254740991],
    ['model.reply', 'supervisor', ['usage', 'prompt_tokens'], 0, 32768],
    ['model.reply', 'supervisor', ['usage', 'completion_tokens'], 0, 32768],
    ['model.reply', 'supervisor', ['usage', 'cost_microusd'], 0, 9007199254740991],
    ['recall', 'supervisor', ['items', 0, 'cite_seq'], 1, 9007199254740991],
    ['status.reply', 'supervisor', ['grant_remaining'], 0, 9007199254740991]
  ]
  for (const [kind, direction, path, minimum, maximum] of cases) {
    for (const value of [minimum, maximum, -1, minimum - 1, '1', null]) {
      if (kind === 'status.reply' && value === null) continue
      const frame = frameOf(kind)
      let target = frame.body
      for (const key of path.slice(0, -1)) target = target[key]
      target[path.at(-1)] = value
      if (value === minimum || value === maximum) assert.doesNotThrow(() => encodeFrame(frame, direction))
      else rejectsCode(() => encodeFrame(frame, direction), 'frame:invalid-field', `${kind} ${path} ${value}`)
    }
    if (maximum < 9007199254740991) {
      const frame = frameOf(kind)
      let target = frame.body
      for (const key of path.slice(0, -1)) target = target[key]
      target[path.at(-1)] = maximum + 1
      rejectsCode(() => encodeFrame(frame, direction), 'frame:invalid-field')
    }
  }
})

test('v1.1 nested field shapes are strict', () => {
  const cases = [
    ['read', 'guest', ['target'], 1, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages'], null, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 0, 'content'], 1, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 0, 'role'], 1, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 1, 'tool_call_id'], null, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 0, 'tool_calls'], null, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 0, 'tool_calls', 0, 'id'], 1, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 0, 'tool_calls', 0, 'type'], 'other', 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 0, 'tool_calls', 0, 'function'], null, 'frame:not-object'],
    ['model.call', 'guest', ['messages', 0, 'tool_calls', 0, 'function', 'arguments'], {}, 'frame:invalid-field'],
    ['model.call', 'guest', ['messages', 0, 'tool_calls', 0, 'function', 'name'], 1, 'frame:invalid-field'],
    ['model.call', 'guest', ['tools'], null, 'frame:invalid-field'],
    ['model.call', 'guest', ['tools', 0, 'type'], 'other', 'frame:invalid-field'],
    ['model.call', 'guest', ['tools', 0, 'function'], null, 'frame:not-object'],
    ['model.call', 'guest', ['tools', 0, 'function', 'description'], 1, 'frame:invalid-field'],
    ['model.call', 'guest', ['tools', 0, 'function', 'name'], 1, 'frame:invalid-field'],
    ['model.call', 'guest', ['tools', 0, 'function', 'parameters'], [], 'frame:not-object'],
    ['model.reply', 'supervisor', ['content'], 1, 'frame:invalid-field'],
    ['model.reply', 'supervisor', ['finish_reason'], 1, 'frame:invalid-field'],
    ['model.reply', 'supervisor', ['tool_calls'], null, 'frame:invalid-field'],
    ['model.reply', 'supervisor', ['usage'], null, 'frame:not-object'],
    ['status.reply', 'supervisor', ['bound'], 1, 'frame:invalid-field'],
    ['status.reply', 'supervisor', ['ready'], 1, 'frame:invalid-field'],
    ['status.reply', 'supervisor', ['grant_id'], 1, 'frame:invalid-field'],
    ['recall', 'supervisor', ['items', 0, 'note_id'], 1, 'frame:invalid-field'],
    ['recall', 'supervisor', ['items', 0, 'text'], 1, 'frame:invalid-field'],
    ['outcome', 'supervisor', ['state'], 'bogus', 'frame:invalid-field']
  ]
  for (const [kind, direction, path, value, code] of cases) {
    const frame = frameOf(kind)
    let target = frame.body
    for (const key of path.slice(0, -1)) target = target[key]
    target[path.at(-1)] = value
    rejectsCode(() => encodeFrame(frame, direction), code, `${kind} ${path}`)
  }
})

test('refusal codes are registered stable strings', () => {
  const frame = frameOf('refusal')
  frame.body.code = 'unregistered:code'
  rejectsCode(() => encodeFrame(frame, 'supervisor'), 'frame:invalid-field')
})

test('strict body sets reject unknown and missing fields', () => {
  rejectsCode(() => decodeGuestFrame('{ "body":{},"id":"x","kind":"status","v":1}'), 'frame:not-canonical')
  rejectsCode(() => decodeGuestFrame('{"body":{"extra":1},"id":"x","kind":"status","v":1}'), 'frame:unknown-field')
  rejectsCode(() => decodeSupervisorFrame('{"body":{},"id":"x","kind":"accepted","v":1}'), 'frame:missing-field')
})

test('depth and frame byte limits are inclusive', () => {
  assert.doesNotThrow(() => parse(`${'['.repeat(64)}0${']'.repeat(64)}`))
  rejectsCode(() => parse(`${'['.repeat(65)}0${']'.repeat(65)}`), 'canon:nesting-too-deep')
  assert.doesNotThrow(() => parse(`${'{"a":'.repeat(64)}0${'}'.repeat(64)}`))
  rejectsCode(() => parse(`${'{"a":'.repeat(65)}0${'}'.repeat(65)}`), 'canon:nesting-too-deep')
  const prefix = '{"body":{"code":"gate:stale-base","next":"'
  const suffix = '"},"id":"x","kind":"refusal","v":1}'
  const exact = Buffer.from(`${prefix}${'a'.repeat(65536 - Buffer.byteLength(prefix) - Buffer.byteLength(suffix))}${suffix}`)
  assert.equal(exact.length, 65536)
  assert.doesNotThrow(() => decodeSupervisorFrame(exact))
  rejectsCode(() => decodeSupervisorFrame(Buffer.concat([exact, Buffer.from(' ')])), 'frame:too-large')
})

test('FrameReader handles partial chunks, multiple frames, limits and clean EOF', async () => {
  const payload = Buffer.from(encodeFrame(frameOf('status'), 'guest'))
  const bytes = wire(payload)
  for (let split = 1; split < bytes.length; split++) {
    const reader = new FrameReader(Readable.from([bytes.subarray(0, split), bytes.subarray(split)]))
    assert.deepEqual(await reader.read(), payload)
    await assert.rejects(reader.read(), error => error.code === 'frame:short-read')
  }
  const oneByte = new FrameReader(Readable.from([...bytes].map(byte => Buffer.from([byte]))))
  assert.deepEqual(await oneByte.read(), payload)
  const together = new FrameReader(Readable.from([Buffer.concat([bytes, bytes])]))
  const received = []
  for await (const item of together) received.push(item)
  assert.deepEqual(received, [payload, payload])
  const maximum = Buffer.alloc(65536, 0x61)
  assert.deepEqual(await new FrameReader(Readable.from([wire(maximum)])).read(), maximum)
  assert.deepEqual(await new FrameReader(Readable.from([wire(Buffer.from('x'))])).readFrame(), Buffer.from('x'))
})

test('FrameReader fatal lengths, short reads and IO errors close the stream', async () => {
  const large = Buffer.alloc(4); large.writeUInt32BE(65537)
  const short = Buffer.alloc(4); short.writeUInt32BE(3)
  for (const [bytes, code] of [[Buffer.alloc(0), 'frame:short-read'], [Buffer.alloc(4), 'frame:zero-length'], [large, 'frame:too-large'], [Buffer.from([0]), 'frame:short-read'], [Buffer.from([0, 0, 0]), 'frame:short-read'], [short, 'frame:short-read'], [Buffer.concat([short, Buffer.from('ab')]), 'frame:short-read']]) {
    for (const stream of [Readable.from([bytes]), {
      destroyed: false,
      destroy() { this.destroyed = true },
      async *[Symbol.asyncIterator]() { yield bytes }
    }]) {
      const reader = new FrameReader(stream)
      await assert.rejects(reader.read(), error => error.code === code)
      assert.equal(stream.destroyed, true)
      await assert.rejects(reader.read(), error => error.code === code)
    }
  }
  const stream = new Readable({ read() { this.destroy(new Error('read failed')) } })
  await assert.rejects(new FrameReader(stream).read(), error => error.code === 'frame:io')
  assert.equal(stream.destroyed, true)
})

test('writeFrame prefixes bytes and permits only one write in flight', async () => {
  let active = 0
  let maximum = 0
  const output = []
  const stream = {
    destroyed: false,
    destroy() { this.destroyed = true },
    write(bytes, callback) {
      active++
      maximum = Math.max(maximum, active)
      output.push(bytes)
      setImmediate(() => { active--; callback() })
    }
  }
  await Promise.all([writeFrame(stream, Buffer.from('a')), writeFrame(stream, Buffer.from('bc'))])
  assert.equal(maximum, 1)
  assert.deepEqual(output, [wire(Buffer.from('a')), wire(Buffer.from('bc'))])
  for (const [bytes, code] of [[Buffer.alloc(0), 'frame:zero-length'], [Buffer.alloc(65537), 'frame:too-large']]) {
    await assert.rejects(writeFrame(stream, bytes), error => error.code === code)
    assert.equal(stream.destroyed, true)
  }
  const failed = { destroyed: false, destroy() { this.destroyed = true }, write(_bytes, callback) { callback(new Error('write failed')) } }
  await assert.rejects(writeFrame(failed, Buffer.from('x')), error => error.code === 'frame:io')
  assert.equal(failed.destroyed, true)
  let calls = 0
  const realFailure = new Writable({ write(_bytes, _encoding, callback) { calls++; callback(new Error('write failed')) } })
  const failures = await Promise.allSettled([writeFrame(realFailure, Buffer.from('x')), writeFrame(realFailure, Buffer.from('y'))])
  for (const failure of failures) {
    assert.equal(failure.status, 'rejected')
    assert.equal(failure.reason.code, 'frame:io')
  }
  assert.equal(calls, 1)
  assert.equal(realFailure.destroyed, true)
})
