// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { bindCall, callDigestHex, CanonError, canonicalize, MAX_SAFE_INTEGER } from '../src/canonical.ts'

interface Vector {
  name: string
  tool: string
  args: unknown
  canonical: string
  args_canonical_b64: string
  digest_sha256: string
}

const vectors = (JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8')) as { vectors: Vector[] }).vectors

for (const vector of vectors) {
  test(`vector ${vector.name} matches the independent Python implementation`, () => {
    const bound = bindCall(vector.tool, vector.args)
    assert.equal(bound.argsText, vector.canonical)
    assert.equal(bound.argsBytes.toString('base64'), vector.args_canonical_b64)
    assert.equal(bound.digest, vector.digest_sha256)
  })
}

function refuses(value: unknown, code: string): void {
  assert.throws(() => canonicalize(value), (error: unknown) => error instanceof CanonError && error.code === code, `expected ${code}`)
}

test('only integers are canonical', () => {
  refuses(1.5, 'canon-number')
  refuses(Number.NaN, 'canon-number')
  refuses(Number.POSITIVE_INFINITY, 'canon-number')
  refuses(-0, 'canon-number')
  refuses(MAX_SAFE_INTEGER + 2, 'canon-number')
  assert.equal(canonicalize(MAX_SAFE_INTEGER), '9007199254740991')
  assert.equal(canonicalize(-MAX_SAFE_INTEGER), '-9007199254740991')
})

test('only plain data is canonical', () => {
  refuses(undefined, 'canon-type')
  refuses(() => 1, 'canon-type')
  refuses(Symbol('s'), 'canon-type')
  refuses(10n, 'canon-type')
  refuses(new Date(0), 'canon-class')
  refuses(new Map(), 'canon-class')
  class Thing { value = 1 }
  refuses(new Thing(), 'canon-class')
  refuses(new Proxy({}, {}), 'canon-proxy')
  refuses(new Proxy([], {}), 'canon-proxy')
  refuses({ [Symbol('k')]: 1 }, 'canon-symbol')
})

test('accessors and hidden properties are refused, never read', () => {
  let reads = 0
  const trap = {}
  Object.defineProperty(trap, 'a', { enumerable: true, get() { reads += 1; return 1 } })
  refuses(trap, 'canon-accessor')
  assert.equal(reads, 0)
  const hidden = {}
  Object.defineProperty(hidden, 'a', { enumerable: false, value: 1 })
  refuses(hidden, 'canon-hidden')
})

test('sparse arrays, extra array properties and array subclasses are refused', () => {
  refuses([1, , 3], 'canon-array') // eslint-disable-line no-sparse-arrays
  const extra = [1, 2] as unknown[] & { x?: number }
  extra.x = 1
  refuses(extra, 'canon-array')
  class Sub extends Array {}
  refuses(Sub.from([1]), 'canon-class')
})

test('lone surrogates are refused in values, keys and tool names', () => {
  refuses('\ud800', 'canon-surrogate')
  refuses({ '\udc00': 1 }, 'canon-surrogate')
  assert.throws(() => callDigestHex('bad\ud800', Buffer.from('{}')), CanonError)
})

test('nesting of 64 containers is accepted and 65 is refused', () => {
  const nest = (levels: number): unknown => {
    let value: unknown = 1
    for (let i = 0; i < levels; i += 1) value = [value]
    return value
  }
  assert.doesNotThrow(() => canonicalize(nest(64)))
  refuses(nest(65), 'canon-depth')
})

test('object keys sort by UTF-16 code units, not code points', () => {
  assert.equal(canonicalize({ '': 1, '\u{10000}': 2 }), '{"\u{10000}":2,"":1}')
})

test('tool names are bound by length prefix, so name and arguments cannot trade bytes', () => {
  const a = callDigestHex('ab', Buffer.from('{}'))
  const b = callDigestHex('a', Buffer.from('b{}'))
  assert.notEqual(a, b)
  assert.throws(() => callDigestHex('', Buffer.from('{}')), CanonError)
  assert.throws(() => callDigestHex('a\0b', Buffer.from('{}')), CanonError)
  assert.throws(() => callDigestHex('x'.repeat(257), Buffer.from('{}')), CanonError)
})

test('the digest does not depend on how the caller built the object', () => {
  const left = bindCall('t', { b: 1, a: 2 })
  const right = bindCall('t', JSON.parse('{"a":2,"b":1}'))
  assert.equal(left.digest, right.digest)
})
