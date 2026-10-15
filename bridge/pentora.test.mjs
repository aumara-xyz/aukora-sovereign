// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { primeFile } from '../tests/support/prime.mjs'
import {
  PENTORA,
  PENTORA_SETTLE_MS,
  PENTORA_TRANSITION_MS,
  balancedCells,
  createPentoraMotion,
  pentoraCells,
  pentoraDigest,
  pentoraDigits,
  pentoraMotionFrame,
} from './pentora.mjs'

const vectorUrls = [
  new URL('../crates/pentora/vectors/expansion_vectors_1006.json', import.meta.url),
  new URL('../crates/pentora/vectors/expansion_vectors_4354.json', import.meta.url),
]
const vectors = vectorUrls.flatMap(url => JSON.parse(readFileSync(url, 'utf8')))
const moduleUrl = new URL('./pentora.mjs', import.meta.url)
const moduleSource = readFileSync(moduleUrl, 'utf8')
const sha256 = bytes => new Uint8Array(createHash('sha256').update(bytes).digest())
const unhex = text => Uint8Array.from(Buffer.from(text, 'hex'))
const hex = bytes => Buffer.from(bytes).toString('hex')
const repository = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const primePath = primeFile('plugins/aukora-face/settings/src/aura/pentora.mjs')

function pseudoRandomRoots(seed, count) {
  let state = seed >>> 0
  return Array.from({ length: count }, () => {
    const root = new Uint8Array(32)
    for (let index = 0; index < root.length; index += 1) {
      state ^= state << 13; state >>>= 0
      state ^= state >>> 17
      state ^= state << 5; state >>>= 0
      root[index] = state & 0xff
    }
    return root
  })
}

test('all 5360 normative vectors match digest and raw trits', async () => {
  assert.equal(vectors.length, 5360)
  for (const [index, vector] of vectors.entries()) {
    const root = unhex(vector.head)
    assert.equal(hex(await pentoraDigest(root, sha256)), vector.sha256, `vector ${index} digest`)
    const trits = await pentoraDigits(root, sha256)
    assert.equal(hex(trits), vector.wire_hex, `vector ${index} trits`)
    assert.equal(hex(await pentoraCells(root, sha256)), vector.wire_hex, `vector ${index} Prime cells`)
    if (vector.balanced !== undefined) assert.deepEqual(Array.from(balancedCells(trits)), vector.balanced, `vector ${index} balanced`)
    assert.equal(hex(root), vector.head, `vector ${index} root preserved`)
  }
})

test('input and hash refusals are named', async () => {
  for (const bad of [new Uint8Array(31), new Uint8Array(33), new Uint16Array(32), '00'.repeat(32)]) {
    await assert.rejects(pentoraDigest(bad, sha256), { message: 'pentora:head-invalid' })
  }
  for (const badHash of [() => new Uint8Array(31), () => null, () => '00'.repeat(32)]) {
    await assert.rejects(pentoraDigest(new Uint8Array(32), badHash), { message: 'pentora:hash-invalid' })
  }
  for (const bad of [new Uint8Array(109), new Uint8Array(111), new Uint8Array(110).fill(3)]) {
    assert.throws(() => balancedCells(bad), { message: 'pentora:trits-invalid' })
  }
})

test('browser hashing refusal and returned state are immutable', async () => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined })
    await assert.rejects(pentoraCells(new Uint8Array(32)), { code: 'pentora:hash-unavailable' })
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor)
    else delete globalThis.crypto
  }

  const motion = await createPentoraMotion('00'.repeat(32), '11'.repeat(32), sha256)
  const frame = pentoraMotionFrame(motion, 1200)
  assert.throws(() => { motion.nextHead = motion.previousHead }, TypeError)
  assert.throws(() => { frame.cells[0] = 7 }, TypeError)
  assert.throws(() => { frame.changedCells[0] = false }, TypeError)
  assert.throws(() => { frame.status = 'in-motion' }, TypeError)
})

test('integer index state is the Prime display state without float geometry', () => {
  assert.deepEqual(Object.keys(PENTORA), ['centre', 'mutable', 'edges', 'cubes'])
  assert.equal(PENTORA.centre, 55)
  assert.deepEqual(PENTORA.mutable, Array.from({ length: 111 }, (_, index) => index).filter(index => index !== 55))
  assert.equal(PENTORA.edges.length, 60)
  assert.equal(PENTORA.cubes.length, 5)
  assert.ok(PENTORA.cubes.every(cube => cube.length === 27 && cube[13] === 55))
})

test('motion follows Prime transition and settlement boundaries', async () => {
  assert.equal(PENTORA_TRANSITION_MS, 400)
  assert.equal(PENTORA_SETTLE_MS, 1200)
  const previousHead = '00'.repeat(32)
  const nextHead = '11'.repeat(32)
  const motion = await createPentoraMotion(previousHead, nextHead, sha256)
  const previous = Array.from(await pentoraCells(unhex(previousHead), sha256))
  const next = Array.from(await pentoraCells(unhex(nextHead), sha256))
  for (const elapsed of [0, 40, 199, 399, 400, 800, 1199, 1200, 1800]) {
    const frame = pentoraMotionFrame(motion, elapsed)
    const moved = Math.floor(110 * Math.min(1, elapsed / PENTORA_TRANSITION_MS))
    assert.equal(frame.movedCells, moved)
    assert.deepEqual(frame.cells, next.map((value, index) => index < moved ? value : previous[index]))
    assert.equal(frame.status, elapsed < PENTORA_SETTLE_MS ? 'in-motion' : 'solid')
    assert.equal(frame.head, elapsed < PENTORA_SETTLE_MS ? null : nextHead)
  }
  assert.equal(pentoraMotionFrame(motion, 0, true).status, 'solid')
  assert.throws(() => pentoraMotionFrame(motion, -1), { code: 'aura:pentora-time' })
  assert.throws(() => pentoraMotionFrame({}, 0), { code: 'aura:pentora-motion' })
  await assert.rejects(createPentoraMotion('AA'.repeat(32), nextHead, sha256), { code: 'aura:pentora-head' })
})

test('Rust matches Prime on 200 deterministic random roots', async () => {
  const prime = await import(pathToFileURL(primePath).href)
  assert.deepEqual(PENTORA, {
    centre: prime.PENTORA.centre,
    mutable: prime.PENTORA.mutable,
    edges: prime.PENTORA.edges,
    cubes: prime.PENTORA.cubes,
  })
  const roots = pseudoRandomRoots(0x9e3779b9, 200)
  const rust = spawnSync('cargo', [
    'run', '-q', '-p', 'pentora', '--example', 'expand', '--offline', '--', ...roots.map(hex),
  ], { cwd: repository, encoding: 'utf8' })
  assert.equal(rust.status, 0, rust.stderr)
  const lines = rust.stdout.trim().split('\n')
  assert.equal(lines.length, roots.length)
  for (const [index, root] of roots.entries()) {
    const [rustDigest, rustTrits] = lines[index].split(' ')
    assert.equal(rustDigest, hex(await prime.pentoraDigest(root, sha256)), `root ${index} digest`)
    assert.equal(rustTrits, hex(await prime.pentoraDigits(root, sha256)), `root ${index} trits`)
  }
})

async function importMutant(from, to) {
  assert.equal(moduleSource.split(from).length, 2, `one mutation anchor: ${from}`)
  const changed = moduleSource.replace(from, to)
  return import(`data:text/javascript;base64,${Buffer.from(changed).toString('base64')}#${encodeURIComponent(from)}`)
}

async function checkBrowserHashRefusal(api) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  try {
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: undefined })
    await assert.rejects(api.pentoraCells(new Uint8Array(32)), { code: 'pentora:hash-unavailable' })
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor)
    else delete globalThis.crypto
  }
}

async function checkImmutable(api) {
  const motion = await api.createPentoraMotion('00'.repeat(32), '11'.repeat(32), sha256)
  const frame = api.pentoraMotionFrame(motion, 1200)
  assert.throws(() => { motion.nextHead = motion.previousHead }, TypeError)
  assert.throws(() => { frame.cells[0] = 7 }, TypeError)
  assert.throws(() => { frame.changedCells[0] = false }, TypeError)
  assert.throws(() => { frame.status = 'in-motion' }, TypeError)
}

test('bridge protection mutations are killed', async () => {
  const mutations = [
    [
      "if (!(root32 instanceof Uint8Array) || root32.length !== 32) throw new RangeError('pentora:head-invalid')",
      '',
      api => assert.rejects(api.pentoraDigest(new Uint8Array(31), sha256), { message: 'pentora:head-invalid' }),
    ],
    [
      "if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new TypeError('pentora:hash-invalid')",
      '',
      api => assert.rejects(api.pentoraDigest(new Uint8Array(32), () => null), { message: 'pentora:hash-invalid' }),
    ],
    [
      "if (!(trits instanceof Uint8Array) || trits.length !== 110 || trits.some(value => value > 2)) {",
      'if (false) {',
      async api => assert.throws(() => api.balancedCells(new Uint8Array(110).fill(3)), { message: 'pentora:trits-invalid' }),
    ],
    [
      "if (!globalThis.crypto?.subtle) throw Object.assign(new TypeError('pentora:hash-unavailable'), { code: 'pentora:hash-unavailable' })",
      '',
      checkBrowserHashRefusal,
    ],
    [
      "if (typeof head !== 'string' || !/^[a-f0-9]{64}$/.test(head)) refuse('aura:pentora-head')",
      '',
      api => assert.rejects(api.createPentoraMotion('AA'.repeat(32), '11'.repeat(32), sha256), { code: 'aura:pentora-head' }),
    ],
    [
      "if (cells === undefined) refuse('aura:pentora-motion')",
      '',
      async api => assert.throws(() => api.pentoraMotionFrame({}, 0), { code: 'aura:pentora-motion' }),
    ],
    [
      "if (!Number.isFinite(elapsedMs) || elapsedMs < 0) refuse('aura:pentora-time')",
      '',
      async api => {
        const motion = await api.createPentoraMotion('00'.repeat(32), '11'.repeat(32), sha256)
        assert.throws(() => api.pentoraMotionFrame(motion, -1), { code: 'aura:pentora-time' })
      },
    ],
    [
      'const motion = Object.freeze({ previousHead, nextHead })',
      'const motion = { previousHead, nextHead }',
      checkImmutable,
    ],
    [
      'cells: Object.freeze(cells.nextCells.map((value, index) => index < moved ? value : cells.previousCells[index]))',
      'cells: cells.nextCells.map((value, index) => index < moved ? value : cells.previousCells[index])',
      checkImmutable,
    ],
    [
      'changedCells: Object.freeze(cells.nextCells.map((value, index) => value !== cells.previousCells[index]))',
      'changedCells: cells.nextCells.map((value, index) => value !== cells.previousCells[index])',
      checkImmutable,
    ],
    [
      'return Object.freeze({',
      'return ({',
      checkImmutable,
    ],
  ]
  for (const [from, to, check] of mutations) {
    await assert.rejects(check(await importMutant(from, to)), undefined, `surviving mutation: ${from}`)
  }
  console.log(`MUTATION bridge-pentora: ${mutations.length}/${mutations.length} killed`)
})
