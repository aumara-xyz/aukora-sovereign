// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { Duplex } from 'node:stream'
import { encodeFrame } from '../canon.mjs'
import { Fd3Link } from '../fd3.mjs'

const tick = () => new Promise(resolve => setImmediate(resolve))

function mockSocket(write) {
  return new Duplex({ read() {}, write })
}

function supervisor(scenario) {
  return new Promise((resolve, reject) => {
    const child = spawn('python3', [fileURLToPath(new URL('./supervisor.py', import.meta.url)), process.execPath, fileURLToPath(new URL('./fd3-child.mjs', import.meta.url)), scenario])
    let stdout = ''; let stderr = ''
    child.stdout.on('data', bytes => { stdout += bytes })
    child.stderr.on('data', bytes => { stderr += bytes })
    child.on('error', reject)
    child.on('exit', code => {
      if (code !== 0) reject(new Error(`supervisor ${scenario} exit ${code}: ${stderr}`))
      else { try { resolve(JSON.parse(stdout)) } catch (error) { reject(error) } }
    })
  })
}

test('AF_UNIX socketpair inherited as FD 3: C4 calls, reversed replies, pushes and fragmented/coalesced frames', async () => {
  const result = await supervisor('roundtrip')
  assert.equal(result.replies.length, 6)
  assert.deepEqual(result.pushed, [{ proposal_id: 'proposal', state: 'applied' }])
})

test('adapter exchanges status and chat-completions tool calls through inherited FD 3', async () => {
  const result = await supervisor('adapter')
  assert.deepEqual(result.types, ['block-start', 'text-delta', 'block-end', 'block-start', 'tool-call-delta', 'block-end', 'usage', 'finish'])
})

test('tools exchange read/propose/recall/pinned-cell memory.put through inherited FD 3', async () => {
  const result = await supervisor('tools')
  assert.equal(result.proposal.state, 'PENDING_OWNER')
  assert.equal(result.memory.state, 'ACKNOWLEDGED_PENDING')
})

test('antibody_path0_tool_sends_pinned_cell_effect_and_evidence_over_fd3', async () => {
  assert.deepEqual(await supervisor('path0'), { state: 'PENDING_OWNER', proposal_id: 'path0' })
})

for (const scenario of ['timeout', 'abort']) test(`${scenario} resolves unknown, drops late reply and never retries`, async () => {
  assert.deepEqual(await supervisor(scenario), { state: 'unknown' })
})

for (const [scenario, code] of [
  ['zero', 'frame:zero-length'], ['oversize', 'frame:too-large'], ['short', 'frame:short-read'], ['short-header', 'frame:short-read'],
  ['noncanonical', 'frame:not-canonical'], ['duplicate', 'canon:duplicate-key'], ['utf8', 'canon:invalid-utf8'],
  ['version', 'frame:unsupported-version'], ['kind', 'frame:unknown-kind'], ['wrong-reply', 'frame:unknown-kind'], ['id', 'frame:invalid-id'],
  ['envelope', 'frame:unknown-field'], ['outcome', 'frame:invalid-field'], ['refusal', 'frame:invalid-field'],
]) test(`fatal ${scenario} closes the inherited link and leaves request unknown`, async () => {
  assert.deepEqual(await supervisor(scenario), { state: 'unknown', code })
})

test('only one write is in flight and expired queued calls never get dispatched', async () => {
  const writes = []
  const socket = mockSocket((bytes, _encoding, callback) => { writes.push({ bytes, callback }) })
  const link = new Fd3Link({ socket })
  const first = link.call('status', {}, { timeoutMs: 100 })
  const second = link.call('status', {}, { timeoutMs: 20 })
  await tick()
  assert.equal(writes.length, 1)
  assert.deepEqual(await second, { state: 'unknown' })
  writes[0].callback()
  await tick()
  assert.equal(writes.length, 1)
  link.close()
  assert.deepEqual(await first, { state: 'unknown' })
})

test('outbound frame size, kinds, bodies and timeout values are bounded', async () => {
  assert.ok(encodeFrame({ body: {}, id: 'a', kind: 'status', v: 1 }, 'guest').length > 0)
  assert.throws(() => encodeFrame({ body: { code: 'gate:stale-base', next: 'x'.repeat(65_536) }, id: 'a', kind: 'refusal', v: 1 }, 'supervisor'), { code: 'frame:too-large' })
  const socket = mockSocket((_bytes, _encoding, callback) => callback())
  const link = new Fd3Link({ socket })
  await assert.rejects(link.call('apply', {}), { code: 'frame:unknown-kind' })
  await assert.rejects(link.call('status', []), { code: 'frame:not-object' })
  await assert.rejects(link.call('status', {}, { timeoutMs: 0 }), { code: 'guest:timeout' })
  link.close()
})

test('fatal errors destroy the socket and settle pending calls', async () => {
  let destroyed = false
  const socket = mockSocket((_bytes, _encoding, _callback) => {})
  const destroy = socket.destroy.bind(socket)
  socket.destroy = error => { destroyed = true; return destroy(error) }
  const link = new Fd3Link({ socket })
  const call = link.call('status', {})
  socket.push(Buffer.alloc(4))
  await tick()
  assert.equal(destroyed, true)
  assert.equal(link.closed, true)
  const settled = await Promise.race([
    call,
    new Promise(resolve => setTimeout(() => resolve({ state: 'not-settled' }), 50)),
  ])
  for (const request of link.pending.values()) clearTimeout(request.timer)
  assert.deepEqual(settled, { state: 'unknown' })
  assert.deepEqual(await link.call('status', {}), { state: 'unknown' })
  let manuallyDestroyed = false
  const manual = mockSocket((_bytes, _encoding, callback) => callback())
  const manualDestroy = manual.destroy.bind(manual)
  manual.destroy = error => { manuallyDestroyed = true; return manualDestroy(error) }
  new Fd3Link({ socket: manual }).close()
  assert.equal(manuallyDestroyed, true)
})
