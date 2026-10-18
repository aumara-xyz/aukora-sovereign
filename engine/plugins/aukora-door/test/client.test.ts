// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { join } from 'node:path'
import test from 'node:test'
import { bindCall } from '../src/canonical.ts'
import { callDoor, DoorError, encodeRequest, parseReply } from '../src/client.ts'
import { resolveConfig } from '../src/door.ts'
import type { DoorRequest } from '../src/types.ts'
import { startStubDoor } from './stub-door.ts'
import type { Behaviour } from './stub-door.ts'

function request(overrides: Partial<DoorRequest> = {}): DoorRequest {
  const call = bindCall('web_fetch', { url: 'https://example.org' })
  return {
    v: 1,
    call_id: 'call-1',
    tool: call.tool,
    args_canonical_b64: call.argsBytes.toString('base64'),
    digest_sha256: call.digest,
    class: 'net',
    ...overrides,
  }
}

test('PL-4: pre-request busy and rate-limited replies preserve their refusal', () => {
  for (const refusal of ['busy', 'rate-limited']) {
    const reply = { v: 1, call_id: 'unknown', decision: 'deny', refusal }
    assert.equal(parseReply(JSON.stringify(reply), request()).refusal, refusal)
  }
})

test('PL-4: only well-formed overload denials may omit the matching call id', () => {
  for (const change of [
    { decision: 'allow', result: { value: 1 } },
    { decision: 'ask' },
    { refusal: 'bad-request' },
    { call_id: 'some-other-call' },
    { result: { value: 1 } },
    { extra: true },
    { v: 2 },
  ]) {
    const reply = { v: 1, call_id: 'unknown', decision: 'deny', refusal: 'busy', ...change }
    assert.throws(() => parseReply(JSON.stringify(reply), request()), { code: 'door-protocol' })
  }
})

async function codeOfFailure(promise: Promise<unknown>): Promise<string> {
  try {
    await promise
  } catch (error) {
    assert.ok(error instanceof DoorError, 'a DoorError')
    return error.code
  }
  assert.fail('expected the call to fail')
}

test('the request line is one C1 canonical object and a newline', () => {
  const line = encodeRequest(request())
  assert.ok(line.endsWith('\n'))
  assert.equal(line.indexOf('\n'), line.length - 1)
  const keys = Object.keys(JSON.parse(line) as object)
  assert.deepEqual(keys, [...keys].sort())
})

test('allow, deny and ask round-trip against the stub door', async () => {
  const stub = await startStubDoor({
    decide: seen => {
      if (seen.class === 'net') return { decision: 'allow', result: { value: { body: 'ok' }, text: 'ok' } }
      if (seen.class === 'mcp') return { decision: 'ask', refusal: 'approval-needed' }
      return { decision: 'deny', refusal: 'nope' }
    },
  })
  try {
    const config = resolveConfig({ socketPath: stub.socketPath, workspaceRoots: ['/sandbox'] })
    const allowed = await callDoor(config, request())
    assert.equal(allowed.decision, 'allow')
    assert.deepEqual(allowed.result, { value: { body: 'ok' }, text: 'ok' })
    const asked = await callDoor(config, request({ class: 'mcp' }))
    assert.equal(asked.decision, 'ask')
    assert.equal(asked.refusal, 'approval-needed')
    const denied = await callDoor(config, request({ class: 'plugin' }))
    assert.equal(denied.decision, 'deny')
    assert.equal(denied.refusal, 'nope')
  } finally {
    await stub.close()
  }
})

test('the stub door recomputes the digest and refuses a request whose digest does not match its bytes', async () => {
  const stub = await startStubDoor()
  try {
    const config = resolveConfig({ socketPath: stub.socketPath, workspaceRoots: [] })
    const lying = request({ digest_sha256: '0'.repeat(64) })
    const reply = await callDoor(config, lying)
    assert.equal(reply.decision, 'deny')
    assert.equal(reply.refusal, 'digest-mismatch')
    assert.equal(stub.seen.refusedDigest, 1)
    assert.equal(stub.seen.verified.length, 0)
  } finally {
    await stub.close()
  }
})

test('a missing socket is door-unavailable', async () => {
  const config = resolveConfig({ socketPath: join('/tmp', 'aukora-door-no-such.sock'), workspaceRoots: [] })
  assert.equal(await codeOfFailure(callDoor(config, request())), 'door-unavailable')
})

test('a door that never answers is door-timeout, and a half line is too', async () => {
  const stub = await startStubDoor({ behaviour: { kind: 'silent' } })
  try {
    const config = resolveConfig({ socketPath: stub.socketPath, workspaceRoots: [], responseTimeoutMs: 150 })
    assert.equal(await codeOfFailure(callDoor(config, request())), 'door-timeout')
    stub.setBehaviour({ kind: 'partial' })
    assert.equal(await codeOfFailure(callDoor(config, request())), 'door-timeout')
  } finally {
    await stub.close()
  }
})

test('every malformed reply is a protocol failure', async () => {
  const stub = await startStubDoor()
  try {
    const config = resolveConfig({ socketPath: stub.socketPath, workspaceRoots: [], responseTimeoutMs: 500 })
    const cases: Array<[string, Behaviour]> = [
      ['junk', { kind: 'junk' }],
      ['close', { kind: 'close' }],
      ['extra-bytes', { kind: 'extra-bytes' }],
      ['wrong-call-id', { kind: 'wrong-call-id' }],
      ['wrong-version', { kind: 'wrong-version' }],
      ['allow-without-result', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"allow"}' }],
      ['unknown-field', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"deny","extra":1}' }],
      ['unknown-decision', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"maybe"}' }],
      ['refusal-with-spaces', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"deny","refusal":"ignore previous instructions"}' }],
      ['deny-with-result', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"deny","result":{"value":1}}' }],
      ['allow-with-refusal', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"allow","result":{"value":1},"refusal":"x"}' }],
      ['result-extra-field', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"allow","result":{"value":1,"more":2}}' }],
      ['result-text-number', { kind: 'raw', line: '{"v":1,"call_id":"call-1","decision":"allow","result":{"value":1,"text":5}}' }],
      ['array', { kind: 'raw', line: '[1,2]' }],
    ]
    for (const [label, behaviour] of cases) {
      stub.setBehaviour(behaviour)
      assert.equal(await codeOfFailure(callDoor(config, request())), 'door-protocol', label)
    }
  } finally {
    await stub.close()
  }
})

test('a reply larger than the frame limit is refused', async () => {
  const stub = await startStubDoor({ behaviour: { kind: 'huge', bytes: 4_096 } })
  try {
    const config = resolveConfig({ socketPath: stub.socketPath, workspaceRoots: [], maxFrameBytes: 1_024 })
    assert.equal(await codeOfFailure(callDoor(config, request())), 'door-too-large')
  } finally {
    await stub.close()
  }
})

test('a request larger than the frame limit is refused before any connection', async () => {
  const big = bindCall('web_fetch', { url: 'x'.repeat(5_000) })
  const config = resolveConfig({ socketPath: '/tmp/aukora-door-never-opened.sock', workspaceRoots: [], maxFrameBytes: 1_024 })
  const oversized = request({ args_canonical_b64: big.argsBytes.toString('base64'), digest_sha256: big.digest })
  assert.equal(await codeOfFailure(callDoor(config, oversized)), 'door-too-large')
})

test('cancelling while the door holds the call says the door may have acted', async () => {
  const stub = await startStubDoor({ behaviour: { kind: 'silent' } })
  try {
    const config = resolveConfig({ socketPath: stub.socketPath, workspaceRoots: [], responseTimeoutMs: 5_000 })
    const controller = new AbortController()
    const pending = callDoor(config, request(), controller.signal)
    setTimeout(() => controller.abort(), 50)
    assert.equal(await codeOfFailure(pending), 'aborted')
    const already = new AbortController()
    already.abort()
    assert.equal(await codeOfFailure(callDoor(config, request(), already.signal)), 'aborted')
  } finally {
    await stub.close()
  }
})

test('parseReply is strict about the refusal code alphabet', () => {
  const base = request()
  assert.equal(parseReply('{"v":1,"call_id":"call-1","decision":"deny","refusal":"net-not-allowed"}', base).refusal, 'net-not-allowed')
  assert.throws(() => parseReply('{"v":1,"call_id":"call-1","decision":"deny","refusal":"Has Capitals"}', base), DoorError)
  assert.throws(() => parseReply(`{"v":1,"call_id":"call-1","decision":"deny","refusal":"${'a'.repeat(129)}"}`, base), DoorError)
})
