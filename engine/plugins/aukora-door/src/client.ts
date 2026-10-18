// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The door client: one C1 canonical JSON line out, one JSON line back, over a unix socket, then close.
// Anything that is not exactly the protocol in PROTOCOL.md is a refusal, never a guess.

import { createConnection } from 'node:net'
import { canonicalize } from './canonical.ts'
import type { DoorReply, DoorRequest, ResolvedConfig } from './types.ts'

/** A door failure with a stable code; every one of them means the call must not run. */
export class DoorError extends Error {
  code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'DoorError'
    this.code = code
  }
}

const REQUEST_KEYS = ['args_canonical_b64', 'call_id', 'class', 'digest_sha256', 'tool', 'v']
const REPLY_KEYS = new Set(['v', 'call_id', 'decision', 'result', 'refusal'])
const REFUSAL = /^[a-z0-9][a-z0-9:._-]{0,127}$/

/** Parse and validate one reply line against its request; a DoorError says what was wrong. */
export function parseReply(line: string, request: DoorRequest): DoorReply {
  let parsed: unknown
  try {
    parsed = JSON.parse(line)
  } catch {
    throw new DoorError('door-protocol', 'the reply is not JSON')
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new DoorError('door-protocol', 'the reply is not an object')
  const reply = parsed as Record<string, unknown>
  for (const key of Object.keys(reply)) {
    if (!REPLY_KEYS.has(key)) throw new DoorError('door-protocol', `the reply has an unknown field ${JSON.stringify(key).slice(0, 40)}`)
  }
  if (reply.v !== 1) throw new DoorError('door-protocol', 'the reply version is not 1')
  // The door may refuse overload before reading the request. Only these result-free denials are uncorrelated.
  const overload = reply.call_id === 'unknown' && reply.decision === 'deny' &&
    (reply.refusal === 'busy' || reply.refusal === 'rate-limited')
  if (reply.call_id !== request.call_id && !overload) throw new DoorError('door-protocol', 'the reply answers a different call')
  const decision = reply.decision
  if (decision !== 'allow' && decision !== 'deny' && decision !== 'ask') throw new DoorError('door-protocol', 'the reply decision is unknown')
  if (reply.refusal !== undefined && (typeof reply.refusal !== 'string' || !REFUSAL.test(reply.refusal))) {
    throw new DoorError('door-protocol', 'the reply refusal is not a plain code')
  }
  if (decision === 'allow') {
    const result = reply.result
    if (typeof result !== 'object' || result === null || Array.isArray(result) || !Object.hasOwn(result, 'value')) {
      throw new DoorError('door-protocol', 'an allow reply carries no result value')
    }
    const { text, ...rest } = result as Record<string, unknown>
    if (Object.keys(rest).some(key => key !== 'value')) throw new DoorError('door-protocol', 'the result has an unknown field')
    if (text !== undefined && typeof text !== 'string') throw new DoorError('door-protocol', 'the result text is not a string')
    if (reply.refusal !== undefined) throw new DoorError('door-protocol', 'an allow reply carries a refusal')
  } else if (reply.result !== undefined) {
    throw new DoorError('door-protocol', 'a deny or ask reply carries a result')
  }
  return reply as unknown as DoorReply
}

/** The exact bytes written for a request: its C1 canonical text and one newline. */
export function encodeRequest(request: DoorRequest): string {
  const keys = Object.keys(request).sort()
  if (keys.join() !== REQUEST_KEYS.join()) throw new DoorError('door-protocol', 'the request fields are not the protocol fields')
  return `${canonicalize(request)}\n`
}

/** Send one request to the door and return its validated reply. Never resolves on anything but a full valid reply. */
export function callDoor(config: ResolvedConfig, request: DoorRequest, signal?: AbortSignal): Promise<DoorReply> {
  const line = encodeRequest(request)
  if (Buffer.byteLength(line) > config.maxFrameBytes) {
    return Promise.reject(new DoorError('door-too-large', 'the request is larger than the frame limit'))
  }
  return new Promise<DoorReply>((resolve, reject) => {
    const socket = createConnection({ path: config.socketPath })
    const chunks: Buffer[] = []
    let received = 0
    let settled = false
    let connected = false

    let connectTimer: ReturnType<typeof setTimeout> | undefined
    let replyTimer: ReturnType<typeof setTimeout> | undefined

    const finish = (error: DoorError | undefined, reply?: DoorReply): void => {
      if (settled) return
      settled = true
      clearTimeout(connectTimer)
      clearTimeout(replyTimer)
      signal?.removeEventListener('abort', onAbort)
      socket.destroy()
      if (error !== undefined) reject(error)
      else resolve(reply as DoorReply)
    }
    const onAbort = (): void => finish(new DoorError('aborted', 'the call was cancelled while the door held it; the door may have acted'))

    if (signal?.aborted) {
      onAbort()
      return
    }
    signal?.addEventListener('abort', onAbort, { once: true })
    connectTimer = setTimeout(
      () => finish(new DoorError('door-unavailable', 'the door did not accept the connection in time')),
      config.connectTimeoutMs,
    )

    socket.on('connect', () => {
      connected = true
      clearTimeout(connectTimer)
      replyTimer = setTimeout(
        () => finish(new DoorError('door-timeout', 'the door did not answer in time; it may have acted')),
        config.responseTimeoutMs,
      )
      socket.write(line)
    })
    socket.on('error', () => {
      finish(new DoorError(connected ? 'door-protocol' : 'door-unavailable', connected ? 'the door connection failed' : 'the door is not reachable'))
    })
    socket.on('data', (chunk: Buffer) => {
      received += chunk.length
      if (received > config.maxFrameBytes) {
        finish(new DoorError('door-too-large', 'the reply is larger than the frame limit'))
        return
      }
      chunks.push(chunk)
      const all = Buffer.concat(chunks)
      const newline = all.indexOf(0x0a)
      if (newline < 0) return
      if (newline !== all.length - 1) {
        finish(new DoorError('door-protocol', 'the reply has bytes after its line'))
        return
      }
      try {
        finish(undefined, parseReply(all.subarray(0, newline).toString('utf8'), request))
      } catch (error) {
        finish(error instanceof DoorError ? error : new DoorError('door-protocol', 'the reply could not be read'))
      }
    })
    socket.on('close', () => {
      finish(new DoorError('door-protocol', 'the door closed the connection without a complete reply'))
    })
  })
}
