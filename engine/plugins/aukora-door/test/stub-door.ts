// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A stub of the Rust door, for tests. It implements the server side of PROTOCOL.md the way the Rust door must:
// it trusts nothing the client says. It decodes the bytes, checks they are C1 canonical, recomputes the digest
// itself and compares, and only then applies a policy. `Behaviour` lets a test make it misbehave on purpose.

import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:net'
import type { Server, Socket } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { callDigestHex, canonicalize } from '../src/canonical.ts'

/** Everything the stub saw, so a test can assert the door was (or was not) contacted. */
export interface Seen {
  lines: string[]
  verified: Array<{ tool: string; class: string; args: unknown; callId: string }>
  refusedDigest: number
}

export type Behaviour =
  | { kind: 'policy' }
  | { kind: 'silent' }
  | { kind: 'close' }
  | { kind: 'junk' }
  | { kind: 'partial' }
  | { kind: 'huge'; bytes: number }
  | { kind: 'extra-bytes' }
  | { kind: 'wrong-call-id' }
  | { kind: 'wrong-version' }
  | { kind: 'raw'; line: string }

export interface StubOptions {
  behaviour?: Behaviour
  /** Decide an authenticated, digest-verified request. Default: allow `memory`, deny everything else. */
  decide?: (request: { tool: string; class: string; args: unknown; callId: string }) => Record<string, unknown>
}

export interface Stub {
  socketPath: string
  seen: Seen
  setBehaviour(behaviour: Behaviour): void
  close(): Promise<void>
}

const defaultDecide: NonNullable<StubOptions['decide']> = request => (
  request.class === 'memory'
    ? { decision: 'allow', result: { value: { stored: true }, text: 'stored' } }
    : { decision: 'deny', refusal: `${request.class}-not-allowed` }
)

function frame(callId: string, fields: Record<string, unknown>): string {
  return `${JSON.stringify({ v: 1, call_id: callId, ...fields })}\n`
}

export async function startStubDoor(options: StubOptions = {}): Promise<Stub> {
  const dir = mkdtempSync(join(tmpdir(), 'ad-'))
  const socketPath = join(dir, 'door.sock')
  const seen: Seen = { lines: [], verified: [], refusedDigest: 0 }
  let behaviour: Behaviour = options.behaviour ?? { kind: 'policy' }
  const decide = options.decide ?? defaultDecide
  const sockets = new Set<Socket>()

  const server: Server = createServer(socket => {
    sockets.add(socket)
    socket.on('close', () => sockets.delete(socket))
    socket.on('error', () => {})
    let buffer = ''
    socket.on('data', chunk => {
      buffer += chunk.toString('utf8')
      const newline = buffer.indexOf('\n')
      if (newline < 0) return
      const line = buffer.slice(0, newline)
      seen.lines.push(line)
      respond(socket, line)
    })
  })

  function respond(socket: Socket, line: string): void {
    let request: Record<string, unknown>
    try {
      request = JSON.parse(line) as Record<string, unknown>
    } catch {
      socket.end(frame('?', { decision: 'deny', refusal: 'bad-json' }))
      return
    }
    const callId = String(request.call_id)
    switch (behaviour.kind) {
      case 'silent': return
      case 'close': socket.destroy(); return
      case 'junk': socket.end('this is not json\n'); return
      case 'partial': socket.write('{"v":1,'); return
      case 'huge': socket.end(`${'x'.repeat(behaviour.bytes)}\n`); return
      case 'extra-bytes': socket.end(`${frame(callId, { decision: 'deny', refusal: 'x' })}more\n`); return
      case 'wrong-call-id': socket.end(frame('some-other-call', { decision: 'deny', refusal: 'x' })); return
      case 'wrong-version': socket.end(`${JSON.stringify({ v: 2, call_id: callId, decision: 'deny', refusal: 'x' })}\n`); return
      case 'raw': socket.end(`${behaviour.line}\n`); return
      case 'policy': break
    }
    const keys = Object.keys(request).sort().join()
    if (keys !== 'args_canonical_b64,call_id,class,digest_sha256,tool,v' || request.v !== 1) {
      socket.end(frame(callId, { decision: 'deny', refusal: 'bad-request' }))
      return
    }
    const tool = String(request.tool)
    const bytes = Buffer.from(String(request.args_canonical_b64), 'base64')
    let args: unknown
    try {
      args = JSON.parse(bytes.toString('utf8'))
      if (canonicalize(args) !== bytes.toString('utf8')) throw new Error('not canonical')
      if (callDigestHex(tool, bytes) !== request.digest_sha256) throw new Error('digest')
    } catch {
      seen.refusedDigest += 1
      socket.end(frame(callId, { decision: 'deny', refusal: 'digest-mismatch' }))
      return
    }
    const verified = { tool, class: String(request.class), args, callId }
    seen.verified.push(verified)
    socket.end(frame(callId, decide(verified)))
  }

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(socketPath, () => resolve())
  })

  return {
    socketPath,
    seen,
    setBehaviour(next) { behaviour = next },
    async close() {
      for (const socket of sockets) socket.destroy()
      await new Promise<void>(resolve => server.close(() => resolve()))
      rmSync(dir, { recursive: true, force: true })
    },
  }
}
