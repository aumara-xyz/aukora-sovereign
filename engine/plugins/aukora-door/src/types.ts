// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The few shapes this plugin shares between its parts. The execution and result shapes mirror what DSH's tool
// registry hands a plugin (@deepseek-ai/dsh-tools, packages/core/tools/src/index.ts at 1517a4d), declared locally so
// the logic has no runtime dependency on DSH and the tests run without it.

/** The part of a DSH tool execution this plugin reads. `token` is assigned by the registry; callers cannot pick it. */
export interface ExecLike {
  readonly callId: string
  readonly rootCallId?: string
  readonly name: string
  readonly arguments: unknown
  readonly token: symbol
  signal?: AbortSignal
  readonly agent?: unknown
  readonly parent?: unknown
}

/** A tool result in DSH's shape: success carries `value`, failure carries `error`. */
export type ResultLike =
  | { isError: false; value: unknown; content: Array<{ type: 'text'; text: string }> }
  | { isError: true; error: { message: string; info?: { name: string; code: string } }; content: Array<{ type: 'text'; text: string }> }

/** Pre-dispatch decision in DSH's shape (the subset this plugin returns). */
export type PreDecisionLike =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string; info?: { name: string; code: string } }
  | { kind: 'cancel' }
  | { kind: 'ask'; reason?: string }

/** Crossing classes the door understands, plus `local` which never leaves this process. */
export type CallClass = 'local' | 'net' | 'mcp' | 'plugin' | 'memory' | 'persist' | 'delegate' | 'shell-interactive' | 'fs-outside' | 'unknown'

/** Static configuration, supplied by the supervisor when it starts the engine. The engine never writes it. */
export interface DoorConfig {
  /** Absolute path of the Rust door's unix socket (at most 100 bytes). */
  socketPath: string
  /** Absolute workspace roots; a file tool whose path leaves them is a crossing. Empty means every file tool crosses. */
  workspaceRoots: string[]
  /** Milliseconds to wait for the socket to accept. Default 2,000. */
  connectTimeoutMs?: number
  /** Milliseconds to wait for the door's reply once the request is written. Default 120,000. */
  responseTimeoutMs?: number
  /** Largest request or reply line in bytes. Default 1,048,576. */
  maxFrameBytes?: number
}

/** A validated DoorConfig with every default filled in. */
export interface ResolvedConfig {
  socketPath: string
  workspaceRoots: string[]
  connectTimeoutMs: number
  responseTimeoutMs: number
  maxFrameBytes: number
}

/** One request line to the door. Field order on the wire is the C1 canonical order. */
export interface DoorRequest {
  v: 1
  call_id: string
  tool: string
  args_canonical_b64: string
  digest_sha256: string
  class: Exclude<CallClass, 'local'>
}

/** One reply line from the door. */
export interface DoorReply {
  v: 1
  call_id: string
  decision: 'allow' | 'deny' | 'ask'
  result?: { value: unknown; text?: string }
  refusal?: string
}

/** What the pre-execute listener records and the guard and the execute wrapper check. */
export interface Verdict {
  callId: string
  tool: string
  class: CallClass
  digest: string
}
