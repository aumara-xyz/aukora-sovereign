// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The door plugin's logic, free of any DSH import so it runs under plain Node in the tests.
//
// Three hooks, one rule: the bytes that were judged are the bytes that run.
//  1. preExecute  records a verdict per execution (class, digest of name + canonical arguments).
//  2. guard       denies a call that has no verdict, or whose name or arguments no longer match it.
//  3. execute     is the outermost tools/execute wrapper. It re-digests, refuses on any mismatch, and then either
//                 (local) pins the judged arguments onto the execution and lets the tool run, or
//                 (crossing) sends the exact canonical bytes to the Rust door and returns the door's authored
//                 result WITHOUT ever calling next(): the tool body in this process never runs.
//
// Everything fails closed: a missing socket, a timeout, a malformed reply, a mismatch, an unknown tool.

import { randomBytes } from 'node:crypto'
import { bindCall, CanonError } from './canonical.ts'
import type { BoundCall } from './canonical.ts'
import { callDoor, DoorError } from './client.ts'
import { classifyCall } from './classify.ts'
import type {
  CallClass, DoorConfig, DoorReply, DoorRequest, ExecLike, PreDecisionLike, ResolvedConfig, ResultLike, Verdict,
} from './types.ts'

/** Name carried in `error.info.name` of every result this plugin authors, so policy and replay can route on it. */
export const REFUSAL_NAME = 'AukoraDoorRefusal'

const MAX_VERDICTS = 4096

/**
 * The id a request carries on the wire. The model's own call id is not unique (some providers number calls from
 * zero in every turn) and not safe for a line-oriented log, so the door sees `<process nonce>-<counter>-<call id>`,
 * with the model's id reduced to `[A-Za-z0-9_.:-]` and cut to 64 characters: unique per request, printable ASCII,
 * at most 256 bytes. The server consumes each wire id once.
 */
function wireIdFactory(): (callId: string) => string {
  const nonce = randomBytes(8).toString('hex')
  let counter = 0
  return callId => {
    counter += 1
    return `${nonce}-${counter}-${String(callId).replace(/[^A-Za-z0-9_.:-]/g, '_').slice(0, 64)}`
  }
}

/** Validate a DoorConfig and fill in defaults. Throws a plain Error naming the first problem. */
export function resolveConfig(raw: DoorConfig): ResolvedConfig {
  if (typeof raw !== 'object' || raw === null) throw new Error('aukora-door: config is required')
  const { socketPath, workspaceRoots } = raw
  if (typeof socketPath !== 'string' || !socketPath.startsWith('/') || Buffer.byteLength(socketPath) > 100 || socketPath.includes('\0')) {
    throw new Error('aukora-door: socketPath must be an absolute path of at most 100 bytes')
  }
  if (!Array.isArray(workspaceRoots) || !workspaceRoots.every(root => typeof root === 'string' && root.startsWith('/') && !root.includes('\0'))) {
    throw new Error('aukora-door: workspaceRoots must be a list of absolute paths')
  }
  const number = (value: number | undefined, fallback: number, low: number, high: number, label: string): number => {
    const chosen = value ?? fallback
    if (!Number.isInteger(chosen) || chosen < low || chosen > high) throw new Error(`aukora-door: ${label} must be an integer in ${low}..${high}`)
    return chosen
  }
  return {
    socketPath,
    workspaceRoots: workspaceRoots.map(root => (root.length > 1 && root.endsWith('/') ? root.slice(0, -1) : root)),
    connectTimeoutMs: number(raw.connectTimeoutMs, 2_000, 1, 60_000, 'connectTimeoutMs'),
    responseTimeoutMs: number(raw.responseTimeoutMs, 120_000, 1, 3_600_000, 'responseTimeoutMs'),
    maxFrameBytes: number(raw.maxFrameBytes, 1_048_576, 1_024, 16_777_216, 'maxFrameBytes'),
  }
}

/** A failure result in DSH's shape. `code` is stable; `message` is what the model reads. */
export function refusalResult(code: string, message: string): ResultLike {
  return {
    isError: true,
    error: { message, info: { name: REFUSAL_NAME, code } },
    content: [{ type: 'text', text: `Error: ${message}` }],
  }
}

function successResult(value: unknown, text: string | undefined): ResultLike {
  return { isError: false, value, content: [{ type: 'text', text: text ?? JSON.stringify(value) }] }
}

function replyResult(reply: DoorReply): ResultLike {
  if (reply.decision === 'allow') {
    return successResult((reply.result as { value: unknown }).value, reply.result?.text)
  }
  const code = reply.refusal ?? (reply.decision === 'ask' ? 'owner-approval-required' : 'door-denied')
  return reply.decision === 'ask'
    ? refusalResult(`ask:${code}`, `the owner has to approve this first (${code}); nothing ran`)
    : refusalResult(code, `the door refused this action (${code}); nothing ran`)
}

function bytesOf(call: BoundCall): string {
  return call.argsBytes.toString('base64')
}

/**
 * Pin the judged name and arguments onto the live execution so a later wrapper cannot swap them before the body
 * reads them. The arguments are replaced by a frozen copy parsed from the very canonical bytes that were judged.
 * Throws when the execution refuses the lock; the caller then refuses the call.
 */
function lockExecution(exec: ExecLike, call: BoundCall): void {
  const judged = deepFreeze(JSON.parse(call.argsText) as unknown)
  const fixed = (value: unknown): PropertyDescriptor => ({ value, writable: false, configurable: false, enumerable: true })
  Object.defineProperty(exec, 'arguments', fixed(judged))
  Object.defineProperty(exec, 'name', fixed(call.tool))
  Object.defineProperty(exec, 'callId', fixed(exec.callId))
  Object.defineProperty(exec, 'token', fixed(exec.token))
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) deepFreeze((value as Record<string | symbol, unknown>)[key])
    Object.freeze(value)
  }
  return value
}

/** The three hooks plus the verdict store, bound to one configuration. */
export interface Door {
  readonly config: ResolvedConfig
  /** Number of verdicts currently held (tests and diagnostics). */
  size(): number
  preExecute(exec: ExecLike, next: () => Promise<PreDecisionLike>): Promise<PreDecisionLike>
  guard(exec: Readonly<ExecLike>): string | undefined
  execute(exec: ExecLike, next: () => Promise<ResultLike>): Promise<ResultLike>
  /** Forget the verdict of a finished execution. */
  forget(exec: Readonly<ExecLike>): void
}

export function createDoor(rawConfig: DoorConfig): Door {
  const config = resolveConfig(rawConfig)
  const verdicts = new Map<symbol, Verdict>()
  const wireId = wireIdFactory()

  const record = (exec: ExecLike, call: BoundCall, callClass: CallClass): void => {
    if (verdicts.size >= MAX_VERDICTS) {
      const oldest = verdicts.keys().next()
      if (!oldest.done) verdicts.delete(oldest.value)
    }
    verdicts.set(exec.token, { callId: exec.callId, tool: call.tool, class: callClass, digest: call.digest })
  }

  const door: Door = {
    config,
    size: () => verdicts.size,

    async preExecute(exec, next) {
      let call: BoundCall
      try {
        call = bindCall(exec.name, exec.arguments)
      } catch (error) {
        const code = error instanceof CanonError ? error.code : 'args-not-canonical'
        return {
          kind: 'deny',
          reason: `the door cannot read these arguments as plain canonical data (args-not-canonical: ${code}); nothing ran`,
          info: { name: REFUSAL_NAME, code: 'args-not-canonical' },
        }
      }
      record(exec, call, classifyCall(call.tool, JSON.parse(call.argsText) as unknown, config.workspaceRoots))
      return next()
    },

    guard(exec) {
      const verdict = verdicts.get(exec.token)
      if (verdict === undefined) return 'the door recorded no verdict for this call (no-verdict)'
      let call: BoundCall
      try {
        call = bindCall(exec.name, exec.arguments)
      } catch {
        return 'the arguments changed into something the door cannot read (args-not-canonical)'
      }
      return call.digest === verdict.digest ? undefined : 'the arguments or tool name changed after the door judged them (digest-mismatch)'
    },

    async execute(exec, next) {
      const verdict = verdicts.get(exec.token)
      if (verdict === undefined) return refusalResult('no-verdict', 'the door recorded no verdict for this call; nothing ran')
      let call: BoundCall
      try {
        call = bindCall(exec.name, exec.arguments)
      } catch {
        return refusalResult('args-not-canonical', 'the arguments are not plain canonical data; nothing ran')
      }
      if (call.digest !== verdict.digest) {
        return refusalResult('digest-mismatch', 'the arguments or tool name changed after the door judged them; nothing ran')
      }

      if (verdict.class === 'local') {
        try {
          lockExecution(exec, call)
        } catch {
          return refusalResult('lock-failed', 'the door could not pin the judged arguments to this call; nothing ran')
        }
        return next()
      }

      const request: DoorRequest = {
        v: 1,
        call_id: wireId(exec.callId),
        tool: call.tool,
        args_canonical_b64: bytesOf(call),
        digest_sha256: call.digest,
        class: verdict.class,
      }
      try {
        return replyResult(await callDoor(config, request, exec.signal))
      } catch (error) {
        const code = error instanceof DoorError ? error.code : 'door-unavailable'
        const message = error instanceof DoorError ? error.message : 'the door could not be reached'
        return refusalResult(code, `${message}; nothing ran in this process`)
      }
    },

    forget(exec) {
      verdicts.delete(exec.token)
    },
  }
  return door
}
