// SPDX-License-Identifier: AGPL-3.0-or-later
//
// AUKORA door plugin for the DeepSeek Harness (DSH 0.2.1-alpha.5, master 1517a4d) on Cordis.
//
// It is a policy hook with a Rust executor behind it, not a boundary: a hostile plugin in the same process can
// bypass any in-process hook (see README.md). What it guarantees is narrower and checkable: on every honest path
// the bytes that were judged are the bytes that run, a crossing is executed by the Rust door and never by this
// process, and every failure refuses. The OS wall around the whole engine is the boundary.

import type { Context } from '@deepseek-ai/cordis'
import { watchAuthority } from './authority.ts'
import { createDoor } from './door.ts'
import type { DoorConfig, ExecLike, PreDecisionLike, ResultLike } from './types.ts'

export { createDoor, refusalResult, resolveConfig, REFUSAL_NAME } from './door.ts'
export { bindCall, canonicalize, callDigestHex, CanonError, DOOR_CALL_DOMAIN } from './canonical.ts'
export { classifyCall, insideWorkspace } from './classify.ts'
export { callDoor, DoorError } from './client.ts'
export type { DoorConfig, DoorReply, DoorRequest, CallClass } from './types.ts'

/** Cordis plugin name used by loader diagnostics. */
export const name = 'aukora-door'

/** The tool registry service this plugin hooks. */
export const inject = ['tools']

/**
 * Register the door. Three hooks, all ahead of every other listener:
 *  - `tools/pre-execute` records a verdict per execution,
 *  - `ctx.tools.guard` denies any call without a matching verdict (a guard cannot be skipped by an earlier listener),
 *  - `tools/execute` runs first, refuses on any mismatch and sends crossings to the Rust door.
 * `tools/result` forgets the verdict. Throws at load time on a bad configuration, so a misconfigured engine does
 * not start with the door half-open.
 */
export function apply(ctx: Context, config: DoorConfig): void {
  const door = createDoor(config)
  const first = { prepend: true, global: true }
  // The registry's own types describe these executions; ours are the readable subset, so one cast per hook.
  ctx.on('tools/pre-execute', ((exec: ExecLike, next: () => Promise<PreDecisionLike>) => door.preExecute(exec, next)) as never, first)
  ctx.tools.guard(((exec: Readonly<ExecLike>) => door.guard(exec)) as never)
  ctx.on('tools/execute', ((exec: ExecLike, next: () => Promise<ResultLike>) => door.execute(exec, next)) as never, first)
  ctx.on('tools/result', ((exec: Readonly<ExecLike>) => { door.forget(exec) }) as never, first)
  watchAuthority(ctx as never)
}
