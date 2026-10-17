// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Test rig: the door wired into the pipeline simulation exactly as apply() wires it into Cordis
// (pre-execute and execute listeners prepended, a guard, a result listener), with a stub Rust door behind it.

import { createDoor } from '../src/door.ts'
import type { Door } from '../src/door.ts'
import type { Spy } from './pipeline-sim.ts'
import { PipelineSim } from './pipeline-sim.ts'
import { startStubDoor } from './stub-door.ts'
import type { Stub, StubOptions } from './stub-door.ts'

export interface Rig {
  stub: Stub
  door: Door
  sim: PipelineSim
  spies: Record<string, Spy>
  close(): Promise<void>
}

export interface RigOptions {
  stub?: StubOptions
  socketPath?: string
  responseTimeoutMs?: number
  workspaceRoots?: string[]
}

export async function makeRig(options: RigOptions = {}): Promise<Rig> {
  const stub = await startStubDoor(options.stub)
  const door = createDoor({
    socketPath: options.socketPath ?? stub.socketPath,
    workspaceRoots: options.workspaceRoots ?? ['/sandbox'],
    connectTimeoutMs: 500,
    responseTimeoutMs: options.responseTimeoutMs ?? 500,
  })
  const sim = new PipelineSim()
  sim.onPre((exec, next) => door.preExecute(exec, next), true)
  sim.guards.push(exec => door.guard(exec))
  sim.onExecute((exec, next) => door.execute(exec, next), true)
  sim.results.push(exec => door.forget(exec))
  const spies: Record<string, Spy> = {
    read: sim.tool('read'),
    write: sim.tool('write'),
    web_fetch: sim.tool('web_fetch'),
    kira_remember: sim.tool('kira_remember'),
    totally_new_tool: sim.tool('totally_new_tool'),
    evil_tool: sim.tool('evil_tool', { class: 'local', readOnly: true, description: 'harmless local helper' }),
  }
  return { stub, door, sim, spies, close: () => stub.close() }
}

/** The structured refusal code of a failure result, or undefined for a success. */
export function codeOf(result: { isError: boolean; error?: { info?: { code: string } } }): string | undefined {
  return result.isError ? result.error?.info?.code : undefined
}
