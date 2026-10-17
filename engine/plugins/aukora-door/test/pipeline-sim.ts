// SPDX-License-Identifier: AGPL-3.0-or-later
//
// A small stand-in for DSH's tool registry pipeline, faithful to the parts the door depends on
// (ToolRuntime.prepareExecution and dispatchScheduledExecution, packages/core/tools/src/index.ts at 1517a4d):
//   - the execution is ONE plain object, not frozen until the result is final; only its `arguments` value is frozen
//   - tools/pre-execute is a waterfall; a listener that does not call next() skips every listener after it
//   - monotonic guards run after the whole pre-execute waterfall and may only deny
//   - tools/execute is a waterfall whose last step looks the tool up by `exec.name` and runs it with `exec.arguments`
//   - a thrown error becomes a failure result; tools/result listeners see the final result
// Listener order follows Cordis: `prepend` puts a listener in front of every existing one.

import type { ExecLike, PreDecisionLike, ResultLike } from '../src/types.ts'

type PreListener = (exec: ExecLike, next: () => Promise<PreDecisionLike>) => Promise<PreDecisionLike>
type ExecListener = (exec: ExecLike, next: () => Promise<ResultLike>) => Promise<ResultLike>
type Guard = (exec: Readonly<ExecLike>) => string | undefined

export interface SimTool {
  /** Metadata a plugin may claim for itself. The door must ignore all of it. */
  meta?: Record<string, unknown>
  execute(args: unknown, exec: ExecLike): Promise<unknown>
}

export interface Spy {
  calls: unknown[]
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    for (const key of Reflect.ownKeys(value)) deepFreeze((value as Record<string | symbol, unknown>)[key])
    Object.freeze(value)
  }
  return value
}

function failure(message: string): ResultLike {
  return { isError: true, error: { message }, content: [{ type: 'text', text: `Error: ${message}` }] }
}

export class PipelineSim {
  pre: PreListener[] = []
  exe: ExecListener[] = []
  guards: Guard[] = []
  results: Array<(exec: ExecLike, result: ResultLike) => void> = []
  tools = new Map<string, SimTool>()
  private counter = 0

  onPre(listener: PreListener, prepend = false): void {
    if (prepend) this.pre.unshift(listener)
    else this.pre.push(listener)
  }

  onExecute(listener: ExecListener, prepend = false): void {
    if (prepend) this.exe.unshift(listener)
    else this.exe.push(listener)
  }

  /** Register a tool whose body records every call it receives. */
  tool(name: string, meta?: Record<string, unknown>, result: unknown = { ok: true }): Spy {
    const spy: Spy = { calls: [] }
    this.tools.set(name, {
      meta,
      execute: async args => {
        spy.calls.push(args)
        return result
      },
    })
    return spy
  }

  async run(name: string, args: unknown): Promise<ResultLike> {
    this.counter += 1
    const callId = `call-${this.counter}`
    // createExecution: one lossless-JSON snapshot, deep-frozen, inside a plain mutable object.
    const exec: ExecLike = { callId, rootCallId: callId, name, arguments: deepFreeze(JSON.parse(JSON.stringify(args))), token: Symbol(callId) }
    let result: ResultLike
    try {
      let index = 0
      const nextPre = (): Promise<PreDecisionLike> => {
        const listener = this.pre[index]
        index += 1
        return listener === undefined ? Promise.resolve({ kind: 'allow' }) : listener(exec, nextPre)
      }
      const gate = await nextPre()
      let denial: string | undefined
      if (gate.kind === 'deny') denial = gate.reason
      else if (gate.kind === 'allow') {
        for (const guard of this.guards) {
          denial = guard(exec)
          if (denial !== undefined) break
        }
      } else denial = 'not allowed'
      if (denial !== undefined) {
        result = failure(denial)
      } else {
        let at = 0
        const nextExec = (): Promise<ResultLike> => {
          const listener = this.exe[at]
          at += 1
          return listener === undefined ? this.body(exec) : listener(exec, nextExec)
        }
        result = await nextExec()
      }
    } catch (error) {
      result = failure(error instanceof Error ? error.message : String(error))
    }
    Object.freeze(exec)
    for (const listener of this.results) listener(exec, result)
    return result
  }

  private async body(exec: ExecLike): Promise<ResultLike> {
    exec.signal = new AbortController().signal
    const tool = this.tools.get(exec.name)
    if (tool === undefined) return failure(`unknown tool ${exec.name}`)
    try {
      const value = await tool.execute(exec.arguments, exec)
      return { isError: false, value, content: [{ type: 'text', text: JSON.stringify(value) }] }
    } catch (error) {
      return failure(error instanceof Error ? error.message : String(error))
    }
  }
}
