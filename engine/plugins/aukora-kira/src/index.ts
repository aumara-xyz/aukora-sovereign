// SPDX-License-Identifier: AGPL-3.0-or-later
//
// @aukora/kira — Kira 2 shared-memory plugin for DeepSeek Harness (DSH 0.2.1-alpha.5, master 1517a4d) on Cordis.
//
// Architectural guarantees:
//  1. Zero credentials in the engine: this plugin holds NO Kira socket path and NO Kira token.
//     Every `kira_*` tool call is classified as `class: 'memory'` by @aukora/door and forwarded over
//     the door socket to the Rust door (`sovereign door serve`), whose memory executor attaches the
//     door's 0600 token and enforces engine ceilings (`capture-ceiling`, `owner-only`, `lane-closed`).
//  2. Fail-closed local body: if @aukora/door is absent or bypassed and a `kira_*` tool body runs locally,
//     it immediately throws `KiraDoorRequiredError` (`code: 'door-required'`).
//  3. Turn-level provenance taint: once a turn calls `web_fetch`, `web_search`, or `mcp__*`, reads a `web-derived`
//     note back from Kira, or receives a delegated agent's result while anything was tainted, any subsequent
//     `kira_remember` or `memory_remember` in that turn (across all steps of the turn) must declare
//     `capture: "web-derived"`.
//  4. Session-start slot injection: `aukora:self` (up to 4,096 UTF-8 bytes) and `aukora:resume` (up to 2,048
//     UTF-8 bytes) are fetched once at session start via `kira_list_recent` through the door and injected as
//     `systemPrompt` sections with `interpolate: false`, outside the 4,800-char `kira_recall` budget.

import { randomBytes } from 'node:crypto'
import type { Context } from '@deepseek-ai/cordis'
import { createKiraController, resolveKiraConfig } from './kira.ts'
import type { KiraController, ToolExecutor } from './kira.ts'
import {
  RESUME_SECTION_ORDER,
  SELF_SECTION_ORDER,
  isLiveVerifiedNote,
  noteText,
  selectSlotNote,
  truncateUtf8,
} from './slots.ts'
import {
  AGENT_CAPTURES,
  AGENT_LANES,
  DELEGATION_TOOL_NAMES,
  KIRA_READ_TOOL_NAMES,
  KIRA_REFUSAL_NAME,
  KIRA_TOOL_NAMES,
  KiraDoorRequiredError,
  NOTE_FORMS,
  PRIVACY_CLASSES,
  REMEMBER_TOOL_NAMES,
  buildRememberArgs,
  createKiraTools,
  isTaintingTool,
  kiraRefusalResult,
} from './tools.ts'
import type {
  ExecLike,
  KiraNote,
  KiraPluginConfig,
  PreDecisionLike,
  PromptAssemblyLike,
  ResolvedKiraConfig,
  ResultLike,
} from './types.ts'

export {
  AGENT_CAPTURES,
  AGENT_LANES,
  DELEGATION_TOOL_NAMES,
  KIRA_READ_TOOL_NAMES,
  KIRA_REFUSAL_NAME,
  KIRA_TOOL_NAMES,
  KiraDoorRequiredError,
  NOTE_FORMS,
  PRIVACY_CLASSES,
  REMEMBER_TOOL_NAMES,
  RESUME_SECTION_ORDER,
  SELF_SECTION_ORDER,
  buildRememberArgs,
  createKiraController,
  createKiraTools,
  isLiveVerifiedNote,
  isTaintingTool,
  kiraRefusalResult,
  noteText,
  resolveKiraConfig,
  selectSlotNote,
  truncateUtf8,
}
export type {
  ExecLike,
  KiraController,
  KiraNote,
  KiraPluginConfig,
  PreDecisionLike,
  PromptAssemblyLike,
  ResolvedKiraConfig,
  ResultLike,
  ToolExecutor,
}

/** Cordis plugin name used by loader diagnostics. */
export const name = 'aukora-kira'

/** DSH services required by this plugin. */
export const inject = ['tools', 'systemPrompt']

/**
 * Register @aukora/kira on a Cordis context.
 *
 * Notice that `tools/pre-execute` is registered with `{ global: true }` (NOT `prepend: true`),
 * so @aukora/door (`{ prepend: true, global: true }`) always runs first to bind and hash the
 * canonical arguments before @aukora/kira's non-mutating taint/ceiling check runs.
 */
export function apply(ctx: Context, rawConfig: KiraPluginConfig = {}): KiraController {
  const callPrefix = randomBytes(6).toString('hex')
  let callSeq = 0

  const executeTool: ToolExecutor = async (toolName, args) => {
    callSeq += 1
    const toolsSvc = (ctx as unknown as { tools: { execute(input: unknown): Promise<ResultLike> } }).tools
    return toolsSvc.execute({
      callId: `kira-slot-${callPrefix}-${callSeq}`,
      name: toolName,
      arguments: args,
      signal: new AbortController().signal,
    })
  }

  const controller = createKiraController(rawConfig, executeTool)
  const toolsSvc = (ctx as unknown as { tools: { register(def: unknown): unknown } }).tools
  const promptSvc = (ctx as unknown as { systemPrompt: { section(sec: unknown): unknown } }).systemPrompt

  for (const tool of createKiraTools()) {
    toolsSvc.register(tool)
  }

  promptSvc.section(controller.selfSection())
  promptSvc.section(controller.resumeSection())

  const globalOnly = { global: true }
  ctx.on(
    'tools/pre-execute',
    ((exec: ExecLike, next: () => Promise<PreDecisionLike>) => controller.preExecute(exec, next)) as never,
    globalOnly,
  )
  ctx.on(
    'tools/result',
    ((exec: Readonly<ExecLike>, result: Readonly<ResultLike>) => {
      controller.onToolResult(exec, result)
    }) as never,
    globalOnly,
  )
  ctx.on(
    'agent/pre-step',
    (async (payload: { agent?: object; step?: number }, next: () => Promise<unknown>) => {
      if (payload.step === 1) {
        controller.clearTurnTaint(payload.agent)
      }
      await controller.ensureSlotsLoaded()
      return next()
    }) as never,
    globalOnly,
  )
  ctx.on(
    'agent/created',
    (async (payload: { agent?: object }) => {
      controller.clearTurnTaint(payload.agent)
      await controller.ensureSlotsLoaded()
    }) as never,
    globalOnly,
  )
  ctx.on(
    'system-prompt/assemble',
    ((assembly: PromptAssemblyLike, _context: unknown, next: () => Promise<PromptAssemblyLike>) =>
      controller.assemblePrompt(assembly, next)) as never,
    globalOnly,
  )

  return controller
}
