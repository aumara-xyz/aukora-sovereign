// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Core logic of @aukora/kira, free of any DSH import so it runs under plain Node in unit tests.
//
// Responsibilities:
//  1. Validate configuration (no Kira socket or token is ever held here).
//  2. Enforce turn-level provenance taint: once a turn invokes an external tool (`web_fetch`, `web_search`,
//     or `mcp__*`), reads a `web-derived` note back from Kira, or gets a delegated agent's result while anything
//     was tainted, any `kira_remember` (or `memory_remember`) call in that turn must declare
//     `capture: "web-derived"` or it is denied in `tools/pre-execute` before reaching the wire.
//  3. Enforce defense-in-depth client-side checks matching `crates/supervisor/src/door/memory.rs`
//     (`capture-ceiling`, `owner-only`, `lane-closed`) without ever mutating `exec.arguments` (preserving
//     @aukora/door's judge-then-lock digest invariant).
//  4. Load `aukora:self` (capped at 4,096 UTF-8 bytes) and `aukora:resume` (capped at 2,048 UTF-8 bytes)
//     at session start through `kira_list_recent` (routed through @aukora/door -> Rust door -> Kira 2)
//     and inject them into the system prompt with `interpolate: false`, outside the 4,800-char recall budget.

import {
  RESUME_SECTION_ORDER,
  SELF_SECTION_ORDER,
  noteText,
  selectSlotNote,
  truncateUtf8,
} from './slots.ts'
import {
  AGENT_CAPTURES,
  AGENT_LANES,
  DELEGATION_TOOL_NAMES,
  isTaintingTool,
  KIRA_READ_TOOL_NAMES,
  KIRA_REFUSAL_NAME,
  REMEMBER_TOOL_NAMES,
} from './tools.ts'
import type {
  ExecLike,
  KiraNote,
  KiraPluginConfig,
  PreDecisionLike,
  PromptAssemblyLike,
  PromptSectionLike,
  ResolvedKiraConfig,
  ResultLike,
} from './types.ts'

const CLOSED_LANES = new Set(['charter', 'ruling', 'decision', 'self', 'resume'])
const ALLOWED_LANES = new Set<string>(AGENT_LANES)
const ALLOWED_CAPTURES = new Set<string>(AGENT_CAPTURES)
const REMEMBER_TOOLS = new Set<string>(REMEMBER_TOOL_NAMES)
const READ_TOOLS = new Set<string>(KIRA_READ_TOOL_NAMES)
const DELEGATION_TOOLS = new Set<string>(DELEGATION_TOOL_NAMES)
/** Open delegations remembered at once (each is forgotten on its result); the oldest goes first past this. */
const MAX_DELEGATIONS = 4096

/** Whether a Kira read result carries a `web-derived` note (`kira_get` returns one note, recall `items`, a list `notes`). */
function carriesWebDerived(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  if (record.capture === 'web-derived') return true
  for (const key of ['items', 'notes']) {
    const list = record[key]
    if (Array.isArray(list) && list.some(note => typeof note === 'object' && note !== null && (note as Record<string, unknown>).capture === 'web-derived')) {
      return true
    }
  }
  return false
}

/** Validate a KiraPluginConfig and fill in defaults. */
export function resolveKiraConfig(raw: KiraPluginConfig = {}): ResolvedKiraConfig {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    throw new Error('aukora-kira: config must be an object')
  }
  const intInRange = (val: number | undefined, fallback: number, low: number, high: number, label: string): number => {
    const chosen = val ?? fallback
    if (!Number.isInteger(chosen) || chosen < low || chosen > high) {
      throw new Error(`aukora-kira: ${label} must be an integer in ${low}..${high}`)
    }
    return chosen
  }
  const nonEmptyString = (val: string | undefined, fallback: string, label: string): string => {
    const chosen = val ?? fallback
    if (typeof chosen !== 'string' || chosen.trim().length === 0 || chosen.includes('\0')) {
      throw new Error(`aukora-kira: ${label} must be a non-empty string`)
    }
    return chosen
  }
  return {
    epoch: intInRange(raw.epoch, 2, 1, 1_000_000, 'epoch'),
    selfSlot: nonEmptyString(raw.selfSlot, 'aukora:self', 'selfSlot'),
    resumeSlot: nonEmptyString(raw.resumeSlot, 'aukora:resume', 'resumeSlot'),
    maxSelfBytes: intInRange(raw.maxSelfBytes, 4_096, 64, 65_536, 'maxSelfBytes'),
    maxResumeBytes: intInRange(raw.maxResumeBytes, 2_048, 64, 65_536, 'maxResumeBytes'),
    scanLimit: intInRange(raw.scanLimit, 500, 1, 500, 'scanLimit'),
  }
}

/** Function signature used by @aukora/kira to invoke a tool through DSH's ToolRuntime (and therefore through @aukora/door). */
export type ToolExecutor = (name: string, args: Record<string, unknown>) => Promise<ResultLike>

export interface KiraController {
  readonly config: ResolvedKiraConfig
  /** Whether the given agent scope (or global fallback) is currently tainted by external input in this turn. */
  isTurnTainted(agent?: object): boolean
  /** Mark the current turn as tainted by external input (`web_fetch`, `web_search`, `mcp__*`). */
  markTurnTainted(agent?: object): void
  /** Clear external-input taint at the start of a new agent turn. */
  clearTurnTaint(agent?: object): void
  /**
   * `tools/pre-execute` hook: enforces turn-taint (`capture: "web-derived"`) and engine ceilings on `kira_remember`,
   * and marks the turn tainted when an external tool is dispatched. Never mutates `exec.arguments`.
   */
  preExecute(exec: ExecLike, next: () => Promise<PreDecisionLike>): Promise<PreDecisionLike>
  /** `tools/result` observer: marks the turn tainted if an external tool ran. */
  onToolResult(exec: Readonly<ExecLike>, result?: Readonly<ResultLike>): void
  /** Load `aukora:self` and `aukora:resume` once per session through `executeTool('kira_list_recent', ...)`. */
  ensureSlotsLoaded(force?: boolean): Promise<{ selfText: string; resumeText: string; loaded: boolean }>
  /** Current cached text for the `aukora:self` section (<= maxSelfBytes UTF-8 bytes). */
  selfText(): string
  /** Current cached text for the `aukora:resume` section (<= maxResumeBytes UTF-8 bytes). */
  resumeText(): string
  /** DSH SystemPrompt section descriptor for `aukora:self` (`interpolate: false`). */
  selfSection(): PromptSectionLike
  /** DSH SystemPrompt section descriptor for `aukora:resume` (`interpolate: false`). */
  resumeSection(): PromptSectionLike
  /**
   * `system-prompt/assemble` waterfall handler: awaits `ensureSlotsLoaded()` on first assembly and guarantees
   * that `aukora:self` and `aukora:resume` carry the loaded text with `interpolate: false`.
   */
  assemblePrompt<T extends PromptAssemblyLike>(assembly: T, next: () => Promise<T>): Promise<T>
}

function denyDecision(code: string, reason: string): PreDecisionLike {
  return {
    kind: 'deny',
    reason,
    info: { name: KIRA_REFUSAL_NAME, code },
  }
}

export function createKiraController(rawConfig: KiraPluginConfig, executeTool: ToolExecutor): KiraController {
  const config = resolveKiraConfig(rawConfig)
  const taintedAgents = new WeakSet<object>()
  let globalTainted = false
  // Counts every taint ever marked, so a delegation can tell whether anything was tainted while it ran.
  let taintCount = 0
  const delegations = new Map<symbol, number>()

  let cachedSelfText = ''
  let cachedResumeText = ''
  let slotsLoaded = false
  let inflightLoad: Promise<{ selfText: string; resumeText: string; loaded: boolean }> | null = null

  const isTurnTainted = (agent?: object): boolean => {
    return agent !== undefined ? taintedAgents.has(agent) : globalTainted
  }

  const markTurnTainted = (agent?: object): void => {
    taintCount += 1
    if (agent !== undefined) {
      taintedAgents.add(agent)
    } else {
      globalTainted = true
    }
  }

  const clearTurnTaint = (agent?: object): void => {
    if (agent !== undefined) {
      taintedAgents.delete(agent)
    } else {
      globalTainted = false
    }
  }

  const loadSlots = async (): Promise<{ selfText: string; resumeText: string; loaded: boolean }> => {
    try {
      const result = await executeTool('kira_list_recent', {
        limit: config.scanLimit,
        epoch: config.epoch,
      })
      if (!result.isError && typeof result.value === 'object' && result.value !== null) {
        const rawNotes = (result.value as { notes?: unknown }).notes
        if (Array.isArray(rawNotes)) {
          const notes = rawNotes as KiraNote[]
          const selfNote = selectSlotNote(notes, config.selfSlot, 'self')
          const resumeNote = selectSlotNote(notes, config.resumeSlot, 'resume')
          cachedSelfText = selfNote !== undefined ? truncateUtf8(noteText(selfNote), config.maxSelfBytes).text : ''
          cachedResumeText = resumeNote !== undefined ? truncateUtf8(noteText(resumeNote), config.maxResumeBytes).text : ''
          slotsLoaded = true
          return { selfText: cachedSelfText, resumeText: cachedResumeText, loaded: true }
        }
      }
    } catch {
      // Fail closed on slot load errors: leave sections empty rather than crashing prompt assembly,
      // and allow a later retry if the door was not yet listening.
    }
    return { selfText: cachedSelfText, resumeText: cachedResumeText, loaded: slotsLoaded }
  }

  const ensureSlotsLoaded = async (force = false): Promise<{ selfText: string; resumeText: string; loaded: boolean }> => {
    if (slotsLoaded && !force) {
      return { selfText: cachedSelfText, resumeText: cachedResumeText, loaded: true }
    }
    if (inflightLoad !== null && !force) {
      return inflightLoad
    }
    inflightLoad = loadSlots().finally(() => {
      inflightLoad = null
    })
    return inflightLoad
  }

  const controller: KiraController = {
    config,
    isTurnTainted,
    markTurnTainted,
    clearTurnTaint,

    async preExecute(exec, next) {
      if (isTaintingTool(exec.name)) {
        markTurnTainted(exec.agent)
        return next()
      }

      if (DELEGATION_TOOLS.has(exec.name)) {
        if (delegations.size >= MAX_DELEGATIONS) {
          const oldest = delegations.keys().next()
          if (!oldest.done) delegations.delete(oldest.value)
        }
        delegations.set(exec.token, taintCount)
        return next()
      }

      if (REMEMBER_TOOLS.has(exec.name)) {
        const args = (typeof exec.arguments === 'object' && exec.arguments !== null ? exec.arguments : {}) as Record<string, unknown>

        if (args.owner_signed === true) {
          return denyDecision('owner-only', 'aukora-kira: engine cannot set owner_signed on kira_remember (owner-only)')
        }
        if (args.slot !== undefined && args.slot !== null) {
          return denyDecision('lane-closed', 'aukora-kira: engine cannot write slotted notes via kira_remember (lane-closed)')
        }
        if (typeof args.lane !== 'string' || CLOSED_LANES.has(args.lane) || !ALLOWED_LANES.has(args.lane)) {
          return denyDecision('lane-closed', `aukora-kira: lane ${JSON.stringify(args.lane)} is closed to the engine (lane-closed)`)
        }
        if (typeof args.capture !== 'string' || !ALLOWED_CAPTURES.has(args.capture)) {
          return denyDecision('capture-ceiling', `aukora-kira: capture ${JSON.stringify(args.capture)} exceeds the engine ceiling (capture-ceiling)`)
        }
        if (isTurnTainted(exec.agent) && args.capture !== 'web-derived') {
          return denyDecision(
            'turn-tainted',
            'aukora-kira: this turn read external web/MCP input; kira_remember must use capture: "web-derived" (turn-tainted)',
          )
        }
      }

      return next()
    },

    onToolResult(exec, result) {
      if (isTaintingTool(exec.name)) {
        markTurnTainted(exec.agent)
      } else if (DELEGATION_TOOLS.has(exec.name)) {
        // A child that read the web hands its text back here. Unknown start (never seen pre-execute): assume it did.
        const started = delegations.get(exec.token)
        delegations.delete(exec.token)
        if (started === undefined || taintCount > started) markTurnTainted(exec.agent)
      } else if (READ_TOOLS.has(exec.name) && result !== undefined && !result.isError && carriesWebDerived(result.value)) {
        markTurnTainted(exec.agent)
      }
    },

    ensureSlotsLoaded,
    selfText: () => cachedSelfText,
    resumeText: () => cachedResumeText,

    selfSection(): PromptSectionLike {
      return {
        name: config.selfSlot,
        order: SELF_SECTION_ORDER,
        text: () => cachedSelfText,
        interpolate: false,
      }
    },

    resumeSection(): PromptSectionLike {
      return {
        name: config.resumeSlot,
        order: RESUME_SECTION_ORDER,
        text: () => cachedResumeText,
        interpolate: false,
      }
    },

    async assemblePrompt(assembly, next) {
      await ensureSlotsLoaded()
      const syncSection = (name: string, text: string): void => {
        const existing = assembly.sections.find(section => section.name === name)
        if (existing !== undefined) {
          existing.text = text
          existing.interpolate = false
        } else if (text.length > 0) {
          assembly.sections.push({ name, text, interpolate: false })
        }
      }
      syncSection(config.selfSlot, cachedSelfText)
      syncSection(config.resumeSlot, cachedResumeText)
      return next()
    },
  }

  return controller
}
