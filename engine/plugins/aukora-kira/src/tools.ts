// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Tool definitions for @aukora/kira.
//
// Architectural invariant: the engine holds NO Kira token and NO Kira socket path. Every `kira_*`
// tool is classified as `class: 'memory'` by @aukora/door (`src/classify.ts`), which intercepts
// `tools/execute` before `next()` and forwards the canonical bytes to the Rust door (`sovereign door serve`).
// The Rust door's memory executor (`crates/supervisor/src/door/memory.rs`) enforces the engine ceilings
// and forwards the call to the live Kira 2 service using the door's own 0600 token file.
//
// If a `kira_*` tool body in this file is ever reached directly (meaning @aukora/door is missing or bypassed),
// it fails closed immediately with `door-required`.

import type { ResultLike } from './types.ts'

/** Error name carried in `error.info.name` of refusals authored by @aukora/kira. */
export const KIRA_REFUSAL_NAME = 'AukoraKiraRefusal'

/** All memory tools registered by @aukora/kira. */
export const KIRA_TOOL_NAMES = [
  'kira_taint',
  'kira_recall',
  'kira_remember',
  'kira_get',
  'kira_list_recent',
  'kira_supersede',
] as const

export type KiraToolName = (typeof KIRA_TOOL_NAMES)[number]

/** Allowed agent lanes enforced by `crates/supervisor/src/door/memory.rs`. */
export const AGENT_LANES = ['finding', 'evidence', 'experience'] as const

/** Allowed agent capture paths enforced by `crates/supervisor/src/door/memory.rs`. */
export const AGENT_CAPTURES = ['model-generated', 'web-derived'] as const

/** Allowed note forms (`crates/kira/src/shared/note.rs`). */
export const NOTE_FORMS = ['fact', 'snapshot', 'counterevidence'] as const

/** Allowed privacy classes (`crates/kira/src/shared/note.rs`). */
export const PRIVACY_CLASSES = ['builders', 'public', 'local'] as const

/**
 * Whether a tool name brings untrusted external content into the current turn, tainting later `kira_remember` calls:
 * the web, MCP servers, and every delegation (another agent's output may carry what it read; see
 * DELEGATION_TOOL_NAMES).
 */
export function isTaintingTool(name: string): boolean {
  return name === 'web_fetch' || name === 'web_search' || name.startsWith('mcp__') || isDelegationTool(name) || SESSION_HISTORY_TOOL_NAMES.includes(name)
}

/**
 * Tools that read the session's own history. A turn that never fetched anything can still surface a `web_fetch` result
 * from an earlier turn through them, so they taint like the tool that produced it (Argon RT-6).
 */
export const SESSION_HISTORY_TOOL_NAMES: readonly string[] = [
  'session_search', 'session_event_search', 'session_trace', 'session_event_trace', 'session_event_read',
]

/**
 * The remember tool, and `memory_remember`: the Rust door no longer forwards `memory_*` (DSH 0.2.1-alpha.5 registers
 * no such tool), but the check costs nothing if a door that still does is paired with this plugin.
 */
export const REMEMBER_TOOL_NAMES: readonly string[] = ['kira_remember', 'memory_remember']

/**
 * Tool names whose results carry Kira notes; a returned `web-derived` note brings web content into the turn. Supersede
 * returns the superseded note (`target`) with its text.
 */
export const KIRA_READ_TOOL_NAMES: readonly string[] = [
  'kira_recall', 'kira_get', 'kira_list_recent', 'kira_supersede',
  'memory_recall', 'memory_get', 'memory_list_recent', 'memory_supersede',
]

/**
 * Tools that hand the caller another agent's output: a native child, a fork, a ralph loop, a workflow script, and the
 * agent-team tools that spawn a teammate or read back its work. A child may run in a fresh process whose taint this
 * process never sees, and no authenticated signal says a child stayed clean, so every delegation taints the caller's
 * turn. Agent-team names by prefix (`team_`, `spawn_`), so a new one is covered.
 */
export const DELEGATION_TOOL_NAMES: readonly string[] = ['subagent', 'subagent_fork', 'ralph', 'workflow', 'wait_agent']

/** Whether a tool hands back another agent's output (DELEGATION_TOOL_NAMES, or an agent-team `team_`/`spawn_` tool). */
export function isDelegationTool(name: string): boolean {
  return DELEGATION_TOOL_NAMES.includes(name) || name.startsWith('team_') || name.startsWith('spawn_')
}

/** Error thrown if a `kira_*` tool body is ever invoked in-process without @aukora/door intercepting it. */
export class KiraDoorRequiredError extends Error {
  readonly code: string = 'door-required'
  constructor(toolName: string) {
    super(`aukora-kira: ${toolName} must execute through @aukora/door; local execution is disabled (door-required)`)
    this.name = KIRA_REFUSAL_NAME
  }
}

/** A refusal result in DSH's shape. */
export function kiraRefusalResult(code: string, message: string): ResultLike {
  return {
    isError: true,
    error: { message, info: { name: KIRA_REFUSAL_NAME, code } },
    content: [{ type: 'text', text: `Error: ${message}` }],
  }
}

/** Input for `buildRememberArgs`, filling in safe agent defaults before calling `kira_remember`. */
export interface RememberInput {
  text: string
  subject: string
  scope?: string
  lane?: 'finding' | 'evidence' | 'experience'
  form?: 'fact' | 'snapshot' | 'counterevidence'
  privacy?: 'builders' | 'public' | 'local'
  capture?: 'model-generated' | 'web-derived'
  sources?: string[]
  valid_from?: number
  valid_to?: number
  /**
   * For a slot write: the id of the slot's note the writer last read (`KiraController.slotHead`), or `'none'` for a
   * slot it saw empty. Kira refuses a slot write without it (`kira:expected-head-required`) and one whose head is no longer that note (`kira:resume-stale`).
   * (The engine's own slot writes are closed at the door; this is for the session wrapper that writes the handoff.)
   */
  expected_head?: string
}

/** Build a canonical `kira_remember` argument object matching `RememberParams` in `crates/kira/src/shared/service/mod.rs`. */
export function buildRememberArgs(input: RememberInput): Record<string, unknown> {
  const args: Record<string, unknown> = {
    text: input.text,
    subject: input.subject,
    scope: input.scope ?? 'builders',
    lane: input.lane ?? 'finding',
    form: input.form ?? 'fact',
    privacy: input.privacy ?? 'builders',
    capture: input.capture ?? 'model-generated',
  }
  if (input.sources !== undefined) args.sources = input.sources
  if (input.valid_from !== undefined) args.valid_from = input.valid_from
  if (input.valid_to !== undefined) args.valid_to = input.valid_to
  if (input.expected_head !== undefined) args.expected_head = input.expected_head
  return args
}

/** Shape of a DSH tool definition accepted by `ctx.tools.register()`. */
export interface DshToolDefinition {
  name: KiraToolName
  description: string
  parameters: Record<string, unknown>
  output: {
    schema: Record<string, unknown>
    render(args: unknown, value: unknown): Array<{ type: 'text'; text: string }>
  }
  isConcurrencySafe?(args: unknown): boolean
  execute(args: unknown, exec?: unknown): Promise<never>
}

function renderOutput(_args: unknown, value: unknown): Array<{ type: 'text'; text: string }> {
  return [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value) }]
}

function failClosedExecute(toolName: KiraToolName): () => Promise<never> {
  return async () => {
    throw new KiraDoorRequiredError(toolName)
  }
}

/** Construct the Kira 2 tool definitions for DSH's ToolRuntime. */
export function createKiraTools(): DshToolDefinition[] {
  return [
    {
      name: 'kira_taint',
      description: 'Read the door-owned durable engine taint, or mark it before consuming external input. Only the owner can clear it.',
      parameters: { type: 'object', properties: { mark: { type: 'boolean', const: true } }, additionalProperties: false },
      output: { schema: { type: 'object', properties: { tainted: { type: 'boolean' } }, required: ['tainted'], additionalProperties: false }, render: renderOutput },
      execute: failClosedExecute('kira_taint'),
    },
    {
      name: 'kira_recall',
      description:
        "Search shared memory (Kira 2) by keyword and semantic meaning. Returns found, empty, or undetermined, with attribution and an evidence label on each note. Evidence labels apply to each note; found does not verify every returned claim. For undetermined with reason similar-note-unverified: Related notes were found, but K2 couldn't establish an evidence-backed answer. Use these as leads to check. Other undetermined reasons name the condition that prevented an answer.",
      parameters: {
        type: 'object',
        properties: {
          query: {
            type: 'string',
            description: 'Question or keywords to search for in shared memory.',
          },
          epoch: {
            type: 'integer',
            description: 'Optional epoch number (defaults to current epoch 2).',
          },
          scopes: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional list of scopes to search within.',
          },
          author: {
            type: 'string',
            description: 'Optional author name or 64-hex pubkey filter.',
          },
          budget_chars: {
            type: 'integer',
            description: 'Optional character budget for returned notes (capped at 4,800 chars).',
          },
        },
        required: ['query'],
        additionalProperties: false,
      },
      output: {
        schema: { description: 'Kira 2 recall status, reason and message, with per-note evidence labels. A found result can include unverified notes.' },
        render: renderOutput,
      },
      isConcurrencySafe: () => true,
      execute: failClosedExecute('kira_recall'),
    },
    {
      name: 'kira_remember',
      description:
        'Write a signed note to shared memory (Kira 2) through the AUKORA door. Engine ceilings apply: lane must be finding/evidence/experience, capture must be model-generated or web-derived (web-derived is required if this turn used web_fetch/web_search/MCP), and owner_signed/slot are closed.',
      parameters: {
        type: 'object',
        properties: {
          text: {
            type: 'string',
            description: 'The note content to record.',
          },
          subject: {
            type: 'string',
            description: 'Short subject or topic tag (e.g. "door-live", "kira-plugin").',
          },
          scope: {
            type: 'string',
            description: 'Memory scope permitted for this agent token (e.g. "builders").',
          },
          lane: {
            type: 'string',
            enum: ['finding', 'evidence', 'experience'],
            description: 'Agent memory lane (charter/ruling/decision/self/resume are owner-only).',
          },
          form: {
            type: 'string',
            enum: ['fact', 'snapshot', 'counterevidence'],
            description: 'Epistemic form of the note.',
          },
          privacy: {
            type: 'string',
            enum: ['builders', 'public', 'local'],
            description: 'Privacy class of the note.',
          },
          capture: {
            type: 'string',
            enum: ['model-generated', 'web-derived'],
            description: 'Provenance capture path. Must be "web-derived" if the turn read external web/MCP input.',
          },
          sources: {
            type: 'array',
            items: { type: 'string' },
            description: 'Optional list of source references or 64-hex note IDs.',
          },
          valid_from: {
            type: 'integer',
            description: 'Optional unix timestamp (seconds) from which the note is valid.',
          },
          valid_to: {
            type: 'integer',
            description: 'Optional unix timestamp (seconds) until which the note is valid.',
          },
          expected_head: {
            type: 'string',
            description: 'Required for any slot write: the id of the slot note you last read, or "none" for an empty slot. A newer note in the slot refuses the write (kira:resume-stale).',
          },
        },
        required: ['text', 'subject', 'scope', 'lane', 'form', 'privacy', 'capture'],
        additionalProperties: false,
      },
      output: {
        schema: { description: 'Signed Kira 2 note metadata (id, seq, author, pubkey, sig_verified).' },
        render: renderOutput,
      },
      isConcurrencySafe: () => false,
      execute: failClosedExecute('kira_remember'),
    },
    {
      name: 'kira_get',
      description: 'Fetch a single verified note from shared memory (Kira 2) by its 64-hex event ID, or the current note of a slot.',
      parameters: {
        type: 'object',
        properties: {
          id: {
            type: 'string',
            description: '64-character hex event ID of the note, or a slot name: aukora:self, aukora:resume or resume:<agent>.',
          },
        },
        required: ['id'],
        additionalProperties: false,
      },
      output: {
        schema: { description: 'Verified Kira 2 note or null if not found.' },
        render: renderOutput,
      },
      isConcurrencySafe: () => true,
      execute: failClosedExecute('kira_get'),
    },
    {
      name: 'kira_list_recent',
      description: 'List the most recent verified notes in shared memory (Kira 2), newest first.',
      parameters: {
        type: 'object',
        properties: {
          limit: {
            type: 'integer',
            description: 'Maximum number of notes to return (1..500, default 20).',
          },
          before: {
            type: 'integer',
            description: 'Optional sequence cursor to paginate before.',
          },
          epoch: {
            type: 'integer',
            description: 'Optional epoch filter (defaults to current epoch 2).',
          },
        },
        additionalProperties: false,
      },
      output: {
        schema: { description: 'Recent verified Kira 2 notes.' },
        render: renderOutput,
      },
      isConcurrencySafe: () => true,
      execute: failClosedExecute('kira_list_recent'),
    },
    {
      name: 'kira_supersede',
      description:
        'Correct a note in shared memory (Kira 2) without deleting it: name the note that replaces it. On your own note it is in force at once. On another author\'s note it needs your own replacement note and is only a proposal until the author or the owner accepts it. A concurrent correction refuses as kira:supersede-stale; read again before retrying.',
      parameters: {
        type: 'object',
        properties: {
          target: {
            type: 'string',
            description: '64-character hex event ID of the note being superseded.',
          },
          replacement: {
            type: 'string',
            description: 'Optional 64-character hex event ID of the replacement note (required, and your own, when the target is not yours).',
          },
          expected_current: {
            type: 'string',
            description: 'The target\'s superseded_by event ID last read, when changing an existing correction. Omit or use none for a live target; a changed head refuses as kira:supersede-stale.',
          },
          reason: {
            type: 'string',
            description: 'Optional reason, up to 512 characters.',
          },
        },
        required: ['target'],
        additionalProperties: false,
      },
      output: {
        schema: { description: 'Signed supersession event receipt.' },
        render: renderOutput,
      },
      isConcurrencySafe: () => false,
      execute: failClosedExecute('kira_supersede'),
    },
  ]
}
