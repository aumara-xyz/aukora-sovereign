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

/** Whether a tool name brings untrusted external content into the current turn, tainting later `kira_remember` calls. */
export function isTaintingTool(name: string): boolean {
  return name === 'web_fetch' || name === 'web_search' || name.startsWith('mcp__')
}

/**
 * Every tool name the Rust door forwards to Kira's `remember` (`crates/supervisor/src/door/memory.rs` `method`: the
 * `kira_` and the `memory_` prefix). The taint check must cover all of them: a `memory_remember` registered by any
 * other plugin reaches the same write.
 */
export const REMEMBER_TOOL_NAMES: readonly string[] = ['kira_remember', 'memory_remember']

/** Tool names whose results carry Kira notes; a returned `web-derived` note brings web content into the turn. */
export const KIRA_READ_TOOL_NAMES: readonly string[] = [
  'kira_recall', 'kira_get', 'kira_list_recent', 'memory_recall', 'memory_get', 'memory_list_recent',
]

/**
 * Tools whose result is another agent's output (a native child, a fork, a ralph loop, a workflow script). The child
 * can read the web in its own turn and hand the text back; when anything was tainted while the delegation ran, its
 * result taints the caller's turn too.
 */
export const DELEGATION_TOOL_NAMES: readonly string[] = ['subagent', 'subagent_fork', 'ralph', 'workflow']

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

/** Construct the five Kira 2 tool definitions for DSH's ToolRuntime. */
export function createKiraTools(): DshToolDefinition[] {
  return [
    {
      name: 'kira_recall',
      description:
        'Search shared memory (Kira 2) by keyword and semantic meaning. Returns a three-way outcome (found, empty, or undetermined) with verified notes and attribution.',
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
        schema: { description: 'Kira 2 recall outcome (found, empty, or undetermined) with verified notes.' },
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
        'Supersede an existing note in shared memory (Kira 2) without deleting it. Agents may only supersede notes authored by their own key.',
      parameters: {
        type: 'object',
        properties: {
          target: {
            type: 'string',
            description: '64-character hex event ID of the note being superseded.',
          },
          replacement: {
            type: 'string',
            description: 'Optional 64-character hex event ID of the replacement note.',
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
