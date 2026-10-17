// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared shapes for @aukora/kira. Mirrors the subset of DSH's ToolRuntime and SystemPrompt types
// (@deepseek-ai/dsh-tools, @deepseek-ai/dsh-system-prompt at 0.2.1-alpha.5 / 1517a4d) so the plugin
// logic and unit tests run under plain Node without a runtime dependency on DSH.

/** The part of a DSH tool execution this plugin reads. */
export interface ExecLike {
  readonly callId: string
  readonly rootCallId?: string
  readonly name: string
  readonly arguments: unknown
  readonly token: symbol
  signal?: AbortSignal
  readonly agent?: object
  readonly parent?: unknown
}

/** A tool result in DSH's shape: success carries `value`, failure carries `error`. */
export type ResultLike =
  | { isError: false; value: unknown; content: Array<{ type: 'text'; text: string }> }
  | { isError: true; error: { message: string; info?: { name: string; code: string } }; content: Array<{ type: 'text'; text: string }> }

/** Pre-dispatch decision in DSH's shape. */
export type PreDecisionLike =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string; info?: { name: string; code: string } }
  | { kind: 'cancel' }
  | { kind: 'ask'; reason?: string }

/** Static configuration for @aukora/kira. Notice: no socket path and no token (the Rust door owns both). */
export interface KiraPluginConfig {
  /** Active Kira epoch to read session-start slots from. Default 2. */
  epoch?: number
  /** Slot name for the agent's self note. Default 'aukora:self'. */
  selfSlot?: string
  /** Slot name for the session resume note. Default 'aukora:resume'. */
  resumeSlot?: string
  /** Maximum UTF-8 bytes injected for the self slot (outside recall budget). Default 4,096. */
  maxSelfBytes?: number
  /** Maximum UTF-8 bytes injected for the resume slot (outside recall budget). Default 2,048. */
  maxResumeBytes?: number
  /** Number of recent notes scanned via kira_list_recent at session start to resolve slots. Default 500. */
  scanLimit?: number
}

/** Validated KiraPluginConfig with all defaults filled in. */
export interface ResolvedKiraConfig {
  epoch: number
  selfSlot: string
  resumeSlot: string
  maxSelfBytes: number
  maxResumeBytes: number
  scanLimit: number
}

/**
 * A verified note as returned on the wire by Kira 2 (`note_json` in `crates/kira/src/shared/service/mod.rs:374-384`).
 * `text` is the wire field produced by `note_json`; `content` is accepted as a fallback for raw Nostr event fixtures.
 */
export interface KiraNote {
  id: string
  seq?: number
  epoch: number
  /** 64-hex public key of the signing author. */
  author: string
  /** Human-readable registered agent name (e.g. "argon", "peter", "auma"). */
  author_name?: string | null
  created_at: number
  /** Statement text on the Kira 2 service wire (`note_json`). */
  text?: string
  /** Optional fallback when reading raw Nostr event objects in tests. */
  content?: string
  lane: string
  scope: string
  subject: string
  form: string
  review?: string
  privacy: string
  capture: string
  sources: string[]
  slot?: string | null
  valid_from?: number | null
  valid_to?: number | null
  roots?: string[]
  superseded_by?: string | null
  quarantined: boolean
  withheld?: boolean
  correction?: string | null
  sig_verified?: boolean
}

/** A system-prompt section contribution in DSH's SystemPrompt shape. */
export interface PromptSectionLike {
  name: string
  order: number
  text: string | ((context?: unknown) => string)
  interpolate?: boolean
}

/** Assembled prompt structure passed through `system-prompt/assemble`. */
export interface PromptAssemblyLike {
  sections: Array<{ name: string; text: string; interpolate?: boolean }>
  contexts: Array<{ name: string; text: string; interpolate?: boolean }>
  tools: unknown[]
  variables: Record<string, string | undefined>
}
