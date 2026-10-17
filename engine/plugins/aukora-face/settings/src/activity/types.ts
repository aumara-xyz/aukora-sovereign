// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * Aura's live activity, folded from the durable session log (content-free: no message text, no tool arguments, no
 * tool results, no approval reasons). It is what makes the Pentora react while Auma works. Shared by the host
 * projection (`projection.ts`) and the client surface.
 */

/** The organ a session event belongs to, or `null` when it belongs to none (the owner speaking, a session tool). */
export type ActivityOrgan = 'aumlok' | 'gate-aura' | 'kira' | 'network' | 'body' | null

/** The door's class of a tool, judged from the tool's NAME only (the same table as aukora-door's classify.ts). */
export type ToolClass =
  | 'local-file' | 'local-exec' | 'session' | 'net' | 'mcp' | 'plugin' | 'memory' | 'persist' | 'delegate'
  | 'shell-interactive' | 'unknown'

/** One content-free descriptor of a session event. */
export interface ActivityEvent {
  readonly seq: number
  /** Durable event time, Unix ms. */
  readonly time: number
  /** Exact session event type. */
  readonly type: string
  readonly organ: ActivityOrgan
  /** A short label: a tool name, a class, an outcome; never content. */
  readonly label: string
  /** For a tool result: completed, failed, refused by the door, or asked of the owner by the door. */
  readonly outcome?: 'ok' | 'error' | 'door-refused' | 'door-asked'
}

export interface AuraActivityState {
  readonly version: 1
  /** True between `turn/start` and `turn/end`: Auma is at work in this session. */
  readonly turnOpen: boolean
  readonly turns: number
  readonly lastSeq: number
  /** The newest descriptors, oldest first (bounded). */
  readonly recent: readonly ActivityEvent[]
  /** Open tool calls by call id -> tool name, so a result can be named (bounded). */
  readonly open: Readonly<Record<string, string>>
}

declare module '@deepseek-ai/dsh-session-projection/types' {
  interface SessionProjectionStateMap {
    /** Aura's content-free live activity for the Pentora. */
    auraActivity: AuraActivityState
  }

  interface SessionProjectionMap {
    /** Aura's content-free live activity for the Pentora. */
    auraActivity: AuraActivityState
  }
}
