// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * AURA'S LIVE ACTIVITY: a content-free session projection, the successor of Prime's `auraCoherence` adapter.
 *
 * It folds only event metadata the harness already records durably, and maps each event to the organ that does that
 * work, so the Pentora can react while Auma works. Nothing here is guessed or made up:
 *   turn/start, turn/end        Auma at work in a session (no organ: the whole figure wakes and settles)
 *   step/start, step/end        one model call through the broker                      -> Body
 *   assistant/message           her reply arrived (the broker's stream settled)          -> Body
 *   tool/call by NAME           kira_* -> Kira; files, shell, net, mcp, plugin, persist, delegate, interactive
 *                               terminal, unknown -> Body (the cage and the door); session tools -> none
 *   tool/result                 named through its call; a result the door authored (error name AukoraDoorRefusal)
 *                               is "refused by the door", or "asked of the owner" when its code is `ask:*`
 *                               (a door ask becomes a gate proposal)                     -> Body, and Gate & Aura
 *   approval/asked, /decided    the harness's own approval prompt                         -> Gate & Aura
 *   approval/policy, permission/preset   approval posture                                 -> Gate & Aura
 *   sandbox/mode                the cage's mode                                           -> Body
 *   user/message                the owner spoke (no organ)
 * AUMLOK and Network have no session events: the view says "not connected yet" for their live activity.
 */
import { z } from 'zod'
import type { SessionEvent } from '@deepseek-ai/dsh-session'
import type { ProjectionDefinition } from '@deepseek-ai/dsh-session-projection'
import type {} from '@deepseek-ai/dsh-permission-presets'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type {} from '@deepseek-ai/dsh-user-approval'
import type { ActivityEvent, ActivityOrgan, AuraActivityState, ToolClass } from './types.ts'

const RECENT_LIMIT = 40
const OPEN_LIMIT = 32
const DOOR_REFUSAL = 'AukoraDoorRefusal'

const FILE_TOOLS = new Set(['read', 'write', 'edit', 'str_replace_editor', 'read_image', 'glob', 'grep', 'working_directory', 'lsp', 'present'])
const EXEC_TOOLS = new Set(['bash', 'pwsh', 'job_kill', 'job_list', 'job_output', 'run_code'])
const SESSION_TOOLS = new Set([
  'todo_write', 'ask_user_question', 'create_goal', 'get_goal', 'update_goal', 'skill', 'load_workspace_dependencies',
  'cordis_inspect_list', 'cordis_inspect_query', 'list_agents', 'list_subagent_models', 'interrupt_agent', 'send_message',
  'session_search', 'session_event_search', 'session_trace', 'session_event_trace', 'session_event_read',
  'auma_canvas_read', 'auma_canvas_render', 'schedule_list', 'schedule_delete', 'subagent', 'subagent_fork', 'ralph',
])

/** The door's class of a tool by name alone (aukora-door/src/classify.ts; arguments are not kept here). */
export function toolClassOf(name: string): ToolClass {
  if (FILE_TOOLS.has(name)) return 'local-file'
  if (EXEC_TOOLS.has(name)) return 'local-exec'
  if (SESSION_TOOLS.has(name)) return 'session'
  if (name === 'web_fetch' || name === 'web_search') return 'net'
  if (name.startsWith('mcp__')) return 'mcp'
  if (name === 'plugin_manager' || name.startsWith('plugin_') || name.startsWith('dsh_plugin')) return 'plugin'
  if (name.startsWith('terminal_')) return 'shell-interactive'
  if (name.startsWith('kira_')) return 'memory'
  if (name === 'schedule_create' || name === 'schedule_update') return 'persist'
  if (name === 'workflow') return 'delegate'
  return 'unknown'
}

function organOfTool(name: string): ActivityOrgan {
  const cls = toolClassOf(name)
  if (cls === 'memory') return 'kira'
  if (cls === 'session') return null
  return 'body'
}

const eventSchema = z.object({
  seq: z.number().int().nonnegative(),
  time: z.number().nonnegative(),
  type: z.string(),
  organ: z.union([z.literal('aumlok'), z.literal('gate-aura'), z.literal('kira'), z.literal('network'), z.literal('body'), z.null()]),
  label: z.string(),
  outcome: z.union([z.literal('ok'), z.literal('error'), z.literal('door-refused'), z.literal('door-asked')]).optional(),
}).strict()

const stateSchema: z.ZodType<AuraActivityState> = z.object({
  version: z.literal(1),
  turnOpen: z.boolean(),
  turns: z.number().int().nonnegative(),
  lastSeq: z.number().int().min(-1),
  recent: z.array(eventSchema).max(RECENT_LIMIT),
  open: z.record(z.string(), z.string()),
}).strict() as z.ZodType<AuraActivityState>

export function emptyAuraActivity(): AuraActivityState {
  return { version: 1, turnOpen: false, turns: 0, lastSeq: -1, recent: [], open: {} }
}

/** Fold one durable event. Unknown event types change nothing but the sequence. */
export function applyAuraActivity(state: AuraActivityState, event: SessionEvent): AuraActivityState {
  const at = (organ: ActivityOrgan, label: string, outcome?: ActivityEvent['outcome']): ActivityEvent =>
    outcome === undefined ? { seq: event.seq, time: event.time, type: event.type, organ, label } : { seq: event.seq, time: event.time, type: event.type, organ, label, outcome }
  const push = (next: Partial<AuraActivityState>, ...items: ActivityEvent[]): AuraActivityState =>
    ({ ...state, ...next, lastSeq: event.seq, recent: [...state.recent, ...items].slice(-RECENT_LIMIT) })
  switch (event.type) {
    case 'turn/start':
      return push({ turnOpen: true, turns: state.turns + 1 }, at(null, `turn ${String(event.data.turn)} opened`))
    case 'turn/end':
      return push({ turnOpen: false, open: {} }, at(null, `turn ${String(event.data.turn)} ${event.data.reason.kind}`))
    case 'step/start':
      return push({}, at('body', 'model call'))
    case 'step/end':
      return push({}, at('body', 'model call closed'))
    case 'assistant/message':
      return push({}, at('body', event.data.interrupted === true ? 'reply interrupted' : 'reply'))
    case 'user/message':
      return push({}, at(null, event.data.source.kind === 'user' ? 'owner message' : 'context entered'))
    case 'tool/call': {
      const ids = Object.keys(state.open)
      const kept = ids.length >= OPEN_LIMIT ? Object.fromEntries(ids.slice(1).map(id => [id, state.open[id] ?? ''])) : state.open
      return push({ open: { ...kept, [String(event.data.callId)]: event.data.name } }, at(organOfTool(event.data.name), event.data.name))
    }
    case 'tool/result': {
      const callId = String(event.data.message.source.callId)
      const name = state.open[callId] ?? 'tool'
      const { [callId]: _closed, ...open } = state.open
      const error = event.data.error
      if (error !== undefined && error.name === DOOR_REFUSAL) {
        const asked = error.code.startsWith('ask:')
        const door = at('body', `${name}: door ${asked ? 'asked the owner' : 'refused'} (${error.code})`, asked ? 'door-asked' : 'door-refused')
        return asked ? push({ open }, door, at('gate-aura', `${name}: an ask for the owner's passkey`, 'door-asked')) : push({ open }, door)
      }
      return push({ open }, at(organOfTool(name), `${name} ${error === undefined ? 'done' : 'failed'}`, error === undefined ? 'ok' : 'error'))
    }
    case 'approval/asked':
      return push({}, at('gate-aura', `harness approval asked: ${event.data.toolName}`))
    case 'approval/decided':
      return push({}, at('gate-aura', `harness approval ${event.data.outcome}`))
    case 'approval/policy':
      return push({}, at('gate-aura', `approval policy ${event.data.policy}`))
    case 'permission/preset':
      return push({}, at('gate-aura', `preset ${event.data.preset}`))
    case 'sandbox/mode':
      return push({}, at('body', `sandbox ${event.data.mode}`))
    default:
      return { ...state, lastSeq: event.seq }
  }
}

/** Registered on `ctx.sessionProjections` by the settings host plugin. */
export const auraActivityProjectionDefinition = {
  key: 'auraActivity',
  stateVersion: 1,
  stateSchema,
  init: emptyAuraActivity,
  apply: applyAuraActivity,
  wire: { viewSchema: stateSchema, view: state => state },
} satisfies ProjectionDefinition<'auraActivity', AuraActivityState>
