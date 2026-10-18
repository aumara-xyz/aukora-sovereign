// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Classify one tool call by the CHANNEL it uses, never by what a plugin says about itself.
//
// The only inputs are the tool name and the parsed arguments. Nothing here reads a tool definition, a description,
// a read-only hint or any other metadata a plugin controls. A name this table does not know is a crossing.
//
// Honest limits, kept in the open:
//  - A plugin can register a tool under a name this table calls local. The OS wall, not this table, is what stops
//    that tool from doing harm; the table only decides which calls the door must see.
//  - File tools are checked lexically (no symlink resolution): the kernel enforces the real workspace boundary.
//  - Shell and code tools are local: the process channel is confined by the OS wall and egress goes through the
//    door and the broker. This file does not parse shell text.

import { posix } from 'node:path'
import type { CallClass } from './types.ts'

/** File tools whose path arguments must stay inside the workspace. */
const FILE_TOOLS = new Set([
  'read', 'write', 'edit', 'str_replace_editor', 'read_image', 'glob', 'grep', 'working_directory', 'lsp',
])

/** Process and code tools: local by design (Auma executes inside the cage); their working directory is still checked. */
const EXEC_TOOLS = new Set(['bash', 'pwsh', 'job_kill', 'job_list', 'job_output', 'run_code'])

/** Session-internal tools: no file, process, network or persistence channel of their own. */
const SESSION_TOOLS = new Set([
  'todo_write', 'ask_user_question', 'create_goal', 'get_goal', 'update_goal', 'skill', 'load_workspace_dependencies',
  // The harness reviews the plan through userQuestions and changes only session plan state, never door grants.
  'exit_plan_mode',
  'cordis_inspect_list', 'cordis_inspect_query', 'list_agents', 'list_subagent_models', 'interrupt_agent', 'send_message',
  // Read-only queries over the engine's own persisted session history (DSH authorizes which sessions a caller may see).
  // Listed by name, never by prefix: a future `session_*` tool that writes must not inherit `local`.
  'session_search', 'session_event_search', 'session_trace', 'session_event_trace', 'session_event_read',
  // The Spatial face's Auma Canvas tools. Read returns, and render appends, one `auma-canvas/document` event on the
  // calling agent's own session (aukora-face apps/src/auma-canvas-tool.ts): no workspace file, process or network.
  // Explicit exact names, never the `auma_canvas_` prefix: a future canvas tool that does more must not inherit `local`.
  'auma_canvas_read', 'auma_canvas_render',
])

/** Argument names that carry a filesystem path (string) or a list of paths (array of strings). */
const PATH_KEYS = ['file_path', 'path', 'paths', 'cwd', 'workdir', 'directory', 'dir']

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function pathValues(args: Record<string, unknown>): string[] | undefined {
  const found: string[] = []
  for (const key of PATH_KEYS) {
    if (!Object.hasOwn(args, key)) continue
    const value = args[key]
    if (typeof value === 'string') found.push(value)
    else if (Array.isArray(value) && value.every(item => typeof item === 'string')) found.push(...(value as string[]))
    else return undefined
  }
  return found
}

/** Whether one path stays inside a workspace root, judged lexically. */
export function insideWorkspace(path: string, roots: readonly string[]): boolean {
  if (path.length === 0 || path.includes('\0') || path.startsWith('~')) return false
  const clean = posix.normalize(path)
  if (posix.isAbsolute(clean)) {
    return roots.some(root => clean === root || clean.startsWith(root.endsWith('/') ? root : `${root}/`))
  }
  return clean !== '..' && !clean.startsWith('../')
}

function pathsInside(args: unknown, roots: readonly string[]): boolean {
  if (!isPlainObject(args)) return false
  const paths = pathValues(args)
  if (paths === undefined) return false
  return paths.every(path => insideWorkspace(path, roots))
}

/** `present` names its files as `files[].path`, an array of objects, which the flat path keys cannot see. */
function presentPathsInside(args: unknown, roots: readonly string[]): boolean {
  if (!pathsInside(args, roots) || !isPlainObject(args)) return false
  const files = args['files']
  if (!Array.isArray(files) || files.length === 0) return false
  return files.every(file => isPlainObject(file) && typeof file['path'] === 'string' && insideWorkspace(file['path'], roots))
}

/** The class of one call. `local` means the call may run in this process; anything else must cross the door. */
export function classifyCall(tool: string, args: unknown, workspaceRoots: readonly string[]): CallClass {
  if (FILE_TOOLS.has(tool) || EXEC_TOOLS.has(tool)) {
    return pathsInside(args, workspaceRoots) ? 'local' : 'fs-outside'
  }
  if (tool === 'present') return presentPathsInside(args, workspaceRoots) ? 'local' : 'fs-outside'
  if (SESSION_TOOLS.has(tool)) return 'local'
  if (tool === 'web_fetch' || tool === 'web_search') return 'net'
  if (tool.startsWith('mcp__')) return 'mcp'
  if (tool === 'plugin_manager' || tool.startsWith('plugin_') || tool.startsWith('dsh_plugin')) return 'plugin'
  // A persistent terminal is a long-lived interactive process: what runs later (`terminal_send` text, a REPL, a
  // debugger) is not in the bytes judged when it was opened, so it is not `bash`. Every terminal_* tool crosses, by
  // prefix, so a new one fails closed. No executor exists for the class: it can be denied or asked, never allowed.
  if (tool.startsWith('terminal_')) return 'shell-interactive'
  // Only `kira_*`: DSH 0.2.1-alpha.5 registers no `memory_*` tool, so that prefix is not a memory channel (unknown).
  if (tool.startsWith('kira_')) return 'memory'
  if (tool === 'schedule_create' || tool === 'schedule_update') return 'persist'
  if (tool === 'schedule_list' || tool === 'schedule_delete') return 'local'
  // A workflow is a script: it can name a `provider` on any `agent()` call, in code this table does not parse and
  // cannot judge from arguments, so it is always an external-delegation crossing.
  if (tool === 'workflow') return 'delegate'
  // `ralph` runs fresh native children; the provider is deployment configuration, not a model argument. Same rule as
  // a subagent: an explicit `provider` argument would cross.
  if (tool === 'subagent' || tool === 'subagent_fork' || tool === 'ralph') {
    // A native in-process child runs the same pipeline for every tool it calls. A named provider is an external
    // CLI that runs its own tools outside this pipeline, so it crosses.
    return isPlainObject(args) && !Object.hasOwn(args, 'provider') ? 'local' : 'delegate'
  }
  return 'unknown'
}
