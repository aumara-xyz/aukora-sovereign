// SPDX-License-Identifier: AGPL-3.0-or-later
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { inspect } from 'node:util'
import { Fd3Link, GuestRefusal } from './fd3.mjs'
import { registerAdapter } from './llm-adapter.mjs'
import { registerTools } from './tools.mjs'
import { registerOrgansRoute } from './organs.mjs'
import { registerMemoryRoutes } from './memory.mjs'

export const name = 'sovereign-bridge'
export const inject = ['llm', 'tools']

/** One harness log message as one bounded stderr line (the supervisor keeps it as untrusted diagnostics). */
export function formatLogMessage(message) {
  const args = Array.isArray(message?.args) ? message.args : []
  const text = args.map(arg => arg instanceof Error ? (arg.stack ?? arg.message)
    : typeof arg === 'string' ? arg : inspect(arg, { depth: 4, breakLength: Infinity })).join(' ')
  return `harness ${String(message?.type)} ${String(message?.name)}: ${text}`.replace(/[\r\n\u2028\u2029]+/g, ' | ').slice(0, 4096) + '\n'
}

function exportLogs(ctx, level) {
  if (typeof ctx.logger?.exporter !== 'function') return
  const write = message => { process.stderr.write(formatLogMessage(message)) }
  for (const message of Array.isArray(ctx.logger.buffer) ? ctx.logger.buffer : []) {
    if (message.level <= level) write(message)
  }
  ctx.logger.exporter({ levels: { default: level }, export: write })
}

export async function apply(ctx, config = {}) {
  exportLogs(ctx, config.logLevel ?? 2)
  const internal = ctx.loader?.internal
  if (typeof internal?.import !== 'function' || !process.argv[1]) throw new GuestRefusal('guest:harness-loader-unavailable')
  const base = pathToFileURL(resolve(process.argv[1])).href
  const harness = await internal.import('@deepseek-ai/dsh-llm', base, {})
  if (typeof harness?.LlmAdapter !== 'function' || typeof harness?.LlmError !== 'function') {
    throw new GuestRefusal('guest:harness-llm-unavailable')
  }
  ctx.effect(() => {
    const link = new Fd3Link({ timeoutMs: config.timeoutMs ?? 30_000 })
    try {
      registerAdapter(ctx, link, config, harness)
      registerTools(ctx, link, config)
      registerOrgansRoute(ctx, link)
      registerMemoryRoutes(ctx, link)
    } catch (error) {
      link.close()
      throw error
    }
    return () => link.close()
  }, 'sovereign-bridge FD 3')
}
