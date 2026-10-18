// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The node's launcher waits for positive activation, rather than treating a successful DSH boot as proof that its
// authority plugins loaded. DSH may disable an incompatible profile row and keep running. Cordis' live Loader
// entries are the same inventory app-boot inspects; ACTIVE is state 2 in the pinned harness.

const REQUIRED_ENV = 'AUKORA_AUTHORITY_PLUGINS'
const ACTIVE = 2
const NAME = /^(?:@[-a-z0-9][-a-z0-9._]*\/)?[-a-z0-9][-a-z0-9._]*$/

interface EntryLike {
  readonly options: { readonly name: string }
  readonly disabled: boolean
  readonly fiber?: { readonly state: number }
}

interface AuthorityContext {
  readonly loader: { entries(): Iterable<EntryLike> }
  effect(effect: () => () => void, label: string): unknown
}

export interface AuthorityMessage {
  type: 'aukora-authority'
  v: 1
  state: 'ready' | 'refused' | 'stopping'
  plugins: string[]
  reason?: 'authority-plugin-inactive' | 'authority-runtime-check'
}

interface AuthorityProcess {
  readonly env: Record<string, string | undefined>
  send?: (message: AuthorityMessage) => unknown
}

type Schedule = (check: () => void) => () => void

function schedule(check: () => void): () => void {
  const timer = setInterval(check, 1_000)
  timer.unref()
  return () => clearInterval(timer)
}

/** Optional outside the node; a configured node must have its launcher-owned IPC channel and a valid package set. */
export function watchAuthority(ctx: AuthorityContext, parent: AuthorityProcess = process, every: Schedule = schedule): void {
  const encoded = parent.env[REQUIRED_ENV]
  if (encoded === undefined) return
  let required: unknown
  try { required = JSON.parse(encoded) } catch { throw new Error('authority-runtime-check: invalid required plugin set') }
  if (!Array.isArray(required) || required.length < 2 || required.length > 256
    || required.some(name => typeof name !== 'string' || name.length > 214 || !NAME.test(name))
    || new Set(required).size !== required.length
    || !required.includes('@aukora/door') || !required.includes('@aukora/kira')
    || typeof parent.send !== 'function') {
    throw new Error('authority-runtime-check: required plugins or launcher IPC missing')
  }
  const plugins = [...required].sort() as string[]
  const send = parent.send.bind(parent)
  let ready = false
  let stopped = false
  const report = (state: AuthorityMessage['state'], reason?: AuthorityMessage['reason']) => {
    try { send({ type: 'aukora-authority', v: 1, state, plugins, ...(reason === undefined ? {} : { reason }) }) }
    catch { stopped = true }
  }
  const refuse = (reason: AuthorityMessage['reason']) => {
    if (stopped) return
    stopped = true
    report('refused', reason)
  }
  const check = () => {
    if (stopped) return
    try {
      const entries = [...ctx.loader.entries()]
      const active = plugins.every(name => entries.some(entry => entry.options.name === name && !entry.disabled && entry.fiber?.state === ACTIVE))
      if (active) {
        ready = true
        report('ready')
      } else if (ready) {
        refuse('authority-plugin-inactive')
      }
    } catch {
      refuse('authority-runtime-check')
    }
  }
  ctx.effect(() => {
    const cancel = every(check)
    check()
    return () => {
      cancel()
      // Disposal is also the harness's crash path (installFailLoud disposes the root fiber, then exits 1). Saying
      // "stopping" makes the launcher stop serving at once without a terminal refusal, so a crash retries; a harness
      // that stays alive without this plugin is still stopped by the launcher's heartbeat timeout.
      if (stopped) return
      stopped = true
      report('stopping')
    }
  }, 'authority plugin monitor')
}
