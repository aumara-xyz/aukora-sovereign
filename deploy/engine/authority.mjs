// SPDX-License-Identifier: AGPL-3.0-or-later
// The launcher's positive load check. This is an honest-loader invariant, not a boundary against hostile code
// in the same process. The OS wall and the root-owned closure remain the boundary.
export const STARTUP_MS = 30_000
export const HEARTBEAT_MS = 10_000

export function priorRefusal(authority, previous) {
  if (previous?.set_hash !== authority.set_hash || previous?.release !== authority.release) return undefined
  // Older launchers persisted silence as a terminal refusal. It proves no plugin loss, so a fresh process may retry.
  if (['authority-plugin-missing', 'authority-plugin-timeout'].includes(previous.reason)) return undefined
  return ['authority-runtime-check', 'authority-plugin-inactive', 'profile-plugin-disabled'].includes(previous.reason)
    ? previous.reason : 'authority-runtime-check'
}

export class AuthorityWatch {
  constructor(required, { now = () => performance.now(), ready, refuse, pause = () => {} }) {
    if (!Array.isArray(required) || required.length > 256 || !required.includes('@aukora/door')
      || !required.includes('@aukora/kira') || required.some(name => typeof name !== 'string')
      || new Set(required).size !== required.length) throw new Error('authority-runtime-config')
    this.required = [...required].sort()
    this.now = now
    this.ready = ready
    this.refuse = refuse
    this.pause = pause
    this.started = now()
    this.seen = undefined
    this.failed = false
    this.stopped = false
    this.paused = false
  }

  close() { this.stopped = true }

  fail(reason, terminal = true) {
    if (this.failed || this.stopped) return
    this.failed = true
    this.refuse(reason, terminal)
  }

  message(value) {
    if (this.failed || this.stopped || value?.type !== 'aukora-authority') return
    if (value.v !== 1 || !Array.isArray(value.plugins)
      || JSON.stringify([...value.plugins].sort()) !== JSON.stringify(this.required)) {
      this.fail('authority-runtime-check')
    } else if (value.state === 'refused') {
      this.fail(value.reason === 'authority-runtime-check' ? value.reason : 'authority-plugin-inactive')
    } else if (value.state === 'ready' && !this.paused) {
      // A delayed timer must not let an overdue heartbeat revive this process before tick() gets CPU time.
      this.tick()
      if (this.failed || this.stopped) return
      this.seen = this.now()
      this.ready()
    } else if (value.state === 'ready') {
      // Ignored once stopping: the same process is never admitted again.
    } else if (value.state === 'stopping') {
      // The plugin is being disposed: a supervisor stop, or the harness's crash path before it exits 1. Stop serving
      // now, but latch nothing: a process that exits retries on its next start, and one that stays alive without
      // its authority plugins is stopped by tick(). Only a fresh process may prove readiness again.
      this.paused = true
      this.pause()
    } else {
      this.fail('authority-runtime-check')
    }
  }

  diagnostic(line) {
    const disabled = /(?:^|\n)dsh: disabling profile plugin row ["']([^"']+)["']/ig
    for (const [, row] of line.matchAll(disabled)) {
      if (this.required.some(name => row === name || row === name.replace(/^@/, '').replace('/', '-'))) {
        this.fail('profile-plugin-disabled')
      }
    }
  }

  tick() {
    if (this.seen === undefined) {
      if (this.now() - this.started >= STARTUP_MS) this.fail('authority-plugin-missing', false)
    } else if (this.now() - this.seen >= HEARTBEAT_MS) {
      this.fail('authority-plugin-timeout', false)
    }
  }
}
