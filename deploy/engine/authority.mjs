// SPDX-License-Identifier: AGPL-3.0-or-later
// The launcher's positive load check. This is an honest-loader invariant, not a boundary against hostile code
// in the same process. The OS wall and the root-owned closure remain the boundary.
export const STARTUP_MS = 30_000
export const HEARTBEAT_MS = 10_000

export function priorRefusal(authority, previous) {
  if (previous?.set_hash !== authority.set_hash || previous?.release !== authority.release) return undefined
  return ['authority-runtime-check', 'authority-plugin-inactive', 'authority-plugin-missing',
    'authority-plugin-timeout', 'profile-plugin-disabled'].includes(previous.reason) ? previous.reason : 'authority-runtime-check'
}

export class AuthorityWatch {
  constructor(required, { now = () => performance.now(), ready, refuse }) {
    if (!Array.isArray(required) || required.length > 256 || !required.includes('@aukora/door')
      || !required.includes('@aukora/kira') || required.some(name => typeof name !== 'string')
      || new Set(required).size !== required.length) throw new Error('authority-runtime-config')
    this.required = [...required].sort()
    this.now = now
    this.ready = ready
    this.refuse = refuse
    this.started = now()
    this.seen = undefined
    this.failed = false
    this.stopped = false
  }

  close() { this.stopped = true }

  fail(reason) {
    if (this.failed || this.stopped) return
    this.failed = true
    this.refuse(reason)
  }

  message(value) {
    if (this.failed || this.stopped || value?.type !== 'aukora-authority') return
    if (value.v !== 1 || !Array.isArray(value.plugins)
      || JSON.stringify([...value.plugins].sort()) !== JSON.stringify(this.required)) {
      this.fail('authority-runtime-check')
    } else if (value.state === 'refused') {
      this.fail(value.reason === 'authority-runtime-check' ? value.reason : 'authority-plugin-inactive')
    } else if (value.state === 'ready') {
      this.seen = this.now()
      this.ready()
    } else {
      this.fail('authority-runtime-check')
    }
  }

  diagnostic(line) {
    if (/(?:^|\n)dsh: disabling profile plugin(?:\s|$)/i.test(line)) this.fail('profile-plugin-disabled')
  }

  tick() {
    if (this.seen === undefined) {
      if (this.now() - this.started >= STARTUP_MS) this.fail('authority-plugin-missing')
    } else if (this.now() - this.seen >= HEARTBEAT_MS) {
      this.fail('authority-plugin-timeout')
    }
  }
}
