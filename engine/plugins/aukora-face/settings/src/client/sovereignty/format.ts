// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/** Pure formatting for the Sovereignty view. Times are always relative to the snapshot's `now_ms`, never the clock. */
import type { OwnerRoute, ProposalState, Tone } from './model.ts'

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** "17 Oct, 13:56 UTC": unambiguous across the owner's devices. */
export function when(ms: number): string {
  const d = new Date(ms)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${String(d.getUTCDate())} ${MONTHS[d.getUTCMonth()] ?? ''}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())} UTC`
}

/** "4 min ago", "in 5 days". */
export function relative(ms: number, now: number): string {
  const delta = ms - now
  const abs = Math.abs(delta)
  const unit = abs < 60_000 ? ['sec', 1000] as const
    : abs < 3_600_000 ? ['min', 60_000] as const
      : abs < 86_400_000 ? ['h', 3_600_000] as const
        : ['day', 86_400_000] as const
  const n = Math.max(1, Math.round(abs / unit[1]))
  const word = unit[0] === 'day' && n !== 1 ? 'days' : unit[0]
  return delta < 0 ? `${String(n)} ${word} ago` : `in ${String(n)} ${word}`
}

/** Micro-dollars as dollars and cents ("$7.41"); sub-cent amounts keep four places. */
export function usd(microusd: number): string {
  const dollars = microusd / 1_000_000
  return dollars !== 0 && dollars < 0.01 ? `$${dollars.toFixed(4)}` : `$${dollars.toFixed(2)}`
}

/** The first 12 hex of a digest, for a row; the full value is always one click below. */
export function short(hex: string): string {
  return hex.length > 16 ? `${hex.slice(0, 12)}…` : hex
}

export function count(n: number): string {
  return n.toLocaleString('en-US')
}

/** Three plain groups for the owner, keeping the exact wire state on the pill. */
export function approvalGroup(state: ProposalState): 'waiting' | 'approved' | 'declined' {
  if (state === 'pending' || state === 'consumed') return 'waiting'
  if (state === 'applied') return 'approved'
  return 'declined'
}

export function stateTone(state: ProposalState): Tone {
  const group = approvalGroup(state)
  return group === 'waiting' ? 'gold' : group === 'approved' ? 'mint' : 'muted'
}

/** The owner-origin URL for a route; `null` routes open the owner origin's front page. */
export function ownerHref(origin: string, route: OwnerRoute | null): string {
  return `${origin}${route ?? '/'}`
}
