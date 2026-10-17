// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * LIVE REACTION: what Auma is doing right now, turned into pulses on the Pentora.
 *
 * The source is real: each session's `auraActivity` projection (settings/src/activity/projection.ts), folded by the
 * host from the durable session log and pushed to the face as events land. A descriptor becomes a pulse only when it
 * is NEW since this view first saw its session, so opening the page never replays history as if it were happening.
 *
 * PREVIEW ONLY: `previewTurn` scripts one turn's worth of pulses (marked `source: 'preview'`) so the preview, which has
 * no model key, can show the reaction. A node never runs it.
 */
import type { ActivityEvent, ActivityOrgan, AuraActivityState } from '../../activity/types.ts'

export interface LivePulse {
  readonly id: string
  readonly organ: ActivityOrgan
  /** When this view saw it (client clock), for the decay. */
  readonly at: number
  readonly label: string
  readonly outcome?: ActivityEvent['outcome']
  readonly session: string
  readonly source: 'session' | 'preview'
}

export interface LiveState {
  pulses: LivePulse[]
  /** A turn is open in some session (or the preview turn is playing). */
  working: boolean
}

const KEEP = 60
/** A pulse's energy halves in about 1.7 s. */
const DECAY_MS = 2500

/** Fold the sessions' projections into the live state; `baselines` remembers what was already there. */
export function absorbSessions(
  live: LiveState,
  baselines: Map<string, number>,
  sessions: readonly { readonly id: string; readonly title: string; readonly activity: AuraActivityState | undefined }[],
  now: number,
  previewWorking: boolean,
): LiveState {
  const fresh: LivePulse[] = []
  let working = previewWorking
  for (const session of sessions) {
    const state = session.activity
    if (state === undefined) continue
    if (state.turnOpen) working = true
    const seen = baselines.get(session.id)
    baselines.set(session.id, state.lastSeq)
    if (seen === undefined) continue
    for (const item of state.recent) {
      if (item.seq <= seen) continue
      fresh.push({
        id: `${session.id}:${String(item.seq)}:${item.type}:${item.label}`,
        organ: item.organ, at: now, label: item.label, session: session.title, source: 'session',
        ...(item.outcome === undefined ? {} : { outcome: item.outcome }),
      })
    }
  }
  if (fresh.length === 0 && working === live.working) return live
  return { pulses: [...live.pulses, ...fresh].slice(-KEEP), working }
}

/** Each organ's energy now (and `null` for activity that belongs to no organ, which wakes the whole figure). */
export function energyOf(live: LiveState, now: number): Map<ActivityOrgan, number> {
  const energy = new Map<ActivityOrgan, number>()
  for (const pulse of live.pulses) {
    const age = now - pulse.at
    if (age < 0 || age > DECAY_MS * 6) continue
    energy.set(pulse.organ, Math.min(1.6, (energy.get(pulse.organ) ?? 0) + Math.exp(-age / DECAY_MS)))
  }
  return energy
}

/** PREVIEW ONLY: one scripted turn, [delay ms, organ, label, outcome?]. */
export const PREVIEW_TURN: readonly (readonly [number, ActivityOrgan, string, ActivityEvent['outcome']?])[] = [
  [0, null, 'owner message'],
  [300, null, 'turn 1 opened'],
  [700, 'body', 'model call'],
  [1900, 'kira', 'kira_recall'],
  [2600, 'kira', 'kira_recall done', 'ok'],
  [3100, 'body', 'model call'],
  [4200, 'body', 'web_fetch'],
  [4700, 'body', 'web_fetch done', 'ok'],
  [5600, 'body', 'read_file: door asked the owner (ask:risky-class)', 'door-asked'],
  [5600, 'gate-aura', 'read_file: an ask for the owner\'s passkey', 'door-asked'],
  [6500, 'kira', 'kira_remember'],
  [7000, 'kira', 'kira_remember done', 'ok'],
  [7600, 'body', 'reply'],
  [8400, null, 'turn 1 completed'],
]
export const PREVIEW_TURN_MS = 8400
