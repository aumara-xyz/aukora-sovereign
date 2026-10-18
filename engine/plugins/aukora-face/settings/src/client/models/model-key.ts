// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * THE OWNER'S DEEPSEEK KEY, AS THE MODELS PAGE MAY SEE IT (deploy/engine/NODE.md section 7).
 *
 * This page runs on the engine origin (`engine.<shell>`), where everything is engine-served script. So it never holds a
 * field for the key: Edit opens the node's own key page on the SHELL origin (`https://<shell>/engine/model-key`) in a
 * new tab, and the key goes from there to the model broker outside the wall. What this does NOT do: stop the engine
 * from drawing a lookalike status or a lookalike key form of its own on this origin (it can read the state below
 * like any script here). It cannot change the key or its approval; a key typed into a lookalike is another matter,
 * which is why the key page tells the owner to check the address bar. What comes back here is only the
 * broker's standing, read from `GET /.aukora/model-key`, which the supervisor's engine proxy answers itself (the engine
 * never sees the request): `{state}` and nothing else. No character of the key, its digest or its fingerprint ever
 * reaches this engine-served script (NODE.md O15 keeps even the provider's last-four out of the engine).
 *
 * Pure functions only (no React, no DOM beyond what is passed in), so `node --test` runs them as they are.
 */

/** The proxy's own route on the engine origin. */
export const MODEL_KEY_STATUS_PATH = '/.aukora/model-key'
/** The shell origin's key page. */
export const MODEL_KEY_PAGE_PATH = '/engine/model-key'
/** Tells the key page it was opened from here, so its "Back to Auma" closes the tab instead of leaving it. */
export const FROM_MODELS = '#from=models'
/** How often the row re-reads the standing while the page is open (and at once when the tab is shown again). */
export const POLL_MS = 5_000

/** The broker's answer, or what the page can honestly say when there is none. */
export type ModelKeyStanding =
  | { readonly state: 'none' }
  | { readonly state: 'awaiting-approval' }
  | { readonly state: 'not-approved' }
  | { readonly state: 'approved' }
  /** 404: this composition has no broker in front of it (not a node). */
  | { readonly state: 'unavailable' }
  /** Not read yet, or the node was busy / the reply was not one this page reads. */
  | { readonly state: 'unknown' }

const BROKER_STATES = new Set(['none', 'awaiting-approval', 'not-approved', 'approved'])

/**
 * Read the proxy's reply strictly: exactly `{state}` with a known state. Anything else (an extra member included) is
 * `unknown`, never a guess.
 */
export function parseStanding(status: number, body: unknown): ModelKeyStanding {
  if (status === 404) return { state: 'unavailable' }
  if (status !== 200 || typeof body !== 'object' || body === null || Array.isArray(body)) return { state: 'unknown' }
  const record = body as Record<string, unknown>
  const keys = Object.keys(record).sort().join(',')
  if (keys === 'state' && typeof record.state === 'string' && BROKER_STATES.has(record.state)) {
    return { state: record.state } as ModelKeyStanding
  }
  return { state: 'unknown' }
}

/**
 * The shell origin for this engine-origin page: the node serves the engine at `engine.` plus the shell's host
 * (NODE.md section 5). Anywhere else (the local preview) there is no shell, and the link goes to a name that cannot
 * resolve: never to this page's own origin, which is the engine's.
 */
export function shellOrigin(place: { readonly protocol: string; readonly host: string } | undefined): string {
  if (place === undefined || !place.host.startsWith('engine.') || place.host.length <= 'engine.'.length) {
    return 'https://node.invalid'
  }
  return `${place.protocol}//${place.host.slice('engine.'.length)}`
}

/** Where Edit goes: the shell's key page, marked as opened from the Models page. */
export function keyPageHref(place: { readonly protocol: string; readonly host: string } | undefined): string {
  return `${shellOrigin(place)}${MODEL_KEY_PAGE_PATH}${FROM_MODELS}`
}

export type Tone = 'mint' | 'blue' | 'violet' | 'gold' | 'red' | 'muted'

/** What the DeepSeek row shows for a standing: the dot's tone, the pill, the one-line summary, the action's words, and
 * the line under the action (what a change means for Auma, said plainly). */
export interface RowView {
  readonly tone: Tone
  readonly pill: string
  readonly summary: string
  readonly action: string
  readonly note: string
  /** False when there is nothing to open (no node behind this page). */
  readonly actionable: boolean
}

/** A new key takes over as soon as its card is up; until a key is approved, model calls are refused (not queued). */
export const WAITING_NOTE = "While your new key waits for approval, Auma can't reach the model. If you decline it, enter a key again."
export const NOT_APPROVED_NOTE = "Auma can't reach the model until a key is approved. The old key doesn't come back by itself: enter a key again."

export function rowView(standing: ModelKeyStanding, shell = 'your node'): RowView {
  const opens = `Opens your key page at ${shell}. Type your key only there.`
  switch (standing.state) {
    case 'none':
      return { tone: 'muted', pill: 'No key', summary: 'Auma has no DeepSeek key yet', action: 'Add your DeepSeek key', note: opens, actionable: true }
    case 'awaiting-approval':
      return { tone: 'gold', pill: 'Waiting for you', summary: "Auma can't reach the model until you approve", action: 'Edit', note: WAITING_NOTE, actionable: true }
    case 'not-approved':
      return { tone: 'red', pill: 'Not approved', summary: "Auma can't reach the model: enter a key again", action: 'Edit', note: NOT_APPROVED_NOTE, actionable: true }
    case 'approved':
      return { tone: 'mint', pill: 'Approved', summary: 'Held by your node, outside the engine', action: 'Edit', note: `${opens} A new key stops Auma's model calls until you approve it.`, actionable: true }
    case 'unavailable':
      return { tone: 'muted', pill: 'Not on this node', summary: 'No model broker answers here', action: 'Edit', note: '', actionable: false }
    case 'unknown':
      return { tone: 'muted', pill: 'Reading…', summary: 'Asking your node', action: 'Edit', note: opens, actionable: true }
  }
}
