// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * AURA COHERENCE ON THE PENTORA: the shapes the view renders.
 *
 * The node's living state is canon's health snapshot (`crates/canon/src/health.rs` `HealthSnapshot`): 110 cells, each
 * Verified, Undetermined or Failed with a reason. They are not drawn on a made-up mapping: canon pins them to the
 * Pentora. Organ i owns cube i of `crates/pentora/vectors/geometry_index_table_v1.json`; the organ's 18 private checks
 * are its cube's 12 edge midpoints and 6 face centres; the 20 shared corners are the compound's 20 vertices, each
 * owned by the two organs whose cubes meet there. `tables.ts` (generated) carries both pinned tables.
 *
 * A health cell is NOT a Pentora fingerprint trit (pentora.display.v1, NORTH-STAR row 55): this view draws health
 * cells on the geometry and never shows, derives or implies a fingerprint.
 *
 * READ-ONLY, LIKE SOVEREIGNTY. A snapshot comes from the preview's stub only in the preview; on a node the view reads
 * nothing yet (the engine origin has no health route), so every cell is Undetermined with reason `missing`, which is
 * exactly what canon calls an absent report, and the view says "Not connected yet".
 */
import type { IconName, Tone } from '@aukora/face-layout/client'
import { CHECKS, CORNERS, CUBES, type OrganWire } from './tables.ts'

export const AURA_SURFACE = 'aura-coherence'

/** canon `Cell` wire names. */
export type CellState = 'verified' | 'undetermined' | 'failed'
/** canon `HealthReason` wire names. */
export type HealthReason =
  | 'satisfied' | 'unwritten' | 'missing' | 'not-checked' | 'unreachable' | 'stale' | 'disagreement'
  | 'invariant-failed' | 'context-mismatch' | 'invalid-evidence'

/** One cell as the view shows it: the state, why, and when it was last observed (null when never). */
export interface CellReport {
  readonly cell: CellState
  readonly reason: HealthReason
  readonly observed_at_ms: number | null
}

/** A health snapshot, reduced to what the view needs (canon `HealthSnapshot` v1). */
export interface AuraHealthView {
  readonly source: 'stub' | 'node'
  readonly epoch: number
  readonly sequence: number
  readonly observed_at_ms: number
  /** 90 private cells, organ order then check index (canon CHECKS order). */
  readonly private: readonly CellReport[]
  /** 20 corner cells, corner index order (canon CORNERS order). */
  readonly corners: readonly CellReport[]
}

export const ORGANS: readonly OrganWire[] = ['aumlok', 'gate-aura', 'kira', 'network', 'body']

/** Each organ's name, what canon says it covers, its colour on the Pentora and its glyph. */
export const ORGAN_FACTS: Readonly<Record<OrganWire, { readonly title: string; readonly covers: string; readonly tone: Tone; readonly icon: IconName }>> = {
  'aumlok': { title: 'AUMLOK', covers: 'identity, root epochs, passkeys, delegated keys', tone: 'gold', icon: 'aumlok' },
  'gate-aura': { title: 'Gate & Aura', covers: 'exact-byte approvals, consumption, the append-only record', tone: 'blue', icon: 'approvals' },
  'kira': { title: 'Kira', covers: 'encrypted memory, cited recall, disclosure permissions', tone: 'violet', icon: 'memory' },
  'network': { title: 'Network', covers: 'contacts, devices, transport, relationship evidence', tone: 'mint', icon: 'devices' },
  'body': { title: 'Body', covers: 'supervisor, cage, frontdoor, door, broker, release, immune', tone: 'muted', icon: 'releases' },
}

/** How long after an observation its edge still pulses: recent activity. */
export const PULSE_WINDOW_MS = 20_000

/** On a node, before any route: every report absent, which canon reduces to Undetermined (reason `missing`). */
export function absentHealth(): AuraHealthView {
  const absent: CellReport = { cell: 'undetermined', reason: 'missing', observed_at_ms: null }
  return { source: 'node', epoch: 0, sequence: 0, observed_at_ms: 0, private: CHECKS.map(() => absent), corners: CORNERS.map(() => absent) }
}

export interface Tally { readonly verified: number; readonly undetermined: number; readonly failed: number }

function tally(cells: readonly CellReport[]): Tally {
  let verified = 0, undetermined = 0, failed = 0
  for (const report of cells) {
    if (report.cell === 'verified') verified++
    else if (report.cell === 'failed') failed++
    else undetermined++
  }
  return { verified, undetermined, failed }
}

/** An organ's 18 private reports, in check order. */
export function privateOf(view: AuraHealthView, organ: OrganWire): CellReport[] {
  const start = ORGANS.indexOf(organ) * 18
  return view.private.slice(start, start + 18)
}

/** The corners an organ shares (8), with their canon index. */
export function cornersOf(organ: OrganWire): number[] {
  return CORNERS.filter(corner => corner.owners.includes(organ)).map(corner => corner.index)
}

export function organTally(view: AuraHealthView, organ: OrganWire): Tally {
  return tally([...privateOf(view, organ), ...cornersOf(organ).map(index => view.corners[index - 1]!)])
}

export function wholeTally(view: AuraHealthView): Tally {
  return tally([...view.private, ...view.corners])
}

/** The calm/alert reading, from the cells alone: any failure is an alert; all verified is calm; otherwise partly known. */
export function postureOf(view: AuraHealthView): { readonly word: string; readonly tone: Tone } {
  if (view.source === 'node' && view.sequence === 0) return { word: 'Not connected yet', tone: 'muted' }
  const t = wholeTally(view)
  if (t.failed > 0) return { word: `Alert · ${String(t.failed)} failed`, tone: 'red' }
  if (t.undetermined > 0) return { word: `Partly known · ${String(t.undetermined)} undetermined`, tone: 'gold' }
  return { word: 'Calm · all 110 verified', tone: 'mint' }
}

/** Where a private check sits on its cube, in words. */
export function placeOf(organ: OrganWire, index: number): string {
  const cube = CUBES[ORGANS.indexOf(organ)]!
  const global = cube.private[index - 1]!
  const edge = cube.edgeMidpoints.indexOf(global)
  return edge >= 0 ? `edge ${String(edge + 1)} of 12 (its midpoint)` : `face ${String(cube.faceCentres.indexOf(global) + 1)} of 6 (its centre)`
}

/** The view's words. English in this preview, like Sovereignty. */
export const AURA_COPY = {
  eyebrow: 'Living system state',
  title: 'Aura Coherence',
  readOnly: 'Read-only',
  stub: 'Preview data',
  notConnected: 'Not connected yet',
  emptyLead: 'Not connected yet. This node does not serve its health snapshot to the view yet; nothing here is made up. These are the checks canon registers, and each will light when its report arrives.',
  footnote: 'This view only reads. Health cells are not the Pentora fingerprint; nothing here grants anything.',
} as const
