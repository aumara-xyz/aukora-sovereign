// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * ************************************************************************************************************
 * STUB DATA, PREVIEW ONLY. NOTHING IN THIS FILE IS READ FROM A NODE.
 * ************************************************************************************************************
 *
 * Read only when `isPreviewComposition()` says so (the one preview switch; a node never has it). The states are made
 * up but shaped like canon's: most cells verified, a few undetermined for an honest reason (stale, not checked,
 * unreachable), one failed because its observer is unwritten (canon: "explicitly unwritten observers reduce to
 * Failed"). `stepStub` re-observes one verified cell every few seconds so the preview shows what recent activity looks
 * like. Wiring is a swap: a reader of the node's `health.snapshot` returns the same `AuraHealthView`.
 */
import type { AuraHealthView, CellReport } from './model.ts'
import { CHECKS, CORNERS } from './tables.ts'

/** Private-check positions (0-based, CHECKS order) that are undetermined in the stub, and why. */
const UNDETERMINED: Readonly<Record<number, CellReport['reason']>> = {
  5: 'stale', 23: 'not-checked', 40: 'unreachable', 41: 'unreachable', 61: 'stale', 77: 'not-checked',
}
/** body #10, the pinned WASM cell re-execution: its observer is not written yet. */
const FAILED: Readonly<Record<number, CellReport['reason']>> = { 81: 'unwritten' }
/** Corner positions (0-based) undetermined in the stub. */
const CORNER_UNDETERMINED: Readonly<Record<number, CellReport['reason']>> = { 11: 'stale', 15: 'not-checked' }

export function readAuraStub(now: number): AuraHealthView {
  const ago = (k: number) => now - 2_000 - ((k * 7919) % 55_000)
  return {
    source: 'stub',
    epoch: 3,
    sequence: 4182,
    observed_at_ms: now - 1_000,
    private: CHECKS.map((_, k): CellReport => {
      const failed = FAILED[k]
      if (failed !== undefined) return { cell: 'failed', reason: failed, observed_at_ms: ago(k) }
      const unknown = UNDETERMINED[k]
      if (unknown !== undefined) return { cell: 'undetermined', reason: unknown, observed_at_ms: unknown === 'stale' ? now - 600_000 : null }
      return { cell: 'verified', reason: 'satisfied', observed_at_ms: ago(k) }
    }),
    corners: CORNERS.map((_, k): CellReport => {
      const unknown = CORNER_UNDETERMINED[k]
      if (unknown !== undefined) return { cell: 'undetermined', reason: unknown, observed_at_ms: unknown === 'stale' ? now - 600_000 : null }
      return { cell: 'verified', reason: 'satisfied', observed_at_ms: ago(k + 90) }
    }),
  }
}

/** One more observation: a verified private cell is seen again now (a stable, wandering order). */
export function stepStub(view: AuraHealthView, now: number, step: number): AuraHealthView {
  const k = (step * 37 + 11) % 90
  const target = view.private[k]
  if (target === undefined || target.cell !== 'verified') return { ...view, sequence: view.sequence + 1 }
  const next = view.private.slice()
  next[k] = { ...target, observed_at_ms: now }
  return { ...view, sequence: view.sequence + 1, observed_at_ms: now, private: next }
}
