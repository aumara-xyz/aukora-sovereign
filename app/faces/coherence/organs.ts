// SPDX-License-Identifier: AGPL-3.0-or-later
// Who owns which health cell. Organ i is cube i of the pinned geometry; the 90 private cells run 18 per organ in organ
// order, and the 20 corner cells run two per organ pair in the pinned pair order. This only labels and counts cells that
// are already decided; it never decides a state.
import type { DecodedHealth, HealthCell } from "./views.js";

export const ORGANS = ["AUMLOK", "Gate & Aura", "Kira", "Network", "Body"] as const;
export const CHECKS_PER_ORGAN = 18;
// Cube pairs in the geometry's pair order; pair p owns corner cells 2p and 2p + 1.
export const PAIRS: readonly (readonly [number, number])[] = [
  [0, 1], [0, 2], [0, 3], [0, 4], [1, 2], [1, 3], [1, 4], [2, 3], [2, 4], [3, 4],
];
export const STATE_ORDER: readonly HealthCell[] = ["verified", "undetermined", "failed"];

export interface Tally {
  verified: number;
  undetermined: number;
  failed: number;
}
export interface OrganTally {
  readonly organ: string;
  readonly private: Tally;
  readonly corners: Tally;
}
export interface OpenCell {
  readonly label: string;
  readonly state: HealthCell;
}

export function pairLabel(pair: number): string {
  const [a, b] = PAIRS[pair];
  return `${ORGANS[a]} × ${ORGANS[b]}`;
}

function count(states: Iterable<HealthCell>): Tally {
  const tally: Tally = { verified: 0, undetermined: 0, failed: 0 };
  for (const state of states) tally[state]++;
  return tally;
}

/** Which private cells (registry positions) an organ owns. */
export function privateOf(organ: number): number[] {
  return Array.from({ length: CHECKS_PER_ORGAN }, (_, at) => organ * CHECKS_PER_ORGAN + at);
}

/** Which corner cells (registry positions) involve an organ: two for each of the four pairs it belongs to. */
export function cornersOf(organ: number): number[] {
  return PAIRS.flatMap(([a, b], pair) => (a === organ || b === organ ? [pair * 2, pair * 2 + 1] : []));
}

export function totals(health: DecodedHealth): Tally {
  return count([...health.private_cells, ...health.corner_cells]);
}

export function organTallies(health: DecodedHealth): OrganTally[] {
  return ORGANS.map((organ, at) => ({
    organ,
    private: count(privateOf(at).map(cell => health.private_cells[cell])),
    corners: count(cornersOf(at).map(cell => health.corner_cells[cell])),
  }));
}

/** Every cell that is not verified, named by owner and position, so the picture has a text equivalent. */
export function openCells(health: DecodedHealth): OpenCell[] {
  const open: OpenCell[] = [];
  health.private_cells.forEach((state, at) => {
    if (state !== "verified") {
      open.push({ label: `${ORGANS[Math.floor(at / CHECKS_PER_ORGAN)]} check ${(at % CHECKS_PER_ORGAN) + 1}`, state });
    }
  });
  health.corner_cells.forEach((state, at) => {
    if (state !== "verified") open.push({ label: `${pairLabel(Math.floor(at / 2))} corner ${(at % 2) + 1}`, state });
  });
  return open;
}
