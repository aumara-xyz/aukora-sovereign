// SPDX-License-Identifier: AGPL-3.0-or-later
// The tri-pane's compositions, with no DOM. Three lanes carry integer weights 0 to 3 that always sum to 3, so a
// visible lane is one third, two thirds or the whole frame: ten compositions. A weight of 0 hides a lane.
export type LaneId = 'threads' | 'surface' | 'menu';
export type PaneWeights = readonly [number, number, number];
/** The four lane edges that grow or shrink a lane: the threads lane's, the surface lane's two, the menu lane's. */
export type Corner = 'left' | 'centre-left' | 'centre-right' | 'right';

export const LANES: readonly LaneId[] = ['threads', 'surface', 'menu'];
export const BALANCED: PaneWeights = Object.freeze([1, 1, 1]) as PaneWeights;
/** Revealing a hidden desktop app gives it two thirds beside the threads and hides the menu. */
export const APP_OPEN: PaneWeights = Object.freeze([1, 2, 0]) as PaneWeights;

export const PANE_WEIGHTS: readonly PaneWeights[] = Object.freeze(
  Array.from({ length: 4 }, (_, left) =>
    Array.from({ length: 4 - left }, (_, centre) =>
      Object.freeze([left, centre, 3 - left - centre]) as PaneWeights)).flat(),
);

export function validWeights(value: readonly number[]): value is PaneWeights {
  return value.length === 3 && value.every(n => Number.isInteger(n) && n >= 0 && n <= 3)
    && value.reduce((sum, n) => sum + n, 0) === 3;
}

function checked(left: number, centre: number, right: number): PaneWeights {
  const next = [left, centre, right];
  if (!validWeights(next)) throw new Error('shell:invalid-weights');
  return Object.freeze(next) as PaneWeights;
}

/** The lane that has the whole frame, or null while two or three lanes share it. */
export function wholeFrameLane(weights: PaneWeights): LaneId | null {
  const at = weights.indexOf(3);
  return at < 0 ? null : LANES[at]!;
}

/** The only visible lane when one lane shows at a time, as the weights that give it the whole frame. */
export function soleLane(lane: LaneId): PaneWeights {
  const at = LANES.indexOf(lane);
  if (at < 0) throw new Error('shell:unknown-lane');
  return checked(at === 0 ? 3 : 0, at === 1 ? 3 : 0, at === 2 ? 3 : 0);
}

/** An outer lane gains one third from the far side first; a lane that has the whole frame gives one third back. */
function outer(weights: PaneWeights, side: 'left' | 'right'): PaneWeights {
  const [left, centre, right] = weights;
  if (side === 'left') {
    if (left === 0) return weights;
    if (left === 3) return checked(2, 1, 0);
    return right > 0 ? checked(left + 1, centre, right - 1) : checked(left + 1, centre - 1, right);
  }
  if (right === 0) return weights;
  if (right === 3) return checked(0, 1, 2);
  return left > 0 ? checked(left - 1, centre, right + 1) : checked(left, centre - 1, right + 1);
}

/** One third crosses a boundary of the surface lane: at the frame edge an outer lane comes in, inset the surface grows. */
function boundary(weights: PaneWeights, side: 'left' | 'right'): PaneWeights {
  const [left, centre, right] = weights;
  if (centre === 0) return weights;
  if (side === 'left') return left === 0 ? checked(1, centre - 1, right) : checked(left - 1, centre + 1, right);
  return right === 0 ? checked(left, centre - 1, 1) : checked(left, centre + 1, right - 1);
}

/** The composition after a lane edge is used. An edge of a hidden lane does nothing. */
export function cycle(weights: PaneWeights, corner: Corner): PaneWeights {
  if (!validWeights(weights)) throw new Error('shell:invalid-weights');
  if (corner === 'left') return outer(weights, 'left');
  if (corner === 'right') return outer(weights, 'right');
  if (corner === 'centre-left') return boundary(weights, 'left');
  if (corner === 'centre-right') return boundary(weights, 'right');
  throw new Error('shell:unknown-corner');
}
