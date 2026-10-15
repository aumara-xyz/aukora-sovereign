// SPDX-License-Identifier: AGPL-3.0-or-later
export const TAU = 2 * Math.PI;
export const MIN_HEIGHT = 100;
export const MAX_HEIGHT = 100_000_000;
const EVALUATION_MAX = MAX_HEIGHT + 20;

export interface Term {
  n: number;
  amplitude: number;
  phase: number;
  real: number;
  imaginary: number;
  rate: number;
  entry: number;
}
export interface Sum { height: number; real: number; imaginary: number }
export interface WindowData { centre: number; half: number; samples: readonly Sum[] }

export function requireHeight(height: number): number {
  if (!Number.isFinite(height) || height < MIN_HEIGHT || height > MAX_HEIGHT) {
    throw new Error("zetaharp:height-range");
  }
  return height;
}

// The extra margin evaluates every W4 fixture without widening navigation.
function evaluationHeight(height: number): number {
  if (!Number.isFinite(height) || height < MIN_HEIGHT || height > EVALUATION_MAX) {
    throw new Error("zetaharp:height-range");
  }
  return height;
}

export function clampHeight(height: number): number {
  if (!Number.isFinite(height)) throw new Error("zetaharp:height-range");
  return Math.min(MAX_HEIGHT, Math.max(MIN_HEIGHT, height));
}

export function theta(height: number): number {
  evaluationHeight(height);
  const inverse = 1 / height;
  return height * (Math.log(height / TAU) - 1) / 2 - Math.PI / 8
    + inverse / 48 + (7 / 5760) * inverse ** 3;
}

export function thetaPrime(height: number): number {
  evaluationHeight(height);
  const inverseSquare = 1 / (height * height);
  return Math.log(height / TAU) / 2 - inverseSquare / 48 - (7 / 1920) * inverseSquare ** 2;
}

export function termCount(height: number): number {
  evaluationHeight(height);
  const radius = Math.sqrt(height / TAU);
  const nearest = Math.round(radius);
  return Math.abs(radius - nearest) <= 2 * Number.EPSILON * radius ? nearest : Math.floor(radius);
}

export function amplitude(n: number): number {
  if (!Number.isSafeInteger(n) || n < 1 || n > termCount(MAX_HEIGHT)) throw new Error("zetaharp:term-range");
  return 2 / Math.sqrt(n);
}

export function phaseAngle(radians: number): number {
  if (!Number.isFinite(radians)) throw new Error("zetaharp:phase-range");
  return Math.atan2(Math.sin(radians), Math.cos(radians));
}

export function term(height: number, n: number): Term {
  if (!Number.isInteger(n) || n < 1 || n > termCount(height)) throw new Error("zetaharp:term-range");
  const phase = phaseAngle(theta(height) - height * Math.log(n));
  const weight = amplitude(n);
  return {
    n, amplitude: weight, phase, real: weight * Math.cos(phase), imaginary: weight * Math.sin(phase),
    rate: (thetaPrime(height) - Math.log(n)) / TAU, entry: TAU * n * n,
  };
}

export function sum(height: number): Sum {
  const angle = theta(height);
  const count = termCount(height);
  let real = 0;
  let imaginary = 0;
  let realError = 0;
  let imaginaryError = 0;
  for (let n = 1; n <= count; n++) {
    const phase = angle - height * Math.log(n);
    const weight = 2 / Math.sqrt(n);
    const x = weight * Math.cos(phase) - realError;
    const nextReal = real + x;
    realError = (nextReal - real) - x;
    real = nextReal;
    const y = weight * Math.sin(phase) - imaginaryError;
    const nextImaginary = imaginary + y;
    imaginaryError = (nextImaginary - imaginary) - y;
    imaginary = nextImaginary;
  }
  return { height, real, imaginary };
}

export function heightWindow(centre: number): WindowData {
  requireHeight(centre);
  const half = Math.max(4, Math.min(24, 40 / Math.log(termCount(centre) + 1)));
  const low = clampHeight(centre - half);
  const high = clampHeight(centre + half);
  const samples = Array.from({ length: 129 }, (_, at) => sum(low + (high - low) * at / 128));
  return { centre, half, samples };
}

// A change in term count is a discontinuity of this finite sum, not a crossing bracket.
export function crossing(left: number, right: number): number | null {
  requireHeight(left);
  requireHeight(right);
  if (right <= left || termCount(left) !== termCount(right)) return null;
  let low = left;
  let high = right;
  let value = sum(low).real;
  const end = sum(high).real;
  if (value === 0) return low;
  if (end === 0) return high;
  if (Math.sign(value) === Math.sign(end)) return null;
  for (let step = 0; step < 48; step++) {
    const middle = low + (high - low) / 2;
    if (middle === low || middle === high) break;
    const current = sum(middle).real;
    if (current === 0) return middle;
    if (Math.sign(current) === Math.sign(value)) { low = middle; value = current; }
    else high = middle;
  }
  return low + (high - low) / 2;
}

export function nearestCrossing(window: WindowData): number | null {
  const found: number[] = [];
  for (let at = 1; at < window.samples.length; at++) {
    const a = window.samples[at - 1];
    const b = window.samples[at];
    if (Math.sign(a.real) !== Math.sign(b.real) || a.real === 0 || b.real === 0) {
      const value = crossing(a.height, b.height);
      if (value !== null) found.push(value);
    }
  }
  return found.sort((a, b) => Math.abs(a - window.centre) - Math.abs(b - window.centre))[0] ?? null;
}
