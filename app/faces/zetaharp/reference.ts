// SPDX-License-Identifier: AGPL-3.0-or-later
import source from "./fixtures.json" with { type: "json" };
import { MAX_HEIGHT, MIN_HEIGHT, sum } from "./math.js";

interface ReferenceWindow {
  id: string;
  range: number[];
  step: number;
  heights: number[];
  main_sum: number[];
  reference_z: number[];
  remainder: number[];
}
export interface ReferenceZero { index: number; height: number; height_decimal: string }
interface Fixtures { schema: string; windows: ReferenceWindow[]; refined_zeros: ReferenceZero[] }
export interface ReferenceValue { window: string; z: number; remainder: number }

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("zetaharp:reference-data");
  return value as Record<string, unknown>;
}

function finite(value: unknown): value is number { return typeof value === "number" && Number.isFinite(value); }

function numbers(value: unknown, length: number): value is number[] {
  return Array.isArray(value) && value.length === length && value.every(finite);
}

function load(value: unknown): Fixtures {
  const data = object(value);
  if (data.schema !== "zetaharp-fixtures-v1" || !Array.isArray(data.windows) || data.windows.length !== 4 ||
      !Array.isArray(data.refined_zeros) || data.refined_zeros.length > 256) throw new Error("zetaharp:reference-data");
  for (const [index, raw] of data.windows.entries()) {
    const window = object(raw);
    const count = Array.isArray(window.heights) ? window.heights.length : 0;
    if (window.id !== `W${index + 1}` || count < 2 || count > 4096 || !numbers(window.range, 2) ||
        !finite(window.step) || window.step <= 0 || !numbers(window.heights, count) ||
        !numbers(window.main_sum, count) || !numbers(window.reference_z, count) || !numbers(window.remainder, count)) {
      throw new Error("zetaharp:reference-data");
    }
    const heights = window.heights as number[];
    const range = window.range as number[];
    if (range[0] !== heights[0] || range[1] !== heights[count - 1]) throw new Error("zetaharp:reference-data");
    for (let at = 0; at < count; at++) {
      if (heights[at] < MIN_HEIGHT || heights[at] > MAX_HEIGHT + 20 ||
          (at > 0 && (heights[at] <= heights[at - 1] || Math.abs(heights[at] - heights[at - 1] - window.step) > .000001))) {
        throw new Error("zetaharp:reference-data");
      }
    }
  }
  let previous = 0;
  for (const raw of data.refined_zeros) {
    const row = object(raw);
    if (!Number.isSafeInteger(row.index) || (row.index as number) < 1 || !finite(row.height) || row.height <= previous ||
        row.height <= 0 || row.height > MAX_HEIGHT + 20 || typeof row.height_decimal !== "string" ||
        !/^\d+\.\d+$/.test(row.height_decimal) ||
        Math.abs(Number(row.height_decimal) - row.height) > 2 * Number.EPSILON * row.height) {
      throw new Error("zetaharp:reference-data");
    }
    previous = row.height;
  }
  return data as unknown as Fixtures;
}

const DATA = load(source);

// These interpolated numerical references are display data, never certified bounds.
export function referenceAt(height: number): ReferenceValue | null {
  for (const window of DATA.windows) {
    if (height < window.range[0] || height > window.range[1]) continue;
    let lower = 0;
    let upper = window.heights.length - 1;
    while (upper - lower > 1) {
      const middle = Math.floor((lower + upper) / 2);
      if (window.heights[middle] <= height) lower = middle;
      else upper = middle;
    }
    const fraction = (height - window.heights[lower]) / (window.heights[upper] - window.heights[lower]);
    const interpolate = (values: readonly number[]) => values[lower] + fraction * (values[upper] - values[lower]);
    return { window: window.id, z: interpolate(window.reference_z), remainder: interpolate(window.remainder) };
  }
  return null;
}

export function nearestReferenceZero(height: number): ReferenceZero | null {
  const available = DATA.refined_zeros.filter(row => row.height >= MIN_HEIGHT && row.height <= MAX_HEIGHT);
  return [...available].sort((a, b) => Math.abs(a.height - height) - Math.abs(b.height - height))[0] ?? null;
}

export function referenceDeviation(): string {
  let maximum = 0;
  let evaluated = 0;
  let total = 0;
  for (const window of DATA.windows) {
    total += window.heights.length;
    for (let at = 0; at < window.heights.length; at++) {
      const height = window.heights[at];
      maximum = Math.max(maximum, Math.abs(sum(height).real - window.main_sum[at]));
      evaluated++;
    }
  }
  return `Computed at load: maximum |M − supplied M_ref| ${maximum.toExponential(4)} across ${evaluated}/${total} fixture points. ` +
    "The evaluation includes W4's 20-unit margin above the navigation limit. This is a numerical comparison, not certification.";
}
