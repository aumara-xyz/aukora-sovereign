// SPDX-License-Identifier: AGPL-3.0-or-later
// The pinned Pentora geometry, imported as data and checked before anything is drawn. The table's
// bytes are pinned by hash in checks/pins.json; a browser holds only the parsed table, so this
// module checks its shape and refuses a table that does not fit it.
import table from "./geometry-data.js";
import { CENTRE_CELL, TRIT_COUNT, refuse } from "./derive.js";

export const POINT_COUNT = 111;
const CUBE_COUNT = 5;
const CUBE_EDGES = 12;
const YAW = 0.62;
const PITCH = -0.42;

export type BloomCell = {
  readonly index: number;
  /** Position after the fixed view turn, in the unit square around the centre cell. */
  readonly x: number;
  readonly y: number;
  /** Towards the viewer is positive. */
  readonly depth: number;
  /** Distance from the centre cell: 0 for the centre, at most 1. */
  readonly reach: number;
};

export type BloomGeometry = {
  readonly cells: readonly BloomCell[];
  /** Pinned cell index for each returned trit. */
  readonly mutableIndices: readonly number[];
  /** Cell indices, farthest from the viewer first. */
  readonly order: readonly number[];
  readonly edges: readonly (readonly [number, number])[];
};

type Fields = { readonly [key: string]: unknown };

function fields(value: unknown): Fields {
  if (typeof value !== "object" || value === null || Array.isArray(value)) refuse("geometry-invalid");
  return value as Fields;
}

function list(value: unknown, length: number): readonly unknown[] {
  if (!Array.isArray(value) || value.length !== length) refuse("geometry-invalid");
  return value;
}

function whole(value: unknown, low: number, high: number): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < low || value > high) refuse("geometry-invalid");
  return value;
}

function rational(value: unknown): number {
  const parts = list(value, 2);
  return whole(parts[0], -1_000_000, 1_000_000) / whole(parts[1], 1, 1_000_000);
}

/** One coordinate of the exact table, (a + b * phi) / sqrt(3) with a and b rational, as the Rust side reads it. */
function axis(value: unknown): number {
  const parts = fields(value);
  return (rational(parts.a) + rational(parts.b) * ((1 + Math.sqrt(5)) / 2)) / Math.sqrt(3);
}

function noncentre(value: unknown): number {
  const cell = whole(value, 0, POINT_COUNT - 1);
  if (cell === CENTRE_CELL) refuse("geometry-invalid");
  return cell;
}

function project(source: unknown): BloomGeometry {
  const root = fields(source);
  if (whole(root.centre_index, 0, POINT_COUNT - 1) !== CENTRE_CELL) refuse("geometry-invalid");
  const mutableIndices = list(root.mutable_indices, TRIT_COUNT).map(noncentre);
  if (new Set(mutableIndices).size !== TRIT_COUNT) refuse("geometry-invalid");
  const sine = { yaw: Math.sin(YAW), pitch: Math.sin(PITCH) }, cosine = { yaw: Math.cos(YAW), pitch: Math.cos(PITCH) };
  const cells: BloomCell[] = list(root.points, POINT_COUNT).map((raw, at) => {
    const point = fields(raw);
    if (whole(point.global_index, 0, POINT_COUNT - 1) !== at) refuse("geometry-invalid");
    const coordinates = list(point.coordinates, 3);
    const x = axis(coordinates[0]), y = axis(coordinates[1]), z = axis(coordinates[2]);
    const reach = Math.hypot(x, y, z);
    // The centre is the origin and every other cell lies inside the unit sphere.
    if ((at === CENTRE_CELL) !== (reach < 1e-9) || reach > 1 + 1e-9) refuse("geometry-invalid");
    const turned = -x * sine.yaw + z * cosine.yaw;
    return {
      index: at,
      x: x * cosine.yaw + z * sine.yaw,
      y: y * cosine.pitch - turned * sine.pitch,
      depth: y * sine.pitch + turned * cosine.pitch,
      reach: Math.min(1, reach),
    };
  });
  const edges: (readonly [number, number])[] = [];
  const seen = new Set<number>();
  for (const cube of list(root.cubes, CUBE_COUNT)) {
    for (const edge of list(fields(cube).edges_global_indices, CUBE_EDGES)) {
      const ends = list(edge, 2);
      const from = noncentre(ends[0]), to = noncentre(ends[1]);
      const key = Math.min(from, to) * POINT_COUNT + Math.max(from, to);
      if (from === to || seen.has(key)) refuse("geometry-invalid");
      seen.add(key);
      edges.push(Object.freeze([from, to] as const));
    }
  }
  const order = cells.map(cell => cell.index).sort((a, b) => (cells[a]?.depth ?? 0) - (cells[b]?.depth ?? 0));
  return Object.freeze({
    cells: Object.freeze(cells),
    mutableIndices: Object.freeze(mutableIndices),
    order: Object.freeze(order),
    edges: Object.freeze(edges),
  });
}

let loaded: BloomGeometry | undefined;

/** The projected geometry, checked once. A table that does not fit refuses with `pentora:geometry-invalid`. */
export function bloomGeometry(): BloomGeometry {
  if (!loaded) loaded = project(table);
  return loaded;
}
