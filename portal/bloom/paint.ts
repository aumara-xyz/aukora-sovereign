// SPDX-License-Identifier: AGPL-3.0-or-later
// Draws a bloom's trits on the pinned geometry. It takes a canvas context and the trits and reads
// nothing else: no health state, no fingerprint. The three trits differ in shape as well as colour:
// a hollow ring, a filled disc, and a larger disc with a halo.
import { CENTRE_CELL, TRIT_COUNT, refuse } from "./derive.js";
import { bloomGeometry } from "./geometry.js";

export const BLOOM_SIZE = 640;
/** The bloom opens from the centre outward over this long, or at once under reduced motion. */
export const BLOOM_MS = 600;

const SCALE = 268;
const BACKGROUND = "#07131e";
const EDGE = "rgba(150, 196, 204, 0.30)";
const CENTRE = "#7d97a3";
const DIM = "#5f8aa0";
const MEDIUM = "#3fb6a8";
const BRIGHT = "#f4d98f";
const GLOW_TOP = "rgba(244, 217, 143, 0.45)";
const GLOW_EDGE = "rgba(244, 217, 143, 0)";

function clamp(value: number): number {
  return value < 0 ? 0 : value > 1 ? 1 : value;
}

function ease(value: number): number {
  return 1 - (1 - clamp(value)) ** 3;
}

/**
 * Paint the bloom at `progress` from 0 (empty) to 1 (settled). A cell opens once the sweep from the
 * centre reaches it, so the settled picture does not depend on how it was reached.
 */
export function paintBloom(context: CanvasRenderingContext2D, trits: Uint8Array, progress: number): void {
  if (!(trits instanceof Uint8Array) || trits.length !== TRIT_COUNT || trits.some(trit => trit > 2)) refuse("trits-invalid");
  const geometry = bloomGeometry();
  const cells = new Map(geometry.mutableIndices.map((cell, digit) => [cell, trits[digit]]));
  const open = clamp(progress);
  const middle = BLOOM_SIZE / 2;
  context.globalAlpha = 1;
  context.fillStyle = BACKGROUND;
  context.fillRect(0, 0, BLOOM_SIZE, BLOOM_SIZE);

  context.globalAlpha = ease(open * 2);
  context.strokeStyle = EDGE;
  context.lineWidth = 1;
  context.beginPath();
  for (const [from, to] of geometry.edges) {
    const a = geometry.cells[from], b = geometry.cells[to];
    if (!a || !b) refuse("geometry-invalid");
    context.moveTo(middle + a.x * SCALE, middle + a.y * SCALE);
    context.lineTo(middle + b.x * SCALE, middle + b.y * SCALE);
  }
  context.stroke();

  for (const index of geometry.order) {
    const cell = geometry.cells[index];
    if (!cell) refuse("geometry-invalid");
    const grow = ease((open - 0.55 * cell.reach) / 0.45);
    if (grow <= 0) continue;
    const x = middle + cell.x * SCALE, y = middle + cell.y * SCALE;
    // Cells nearer the viewer are a little larger and brighter.
    const near = 1 + 0.16 * cell.depth, shade = 0.7 + 0.3 * ((cell.depth + 1) / 2);
    context.globalAlpha = grow * shade;
    if (index === CENTRE_CELL) {
      context.strokeStyle = CENTRE;
      context.lineWidth = 1.4;
      context.beginPath();
      context.arc(x, y, 3.4 * near * grow, 0, Math.PI * 2);
      context.stroke();
      continue;
    }
    const trit = cells.get(index);
    if (trit === 0) {
      context.beginPath();
      context.arc(x, y, 4.4 * near * grow, 0, Math.PI * 2);
      context.fillStyle = "rgba(95, 138, 160, 0.16)";
      context.fill();
      context.strokeStyle = DIM;
      context.lineWidth = 1.6;
      context.stroke();
    } else if (trit === 1) {
      context.beginPath();
      context.arc(x, y, 5.6 * near * grow, 0, Math.PI * 2);
      context.fillStyle = MEDIUM;
      context.fill();
    } else if (trit === 2) {
      const reachOfGlow = 17 * near * grow;
      const glow = context.createRadialGradient(x, y, 0, x, y, reachOfGlow);
      glow.addColorStop(0, GLOW_TOP);
      glow.addColorStop(1, GLOW_EDGE);
      context.beginPath();
      context.arc(x, y, reachOfGlow, 0, Math.PI * 2);
      context.fillStyle = glow;
      context.fill();
      context.beginPath();
      context.arc(x, y, 7.2 * near * grow, 0, Math.PI * 2);
      context.fillStyle = BRIGHT;
      context.fill();
    } else {
      refuse("trits-invalid");
    }
  }
  context.globalAlpha = 1;
}
