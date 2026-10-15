// SPDX-License-Identifier: AGPL-3.0-or-later
import { TOKENS } from "../../design/index.js";
import { TAU, phaseAngle, term, termCount, theta } from "./math.js";
import type { WindowData } from "./math.js";
import { referenceAt } from "./reference.js";

export type TorusView = "shadow" | "slice" | "unfold";
export interface SceneOptions {
  zoom: number;
  yaw: number;
  pitch: number;
  selected: number;
  strings: boolean;
  resultant: boolean;
}
type Point = readonly [number, number];
const C = TOKENS.colors;

function surface(canvas: HTMLCanvasElement): { context: CanvasRenderingContext2D; width: number; height: number } {
  const context = canvas.getContext("2d");
  if (!context) throw new Error("zetaharp:canvas-unavailable");
  const width = Math.max(1, canvas.clientWidth);
  const height = Math.max(1, canvas.clientHeight);
  const ratio = Math.min(2, window.devicePixelRatio || 1);
  const pixelsWide = Math.round(width * ratio);
  const pixelsHigh = Math.round(height * ratio);
  if (canvas.width !== pixelsWide || canvas.height !== pixelsHigh) {
    canvas.width = pixelsWide;
    canvas.height = pixelsHigh;
  }
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  context.clearRect(0, 0, width, height);
  return { context, width, height };
}

function line(context: CanvasRenderingContext2D, points: readonly Point[], color: string, weight = 1): void {
  if (!points.length) return;
  context.strokeStyle = color;
  context.lineWidth = weight;
  context.beginPath();
  points.forEach(([x, y], at) => at ? context.lineTo(x, y) : context.moveTo(x, y));
  context.stroke();
}

function label(context: CanvasRenderingContext2D, text: string, x: number, y: number): void {
  context.fillStyle = C.secondary;
  context.font = "11px system-ui, sans-serif";
  context.fillText(text, x, y);
}

function dot(context: CanvasRenderingContext2D, point: Point, radius: number, color: string): void {
  context.fillStyle = color;
  context.beginPath();
  context.arc(point[0], point[1], radius, 0, TAU);
  context.fill();
}

export function drawTunnel(canvas: HTMLCanvasElement, data: WindowData, height: number, options: SceneOptions): void {
  const { context, width, height: size } = surface(canvas);
  const count = termCount(height);
  const scale = Math.min(width / 12, size / 8) * options.zoom;
  const cosine = Math.cos(options.yaw);
  const sine = Math.sin(options.yaw);
  const project = (x: number, y: number, depth: number): Point => {
    const side = x * cosine - depth * sine;
    const away = x * sine + depth * cosine;
    const vertical = y * Math.cos(options.pitch) - away * Math.sin(options.pitch);
    const distance = 14 + away * Math.cos(options.pitch) + y * Math.sin(options.pitch);
    const perspective = 12 / Math.max(3, distance);
    return [width / 2 + side * scale * perspective, size / 2 - vertical * scale * perspective];
  };
  for (let z = -4; z <= 4; z++) {
    const ring = Array.from({ length: 65 }, (_, at) => {
      const angle = TAU * at / 64;
      return project(2.6 * Math.cos(angle), 2.6 * Math.sin(angle), z);
    });
    line(context, ring, C.border);
  }
  const chosen = new Set(Array.from({ length: Math.min(count, 64) }, (_, at) =>
    1 + Math.floor(at * count / Math.min(count, 64))));
  chosen.add(options.selected);
  if (options.strings) for (const n of chosen) {
    const points = data.samples.filter((_, at) => at % 2 === 0).map(sample => {
      if (n > termCount(sample.height)) return null;
      const value = term(sample.height, n);
      const z = (sample.height - data.centre) / data.half * 4;
      return project(value.real, value.imaginary, z);
    });
    // Cutoff gaps start a fresh path rather than drawing an inactive term.
    let segment: Point[] = [];
    for (const point of points) {
      if (point) segment.push(point);
      else { line(context, segment, C.blue); segment = []; }
    }
    line(context, segment, n === options.selected ? C.mint : C.blue, n === options.selected ? 2 : .6);
  }
  if (options.resultant) {
    const points = data.samples.map(sample => project(sample.real / 3, sample.imaginary / 3,
      (sample.height - data.centre) / data.half * 4));
    line(context, points, C.gold, 2.5);
  }
  dot(context, project(0, 0, 0), 3, C.text);
  label(context, `${chosen.size} of ${count} strings drawn · gold: full complex sum / 3`, 12, size - 16);
}

export function drawChart(canvas: HTMLCanvasElement, data: WindowData, currentHeight: number, showSum: boolean,
  showReference: boolean, showRemainder: boolean): void {
  const { context, width, height } = surface(canvas);
  const padding = 32;
  const low = data.samples[0].height;
  const high = data.samples[data.samples.length - 1].height;
  const references = data.samples.map(sample => referenceAt(sample.height));
  const peak = Math.max(2, ...data.samples.map(sample => Math.abs(sample.real)),
    ...references.map(value => showReference && value ? Math.abs(value.z) : 0),
    ...references.map(value => showRemainder && value ? Math.abs(value.remainder) : 0));
  const xAt = (t: number) => padding + (t - low) / (high - low) * (width - 2 * padding);
  const yAt = (value: number) => height / 2 - value / peak * (height / 2 - 25);
  line(context, [[padding, height / 2], [width - padding, height / 2]], C.muted);
  if (showSum) line(context, data.samples.map(sample => [xAt(sample.height), yAt(sample.real)]), C.gold, 2);
  for (const [visible, key, color] of [[showReference, "z", C.violet], [showRemainder, "remainder", C.blue]] as const) {
    if (!visible) continue;
    let segment: Point[] = [];
    references.forEach((value, at) => {
      if (value) segment.push([xAt(data.samples[at].height), yAt(value[key])]);
      else { line(context, segment, color); segment = []; }
    });
    line(context, segment, color);
  }
  const marker = xAt(currentHeight);
  line(context, [[marker, 12], [marker, height - 20]], C.mint);
  label(context, low.toFixed(2), 6, height - 5);
  label(context, high.toFixed(2), Math.max(6, width - 94), height - 5);
  label(context, `±${peak.toFixed(2)}`, 8, 14);
  const reference = referenceAt(currentHeight);
  label(context, reference ? `${reference.window}: numerical reference` : "No reference data at this height", 74, 14);
}

export function drawFlower(canvas: HTMLCanvasElement, height: number, selected: number): void {
  const { context, width, height: size } = surface(canvas);
  const radius = Math.min(width, size) * .36;
  const centre: Point = [width / 2, size / 2];
  const count = termCount(height);
  const numbers = new Set(Array.from({ length: Math.min(128, count) }, (_, at) =>
    1 + Math.floor(at * count / Math.min(128, count))));
  numbers.add(selected);
  line(context, [[12, centre[1]], [width - 12, centre[1]]], C.border);
  line(context, [[centre[0], 12], [centre[0], size - 26]], C.border);
  for (const n of numbers) {
    const value = term(height, n);
    const endpoint: Point = [centre[0] + value.real * radius / 2, centre[1] - value.imaginary * radius / 2];
    line(context, [centre, endpoint], n === selected ? C.mint : C.violet, n === selected ? 2.5 : .6);
    if (n === selected) dot(context, endpoint, 4, C.mint);
  }
  label(context, `${numbers.size} of ${count} phasors · green n=${selected}`, 12, size - 10);
}

export function drawTorus(canvas: HTMLCanvasElement, height: number, view: TorusView): void {
  const { context, width, height: size } = surface(canvas);
  const first = phaseAngle(theta(height));
  const second = phaseAngle(theta(height) - height * Math.log(2));
  const span = Math.min(width / 3.8, size / 3.8);
  const project = (a: number, b: number): Point => [width / 2 + span * (Math.cos(a) + .4 * Math.cos(b)),
    size / 2 + span * (.65 * Math.sin(a) + .55 * Math.sin(b))];
  if (view === "unfold") {
    const position = (a: number, b: number): Point => [24 + (a + Math.PI) / TAU * (width - 48),
      20 + (b + Math.PI) / TAU * (size - 55)];
    for (let step = 0; step <= 8; step++) {
      const angle = -Math.PI + step * TAU / 8;
      line(context, [position(angle, -Math.PI), position(angle, Math.PI)], C.border);
      line(context, [position(-Math.PI, angle), position(Math.PI, angle)], C.border);
    }
    dot(context, position(first, second), 5, C.gold);
    label(context, "φ₁ → (mod 2π)     φ₂ ↓ (mod 2π)", 12, size - 10);
    return;
  }
  for (let ring = 0; ring < 16; ring++) {
    const angle = ring * TAU / 16;
    if (view === "shadow") line(context, Array.from({ length: 65 }, (_, at) => project(angle, at * TAU / 64)), C.border);
    line(context, Array.from({ length: 65 }, (_, at) => project(at * TAU / 64, angle)), C.border);
  }
  if (view === "slice") {
    line(context, Array.from({ length: 65 }, (_, at) => project(first, at * TAU / 64)), C.mint, 2);
  }
  dot(context, project(first, second), 5, C.gold);
  label(context, view === "slice" ? "Slice: φ₁ fixed; φ₂ circle" : "Linear shadow of S¹ × S¹; no physical surface", 12, size - 10);
}
