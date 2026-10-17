// SPDX-License-Identifier: AGPL-3.0-or-later
export const OPENING_GEOMETRY_SHA256 = "cf83b03f712627dff77828204b9399448cbe91a679d4f9eadfa2aa08cd8b9654";
const SOURCE_DIGEST = "96b27c9b4de41cd961612be5b1e88d40e973a2fded16bd320415b3e15e3b8c61";
const LIMIT = 16_384;
const SVG_NAMESPACE = "http://www.w3.org/2000/svg";
type Position = readonly [number, number, number];
type Edge = readonly [number, number];
type Geometry = { points: Map<number, Position>; cubes: Edge[][] };

function invalid(): never { throw new Error("pentora:opening-data"); }

function object(value: unknown, names: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) invalid();
  const result = value as Record<string, unknown>;
  const keys = Object.keys(result);
  if (keys.length !== names.length || names.some(name => !Object.hasOwn(result, name))) invalid();
  return result;
}

function array(value: unknown, length: number): unknown[] {
  if (!Array.isArray(value) || value.length !== length) invalid();
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum || value > maximum) invalid();
  return value;
}

function rational(value: unknown): number {
  const pair = array(value, 2);
  const numerator = integer(pair[0], -64, 64);
  const denominator = integer(pair[1], 1, 64);
  return numerator / denominator;
}

function decode(value: unknown): Geometry {
  const source = object(value, ["schema", "source_sha256", "points", "cubes"]);
  if (source.schema !== "aukora-pentora-opening-v1" || source.source_sha256 !== SOURCE_DIGEST) invalid();
  const points = new Map<number, Position>();
  for (const item of array(source.points, 20)) {
    const point = object(item, ["global_index", "coordinates"]);
    const index = integer(point.global_index, 0, 110);
    if (index === 55 || points.has(index)) invalid();
    const coordinates = array(point.coordinates, 3).map(value => {
      const coordinate = object(value, ["a", "b"]);
      const phi = (1 + Math.sqrt(5)) / 2;
      return (rational(coordinate.a) + phi * rational(coordinate.b)) / Math.sqrt(3);
    });
    points.set(index, [coordinates[0], coordinates[1], coordinates[2]]);
  }
  const used = new Set<number>();
  const distinctEdges = new Set<string>();
  const cubes = array(source.cubes, 5).map((item, ordinal) => {
    const cube = object(item, ["cube_id", "edges_global_indices"]);
    if (cube.cube_id !== ordinal) invalid();
    const vertices = new Set<number>();
    const edges = array(cube.edges_global_indices, 12).map(value => {
      const endpoints = array(value, 2);
      const a = integer(endpoints[0], 0, 110);
      const b = integer(endpoints[1], 0, 110);
      const key = `${Math.min(a, b)}:${Math.max(a, b)}`;
      if (a === b || !points.has(a) || !points.has(b) || distinctEdges.has(key)) invalid();
      distinctEdges.add(key);
      vertices.add(a); vertices.add(b); used.add(a); used.add(b);
      return [a, b] as Edge;
    });
    if (vertices.size !== 8) invalid();
    return edges;
  });
  if (used.size !== 20 || distinctEdges.size !== 60) invalid();
  return { points, cubes };
}

async function load(signal: AbortSignal, origin: string): Promise<Geometry> {
  const address = new URL("./data/pentora-opening-v1.json", import.meta.url);
  if (address.origin !== origin) invalid();
  const response = await fetch(address, {
    mode: "same-origin", credentials: "same-origin", redirect: "error", cache: "force-cache", signal,
  });
  if (!response.ok || !response.body) invalid();
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let count = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      count += value.byteLength;
      if (count > LIMIT) invalid();
      chunks.push(value);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
  if (count === 0 || signal.aborted) invalid();
  const bytes = new Uint8Array(count);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const hex = Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
  if (hex !== OPENING_GEOMETRY_SHA256 || signal.aborted) invalid();
  return decode(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
}

// The five cubes are drawn in 3D and turned slowly about the vertical axis; each cube is its own group so the cubes can
// arrive one after the other. The geometry is the pinned data; only the view turns. While a pairing is waiting the cubes
// drift a hair out of true; when it is verified they lock: the turn slows to rest, the cubes snap into alignment and a
// pulse of light runs along their edges.
const TILT = 0.5;
type Segment = { line: SVGLineElement; a: number; b: number; cube: number; layer: "glow" | "edge" };
const easeOut = (u: number): number => 1 - (1 - u) ** 3;
const easeOutBack = (u: number): number => { const k = 1.9; return 1 + (k + 1) * (u - 1) ** 3 + k * (u - 1) ** 2; };

function draw(document: Document, geometry: Geometry) {
  const svg = document.createElementNS(SVG_NAMESPACE, "svg");
  svg.classList.add("opening-pentora-geometry");
  svg.setAttribute("viewBox", "-90 -90 180 180");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  const radius = Math.max(...[...geometry.points.values()].map(([x, y, z]) => Math.hypot(x, y, z)));
  const scale = 76 / radius;
  const segments: Segment[] = [];
  geometry.cubes.forEach((edges, ordinal) => {
    const cube = document.createElementNS(SVG_NAMESPACE, "g");
    cube.classList.add("opening-pentora-cube");
    cube.setAttribute("data-cube", String(ordinal));
    // A soft wide underlay first, the fine edge on top: a glow without a filter.
    for (const layer of ["glow", "edge"] as const) {
      for (const [a, b] of edges) {
        const line = document.createElementNS(SVG_NAMESPACE, "line");
        line.classList.add(`pentora-${layer}`);
        line.setAttribute("vector-effect", "non-scaling-stroke");
        cube.append(line);
        segments.push({ line, a, b, cube: ordinal, layer });
      }
    }
    svg.append(cube);
  });
  const place = (index: number, angle: number, size: number): readonly [number, number] => {
    const point = geometry.points.get(index);
    if (!point) invalid();
    const [x, y, z] = point;
    const c = Math.cos(angle), s = Math.sin(angle);
    const turned = -x * s + z * c;
    const tilted = y * Math.cos(TILT) - turned * Math.sin(TILT);
    const depth = y * Math.sin(TILT) + turned * Math.cos(TILT);
    const near = size / (1 - depth / (radius * 4.5));
    return [(x * c + z * s) * scale * near, -tilted * scale * near];
  };
  let lit = false;
  /** `drift` is how far each cube sits out of true (0 = locked); `pulse[c]` is the light on cube c (0 to 1). */
  const render = (angle: number, time: number, drift: number, pulse: readonly number[]): void => {
    const offsets = pulse.map((_, c) => [
      drift * 0.075 * Math.sin(time * 0.0007 * (1 + 0.31 * c) + c * 1.7),
      1 + drift * 0.035 * Math.cos(time * 0.0009 + c * 2.3),
    ] as const);
    const anyLight = pulse.some(value => value > 0.001);
    for (const { line, a, b, cube, layer } of segments) {
      const [turn, size] = offsets[cube];
      const [x1, y1] = place(a, angle + turn, size);
      const [x2, y2] = place(b, angle + turn, size);
      line.setAttribute("x1", x1.toFixed(2));
      line.setAttribute("y1", y1.toFixed(2));
      line.setAttribute("x2", x2.toFixed(2));
      line.setAttribute("y2", y2.toFixed(2));
      if (anyLight || lit) {
        const light = pulse[cube];
        line.style.strokeOpacity = layer === "edge" ? String(0.9 + 0.1 * light) : String(0.09 + 0.55 * light);
        line.style.strokeWidth = layer === "edge" ? `${1.2 + 1.5 * light}px` : `${6 + 9 * light}px`;
      }
    }
    lit = anyLight;
  };
  render(0.7, 0, 0, geometry.cubes.map(() => 0));
  return { svg, render, cubes: geometry.cubes.length };
}

export type PentoraView = { dispose(): void; /** Slow to rest, snap the cubes into alignment, pulse light along the edges (about 2 s). */ lock(): Promise<void> };

export function mountOpeningPentora(host: HTMLElement, signal: AbortSignal): PentoraView {
  const none: PentoraView = { dispose: () => {}, lock: async () => {} };
  if (signal.aborted) return none;
  const document = host.ownerDocument;
  const frame = document.createElement("figure");
  frame.className = "opening-pentora";
  frame.setAttribute("aria-label", "Pentora · five interlocking cubes");
  const status = document.createElement("p");
  status.className = "opening-pentora-status";
  status.setAttribute("role", "status");
  status.textContent = "";
  frame.append(status);
  host.append(frame);
  const lifetime = new AbortController();
  let disposed = false;
  let spinner = 0;
  let view: ReturnType<typeof draw> | null = null;
  let angle = 0.7;
  let speed = 1;
  let drift = 1;
  let pulse: number[] = [];
  let lockedAt = 0;
  let lockDone: (() => void) | null = null;
  const still = typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const timeout = globalThis.setTimeout(() => lifetime.abort(), 5_000);
  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    cancelAnimationFrame(spinner);
    lifetime.abort();
    globalThis.clearTimeout(timeout);
    signal.removeEventListener("abort", dispose);
    lockDone?.();
    frame.remove();
  };
  signal.addEventListener("abort", dispose, { once: true });
  void load(lifetime.signal, document.location?.origin ?? "").then(geometry => {
    if (disposed || lifetime.signal.aborted) return;
    view = draw(document, geometry);
    pulse = geometry.cubes.map(() => 0);
    frame.replaceChildren(view.svg);
    frame.classList.add("opening-pentora-ready");
    if (still) { drift = 0; view.render(angle, 0, drift, pulse); return; }
    // One revolution in about forty seconds.
    let last = performance.now();
    const turn = (now: number): void => {
      if (disposed || !view) return;
      angle += (now - last) * speed / 6400;
      last = now;
      if (lockedAt) {
        const t = (now - lockedAt) / 1000;
        speed = 1 - easeOut(Math.min(1, t / 1.1));
        drift = t < 0.45 ? 1 : 1 - easeOutBack(Math.min(1, (t - 0.45) / 0.65));
        pulse = pulse.map((_, c) => Math.exp(-(((t - 1.0 - c * 0.1) / 0.3) ** 2) * 2.2));
        if (t >= 1.95) { pulse = pulse.map(() => 0); drift = 0; speed = 0; lockedAt = 0; lockDone?.(); lockDone = null; }
      }
      view.render(angle, now, drift, pulse);
      spinner = requestAnimationFrame(turn);
    };
    spinner = requestAnimationFrame(turn);
  }).catch(() => {
    if (disposed) return;
    status.textContent = "";
  }).finally(() => globalThis.clearTimeout(timeout));
  return {
    dispose,
    lock: () => new Promise<void>(resolve => {
      if (disposed || !view) { resolve(); return; }
      if (still) { drift = 0; view.render(angle, 0, 0, pulse); setTimeout(resolve, 400); return; }
      lockDone = resolve;
      lockedAt = performance.now();
    }),
  };
}
