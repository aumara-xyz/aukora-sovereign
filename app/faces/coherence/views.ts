// SPDX-License-Identifier: AGPL-3.0-or-later
import { CENTRE, POINTS, MUTABLE_INDICES, PRIVATE_INDICES, CORNER_INDICES } from "./geometry.js";

export type HealthCell = "verified" | "undetermined" | "failed";
export interface DecodedHealth {
  readonly private_cells: readonly HealthCell[];
  readonly corner_cells: readonly HealthCell[];
}

export interface HealthDecoder {
  decode_snapshot(bytes: Uint8Array): DecodedHealth;
}

export interface PentoraExpansion {
  pentora_expand(digest32: Uint8Array): Uint8Array;
}

export interface CoherenceViews {
  health(snapshotBytes: Uint8Array, decoder: HealthDecoder, repairing?: ReadonlySet<number>): void;
  fingerprint(displayDigest32: Uint8Array, pentora: PentoraExpansion): void;
  clearHealth(reason: string): void;
  clearFingerprint(reason: string): void;
  dispose(): void;
}

function canvasPanel(root: HTMLElement, title: string) {
  const section = document.createElement("section");
  const heading = document.createElement("h2");
  heading.textContent = title;
  const canvas = document.createElement("canvas");
  canvas.width = 640;
  canvas.height = 480;
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", title);
  const summary = document.createElement("p");
  summary.setAttribute("role", "status");
  summary.textContent = "Unavailable";
  section.append(heading, canvas, summary);
  root.append(section);
  const context = canvas.getContext("2d");
  if (!context) throw new Error("coherence:canvas-unavailable");
  return { section, canvas, summary, context };
}

const projected = POINTS.map(([x, y, z], index) => ({
  index, x: 320 + (x * 0.86 + z * 0.5) * 185,
  y: 240 + (y * 0.9 - z * 0.36 + x * 0.2) * 185,
  depth: z * 0.86 - x * 0.5,
})).sort((a, b) => a.depth - b.depth);

function dot(context: CanvasRenderingContext2D, index: number, color: string, alpha: number) {
  const point = projected.find(value => value.index === index);
  if (!point) throw new Error("coherence:cell-index");
  context.globalAlpha = alpha;
  context.fillStyle = color;
  context.beginPath();
  context.arc(point.x, point.y, 5 + (point.depth + 1) * 1.1, 0, Math.PI * 2);
  context.fill();
  context.globalAlpha = 1;
}

export function createCoherenceViews(root: HTMLElement): CoherenceViews {
  const health = canvasPanel(root, "Health · organ evidence");
  const fingerprint = canvasPanel(root, "Fingerprint · display digest");
  const legend = document.createElement("p");
  legend.textContent = "Health: solid verified · dim undetermined · red failed · shimmering repairing. Evidence never authorizes.";
  health.section.append(legend);
  let cells: Map<number, HealthCell> | undefined;
  let repairs = new Set<number>();
  let animation = 0;
  let disposed = false;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");

  const renderHealth = (time: number) => {
    if (disposed || !cells) return;
    health.context.clearRect(0, 0, 640, 480);
    for (const point of projected) {
      if (point.index === CENTRE) continue;
      const state = cells.get(point.index);
      const color = state === "failed" ? "#f36d78" : state === "verified" ? "#79b8ff" : "#687489";
      const alpha = state === "undetermined" ? 0.28 : 1;
      dot(health.context, point.index, color, alpha);
      if (repairs.has(point.index)) {
        const pulse = reduced.matches ? 0.65 : 0.35 + (Math.sin(time / 360 + point.index) + 1) * 0.25;
        health.context.globalAlpha = pulse;
        health.context.strokeStyle = "#d6b7ff";
        health.context.lineWidth = 2;
        health.context.beginPath();
        health.context.arc(point.x, point.y, 10, 0, Math.PI * 2);
        health.context.stroke();
        health.context.globalAlpha = 1;
      }
    }
    if (repairs.size && !reduced.matches) animation = requestAnimationFrame(renderHealth);
  };
  const clearHealth = (reason: string) => {
    cancelAnimationFrame(animation);
    cells = undefined;
    health.context.clearRect(0, 0, 640, 480);
    health.summary.textContent = reason;
  };
  const clearFingerprint = (reason: string) => {
    fingerprint.context.clearRect(0, 0, 640, 480);
    fingerprint.summary.textContent = reason;
  };
  return {
    health(bytes, decoder, repairing = new Set()) {
      if (disposed) throw new Error("coherence:disposed");
      clearHealth("Unavailable");
      if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 65_536) {
        throw new Error("coherence:snapshot-bounds");
      }
      const decoded = decoder.decode_snapshot(bytes.slice());
      if (decoded.private_cells.length !== 90 || decoded.corner_cells.length !== 20) {
        throw new Error("coherence:snapshot-cells");
      }
      const states = [...decoded.private_cells, ...decoded.corner_cells];
      if (states.some(state => !["verified", "undetermined", "failed"].includes(state))) {
        throw new Error("coherence:snapshot-cells");
      }
      const indices = [...PRIVATE_INDICES, ...CORNER_INDICES];
      if ([...repairing].some(index => !indices.includes(index))) throw new Error("coherence:repair-index");
      repairs = new Set(repairing);
      cells = new Map(indices.map((index, at) => [index, states[at]]));
      health.summary.textContent = ["verified", "undetermined", "failed"]
        .map(state => `${states.filter(cell => cell === state).length} ${state}`).join(" · ") + ` · ${repairs.size} repairing`;
      renderHealth(performance.now());
    },
    fingerprint(digest, pentora) {
      if (disposed) throw new Error("coherence:disposed");
      clearFingerprint("Unavailable");
      if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new Error("coherence:digest-length");
      const trits = pentora.pentora_expand(digest.slice());
      if (!(trits instanceof Uint8Array) || trits.length !== 110 || trits.some(trit => trit > 2)) {
        throw new Error("coherence:expansion");
      }
      for (let at = 0; at < 110; at++) {
        dot(fingerprint.context, MUTABLE_INDICES[at], ["#48556b", "#8bc7ff", "#dcc2ff"][trits[at]], 1);
      }
      fingerprint.summary.textContent = Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
    },
    clearHealth, clearFingerprint,
    dispose() {
      disposed = true;
      cancelAnimationFrame(animation);
      health.section.remove();
      fingerprint.section.remove();
    },
  };
}
