// SPDX-License-Identifier: AGPL-3.0-or-later
// The connection map on a 2D canvas: the owner at the centre, each connection a point on a golden-angle
// spiral, and a line from the owner whose style says how the pairing was recorded. The map reads the list
// it is given and decides nothing: a style is evidence, never a grant.
import { safeText } from "./dom.js";
import type { Connection, Pairing } from "./service.js";

const GOLDEN_ANGLE = Math.PI * (3 - Math.sqrt(5));
const MARGIN = 28;
const HIT_RADIUS = 16;
const LABEL_LIMIT = 12;

export const MARKS: Readonly<Record<Pairing, { color: string; dash: readonly number[]; width: number }>> = {
  "screen-to-screen": { color: "#81d4b4", dash: [], width: 1.8 },
  remote: { color: "#c4aaff", dash: [7, 5], width: 1.2 },
  relayed: { color: "#c4aaff", dash: [2, 5], width: 1.2 },
  unknown: { color: "#8b9099", dash: [1, 6], width: 1 },
  none: { color: "#8b9099", dash: [1, 6], width: 1 },
};

export interface Graph {
  show(connections: readonly Connection[], selected: number): void;
  /** The index of the connection under a pointer position, or -1. */
  pick(clientX: number, clientY: number): number;
}

function shorten(text: string, limit: number): string {
  const letters = [...safeText(text)];
  return letters.length > limit ? `${letters.slice(0, limit - 1).join("")}…` : letters.join("");
}

export function createGraph(canvas: HTMLCanvasElement, signal: AbortSignal): Graph {
  const context = canvas.getContext("2d");
  if (!context) throw new Error("humangraph:canvas-unavailable");
  let connections: readonly Connection[] = [];
  let selected = -1;
  let width = 0;
  let height = 0;

  const spots = (): { x: number; y: number }[] => connections.map((_, at) => {
    const reach = 0.3 + 0.7 * Math.sqrt((at + 0.5) / connections.length);
    const angle = at * GOLDEN_ANGLE;
    return {
      x: width / 2 + Math.cos(angle) * reach * (width / 2 - MARGIN),
      y: height / 2 + Math.sin(angle) * reach * (height / 2 - MARGIN),
    };
  });

  const draw = (): void => {
    if (width === 0) return;
    context.clearRect(0, 0, width, height);
    const points = spots();
    const centre = { x: width / 2, y: height / 2 };
    points.forEach((point, at) => {
      const mark = MARKS[connections[at]?.pairing ?? "none"];
      context.beginPath();
      context.setLineDash([...mark.dash]);
      context.strokeStyle = mark.color;
      context.globalAlpha = at === selected ? 1 : 0.55;
      context.lineWidth = at === selected ? mark.width + 0.8 : mark.width;
      context.moveTo(centre.x, centre.y);
      context.lineTo(point.x, point.y);
      context.stroke();
    });
    context.setLineDash([]);
    points.forEach((point, at) => {
      const mark = MARKS[connections[at]?.pairing ?? "none"];
      context.globalAlpha = 1;
      context.fillStyle = mark.color;
      context.beginPath();
      context.arc(point.x, point.y, at === selected ? 8 : 5.5, 0, Math.PI * 2);
      context.fill();
      if (at === selected) {
        context.strokeStyle = "#e8eaed";
        context.lineWidth = 2;
        context.stroke();
      }
    });
    context.fillStyle = "#96b4ff";
    context.beginPath();
    context.arc(centre.x, centre.y, 11, 0, Math.PI * 2);
    context.fill();
    context.font = "12px system-ui, sans-serif";
    context.fillStyle = "#e8eaed";
    context.textAlign = "center";
    context.textBaseline = "top";
    context.fillText("You", centre.x, centre.y + 16);
    points.forEach((point, at) => {
      if (at !== selected && connections.length > LABEL_LIMIT) return;
      const connection = connections[at];
      if (!connection) return;
      const text = shorten(connection.label || connection.key, 18);
      const half = context.measureText(text).width / 2;
      context.fillText(text, Math.min(Math.max(point.x, half + 4), width - half - 4), point.y + 12);
    });
  };

  const fit = (): void => {
    const box = canvas.getBoundingClientRect();
    if (box.width === 0) return;
    const scale = Math.min(window.devicePixelRatio || 1, 2);
    width = box.width;
    height = Math.round(box.width * 0.75);
    canvas.width = Math.round(width * scale);
    canvas.height = Math.round(height * scale);
    context.setTransform(scale, 0, 0, scale, 0, 0);
    draw();
  };

  const watch = new ResizeObserver(fit);
  watch.observe(canvas);
  signal.addEventListener("abort", () => watch.disconnect(), { once: true });
  fit();

  return {
    show(next, chosen) {
      connections = next;
      selected = chosen;
      draw();
    },
    pick(clientX, clientY) {
      const box = canvas.getBoundingClientRect();
      const x = clientX - box.left;
      const y = clientY - box.top;
      let best = -1;
      let nearest = HIT_RADIUS;
      spots().forEach((point, at) => {
        const away = Math.hypot(point.x - x, point.y - y);
        if (away <= nearest) {
          nearest = away;
          best = at;
        }
      });
      return best;
    },
  };
}
