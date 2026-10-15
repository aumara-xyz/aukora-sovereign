// SPDX-License-Identifier: AGPL-3.0-or-later
// Two labelled canvases that share nothing but the geometry: "Organ health" (what the organs report about themselves)
// and "Aura fingerprint" (a digest of the Aura head). A health cell is one of three words, a fingerprint trit is a
// digit; no function here accepts one where the other belongs, and neither picture grants anything. An undetermined cell
// is drawn dim and hollow, never as verified. The palette mirrors app/design/tokens.json.
import { CENTRE, POINTS, MUTABLE_INDICES, PRIVATE_INDICES, CORNER_INDICES } from "./geometry.js";
import { toHex } from "./bytes.js";
import { CHECKS_PER_ORGAN, ORGANS, PAIRS, STATE_ORDER, openCells, organTallies, totals } from "./organs.js";
import type { Tally } from "./organs.js";
import type { AuraSourceView } from "./head.js";

export type HealthCell = "verified" | "undetermined" | "failed";
export interface HealthMeta {
  readonly epoch?: number;
  readonly sequence?: number;
  readonly observed_at_ms?: number;
}
export interface DecodedHealth {
  readonly private_cells: readonly HealthCell[];
  readonly corner_cells: readonly HealthCell[];
  readonly meta?: HealthMeta;
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
  /**
   * Draws a derivation the caller already has: the 32-byte display digest and the 110 trits that came from it. A head
   * that differs from the last one shown sweeps in and keeps the digest and head text hidden until it settles; the
   * first head, a repeated head and reduced motion settle at once. The head text is shown only once settled.
   */
  showFingerprint(digest32: Uint8Array, trits110: Uint8Array, head?: string): void;
  /** A new head is being read: nothing is drawn or named until it completes, but the last one is remembered. */
  loadingFingerprint(): void;
  /** The three sources the head was committed over, or null when the service did not say. */
  showSources(sources: readonly AuraSourceView[] | null): void;
  clearHealth(reason: string): void;
  /** A failure: clears the picture and forgets the last head, so the next one is a first. */
  clearFingerprint(reason: string): void;
  dispose(): void;
}

const W = 640;
const H = 480;
const TAU = Math.PI * 2;
// The display timing of crates/pentora motion.rs: the digits sweep in over TRANSITION_MS and text stays hidden until SETTLE_MS.
const TRANSITION_MS = 400;
const SETTLE_MS = 1_200;
const TRIT_COUNT = MUTABLE_INDICES.length;
const TRIT_AT = new Map(MUTABLE_INDICES.map((index, at) => [index, at] as const));
const PALETTE = {
  canvas: "#0b0d18", text: "#e8eaed", muted: "#8b9099", blue: "#96b4ff", failed: "#f2555a",
  gold: "#e0b76a", mint: "#81d4b4", violet: "#c4aaff",
} as const;
// Fingerprint digits use hues the health map never uses.
const TRIT_COLOURS = [PALETTE.gold, PALETTE.mint, PALETTE.violet] as const;
const SOURCE_TITLES: Readonly<Record<string, string>> = {
  "gate-ledger": "Gate ledger", "kira-chain": "Kira chain", "code-chain": "Code chain",
};
const ABSENCE_TEXT: Readonly<Record<string, string>> = {
  "gate-ledger-empty": "no entries yet", "kira-ledger-empty": "no entries yet", "code-record-missing": "no code record",
};
const PRIVATE_COUNT = PRIVATE_INDICES.length;
const HEALTH_INDICES: readonly number[] = [...PRIVATE_INDICES, ...CORNER_INDICES];

interface Projected { index: number; x: number; y: number; depth: number }
const projected: Projected[] = POINTS.map(([x, y, z], index) => ({
  index, x: 320 + (x * 0.86 + z * 0.5) * 185,
  y: 240 + (y * 0.9 - z * 0.36 + x * 0.2) * 185,
  depth: z * 0.86 - x * 0.5,
})).sort((a, b) => a.depth - b.depth);
const byIndex = new Map(projected.map(point => [point.index, point]));
const radius = (point: Projected) => 5 + (point.depth + 1) * 1.1;

function make<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function canvasPanel(root: HTMLElement, id: string, title: string, caption: string) {
  const section = make("section", "panel");
  section.setAttribute("aria-labelledby", `${id}-title`);
  const heading = make("h2", undefined, title);
  heading.id = `${id}-title`;
  const note = make("p", "caption", caption);
  const canvas = make("canvas");
  const ratio = Math.min(2, Math.max(1, window.devicePixelRatio || 1));
  canvas.width = W * ratio;
  canvas.height = H * ratio;
  canvas.setAttribute("role", "img");
  canvas.setAttribute("aria-label", `${title}: unavailable`);
  const summary = make("p", "summary", "Unavailable");
  summary.setAttribute("role", "status");
  section.append(heading, note, canvas, summary);
  root.append(section);
  const context = canvas.getContext("2d");
  if (!context) throw new Error("coherence:canvas-unavailable");
  context.setTransform(ratio, 0, 0, ratio, 0, 0);
  const label = (text: string) => canvas.setAttribute("aria-label", `${title}: ${text}`);
  return { section, canvas, summary, context, label };
}

function tallyText(tally: Tally): string {
  return `${tally.verified} · ${tally.undetermined} · ${tally.failed}`;
}

function path(context: CanvasRenderingContext2D, x: number, y: number, r: number, corner: boolean) {
  context.beginPath();
  if (corner) {
    context.moveTo(x, y - r * 1.3);
    context.lineTo(x + r * 1.3, y);
    context.lineTo(x, y + r * 1.3);
    context.lineTo(x - r * 1.3, y);
    context.closePath();
  } else context.arc(x, y, r, 0, TAU);
}

interface HealthCellView { state: HealthCell; corner: boolean; owners: readonly number[] }

// What the fingerprint is showing or sweeping toward; `previous` is the last head's digits, equal to `next` for a first head.
interface Motion {
  readonly hex: string;
  readonly head: string | null;
  readonly previous: Uint8Array;
  readonly next: Uint8Array;
  readonly changed: readonly boolean[];
  readonly started: number;
  settled: boolean;
}

export function createCoherenceViews(root: HTMLElement): CoherenceViews {
  const health = canvasPanel(root, "health", "Organ health", "Evidence from the five organs · grants nothing");
  const fingerprint = canvasPanel(root, "fingerprint", "Aura fingerprint", "Fingerprint — display only · digest of the Aura head, not a health signal");

  const legend = make("ul", "legend");
  for (const [state, text] of [
    ["verified", "Verified"], ["undetermined", "Undetermined · verification unavailable"], ["failed", "Failed"],
    ["repairing", "Repairing"], ["corner", "Square: a corner two organs confirm"],
  ] as const) {
    const item = make("li");
    const swatch = make("span", "swatch");
    swatch.dataset.state = state;
    swatch.setAttribute("aria-hidden", "true");
    item.append(swatch, make("span", undefined, text));
    legend.append(item);
  }
  const contextLine = make("p", "context");
  const table = make("table", "organs");
  const headings = make("tr");
  for (const title of ["Organ", "Own checks (18)", "Shared corners (8)"]) {
    const cell = make("th", undefined, title);
    cell.setAttribute("scope", "col");
    headings.append(cell);
  }
  const header = make("thead");
  header.append(headings);
  const body = make("tbody");
  const rows = ORGANS.map((organ, at) => {
    const row = make("tr");
    const name = make("th");
    name.setAttribute("scope", "row");
    const pick = make("button", undefined, organ);
    pick.type = "button";
    pick.setAttribute("aria-pressed", "false");
    name.append(pick);
    const own = make("td", undefined, "—");
    const shared = make("td", undefined, "—");
    row.append(name, own, shared);
    body.append(row);
    return { pick, own, shared, at };
  });
  table.append(make("caption", undefined, "Cells per organ: verified · undetermined · failed"), header, body);
  const open = make("details", "open-cells");
  const openTitle = make("summary", undefined, "Cells not verified");
  const openList = make("ul");
  open.append(openTitle, openList);
  open.hidden = true;
  health.section.append(legend, contextLine, table, open);

  const sources = make("div", "sources");
  sources.hidden = true;
  const note = make("p", "note", "Display only: a picture of the Aura head's digest, drawn by one Rust function compiled to WASM. It is not a security check, it cannot be compared by eye to establish trust, and it grants nothing.");
  fingerprint.section.append(sources, note);

  let cells: Map<number, HealthCellView> | undefined;
  let repairs = new Set<number>();
  let selected: number | null = null;
  let animation = 0;
  let disposed = false;
  const reduced = matchMedia("(prefers-reduced-motion: reduce)");

  const renderHealth = (time: number) => {
    const ctx = health.context;
    ctx.clearRect(0, 0, W, H);
    if (disposed || !cells) return;
    for (const point of projected) {
      if (point.index === CENTRE) continue;
      const cell = cells.get(point.index);
      if (!cell) continue;
      const r = radius(point);
      const picked = selected !== null && cell.owners.includes(selected);
      const base = selected === null || picked ? 1 : 0.3;
      path(ctx, point.x, point.y, r, cell.corner);
      if (cell.state === "undetermined") {
        ctx.globalAlpha = 0.22 * base;
        ctx.fillStyle = PALETTE.muted;
        ctx.fill();
        ctx.globalAlpha = 0.8 * base;
        ctx.strokeStyle = PALETTE.muted;
        ctx.lineWidth = 1;
        ctx.setLineDash([2, 2]);
        ctx.stroke();
        ctx.setLineDash([]);
      } else {
        ctx.globalAlpha = base;
        ctx.fillStyle = cell.state === "failed" ? PALETTE.failed : PALETTE.blue;
        ctx.fill();
        if (cell.state === "failed") {
          ctx.strokeStyle = PALETTE.canvas;
          ctx.lineWidth = 1.6;
          ctx.beginPath();
          ctx.moveTo(point.x - r * 0.55, point.y - r * 0.55);
          ctx.lineTo(point.x + r * 0.55, point.y + r * 0.55);
          ctx.moveTo(point.x + r * 0.55, point.y - r * 0.55);
          ctx.lineTo(point.x - r * 0.55, point.y + r * 0.55);
          ctx.stroke();
        }
      }
      if (picked) {
        ctx.globalAlpha = 0.9;
        ctx.strokeStyle = PALETTE.text;
        ctx.lineWidth = 1.5;
        path(ctx, point.x, point.y, r + 3.5, cell.corner);
        ctx.stroke();
      }
      if (repairs.has(point.index)) {
        ctx.globalAlpha = reduced.matches ? 0.7 : 0.3 + (Math.sin(time / 360 + point.index) + 1) * 0.3;
        ctx.strokeStyle = PALETTE.text;
        ctx.lineWidth = 2;
        path(ctx, point.x, point.y, r + 6, cell.corner);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }
    cancelAnimationFrame(animation);
    if (repairs.size && !reduced.matches) animation = requestAnimationFrame(renderHealth);
  };

  const markSelection = () => {
    for (const row of rows) row.pick.setAttribute("aria-pressed", String(row.at === selected));
  };
  const toggleOrgan = (organ: number) => {
    selected = selected === organ ? null : organ;
    markSelection();
    if (cells) renderHealth(performance.now());
  };
  for (const row of rows) row.pick.addEventListener("click", () => toggleOrgan(row.at));

  // Empties the map and its text. The organ highlight is the viewer's choice, so only an outside clear drops it.
  const emptyHealth = (reason: string) => {
    cancelAnimationFrame(animation);
    cells = undefined;
    repairs = new Set();
    for (const row of rows) {
      row.own.textContent = "—";
      row.shared.textContent = "—";
    }
    health.context.clearRect(0, 0, W, H);
    health.summary.textContent = reason;
    health.label(reason);
    contextLine.textContent = "";
    openList.replaceChildren();
    open.hidden = true;
  };
  const clearHealth = (reason: string) => {
    selected = null;
    markSelection();
    emptyHealth(reason);
  };
  // The fingerprint's motion: the last head shown is remembered across a pending read, so a changed head can sweep in from it.
  let motion: Motion | undefined;
  let pending = false;
  let frame = 0;
  let textSettled: boolean | undefined;
  let sourceList: readonly AuraSourceView[] | null = null;

  const renderSources = () => {
    sources.replaceChildren();
    sources.hidden = sourceList === null;
    if (sourceList === null) return;
    const settled = textSettled === true && motion !== undefined;
    const present = sourceList.filter(item => item.head !== null).length;
    const items = make("ul");
    for (const item of sourceList) {
      const row = make("li");
      row.dataset.present = String(item.head !== null);
      row.append(make("strong", undefined, SOURCE_TITLES[item.name] ?? item.name));
      row.append(make("span", undefined, item.head === null
        ? `absent · ${ABSENCE_TEXT[item.absence ?? ""] ?? "reason not named"}`
        : `${item.entries} entries${settled ? ` · ${item.head.slice(0, 16)}…` : ""}`));
      items.append(row);
    }
    sources.append(make("p", undefined, `Head committed over ${present} of ${sourceList.length} sources`), items);
    if (settled && motion?.head) sources.append(make("p", "head", `Aura head ${motion.head}`));
  };
  // Text follows the motion: nothing that names the digest or a head while the picture is still moving.
  const renderText = (settled: boolean) => {
    if (textSettled === settled || !motion) return;
    textSettled = settled;
    fingerprint.summary.textContent = settled ? motion.hex : "Updating fingerprint…";
    fingerprint.label(settled ? `display digest ${motion.hex.match(/.{8}/g)?.join(" ") ?? motion.hex}` : "updating");
    renderSources();
  };
  const paintFingerprint = (now: number) => {
    const ctx = fingerprint.context;
    ctx.clearRect(0, 0, W, H);
    const m = motion;
    if (!m || pending || disposed) return;
    const elapsed = Math.max(0, now - m.started);
    const settled = m.settled || elapsed >= SETTLE_MS;
    const cut = settled ? TRIT_COUNT : Math.floor((Math.min(elapsed, TRANSITION_MS) * TRIT_COUNT) / TRANSITION_MS);
    const centre = byIndex.get(CENTRE);
    if (centre) {
      ctx.globalAlpha = 0.5;
      ctx.strokeStyle = PALETTE.muted;
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(centre.x, centre.y, 3, 0, TAU);
      ctx.stroke();
    }
    for (const point of projected) {
      const at = TRIT_AT.get(point.index);
      if (at === undefined) continue;
      ctx.globalAlpha = 1;
      ctx.fillStyle = TRIT_COLOURS[at < cut ? m.next[at] : m.previous[at]];
      ctx.beginPath();
      ctx.arc(point.x, point.y, radius(point), 0, TAU);
      ctx.fill();
      if (!settled && m.changed[at]) {
        ctx.globalAlpha = 0.3 + (Math.sin(now / 150 + at) + 1) * 0.3;
        ctx.strokeStyle = PALETTE.text;
        ctx.lineWidth = 1.5;
        ctx.beginPath();
        ctx.arc(point.x, point.y, radius(point) + 3.5, 0, TAU);
        ctx.stroke();
      }
    }
    ctx.globalAlpha = 1;
    if (settled) m.settled = true;
    renderText(settled);
    cancelAnimationFrame(frame);
    if (!settled) frame = requestAnimationFrame(paintFingerprint);
  };

  const loadingFingerprint = () => {
    cancelAnimationFrame(frame);
    pending = true;
    textSettled = undefined;
    sourceList = null;
    fingerprint.context.clearRect(0, 0, W, H);
    fingerprint.summary.textContent = "Loading fingerprint";
    fingerprint.label("loading");
    renderSources();
  };
  const clearFingerprint = (reason: string) => {
    cancelAnimationFrame(frame);
    pending = false;
    motion = undefined;
    textSettled = undefined;
    sourceList = null;
    fingerprint.context.clearRect(0, 0, W, H);
    fingerprint.summary.textContent = reason;
    fingerprint.label(reason);
    renderSources();
  };

  const showFingerprint = (digest: Uint8Array, trits: Uint8Array, head?: string) => {
    if (disposed) throw new Error("coherence:disposed");
    loadingFingerprint();
    if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new Error("coherence:digest-length");
    if (!(trits instanceof Uint8Array) || trits.length !== TRIT_COUNT || trits.some(trit => trit > 2)) {
      throw new Error("coherence:expansion");
    }
    const hex = toHex(digest);
    const now = performance.now();
    if (motion && motion.hex === hex) {
      // The same head again keeps the transition it is in; it does not restart or settle early.
      motion = { ...motion, head: head ?? motion.head };
    } else {
      const previous = motion ? motion.next : trits.slice();
      const moving = motion !== undefined && !reduced.matches;
      motion = {
        hex, head: head ?? null, previous, next: trits.slice(), started: now, settled: !moving,
        changed: Array.from(trits, (trit, at) => trit !== previous[at]),
      };
    }
    pending = false;
    textSettled = undefined;
    paintFingerprint(now);
  };

  return {
    health(bytes, decoder, repairing = new Set()) {
      if (disposed) throw new Error("coherence:disposed");
      emptyHealth("Unavailable");
      if (!(bytes instanceof Uint8Array) || !bytes.length || bytes.length > 65_536) {
        throw new Error("coherence:snapshot-bounds");
      }
      const decoded = decoder.decode_snapshot(bytes.slice());
      const states = [...decoded.private_cells, ...decoded.corner_cells];
      if (decoded.private_cells.length !== PRIVATE_COUNT || decoded.corner_cells.length !== CORNER_INDICES.length
        || states.some(state => !STATE_ORDER.includes(state))) {
        throw new Error("coherence:snapshot-cells");
      }
      if ([...repairing].some(index => !HEALTH_INDICES.includes(index))) throw new Error("coherence:repair-index");
      repairs = new Set(repairing);
      cells = new Map(HEALTH_INDICES.map((index, at) => {
        const corner = at >= PRIVATE_COUNT;
        const owners = corner ? PAIRS[Math.floor((at - PRIVATE_COUNT) / 2)] : [Math.floor(at / CHECKS_PER_ORGAN)];
        return [index, { state: states[at], corner, owners }];
      }));
      const all = totals(decoded);
      const summary = all.verified === states.length
        ? `Whole · ${all.verified} of ${states.length} verified`
        : `${all.verified} verified · ${all.undetermined} undetermined · ${all.failed} failed · ${repairs.size} repairing`;
      health.summary.textContent = summary;
      health.label(summary);
      organTallies(decoded).forEach((tally, at) => {
        rows[at].own.textContent = tallyText(tally.private);
        rows[at].shared.textContent = tallyText(tally.corners);
      });
      const meta = decoded.meta;
      const observed = meta?.observed_at_ms === undefined ? undefined : new Date(meta.observed_at_ms);
      contextLine.textContent = meta ? [
        meta.epoch !== undefined ? `Epoch ${meta.epoch}` : "",
        meta.sequence !== undefined ? `Aura sequence ${meta.sequence}` : "",
        observed && Number.isFinite(observed.getTime()) ? `Observed ${observed.toLocaleTimeString()}` : "",
      ].filter(Boolean).join(" · ") : "";
      const notVerified = openCells(decoded);
      openList.replaceChildren(...notVerified.map(item => make("li", undefined, `${item.label}: ${item.state}`)));
      openTitle.textContent = `Cells not verified (${notVerified.length})`;
      open.hidden = notVerified.length === 0;
      renderHealth(performance.now());
    },
    fingerprint(digest, pentora) {
      if (disposed) throw new Error("coherence:disposed");
      loadingFingerprint();
      if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new Error("coherence:digest-length");
      showFingerprint(digest, pentora.pentora_expand(digest.slice()));
    },
    showFingerprint,
    loadingFingerprint,
    showSources(list) {
      sourceList = list;
      renderSources();
    },
    clearHealth, clearFingerprint,
    dispose() {
      disposed = true;
      cancelAnimationFrame(animation);
      cancelAnimationFrame(frame);
      health.section.remove();
      fingerprint.section.remove();
    },
  };
}
