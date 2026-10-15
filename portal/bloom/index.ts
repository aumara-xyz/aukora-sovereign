// SPDX-License-Identifier: AGPL-3.0-or-later
// The relationship bloom: the shared Pentora of a pairing, a picture and nothing more. The panel
// gives it a canvas and a label of its own, apart from the node fingerprint and the health map, and
// nothing here reads either. It proves no meeting, carries no consent and grants no authority.
import { BLOOM_LABEL, hexOf, pairingExpansion, refuse } from "./derive.ts";
import type { PairingExpansion, PentoraPairingExpansion } from "./derive.ts";
import { bloomGeometry } from "./geometry.ts";
import { BLOOM_MS, BLOOM_SIZE, paintBloom } from "./paint.ts";

export { BLOOM_LABEL, DIGEST_BYTES, IDENTITY_BYTES, TRIT_COUNT, pairingExpansion } from "./derive.ts";
export type { PairingExpansion, PentoraPairingExpansion } from "./derive.ts";
export { BLOOM_MS } from "./paint.ts";
export { bindPairingPentora } from "./wasm.ts";

export const BLOOM_NOTE = "A picture of this pairing. It proves no meeting and grants no authority.";

/** The digest text is offered only once the picture has settled, never while it moves. */
export type BloomState = "empty" | "moving" | "settled";

export type BloomViewOptions = {
  readonly pentora?: PentoraPairingExpansion;
  readonly onState?: (state: BloomState, digest: Uint8Array | null) => void;
  /** Defaults to the reader's reduced-motion setting. */
  readonly reducedMotion?: () => boolean;
};

export interface BloomView {
  /** Receipt and commitment-only calls clear the view and refuse. */
  show(digest: Uint8Array): void;
  /** Draw two person-nostr x-only public keys through Rust, or remain empty if either is unknown. */
  showPairing(first: Uint8Array | null, second: Uint8Array | null): Promise<void>;
  clear(): void;
  dispose(): void;
}

function readerPrefersStillness(): boolean {
  return typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function describe(trits: Uint8Array): string {
  const counts = [0, 0, 0];
  for (const trit of trits) counts[trit] = (counts[trit] ?? 0) + 1;
  return `${counts[0]} dim, ${counts[1]} medium and ${counts[2]} bright cells`;
}

/** Any failure leaves the canvas empty: a bloom is shown whole or not at all. */
export function createBloomView(canvas: HTMLCanvasElement, options: BloomViewOptions = {}): BloomView {
  const context = canvas.getContext("2d");
  if (!context) refuse("canvas-unavailable");
  canvas.width = canvas.height = BLOOM_SIZE;
  // The portal's QR canvases are scaled with hard pixels; a bloom is not.
  canvas.style.imageRendering = "auto";
  canvas.setAttribute("role", "img");
  let generation = 0, frame = 0, shown = "", disposed = false;

  const report = (state: BloomState, digest: Uint8Array | null): void => options.onState?.(state, digest);
  const halt = (): void => {
    if (frame) cancelAnimationFrame(frame);
    frame = 0;
  };
  const blank = (): void => {
    halt();
    shown = "";
    context.clearRect(0, 0, BLOOM_SIZE, BLOOM_SIZE);
    canvas.setAttribute("aria-label", `${BLOOM_LABEL}. Nothing shown.`);
    report("empty", null);
  };
  blank();

  const showExpansion = ({ digest, trits }: PairingExpansion): void => {
    if (disposed) refuse("disposed");
    try {
      bloomGeometry();
    } catch (error) {
      ++generation;
      blank();
      throw error;
    }
    // The caller keeps its own bytes; what is shown and reported is this copy.
    const held = digest.slice();
    const text = hexOf(held);
    if (text === shown) return;
    const token = ++generation;
    halt();
    shown = text;
    canvas.setAttribute("aria-label", `${BLOOM_LABEL}. Opening.`);
    report("moving", null);
    if (token !== generation || disposed) return;
    const paint = (progress: number): void => {
      try {
        paintBloom(context, trits, progress);
      } catch (error) {
        ++generation;
        blank();
        throw error;
      }
    };
    const settle = (): void => {
      if (token !== generation || disposed) return;
      canvas.setAttribute("aria-label", `${BLOOM_LABEL}. ${describe(trits)}. Digest ${text}.`);
      report("settled", held.slice());
    };
    if (typeof requestAnimationFrame !== "function" || (options.reducedMotion ?? readerPrefersStillness)()) {
      if (token !== generation || disposed) return;
      paint(1);
      settle();
      return;
    }
    let started = -1;
    const step = (now: number): void => {
      if (token !== generation || disposed) return;
      if (started < 0) started = now;
      const progress = Math.min(1, (now - started) / BLOOM_MS);
      paint(progress);
      if (progress < 1) {
        frame = requestAnimationFrame(step);
      } else {
        frame = 0;
        settle();
      }
    };
    if (token === generation && !disposed) frame = requestAnimationFrame(step);
  };

  return {
    show(_digest) {
      if (disposed) refuse("disposed");
      ++generation;
      blank();
      refuse("person-keys-required");
    },
    async showPairing(first, second) {
      if (disposed) refuse("disposed");
      // Whatever was on screen belongs to an older request and goes at once.
      const token = ++generation;
      blank();
      if (token !== generation || disposed) return;
      if (first === null || second === null) return;
      let expansion: PairingExpansion;
      try {
        expansion = await pairingExpansion(first, second, options.pentora);
      } catch (error) {
        if (token === generation) blank();
        throw error;
      }
      if (token !== generation || disposed) return;
      showExpansion(expansion);
    },
    clear() {
      ++generation;
      blank();
    },
    dispose() {
      disposed = true;
      ++generation;
      blank();
    },
  };
}

const views = new WeakMap<HTMLCanvasElement, { view: BloomView; pentora: PentoraPairingExpansion }>();

/** Draw a pair of person keys with the host's Rust adapter, one view for each canvas. */
export function drawPersonRelationshipBloom(
  canvas: HTMLCanvasElement,
  firstPersonKey: Uint8Array | null,
  secondPersonKey: Uint8Array | null,
  pentora: PentoraPairingExpansion,
): Promise<void> {
  let entry = views.get(canvas);
  if (!entry || entry.pentora !== pentora) {
    entry?.view.dispose();
    entry = { view: createBloomView(canvas, { pentora }), pentora };
    views.set(canvas, entry);
  }
  return entry.view.showPairing(firstPersonKey, secondPersonKey);
}

export type BloomPanel = {
  readonly element: HTMLElement;
  readonly view: BloomView;
  dispose(): void;
};

/** The labelled panel: heading, canvas of its own, a status line and the evidence note. */
export function createBloomPanel(host: HTMLElement, options: BloomViewOptions = {}): BloomPanel {
  const page = host.ownerDocument;
  const element = page.createElement("section"), heading = page.createElement("h2");
  const canvas = page.createElement("canvas"), status = page.createElement("p"), note = page.createElement("p");
  heading.textContent = BLOOM_LABEL;
  status.setAttribute("role", "status");
  note.textContent = BLOOM_NOTE;
  element.append(heading, canvas, status, note);
  const view = createBloomView(canvas, {
    ...options,
    onState(state, digest) {
      status.textContent = state === "settled" && digest ? `Digest ${hexOf(digest)}` : state === "moving" ? "Opening." : "Nothing shown.";
      options.onState?.(state, digest);
    },
  });
  host.append(element);
  return {
    element,
    view,
    dispose() {
      view.dispose();
      element.remove();
    },
  };
}
