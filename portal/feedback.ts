// SPDX-License-Identifier: AGPL-3.0-or-later
// What the person sees and hears while two screens find each other: four plain states (searching, seen, exchanging, verified),
// a ring that fills while they hold steady, one ring of light the moment the other screen is first recognised, and two soft
// sounds (recognised, locked). Browser only; no network. Shared by the owner's scene and the phone page. It never affects the
// protocol: it only listens to what the engine and the camera already report.
export type FeedbackState = "searching" | "seen" | "exchanging" | "verified";
export const FEEDBACK_STEPS: ReadonlyArray<readonly [FeedbackState, string]> = [
  ["searching", "Searching"], ["seen", "Seen"], ["exchanging", "Exchanging"], ["verified", "Complete"],
];
import { HINT_TEXT, type Hint } from "./guide.js";
const SVG = "http://www.w3.org/2000/svg";
const RING = 2 * Math.PI * 16;

type Phase = "FACE" | "SEENYOU" | "HANDSHAKE" | "BLOOM" | "REFUSED";

/** Which of the four states, and how full the ring is, for what the engine says and whether the camera has read a frame yet. */
export function feedbackFor(phase: Phase, recognised: boolean): { state: FeedbackState; fill: number; message: string } {
  if (phase === "BLOOM") return { state: "verified", fill: 1, message: "Co-presence complete." };
  if (phase === "HANDSHAKE") return { state: "exchanging", fill: 0.8, message: "Exchanging. Hold steady…" };
  if (phase === "SEENYOU") return { state: "seen", fill: 0.5, message: "Seen you. Hold steady…" };
  if (!recognised) return { state: "searching", fill: 0, message: "Searching for the other screen…" };
  return { state: "seen", fill: 0.25, message: "Seen. Hold steady…" };
}

export type ExchangeFeedback = {
  readonly element: HTMLElement;
  /** Show a state; `message` is the one line under the ring (ignored when the page keeps its own message line). */
  show(state: FeedbackState, fill: number, message?: string): void;
  /** One ring of light around `target`, the moment the other screen is first recognised. */
  pulse(target: HTMLElement): void;
  reset(): void;
};

function quietPreference(): boolean {
  try { return globalThis.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true; } catch { return false; }
}

export function exchangeFeedback(doc: Document = document, ownMessage = true): ExchangeFeedback {
  const element = doc.createElement("div");
  element.className = "fb";
  element.dataset.state = "searching";
  const svg = doc.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 40 40");
  svg.setAttribute("class", "fb-ring");
  svg.setAttribute("aria-hidden", "true");
  const track = doc.createElementNS(SVG, "circle");
  const arc = doc.createElementNS(SVG, "circle");
  for (const circle of [track, arc]) {
    circle.setAttribute("cx", "20"); circle.setAttribute("cy", "20"); circle.setAttribute("r", "16"); circle.setAttribute("fill", "none");
  }
  track.setAttribute("class", "fb-track");
  arc.setAttribute("class", "fb-arc");
  arc.setAttribute("stroke-dasharray", `${RING} ${RING}`);
  arc.setAttribute("stroke-dashoffset", String(RING));
  svg.append(track, arc);
  const message = doc.createElement("p");
  message.className = "fb-message";
  message.setAttribute("aria-live", "polite");
  const steps = doc.createElement("ol");
  steps.className = "fb-steps";
  for (const [state, text] of FEEDBACK_STEPS) {
    const item = doc.createElement("li");
    item.dataset.step = state;
    item.textContent = text;
    steps.append(item);
  }
  if (ownMessage) element.append(svg, message, steps); else element.append(svg, steps);
  return {
    element,
    show(state, fill, text) {
      element.dataset.state = state;
      arc.setAttribute("stroke-dashoffset", String(RING * (1 - Math.max(0, Math.min(1, fill)))));
      if (ownMessage && text !== undefined && message.textContent !== text) message.textContent = text;
      const at = FEEDBACK_STEPS.findIndex(([name]) => name === state);
      steps.querySelectorAll("li").forEach((item, index) => {
        item.dataset.done = String(index < at || state === "verified");
        item.dataset.now = String(index === at && state !== "verified");
      });
    },
    pulse(target) {
      if (quietPreference()) return;
      target.classList.remove("fb-pulse");
      void target.offsetWidth;                 // restart the animation
      target.classList.add("fb-pulse");
      target.addEventListener("animationend", () => target.classList.remove("fb-pulse"), { once: true });
    },
    reset() { this.show("searching", 0, ""); },
  };
}

type AudioConstructor = typeof AudioContext;
/** Two gentle sounds (a soft ping when the other screen is recognised, a rising pair when the pairing locks) and a short buzz on
 *  phones that have one. Silent under a reduced-motion preference and whenever the person has switched sound off; the choice is
 *  remembered when storage allows. Browsers only start audio from a tap, so `unlock()` is called from the Start button. */
export function chimes(): {
  unlock(): void; seen(): void; locked(): void; readonly muted: boolean; mute(on: boolean): void;
} {
  let context: AudioContext | null = null;
  let off = quietPreference();
  try { if (globalThis.localStorage?.getItem("aukora.sound") === "off") off = true; } catch { /* storage may be blocked */ }
  function play(notes: ReadonlyArray<readonly [number, number, number]>, level: number): void {
    if (off || !context) return;
    const start = context.currentTime + 0.02;
    for (const [frequency, at, length] of notes) {
      const oscillator = context.createOscillator();
      const gain = context.createGain();
      oscillator.type = "sine";
      oscillator.frequency.value = frequency;
      gain.gain.setValueAtTime(0, start + at);
      gain.gain.linearRampToValueAtTime(level, start + at + 0.03);
      gain.gain.exponentialRampToValueAtTime(0.0001, start + at + length);
      oscillator.connect(gain).connect(context.destination);
      oscillator.start(start + at);
      oscillator.stop(start + at + length + 0.05);
    }
  }
  const buzz = (pattern: number[]): void => { if (!off) { try { globalThis.navigator?.vibrate?.(pattern); } catch { /* optional */ } } };
  return {
    unlock() {
      if (off) return;
      try {
        const Constructor = (globalThis.AudioContext ?? (globalThis as unknown as { webkitAudioContext?: AudioConstructor }).webkitAudioContext);
        context ??= Constructor ? new Constructor() : null;
        void context?.resume();
      } catch { context = null; }
    },
    seen() { play([[660, 0, 0.22]], 0.05); buzz([18]); },
    locked() { play([[523.25, 0, 0.5], [783.99, 0.16, 0.8]], 0.06); buzz([30, 60, 30]); },
    get muted() { return off; },
    mute(on) {
      off = on;
      try { globalThis.localStorage?.setItem("aukora.sound", on ? "off" : "on"); } catch { /* storage may be blocked */ }
      if (!on) this.unlock();
    },
  };
}

/** A small live preview of this device's own camera with a rounded-square guide where the other screen's code should land, and the
 *  hint beneath it (portal/guide.ts decides the words). The caller owns the video element and the camera; this only frames them. */
export function cameraGuide(doc: Document, video: HTMLVideoElement): { element: HTMLElement; show(hint: Hint | null): void } {
  const element = doc.createElement("div");
  element.className = "fb-guide";
  element.hidden = true;
  const box = doc.createElement("div");
  box.className = "fb-camera";
  const svg = doc.createElementNS(SVG, "svg");
  svg.setAttribute("viewBox", "0 0 100 100");
  svg.setAttribute("class", "fb-frame");
  svg.setAttribute("aria-hidden", "true");
  const square = doc.createElementNS(SVG, "rect");
  // The decoder reads the middle 62 percent first; the guide shows the same square.
  square.setAttribute("x", "19"); square.setAttribute("y", "19"); square.setAttribute("width", "62"); square.setAttribute("height", "62");
  square.setAttribute("rx", "9"); square.setAttribute("fill", "none");
  svg.append(square);
  box.append(video, svg);
  const hint = doc.createElement("p");
  hint.className = "fb-hint";
  hint.setAttribute("aria-live", "polite");
  element.append(box, hint);
  return {
    element,
    show(next) {
      element.hidden = next === null;
      if (next === null) return;
      element.dataset.hint = next;
      if (hint.textContent !== HINT_TEXT[next]) hint.textContent = HINT_TEXT[next];
    },
  };
}
