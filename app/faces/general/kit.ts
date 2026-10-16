// SPDX-License-Identifier: AGPL-3.0-or-later
// What the five System settings faces share: how a page opens, how it reads a service and stops printing it the moment
// the read fails, and the small DOM and number formats it prints with. These faces hold no authority. They read data over
// the shell link, print it as text, and have no control that saves, approves, signs or installs anything.
import { connectFace } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import type { FaceClient } from "../../core/index.js";
import type { FaceHost } from "../aumlok/link.js";

/** What a badge reports: data from the node that is fine, data that wants a look, a failure, nothing known, or a plain label. */
export type Tone = "ok" | "attention" | "failed" | "unknown" | "plain";

export function make<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

/**
 * Opens a settings face: the heading and what the page is for appear at once, before and whether or not the shell link
 * comes up, so a page that cannot reach its service still says what it is.
 */
export function openSettings(id: string, title: string, purpose: string, mount: (host: FaceHost) => void | Promise<void>): void {
  openServiceFace(id, title, mount);
  document.getElementById("face")?.querySelector("h1")?.after(make("p", "purpose", purpose));
}

export function openServiceFace(id: string, title: string, mount: (host: FaceHost) => void | Promise<void>): () => void {
  const root = document.getElementById("face");
  if (!root) throw new Error("app:unknown-face");
  const life = new AbortController();
  const heading = make("h1", undefined, title);
  const status = make("p", undefined, "Connecting");
  status.setAttribute("role", "status");
  root.replaceChildren(heading, status);
  let client: FaceClient | undefined;
  const dispose = () => {
    life.abort();
    client?.dispose();
    root.replaceChildren();
  };
  window.addEventListener("pagehide", dispose, { once: true, signal: life.signal });
  void (async () => {
    try {
      if (window.parent === window || !document.referrer) throw new Error("app:shell-required");
      const shellOrigin = new URL(document.referrer).origin;
      if (shellOrigin === "null") throw new Error("app:shell-required");
      client = connectFace({ shellOrigin, pluginId: id, signal: life.signal });
      if (life.signal.aborted) { client.dispose(); return; }
      status.textContent = "";
      await mount({ root, client, signal: life.signal });
    } catch (error) {
      if (!life.signal.aborted) showServiceState(status, error);
    }
  })();
  return dispose;
}

export interface Card {
  readonly section: HTMLElement;
  readonly badge: HTMLElement;
  readonly body: HTMLElement;
}

/** A titled card with a badge at its head; `id` makes the heading's id unique on the page. */
export function card(root: HTMLElement, id: string, title: string): Card {
  const section = make("section", "card");
  section.setAttribute("aria-labelledby", `${id}-title`);
  const head = make("div", "card-head");
  const heading = make("h2", undefined, title);
  heading.id = `${id}-title`;
  const badge = make("p", "badge");
  badge.setAttribute("role", "status");
  head.append(heading, badge);
  const body = make("div", "card-body");
  section.append(head, body);
  root.append(section);
  return { section, badge, body };
}

export function mark(badge: HTMLElement, tone: Tone, label: string): void {
  clearServiceState(badge);
  badge.dataset.tone = tone;
  badge.textContent = label;
}

/** A definition list; each call returns the value cell of a new row. */
export function facts(parent: HTMLElement): (term: string) => HTMLElement {
  const list = make("dl", "facts");
  parent.append(list);
  return term => {
    const row = make("div", "fact");
    const value = make("dd");
    row.append(make("dt", undefined, term), value);
    list.append(row);
    return value;
  };
}

export function note(parent: HTMLElement, text: string, className = "note"): HTMLElement {
  const paragraph = make("p", className, text);
  parent.append(paragraph);
  return paragraph;
}

const NUMBER = new Intl.NumberFormat("en-US");
const WHEN = new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" });
const AGO = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const CLOCK = new Intl.DateTimeFormat("en", { hour: "2-digit", minute: "2-digit", second: "2-digit" });

/** 32768 prints as 32,768. */
export function count(value: number): string {
  return NUMBER.format(value);
}

export function plural(value: number, one: string, many: string): string {
  return `${count(value)} ${value === 1 ? one : many}`;
}

/** Millionths of a dollar as dollars, exactly: 1250000 prints as $1.25 and 123 as $0.000123. */
export function usd(microusd: number): string {
  const part = microusd % 1_000_000;
  const dollars = (microusd - part) / 1_000_000;
  const cents = String(part).padStart(6, "0").replace(/0+$/, "").padEnd(2, "0");
  return `$${NUMBER.format(dollars)}.${cents}`;
}

/** A moment in the reader's own time zone, or null when the number is not a date. */
export function moment(ms: number): string | null {
  const date = new Date(ms);
  return Number.isFinite(date.getTime()) ? WHEN.format(date) : null;
}

/** "3 hours ago" or "in 2 days", counted by this browser's clock, so only a hint beside a time the node gave. */
export function since(ms: number, now: number): string {
  const seconds = Math.round((ms - now) / 1_000);
  const span = Math.abs(seconds);
  const sign = Math.sign(seconds);
  if (span < 60) return AGO.format(sign * span, "second");
  if (span < 3_600) return AGO.format(sign * Math.floor(span / 60), "minute");
  if (span < 86_400) return AGO.format(sign * Math.floor(span / 3_600), "hour");
  if (span < 2_592_000) return AGO.format(sign * Math.floor(span / 86_400), "day");
  if (span < 31_536_000) return AGO.format(sign * Math.floor(span / 2_592_000), "month");
  return AGO.format(sign * Math.floor(span / 31_536_000), "year");
}

/** Hexadecimal digits in groups of eight, the way they are compared by eye. */
export function groups(hex: string): string {
  return hex.match(/.{1,8}/g)?.join(" ") ?? hex;
}

export interface Reading<T> {
  /** Milliseconds between reads while the page is visible; 0 reads only on load and on request. */
  readonly every: number;
  /** Fetches and strictly reads the data; throws a refusal code when anything is wrong. */
  read(signal: AbortSignal): Promise<T>;
  show(value: T, at: number): void;
  /** Called with the read failure; the face must clear whatever it printed from the node. */
  fail(reason: unknown): void;
}

/**
 * Puts the Refresh control and the page's stage on the face, lets `build` fill the stage and name how to read, then reads
 * on load, on request and on a timer. The moment a read fails the face is told to clear what it printed, so a stale value
 * never stands on screen behind a service that has stopped answering. A read that has been superseded is ignored.
 */
export function follow<T>(host: FaceHost, build: (stage: HTMLElement) => Reading<T>): void {
  const { root, signal } = host;
  const refresh = make("button", undefined, "Refresh");
  refresh.type = "button";
  const stamp = make("span", "stamp");
  const bar = make("div", "toolbar");
  bar.append(refresh, stamp);
  const stage = make("div", "stage");
  root.append(bar, stage);
  const reading = build(stage);
  let latest = 0;
  let busy = false;
  const load = async () => {
    const mine = ++latest;
    busy = true;
    refresh.disabled = true;
    try {
      const value = await reading.read(signal);
      if (!signal.aborted && mine === latest) {
        reading.show(value, Date.now());
        stamp.textContent = `Read ${CLOCK.format(new Date())}`;
      }
    } catch (error) {
      if (!signal.aborted && mine === latest) {
        reading.fail(error);
        stamp.textContent = "";
      }
    } finally {
      if (mine === latest) {
        busy = false;
        refresh.disabled = signal.aborted;
      }
    }
  };
  refresh.addEventListener("click", () => void load(), { signal });
  if (reading.every > 0) {
    const timer = setInterval(() => { if (!busy && document.visibilityState === "visible") void load(); }, reading.every);
    signal.addEventListener("abort", () => clearInterval(timer), { once: true });
  }
  void load();
}
