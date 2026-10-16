// SPDX-License-Identifier: AGPL-3.0-or-later
import { CONTENT } from "./content.js";

export interface Review { box: number; due: number; right: number; wrong: number }
export interface Flag { at: number; context: string; verdict: "confusing" | "wrong" | "love" }
interface Progress {
  version: 1;
  completed: number[];
  positions: Record<string, number>;
  reviews: Record<string, Review>;
  readings: string[];
  flags: Flag[];
}
const KEY = "aukora.lingwa.progress.v1";
const INTERVALS = [4 * 60 * 60_000, 86_400_000, 3 * 86_400_000, 7 * 86_400_000, 16 * 86_400_000, 35 * 86_400_000];
const own = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);
const object = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const integer = (value: unknown, max = Number.MAX_SAFE_INTEGER): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
const tokens = new Set(CONTENT.words.map(word => word.token));
const readerIds = new Set(CONTENT.readers.map(reader => reader.id));

function empty(): Progress {
  return { version: 1, completed: [], positions: {}, reviews: {}, readings: [], flags: [] };
}
function valid(value: unknown): value is Progress {
  if (!object(value) || Object.keys(value).sort().join() !== "completed,flags,positions,readings,reviews,version" || value.version !== 1) return false;
  if (!Array.isArray(value.completed) || value.completed.length > 84 || new Set(value.completed).size !== value.completed.length ||
      !value.completed.every(day => integer(day, 84) && day > 0)) return false;
  if (!object(value.positions) || Object.keys(value.positions).length > 84 || !Object.entries(value.positions).every(([day, step]) =>
    /^[1-9][0-9]?$/.test(day) && Number(day) <= 84 && integer(step, CONTENT.lessons[Number(day) - 1].steps.length - 1))) return false;
  if (!object(value.reviews) || Object.keys(value.reviews).length > tokens.size || !Object.entries(value.reviews).every(([token, review]) =>
    tokens.has(token) && object(review) && Object.keys(review).sort().join() === "box,due,right,wrong" && integer(review.box, 5) &&
    integer(review.due, 8_640_000_000_000_000) && integer(review.right) && integer(review.wrong))) return false;
  if (!Array.isArray(value.readings) || value.readings.length > readerIds.size || new Set(value.readings).size !== value.readings.length ||
      !value.readings.every(id => typeof id === "string" && readerIds.has(id))) return false;
  return Array.isArray(value.flags) && value.flags.length <= 256 && value.flags.every(flag => object(flag) &&
    Object.keys(flag).sort().join() === "at,context,verdict" && integer(flag.at, 8_640_000_000_000_000) &&
    typeof flag.context === "string" && flag.context.length > 0 && flag.context.length <= 160 &&
    ["confusing", "wrong", "love"].includes(flag.verdict as string));
}

export class LearningStore {
  private data: Progress = empty();
  private storage: Storage | undefined;
  notice = "Progress stays in this frame until it closes.";

  constructor() {
    try {
      const storage = window.localStorage;
      const raw = storage.getItem(KEY);
      if (raw !== null) {
        if (raw.length > 262_144) throw new Error("lingwa:progress-invalid");
        let parsed: unknown;
        try { parsed = JSON.parse(raw); } catch { throw new Error("lingwa:progress-invalid"); }
        if (!valid(parsed)) throw new Error("lingwa:progress-invalid");
        this.data = parsed;
      }
      this.storage = storage;
      this.notice = "Progress is local to this browser; it is never an approval or an Aura record.";
    } catch (error) {
      this.notice = error instanceof Error && error.message === "lingwa:progress-invalid"
        ? "Saved progress refused. This session uses memory only."
        : "Browser storage is unavailable in this sandbox. Progress lasts until this frame closes.";
    }
  }

  private save(): void {
    if (!this.storage) return;
    try { this.storage.setItem(KEY, JSON.stringify(this.data)); }
    catch {
      this.storage = undefined;
      this.notice = "Browser storage unavailable. Changes last until this frame closes.";
    }
  }
  completed(day: number): boolean { return this.data.completed.includes(day); }
  count(first = 1, last = 84): number { return this.data.completed.filter(day => day >= first && day <= last).length; }
  position(day: number): number { return own(this.data.positions, String(day)) ? this.data.positions[String(day)] : 0; }
  move(day: number, step: number): void {
    if (!integer(day, 84) || day < 1 || !integer(step, CONTENT.lessons[day - 1].steps.length - 1)) throw new Error("lingwa:lesson-invalid");
    this.data.positions[String(day)] = step;
    this.save();
  }
  complete(day: number): void {
    if (!integer(day, 84) || day < 1) throw new Error("lingwa:lesson-invalid");
    if (!this.completed(day)) this.data.completed.push(day);
    this.data.positions[String(day)] = 0;
    for (const step of CONTENT.lessons[day - 1].steps) {
      if (step.kind === "word" && !own(this.data.reviews, step.token)) {
        this.data.reviews[step.token] = { box: 0, due: Date.now(), right: 0, wrong: 0 };
      }
    }
    this.save();
  }
  learned(): string[] { return Object.keys(this.data.reviews); }
  review(token: string): Review | undefined {
    const review = own(this.data.reviews, token) ? this.data.reviews[token] : undefined;
    return review ? { ...review } : undefined;
  }
  due(now = Date.now()): string[] {
    return this.learned().filter(token => this.data.reviews[token].due <= now)
      .sort((a, b) => this.data.reviews[a].due - this.data.reviews[b].due || a.localeCompare(b));
  }
  grade(token: string, right: boolean): void {
    const review = own(this.data.reviews, token) ? this.data.reviews[token] : undefined;
    if (!review || review.right === Number.MAX_SAFE_INTEGER || review.wrong === Number.MAX_SAFE_INTEGER) throw new Error("lingwa:review-invalid");
    review.box = right ? Math.min(5, review.box + 1) : 0;
    if (right) review.right++; else review.wrong++;
    review.due = Date.now() + INTERVALS[review.box];
    this.save();
  }
  read(id: string): boolean { return this.data.readings.includes(id); }
  markRead(id: string): void {
    if (!readerIds.has(id)) throw new Error("lingwa:reader-invalid");
    if (!this.read(id)) this.data.readings.push(id);
    this.save();
  }
  flags(): readonly Flag[] { return this.data.flags.map(flag => ({ ...flag })); }
  flag(context: string, verdict: Flag["verdict"]): void {
    if (!context || context.length > 160 || !["confusing", "wrong", "love"].includes(verdict)) throw new Error("lingwa:feedback-invalid");
    if (this.data.flags.length >= 256) throw new Error("lingwa:feedback-full");
    this.data.flags.push({ at: Date.now(), context, verdict });
    this.save();
  }
}
