// SPDX-License-Identifier: AGPL-3.0-or-later
// Readers for the two kira replies this face shows (C4 memory.list.reply and recall). A reply that breaks its shape
// is refused whole: nothing is repaired, defaulted or partly shown.
import type { JsonValue } from "../../core/index.js";

export type Tier = "remembered" | "forgotten";
export type RecallResult = "found" | "empty" | "undetermined";

export interface Note {
  readonly noteId: string;
  readonly category: string;
  readonly at: number;
  readonly citeSeq: number;
  readonly text: string | null;
  readonly demotedSeq: number | null;
  readonly demotedAt: number | null;
}
export interface NotePage { readonly notes: readonly Note[]; readonly next: string | null }
export interface Recalled { readonly noteId: string; readonly text: string; readonly citeSeq: number }
export interface Recall { readonly result: RecallResult; readonly items: readonly Recalled[] }

const PAGE_NOTES = 100;
const MAX_TEXT_BYTES = 65_536;
const encoder = new TextEncoder();
const clock = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function invalid(): Error { return new Error("app:invalid-reply"); }

function object(value: unknown): { readonly [key: string]: JsonValue } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid();
  return value as { readonly [key: string]: JsonValue };
}

function noteId(value: unknown): string {
  if (typeof value !== "string" || /[\u0000-\u001f\u007f-\u009f]/.test(value)) throw invalid();
  const bytes = encoder.encode(value).length;
  if (bytes < 1 || bytes > 128) throw invalid();
  return value;
}

function category(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{1,64}$/.test(value)) throw invalid();
  return value;
}

function text(value: unknown): string {
  if (typeof value !== "string" || encoder.encode(value).length > MAX_TEXT_BYTES) throw invalid();
  return value;
}

function whole(value: unknown, minimum: number): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) throw invalid();
  return value;
}

function nullable<T>(value: unknown, read: (item: unknown) => T): T | null {
  return value === null ? null : read(value);
}

// Remembered notes carry text and no demotion; forgotten notes carry no text and a demotion after their save.
function readNote(value: unknown, tier: Tier): Note {
  const row = object(value);
  const note: Note = {
    noteId: noteId(row.note_id),
    category: category(row.category),
    at: whole(row.at, 0),
    citeSeq: whole(row.cite_seq, 1),
    text: nullable(row.text, text),
    demotedSeq: nullable(row.demoted_seq, item => whole(item, 1)),
    demotedAt: nullable(row.demoted_at, item => whole(item, 0)),
  };
  const shaped = tier === "remembered"
    ? note.text !== null && note.demotedSeq === null && note.demotedAt === null
    : note.text === null && note.demotedAt !== null && note.demotedSeq !== null && note.demotedSeq > note.citeSeq;
  if (!shaped) throw invalid();
  return note;
}

export function readNotePage(value: JsonValue, tier: Tier): NotePage {
  const reply = object(value);
  if (reply.tier !== tier || !Array.isArray(reply.items) || reply.items.length > PAGE_NOTES) throw invalid();
  const notes = reply.items.map(item => readNote(item, tier));
  if (new Set(notes.map(note => note.noteId)).size !== notes.length) throw invalid();
  const next = nullable(reply.next, noteId);
  if (next !== null && notes.length === 0) throw invalid();
  return { notes, next };
}

function readRecalled(value: unknown): Recalled {
  const row = object(value);
  return { noteId: noteId(row.note_id), text: text(row.text), citeSeq: whole(row.cite_seq, 1) };
}

// Only a found recall carries notes, and a found recall carries at least one.
export function readRecall(value: JsonValue): Recall {
  const reply = object(value);
  const result = reply.result;
  if ((result !== "found" && result !== "empty" && result !== "undetermined")
    || !Array.isArray(reply.items) || reply.items.length > PAGE_NOTES) throw invalid();
  const items = reply.items.map(readRecalled);
  if ((result === "found") !== (items.length > 0)) throw invalid();
  if (new Set(items.map(item => item.noteId)).size !== items.length) throw invalid();
  return { result, items };
}

// The save time comes from the node's clock and is informational; the Aura record number is the order.
export function moment(ms: number): { readonly label: string; readonly iso: string } | null {
  const date = new Date(ms);
  return Number.isFinite(date.getTime()) ? { label: clock.format(date), iso: date.toISOString() } : null;
}
