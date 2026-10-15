// SPDX-License-Identifier: AGPL-3.0-or-later
// Readers for the replies and events this face shows. They follow the pinned v2 records of crates/canon: the session
// summary and entry, the model stream, proposal states and refusals. A value that breaks its shape is refused whole:
// nothing is repaired, defaulted or partly shown. Nothing read here is an instruction; every string is data.
import type { JsonValue } from "../../core/index.js";

export type Mode = "chat" | "build";
export type Role = "owner" | "auma" | "tool" | "context";
export type OutcomeState = "applied" | "refused" | "expired" | "retired" | "incomplete" | "failed" | "conflict" | "unknown";
export type SourceKind = "owner" | "auma" | "document" | "memory" | "app" | "contact";

export interface Summary {
  readonly sessionId: string;
  readonly threadId: string;
  readonly title: string;
  readonly mode: Mode;
  readonly archived: boolean;
  readonly sequence: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
}
// A function-call suggestion. Auma never executes one, and this face only shows it.
export interface Call { readonly id: string; readonly name: string; readonly arguments: string }
export interface Source { readonly kind: SourceKind; readonly detail: string | null }
export interface Entry {
  readonly sessionId: string;
  readonly sequence: number;
  readonly role: Role;
  readonly content: string;
  readonly calls: readonly Call[];
  readonly callId: string | null;
  readonly source: Source;
  readonly atMs: number;
  readonly commitment: string;
}
export interface Receipt {
  readonly model: string;
  readonly promptTokens: number;
  readonly completionTokens: number;
  readonly costMicroUsd: number;
  readonly seq: number;
}
export interface Listed { readonly items: readonly Summary[]; readonly next: string | null }
export interface Opened { readonly summary: Summary; readonly entries: readonly Entry[]; readonly next: number | null }

export type Event =
  | { readonly kind: "entry"; readonly entry: Entry }
  | { readonly kind: "created"; readonly summary: Summary }
  | { readonly kind: "start"; readonly request: string; readonly reservation: string }
  | {
    readonly kind: "delta"; readonly request: string; readonly reservation: string; readonly index: number;
    readonly text: string | null; readonly calls: readonly Call[];
  }
  | {
    readonly kind: "end"; readonly request: string; readonly reservation: string; readonly cancelled: boolean;
    readonly finish: string | null; readonly receipt: Receipt;
  }
  | {
    readonly kind: "failed"; readonly request: string; readonly reservation: string; readonly code: string;
    readonly next: string; readonly receipt: Receipt;
  }
  | { readonly kind: "accepted"; readonly proposal: string }
  | { readonly kind: "outcome"; readonly proposal: string; readonly state: OutcomeState }
  | { readonly kind: "refused"; readonly code: string; readonly next: string }
  | { readonly kind: "other" };

// Bounds of the shared records (crates/canon session.rs): a page, a turn or entry, a title, a stream chunk.
export const PAGE = 100;
export const TEXT_BYTES = 32_768;
export const TITLE_BYTES = 256;
const FRAME_BYTES = 65_536;
const DELTA_BYTES = 8_192;
const CALLS = 32;
const CHUNKS = 16;
const ID_BYTES = 128;

type Row = { readonly [key: string]: JsonValue };

const encoder = new TextEncoder();
const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const CODE = /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/;
const STATES: readonly string[] = ["applied", "refused", "expired", "retired", "incomplete", "failed", "conflict", "unknown"];
const ENVELOPE = ["body", "id", "kind", "provenance", "v"];

function bad(): Error { return new Error("app:invalid-reply"); }

function isRow(value: unknown): value is Row {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// Exactly these keys: an unknown key is as much a break of the shape as a missing one.
function row(value: unknown, keys: readonly string[]): Row {
  if (!isRow(value)) throw bad();
  const found = Object.keys(value);
  if (found.length !== keys.length || found.some(key => !keys.includes(key))) throw bad();
  return value;
}

export function byteLength(value: string): number {
  return encoder.encode(value).length;
}

// A UTF-16 unit is at most three UTF-8 bytes, so most strings are settled without encoding them.
function within(value: string, max: number): boolean {
  return value.length * 3 <= max || encoder.encode(value).length <= max;
}

function text(value: unknown, max: number): string {
  if (typeof value !== "string" || !within(value, max)) throw bad();
  return value;
}

function whole(value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) throw bad();
  return value;
}

function flag(value: unknown): boolean {
  if (typeof value !== "boolean") throw bad();
  return value;
}

function hex(value: unknown, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) throw bad();
  return value;
}

function nullable<T>(value: unknown, read: (item: unknown) => T): T | null {
  return value === null ? null : read(value);
}

function list<T>(value: unknown, max: number, read: (item: unknown) => T): T[] {
  if (!Array.isArray(value) || value.length > max) throw bad();
  return value.map(item => read(item));
}

function code(value: unknown): string {
  if (typeof value !== "string" || !CODE.test(value)) throw bad();
  return value;
}

function identifier(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || !within(value, ID_BYTES) || /[\u0000-\u001f\u007f-\u009f]/.test(value)) {
    throw bad();
  }
  return value;
}

function mode(value: unknown): Mode {
  if (value !== "chat" && value !== "build") throw bad();
  return value;
}

function role(value: unknown): Role {
  if (value !== "owner" && value !== "auma" && value !== "tool" && value !== "context") throw bad();
  return value;
}

// Every v2 record names its version and its commitment algorithm.
function versioned(record: Row): void {
  if (record.v !== 2 || record.algorithm !== "sha256") throw bad();
}

export function readSummary(value: unknown): Summary {
  const o = row(value, [
    "algorithm", "archived", "created_at_ms", "mode", "sequence", "session_id", "thread_id", "title", "updated_at_ms", "v",
  ]);
  versioned(o);
  return {
    sessionId: hex(o.session_id, HEX32),
    threadId: hex(o.thread_id, HEX32),
    title: text(o.title, TITLE_BYTES),
    mode: mode(o.mode),
    archived: flag(o.archived),
    sequence: whole(o.sequence, 0),
    createdAtMs: whole(o.created_at_ms, 0),
    updatedAtMs: whole(o.updated_at_ms, 0),
  };
}

// The ingress label the supervisor stamped. A stranger's data never reaches a session, so that label breaks the shape.
function readSource(value: unknown): Source {
  if (!isRow(value)) throw bad();
  const kind = value.source;
  if (kind === "owner" || kind === "auma" || kind === "document" || kind === "memory") {
    row(value, ["source"]);
    return { kind, detail: null };
  }
  if (kind === "app") {
    return { kind, detail: hex(row(value, ["app_id", "source"]).app_id, HEX32) };
  }
  if (kind === "contact") {
    const o = row(value, ["algorithm", "npub", "source"]);
    const npub = text(o.npub, 128);
    if (o.algorithm !== "secp256k1-schnorr" || !npub.startsWith("npub1")) throw bad();
    return { kind, detail: npub };
  }
  throw bad();
}

function readCall(value: unknown): Call {
  const o = row(value, ["function", "id", "type"]);
  if (o.type !== "function") throw bad();
  const fn = row(o.function, ["arguments", "name"]);
  return { id: text(o.id, FRAME_BYTES), name: text(fn.name, FRAME_BYTES), arguments: text(fn.arguments, FRAME_BYTES) };
}

export function readEntry(value: unknown): Entry {
  const o = row(value, [
    "algorithm", "at_ms", "commitment", "content", "provenance", "role", "sequence", "session_id", "tool_call_id",
    "tool_calls", "v",
  ]);
  versioned(o);
  const entryRole = role(o.role);
  const source = readSource(o.provenance);
  // A role never stands in for the ingress label: owner and Auma lines must carry their own.
  if ((entryRole === "owner" && source.kind !== "owner") || (entryRole === "auma" && source.kind !== "auma")) throw bad();
  return {
    sessionId: hex(o.session_id, HEX32),
    sequence: whole(o.sequence, 1),
    role: entryRole,
    content: text(o.content, TEXT_BYTES),
    calls: list(o.tool_calls, CALLS, readCall),
    callId: nullable(o.tool_call_id, item => text(item, ID_BYTES)),
    source,
    atMs: whole(o.at_ms, 0),
    commitment: hex(o.commitment, HEX64),
  };
}

export function readListed(value: unknown): Listed {
  const o = row(value, ["items", "next"]);
  const items = list(o.items, PAGE, readSummary);
  if (new Set(items.map(item => item.sessionId)).size !== items.length) throw bad();
  const next = nullable(o.next, item => hex(item, HEX32));
  if (next !== null && items.length === 0) throw bad();
  return { items, next };
}

// One page of a session: contiguous entries of the summary's own session, none past its last sequence, and a cursor
// that is the last entry returned whenever the node says another page exists.
export function readOpened(value: unknown): Opened {
  const o = row(value, ["entries", "next_sequence", "summary"]);
  const summary = readSummary(o.summary);
  const entries = list(o.entries, PAGE, readEntry);
  entries.forEach((entry, at) => {
    if (entry.sessionId !== summary.sessionId || entry.sequence > summary.sequence
      || (at > 0 && entry.sequence !== entries[at - 1].sequence + 1)) throw bad();
  });
  const next = nullable(o.next_sequence, item => whole(item, 1));
  if (next !== null && (entries.length === 0 || next !== entries[entries.length - 1].sequence)) throw bad();
  return { summary, entries, next };
}

function readReceipt(value: unknown, request: string, reservation: string): Receipt {
  const o = row(value, [
    "algorithm", "commitment", "model", "receipt_seq", "request_id", "reservation_id", "usage", "v",
  ]);
  versioned(o);
  hex(o.commitment, HEX64);
  if (hex(o.request_id, HEX32) !== request || hex(o.reservation_id, HEX32) !== reservation) throw bad();
  const usage = row(o.usage, ["completion_tokens", "cost_microusd", "prompt_tokens"]);
  return {
    model: text(o.model, TITLE_BYTES),
    promptTokens: whole(usage.prompt_tokens, 0, 32_768),
    completionTokens: whole(usage.completion_tokens, 0, 32_768),
    costMicroUsd: whole(usage.cost_microusd, 0),
    seq: whole(o.receipt_seq, 1),
  };
}

// One value of the session.event topic: an FD 4 event as the node forwards it, with or without its envelope fields.
// Kinds that belong to other faces (memory, health, replies to commands) and kinds this face does not know are not
// errors: they are not this face's to show, so they read as "other".
export function readEvent(value: unknown): Event {
  if (!isRow(value) || typeof value.kind !== "string" || !("body" in value)) throw bad();
  if (Object.keys(value).some(key => !ENVELOPE.includes(key)) || (value.v !== undefined && value.v !== 2)) throw bad();
  const body = value.body;
  switch (value.kind) {
    case "session.entry":
      return { kind: "entry", entry: readEntry(body) };
    case "session.append":
      return { kind: "entry", entry: readEntry(row(body, ["entry"]).entry) };
    case "session.create":
      return { kind: "created", summary: readSummary(body) };
    case "model.start": {
      const o = row(body, ["max_pending_chunks", "request_id", "reservation_id"]);
      whole(o.max_pending_chunks, 1, CHUNKS);
      return { kind: "start", request: hex(o.request_id, HEX32), reservation: hex(o.reservation_id, HEX32) };
    }
    case "model.delta": {
      const o = row(body, ["algorithm", "content", "index", "request_id", "reservation_id", "tool_calls", "v"]);
      versioned(o);
      return {
        kind: "delta",
        request: hex(o.request_id, HEX32),
        reservation: hex(o.reservation_id, HEX32),
        index: whole(o.index, 0),
        text: nullable(o.content, item => text(item, DELTA_BYTES)),
        calls: list(o.tool_calls, CALLS, readCall),
      };
    }
    case "model.end":
    case "model.cancel": {
      const o = row(body, ["finish_reason", "next_index", "receipt", "request_id", "reservation_id"]);
      const request = hex(o.request_id, HEX32);
      const reservation = hex(o.reservation_id, HEX32);
      whole(o.next_index, 0);
      return {
        kind: "end", request, reservation, cancelled: value.kind === "model.cancel",
        finish: nullable(o.finish_reason, item => text(item, TITLE_BYTES)),
        receipt: readReceipt(o.receipt, request, reservation),
      };
    }
    case "model.error": {
      const o = row(body, ["code", "next", "next_index", "receipt", "request_id", "reservation_id"]);
      const request = hex(o.request_id, HEX32);
      const reservation = hex(o.reservation_id, HEX32);
      whole(o.next_index, 0);
      return {
        kind: "failed", request, reservation, code: code(o.code), next: text(o.next, 2_048),
        receipt: readReceipt(o.receipt, request, reservation),
      };
    }
    case "accepted":
      return { kind: "accepted", proposal: identifier(row(body, ["proposal_id"]).proposal_id) };
    case "outcome": {
      const o = row(body, ["proposal_id", "state"]);
      if (typeof o.state !== "string" || !STATES.includes(o.state)) throw bad();
      return { kind: "outcome", proposal: identifier(o.proposal_id), state: o.state as OutcomeState };
    }
    case "refusal": {
      const o = row(body, ["code", "next"]);
      return { kind: "refused", code: code(o.code), next: text(o.next, FRAME_BYTES) };
    }
    default:
      return { kind: "other" };
  }
}

export function randomId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), byte => byte.toString(16).padStart(2, "0")).join("");
}

// Cuts at a code point, never inside a pair.
export function clip(value: string, max: number): string {
  const points = Array.from(value);
  return points.length <= max ? value : `${points.slice(0, max).join("")}…`;
}

const NOT_TITLE = new RegExp(
  "[\\u0000-\\u001f\\u007f-\\u009f\\u061c\\u200b-\\u200f\\u2028-\\u202e\\u2060-\\u206f\\ufeff\\ufff9-\\ufffb]", "gu",
);

// A chat is named by the first line of its first message: no control or bidi characters, 60 code points at most, which
// is 240 UTF-8 bytes at the very worst and so always inside the 256-byte title bound.
export function titleFrom(message: string, fallback: string): string {
  for (const line of message.split(/\r\n|\r|\n/)) {
    const clean = line.replace(NOT_TITLE, "").replace(/\s+/g, " ").trim();
    if (clean) return clip(clean, 60);
  }
  return fallback;
}
