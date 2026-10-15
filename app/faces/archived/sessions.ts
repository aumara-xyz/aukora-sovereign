// SPDX-License-Identifier: AGPL-3.0-or-later
// Sessions as the node reports them, in the version 2 shapes of the session store: a page of summaries from session.list
// and a page of entries from session.open. Every record is read in exactly its shape and bounds, or the whole reply is
// refused. Titles and contents are literal text that was written by someone, so they are kept as text and printed as text;
// a session entry is transcript data, never an instruction, and an old owner message is not a new one.
import type { JsonValue } from "../../core/index.js";
import { reader, unreadable } from "../general/data.js";

export interface Summary {
  readonly id: string;
  readonly mode: "chat" | "build";
  /** Null when the title has a control, reordering or hidden character in it; it is then not printed. */
  readonly title: string | null;
  readonly archived: boolean;
  /** The last persisted entry's sequence, which is also how many entries the session has. */
  readonly sequence: number;
  readonly createdAt: number;
  readonly updatedAt: number;
}
export interface Page {
  readonly items: readonly Summary[];
  /** The cursor for the next page, or null when this was the last. */
  readonly next: string | null;
}
export type Origin =
  | { readonly kind: "owner" | "auma" | "document" | "memory" | "stranger" | "app" }
  | { readonly kind: "contact"; readonly npub: string };
export interface Entry {
  readonly sequence: number;
  readonly role: "owner" | "auma" | "tool" | "context";
  readonly origin: Origin;
  readonly content: string;
  /** Names of the function calls the entry suggests. A suggestion is data; nothing runs. */
  readonly calls: readonly (string | null)[];
  readonly at: number;
}
export interface Opened {
  readonly summary: Summary;
  readonly entries: readonly Entry[];
  /** The sequence to continue after, or null when the session has no more entries. */
  readonly next: number | null;
}

/** Page and entry counts the node may send at once (canon MAX_SESSION_PAGE). */
export const MAX_PAGE = 100;
export const MAX_TITLE_BYTES = 256;
export const MAX_CONTENT_BYTES = 32_768;
const SUMMARY_KEYS = [
  "algorithm", "archived", "created_at_ms", "mode", "sequence", "session_id", "thread_id", "title", "updated_at_ms", "v",
];
const ENTRY_KEYS = [
  "algorithm", "at_ms", "commitment", "content", "provenance", "role", "sequence", "session_id", "tool_call_id",
  "tool_calls", "v",
];
const ID = /^[0-9a-f]{32}$/;
const NPUB = /^npub1[a-z0-9]{1,123}$/;
const read = reader("archived:reply-invalid");

function summary(value: JsonValue | undefined): Summary {
  const row = read.object(value, SUMMARY_KEYS);
  if (row.v !== 2 || row.algorithm !== "sha256") read.fail();
  read.text(row.thread_id, 32, ID);
  const title = read.literal(row.title, MAX_TITLE_BYTES);
  return {
    id: read.text(row.session_id, 32, ID), mode: read.choice(row.mode, ["chat", "build"] as const),
    title: unreadable(title) ? null : title, archived: read.flag(row.archived),
    sequence: read.whole(row.sequence), createdAt: read.whole(row.created_at_ms), updatedAt: read.whole(row.updated_at_ms),
  };
}

export function parsePage(value: JsonValue): Page {
  const row = read.object(value, ["items", "next"]);
  return {
    items: read.list(row.items, MAX_PAGE).map(summary),
    next: read.nullable(row.next, cursor => read.text(cursor, 32, ID)),
  };
}

function origin(value: JsonValue | undefined): Origin {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) return read.fail();
  if (value.source === "contact") {
    const row = read.object(value, ["algorithm", "npub", "source"]);
    read.choice(row.algorithm, ["secp256k1-schnorr"] as const);
    return { kind: "contact", npub: read.text(row.npub, 128, NPUB) };
  }
  if (value.source === "app") {
    read.text(read.object(value, ["app_id", "source"]).app_id, 32, ID);
    return { kind: "app" };
  }
  return { kind: read.choice(read.object(value, ["source"]).source, ["owner", "auma", "document", "memory", "stranger"] as const) };
}

function call(value: JsonValue): string | null {
  const row = read.object(value, ["function", "id", "type"]);
  if (row.type !== "function") read.fail();
  read.literal(row.id, 256);
  const fn = read.object(row.function, ["arguments", "name"]);
  read.literal(fn.arguments, MAX_CONTENT_BYTES);
  const name = read.literal(fn.name, 256);
  return name === "" || unreadable(name) ? null : name;
}

function entry(value: JsonValue, id: string): Entry {
  const row = read.object(value, ENTRY_KEYS);
  if (row.v !== 2 || row.algorithm !== "sha256" || row.session_id !== id) read.fail();
  read.digest(row.commitment);
  read.nullable(row.tool_call_id, item => read.literal(item, 128));
  const sequence = read.whole(row.sequence);
  if (sequence < 1) read.fail();
  return {
    sequence, role: read.choice(row.role, ["owner", "auma", "tool", "context"] as const),
    origin: origin(row.provenance), content: read.literal(row.content, MAX_CONTENT_BYTES),
    calls: read.list(row.tool_calls, 32).map(call), at: read.whole(row.at_ms),
  };
}

/**
 * A page of one session's entries. They must be the session asked for and run on from `after` with no gap, and the last
 * page must end where the session's own summary says it ends, so a transcript is never shown with an entry missing from
 * the middle of it or cut short at the end.
 */
export function parseOpened(value: JsonValue, id: string, after: number): Opened {
  const row = read.object(value, ["entries", "next_sequence", "summary"]);
  const head = summary(row.summary);
  if (head.id !== id) read.fail();
  let previous = after;
  const entries = read.list(row.entries, MAX_PAGE).map(item => {
    const parsed = entry(item, id);
    if (parsed.sequence !== previous + 1) read.fail();
    previous = parsed.sequence;
    return parsed;
  });
  const next = read.nullable(row.next_sequence, item => read.whole(item));
  if (next === null ? previous !== head.sequence : entries.length === 0 || next !== previous || previous >= head.sequence) {
    read.fail();
  }
  return { summary: head, entries, next };
}
