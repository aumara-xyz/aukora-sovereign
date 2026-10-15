// SPDX-License-Identifier: AGPL-3.0-or-later
// The node's list of sessions. Pages are read one after another up to a bound, because the node pages in its own order
// and the newest chat is only known once all of them are read. Entries seen on the event topic move a chat to the top.
import type { FaceClient } from "../../core/index.js";
import { refusalCode } from "./copy.js";
import { PAGE, readListed } from "./model.js";
import type { Event, Summary } from "./model.js";

export interface ListState {
  // Newest update first.
  readonly items: readonly Summary[];
  readonly phase: "loading" | "ready" | "failed";
  readonly failure: string | null;
  // The node lists more than this face read.
  readonly more: boolean;
  readonly stalled: boolean;
  // Chats that took new entries while they were not the open one.
  readonly fresh: ReadonlySet<string>;
}

export interface ListOptions {
  // Whether the node is asked for archived sessions too; only archived ones are kept then.
  readonly archived: boolean;
  readonly changed: () => void;
}

export interface List {
  readonly state: ListState;
  load(): Promise<void>;
  upsert(summary: Summary): void;
  event(event: Event, open: string | null): void;
  seen(sessionId: string): void;
}

type Writable<T> = { -readonly [K in keyof T]: T[K] };

const MAX_ITEMS = 1_000;
const MAX_PAGES = 12;
const REFRESH_MS = 600;

function order(a: Summary, b: Summary): number {
  if (a.updatedAtMs !== b.updatedAtMs) return b.updatedAtMs - a.updatedAtMs;
  return a.sessionId < b.sessionId ? 1 : -1;
}

function newer(a: Summary, b: Summary): Summary {
  return b.sequence > a.sequence || (b.sequence === a.sequence && b.updatedAtMs >= a.updatedAtMs) ? b : a;
}

// What a read found, plus what the event topic reported meanwhile; the newer record of a chat wins.
function merge(found: ReadonlyMap<string, Summary>, meanwhile: readonly Summary[]): Map<string, Summary> {
  const merged = new Map(found);
  for (const item of meanwhile) {
    const have = merged.get(item.sessionId);
    merged.set(item.sessionId, have ? newer(have, item) : item);
  }
  return merged;
}

export function createList(client: FaceClient, signal: AbortSignal, options: ListOptions): List {
  let byId = new Map<string, Summary>();
  const fresh = new Set<string>();
  const state: Writable<ListState> = { items: [], phase: "loading", failure: null, more: false, stalled: false, fresh };
  let generation = 0;
  let during: Summary[] = [];
  let reading = false;
  let refresh: number | undefined;
  signal.addEventListener("abort", () => window.clearTimeout(refresh), { once: true });

  const wanted = (summary: Summary) => !options.archived || summary.archived;
  const publish = () => {
    state.items = [...byId.values()].sort(order);
    if (!signal.aborted) options.changed();
  };
  const put = (summary: Summary) => {
    if (!wanted(summary)) return;
    byId.set(summary.sessionId, summary);
    if (reading) during.push(summary);
  };

  const load = async (): Promise<void> => {
    const token = ++generation;
    const found = new Map<string, Summary>();
    const first = byId.size === 0;
    reading = true;
    during = [];
    state.phase = first ? "loading" : "ready";
    state.failure = null;
    state.more = false;
    state.stalled = false;
    let before: string | null = null;
    try {
      for (let pages = 0; pages < MAX_PAGES; pages++) {
        const page = readListed(await client.call("body", "session.list", {
          thread_id: null, include_archived: options.archived, before, limit: PAGE,
        }, { signal }));
        if (token !== generation || signal.aborted) return;
        for (const item of page.items) if (wanted(item)) found.set(item.sessionId, item);
        if (page.next === null) break;
        // A cursor that does not advance, or a page with nothing in it, ends the reading rather than looping.
        if (page.next === before || page.items.length === 0) { state.more = true; state.stalled = true; break; }
        if (found.size >= MAX_ITEMS || pages === MAX_PAGES - 1) { state.more = true; break; }
        before = page.next;
        if (first) { byId = merge(found, during); state.phase = "ready"; publish(); }
      }
      byId = merge(found, during);
      state.phase = "ready";
    } catch (error) {
      if (token !== generation || signal.aborted) return;
      state.failure = refusalCode(error);
      state.phase = byId.size > 0 ? "ready" : "failed";
    } finally {
      if (token === generation) { reading = false; during = []; publish(); }
    }
  };

  const refreshSoon = () => {
    window.clearTimeout(refresh);
    refresh = window.setTimeout(() => { if (!signal.aborted) void load(); }, REFRESH_MS);
  };

  const upsert = (summary: Summary) => {
    const known = byId.get(summary.sessionId);
    if (!known || summary.sequence >= known.sequence) put(summary);
    publish();
  };

  return {
    state,
    load,
    upsert,
    event(event, open) {
      if (event.kind === "created") { upsert(event.summary); return; }
      if (event.kind !== "entry") return;
      const known = byId.get(event.entry.sessionId);
      // A chat this list has not read is new to it; the archived list never wants one that is not archived.
      if (!known) { if (!options.archived) refreshSoon(); return; }
      if (event.entry.sequence <= known.sequence) return;
      put({ ...known, sequence: event.entry.sequence, updatedAtMs: Math.max(known.updatedAtMs, event.entry.atMs) });
      if (event.entry.sessionId !== open) fresh.add(event.entry.sessionId);
      publish();
    },
    seen(sessionId) {
      if (fresh.delete(sessionId)) publish();
    },
  };
}
