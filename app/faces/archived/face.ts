// SPDX-License-Identifier: AGPL-3.0-or-later
// Lists the archived sessions the node reports and opens one at a time to read. The list is read on load and on request,
// never on a timer: it shows when it was read, and a failed or malformed read replaces it with an explicit unavailable
// state instead of keeping the last list up. Reading is bounded: a few pages at a time, a repeated cursor ends the read
// as a refusal, and a session's entries come a page at a time on request. Nothing here writes to a session.
import type { ServiceFaceHost } from "../general/kit.js";
import { follow } from "../general/kit.js";
import { MAX_PAGE, parseOpened, parsePage } from "./sessions.js";
import type { Summary } from "./sessions.js";
import { createArchivedView } from "./view.js";
import type { ArchivedView } from "./view.js";

/** Pages read when the list loads, and for each press of "Read more sessions". */
export const FIRST_PAGES = 5;
export const MORE_PAGES = 5;

interface Listing {
  readonly sessions: ReadonlyMap<string, Summary>;
  /** Where the next page starts, or null when the node has no more sessions. */
  readonly cursor: string | null;
}

export function mountArchived(host: ServiceFaceHost): void {
  const { client, signal } = host;
  let view: ArchivedView | undefined;
  let current: Listing = { sessions: new Map(), cursor: null };
  // Bumped whenever the list is replaced, so a slow "read more" cannot overwrite a newer list.
  let generation = 0;
  let extending = false;
  let reading = 0;
  let after: number | null = null;
  let session: string | null = null;
  let paging = false;

  const collect = async (from: Listing, pages: number): Promise<Listing> => {
    const sessions = new Map(from.sessions);
    const used = new Set<string>();
    let cursor = from.cursor;
    for (let read = 0; read < pages; read++) {
      const page = parsePage(await client.call("body", "session.list", {
        thread_id: null, include_archived: true, before: cursor, limit: MAX_PAGE,
      }, { signal }));
      for (const item of page.items) if (item.archived) sessions.set(item.id, item);
      // A cursor that comes back is a node that would have this read loop for ever.
      if (page.next !== null && (page.next === cursor || used.has(page.next))) throw new Error("archived:cursor-repeated");
      cursor = page.next;
      if (cursor === null) break;
      used.add(cursor);
    }
    return { sessions, cursor };
  };

  const show = (listing: Listing, at: number) => {
    generation++;
    current = listing;
    view?.show([...listing.sessions.values()], listing.cursor !== null, at);
  };

  // Empties the list and the reader, and cancels whatever was still being read for either.
  const down = (reason: unknown) => {
    generation++;
    reading++;
    session = null;
    after = null;
    current = { sessions: new Map(), cursor: null };
    view?.unavailable(reason);
  };

  const more = async () => {
    if (extending || current.cursor === null) return;
    extending = true;
    const mine = generation;
    view?.working(true);
    try {
      const next = await collect(current, MORE_PAGES);
      if (!signal.aborted && mine === generation) show(next, Date.now());
    } catch (error) {
      if (!signal.aborted && mine === generation) down(error);
    } finally {
      extending = false;
      if (mine === generation) view?.working(false);
    }
  };

  const open = async (summary: Summary, opener: HTMLElement) => {
    const mine = ++reading;
    session = summary.id;
    after = null;
    view?.reader.loading(summary, opener);
    try {
      const opened = parseOpened(await client.call("body", "session.open", {
        session_id: summary.id, after_sequence: 0, limit: MAX_PAGE,
      }, { signal }), summary.id, 0);
      if (signal.aborted || mine !== reading) return;
      after = opened.next;
      view?.reader.show(opened, false);
    } catch (error) {
      if (!signal.aborted && mine === reading) view?.reader.fail(error);
    }
  };

  const moreEntries = async () => {
    if (paging || session === null || after === null) return;
    paging = true;
    const mine = reading;
    const id = session;
    const start = after;
    view?.reader.working(true);
    try {
      const opened = parseOpened(await client.call("body", "session.open", {
        session_id: id, after_sequence: start, limit: MAX_PAGE,
      }, { signal }), id, start);
      if (signal.aborted || mine !== reading) return;
      after = opened.next;
      view?.reader.show(opened, true);
    } catch (error) {
      if (!signal.aborted && mine === reading) view?.reader.fail(error);
    } finally {
      paging = false;
      if (mine === reading) view?.reader.working(false);
    }
  };

  follow<Listing>(host, stage => {
    view = createArchivedView(stage, {
      open: (summary, opener) => void open(summary, opener),
      more: () => void more(),
      close: () => { reading++; session = null; after = null; view?.reader.close(); },
      moreEntries: () => void moreEntries(),
    });
    return {
      every: 0,
      read: () => collect({ sessions: new Map(), cursor: null }, FIRST_PAGES),
      show: (listing, at) => show(listing, at),
      fail: reason => down(reason),
    };
  });
}
