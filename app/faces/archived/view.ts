// SPDX-License-Identifier: AGPL-3.0-or-later
// The Archived sessions screen: a searchable list of archived sessions, and a reader that shows one session's entries as
// they were stored. Titles and contents are text someone wrote and are printed only as text, each in its own direction
// so reordering characters cannot spill into the page around it. Reading is all this screen does: nothing on it restores,
// edits, deletes or sends, and an old owner message shown here is a record, not a request.
import { showServiceState } from "../../core/service-state.js";
import { card, make, mark, moment, plural, since } from "../general/kit.js";
import type { Card } from "../general/kit.js";
import type { Entry, Opened, Origin, Summary } from "./sessions.js";

export interface Actions {
  open(summary: Summary, opener: HTMLElement): void;
  more(): void;
  close(): void;
  moreEntries(): void;
}
export interface ReaderView {
  loading(summary: Summary, opener: HTMLElement): void;
  /** Disables "Show more entries" while a further page is being read. */
  working(on: boolean): void;
  show(opened: Opened, append: boolean): void;
  fail(reason: unknown): void;
  close(): void;
}
export interface ArchivedView {
  reading(): void;
  /** Disables "Read more sessions" while further pages are being read. */
  working(on: boolean): void;
  show(sessions: readonly Summary[], more: boolean, now: number): void;
  unavailable(reason: unknown): void;
  readonly reader: ReaderView;
}

const NOTE = "Archived sessions can be read here. Restoring one to the Threads list is not part of this release, and nothing on this page edits or deletes a session.";
const MODES = { chat: "Chat", build: "Build" } as const;

function titleOf(summary: Summary): string {
  return summary.title === null ? "Unreadable title" : summary.title.trim() === "" ? "Untitled session" : summary.title;
}

/** Who an entry came from, as the trusted ingress stamped it; the role is shown beside it when it adds something. */
function originLabel(origin: Origin): string {
  switch (origin.kind) {
    case "contact": return `Contact ${origin.npub.slice(0, 14)}…`;
    case "owner": return "Owner";
    case "auma": return "Auma";
    case "document": return "Document";
    case "memory": return "Memory";
    case "stranger": return "Stranger";
    case "app": return "App";
  }
}

function status(parent: HTMLElement): HTMLElement {
  const line = make("p", "lead");
  line.setAttribute("role", "status");
  parent.append(line);
  return line;
}

function button(label: string): HTMLButtonElement {
  const control = make("button", undefined, label);
  control.type = "button";
  return control;
}

function message(entry: Entry): HTMLElement {
  const item = make("li", "message");
  item.dataset.origin = entry.origin.kind;
  const head = make("div", "message-head");
  head.append(make("strong", undefined, originLabel(entry.origin)));
  if (entry.role === "tool" || entry.role === "context" || entry.role !== entry.origin.kind) {
    head.append(make("span", "chip", `${entry.role} entry`));
  }
  const when = make("span", "when", moment(entry.at) ?? "Time unreadable");
  head.append(when);
  item.append(head);
  const said = make("p", "said literal", entry.content === "" ? "(empty)" : entry.content);
  said.dir = "auto";
  if (entry.content === "") said.classList.add("empty");
  item.append(said);
  for (const name of entry.calls) {
    item.append(make("p", "call", name === null ? "Suggested a call with an unreadable name." : `Suggested a call to ${name}. The suggestion itself runs nothing.`));
  }
  return item;
}

function readerCard(root: HTMLElement, actions: Actions): ReaderView {
  const target: Card = card(root, "reader", "Session");
  const heading = target.section.querySelector("h2") as HTMLElement;
  heading.tabIndex = -1;
  heading.className = "literal";
  heading.dir = "auto";
  const back = button("Back to archived sessions");
  back.addEventListener("click", () => actions.close());
  const line = status(target.body);
  const log = make("ol", "log");
  const more = button("Show more entries");
  more.addEventListener("click", () => actions.moreEntries());
  target.body.append(back, line, log, more);
  target.section.hidden = true;
  let opener: HTMLElement | null = null;
  const clear = () => {
    log.replaceChildren();
    more.hidden = true;
  };
  const view: ReaderView = {
    loading(summary, from) {
      opener = from;
      clear();
      heading.textContent = titleOf(summary);
      mark(target.badge, "plain", MODES[summary.mode].toUpperCase());
      line.hidden = false;
      line.textContent = "Reading the entries.";
      target.section.hidden = false;
      heading.focus();
    },
    working(on) { more.disabled = on; },
    show(opened, append) {
      if (!append) clear();
      line.hidden = false;
      for (const entry of opened.entries) log.append(message(entry));
      more.hidden = opened.next === null;
      more.disabled = false;
      const shown = log.children.length;
      line.textContent = shown === 0 ? "This session has no entries."
        : `${plural(shown, "entry", "entries")} shown${opened.next === null ? "." : "; more follow."}`;
    },
    fail(reason) {
      clear();
      showServiceState(target.badge, reason);
      line.textContent = "";
      line.hidden = true;
    },
    close() {
      clear();
      target.section.hidden = true;
      opener?.focus();
      opener = null;
    },
  };
  return view;
}

export function createArchivedView(root: HTMLElement, actions: Actions): ArchivedView {
  const list = card(root, "archive", "Archive");
  const line = status(list.body);
  const search = make("input", "search");
  search.type = "search";
  search.maxLength = 256;
  search.placeholder = "Search archived sessions";
  search.setAttribute("aria-label", "Search archived sessions");
  const rows = make("ul", "sessions");
  const more = button("Read more sessions");
  more.addEventListener("click", () => actions.more());
  list.body.append(search, rows, more, make("p", "note", NOTE));
  const reader = readerCard(root, actions);
  // The reader replaces the list while it is open; the list keeps its search and its place.
  const hold = (open: boolean) => { list.section.hidden = open; };

  let sessions: readonly Summary[] = [];
  let hasMore = false;
  let at = 0;
  const draw = () => {
    const query = search.value.trim().toLowerCase();
    const shown = sessions.filter(item => query === "" || titleOf(item).toLowerCase().includes(query));
    rows.replaceChildren(...shown.map(item => {
      const row = make("li", "session");
      const main = make("div", "session-main");
      const title = make("strong", "literal", titleOf(item));
      title.dir = "auto";
      const meta = make("span", "session-meta", `${MODES[item.mode]} · ${plural(item.sequence, "entry", "entries")} · last active ${since(item.updatedAt, at)}`);
      meta.title = moment(item.updatedAt) ?? "";
      main.append(title, meta);
      const read = button("Read");
      read.setAttribute("aria-label", `Read ${titleOf(item)}`);
      read.addEventListener("click", () => actions.open(item, read));
      row.append(main, read);
      return row;
    }));
    search.hidden = sessions.length === 0;
    more.hidden = !hasMore;
    more.disabled = false;
    const tail = hasMore ? " Older sessions have not been read yet." : "";
    line.textContent = sessions.length === 0 ? `No archived sessions.${tail}`
      : shown.length === 0 ? `No archived session matches that search.${tail}`
        : `${plural(shown.length, "archived session", "archived sessions")}${query === "" ? "" : shown.length === 1 ? " matches" : " match"}, most recently active first.${tail}`;
  };
  search.addEventListener("input", draw);

  const view: ArchivedView = {
    reader: {
      loading(summary, from) { hold(true); reader.loading(summary, from); },
      working: on => reader.working(on),
      show: (page, append) => reader.show(page, append),
      fail: reason => reader.fail(reason),
      close() { hold(false); reader.close(); },
    },
    reading() {
      mark(list.badge, "unknown", "CHECKING");
      line.hidden = false;
      line.textContent = "Reading sessions from the node.";
      rows.replaceChildren();
      search.hidden = true;
      more.hidden = true;
    },
    working(on) {
      more.disabled = on;
      if (on) line.textContent = "Reading more sessions from the node.";
    },
    show(next, remaining, now) {
      sessions = [...next].sort((a, b) => b.updatedAt - a.updatedAt || (a.id < b.id ? -1 : 1));
      hasMore = remaining;
      at = now;
      mark(list.badge, "plain", sessions.length === 0 ? "NONE" : `${sessions.length} ARCHIVED`);
      line.hidden = false;
      draw();
    },
    unavailable(reason) {
      sessions = [];
      hasMore = false;
      showServiceState(list.badge, reason);
      rows.replaceChildren();
      search.hidden = true;
      more.hidden = true;
      line.textContent = "";
      line.hidden = true;
      hold(false);
      reader.close();
    },
  };
  view.reading();
  return view;
}
