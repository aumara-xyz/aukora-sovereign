// SPDX-License-Identifier: AGPL-3.0-or-later
// The thread list as cards: a mark, the title, and when it last changed. The title is the node's text and is shown as
// text only. Searching matches the titles of the chats read here; the node has no content search.
import { clearServiceState, serviceState, showServiceState } from "../../core/service-state.js";
import { COPY, countText } from "./copy.js";
import { h, icon, mark, neutralize, visible } from "./dom.js";
import type { List } from "./list.js";
import type { Summary } from "./model.js";
import { ago, stamp } from "./time.js";

export interface ListViewOptions {
  readonly list: List;
  readonly signal: AbortSignal;
  // Keeps element ids apart when two lists share a page.
  readonly id: string;
  readonly empty: string;
  readonly open: (summary: Summary) => void;
  readonly selected: () => string | null;
  readonly running: () => string | null;
  readonly reload: () => void;
  // Cards shown before "Show more"; unset shows every chat read.
  readonly limit?: number;
  // When set, the "more" control calls this instead of showing further cards, and reads "All threads".
  readonly onMore?: () => void;
  readonly search: boolean;
}

export interface ListView {
  readonly element: HTMLElement;
  render(): void;
  focus(): void;
}

interface Card {
  readonly li: HTMLLIElement;
  readonly button: HTMLButtonElement;
  readonly name: HTMLElement;
  readonly when: HTMLElement;
  readonly chip: HTMLElement;
  readonly note: HTMLElement;
  summary: Summary;
  title: string;
}

const STEP = 100;
const CLOCK_MS = 30_000;

export function createListView(options: ListViewOptions): ListView {
  const { list, signal } = options;
  const cards = new Map<string, Card>();
  let limit = options.limit ?? Number.POSITIVE_INFINITY;
  let shownFailure: string | null = null;
  const step = options.limit ?? STEP;

  const input = h("input", {
    type: "search", id: `${options.id}-search`, maxlength: "200", autocomplete: "off", spellcheck: "false",
    placeholder: COPY.list.searchPlaceholder, title: COPY.list.searchHint,
  });
  const clear = h("button", { type: "button", class: "icon-button", hidden: "", "aria-label": COPY.list.clear }, icon("close"));
  const reload = h("button", { type: "button", class: "icon-button", "aria-label": COPY.list.refresh, title: COPY.list.refresh }, icon("refresh"));
  const bar = h("div", { class: "list-bar" },
    options.search && h("div", { class: "search" },
      h("label", { for: `${options.id}-search`, class: "sr" }, COPY.list.searchLabel), icon("search"), input, clear),
    reload);
  const info = h("p", { class: "info", role: "status" });
  const problem = h("p", { class: "problem", role: "status", hidden: "" });
  const rows = h("ul", { class: "cards", "aria-label": COPY.list.heading });
  const more = h("button", { type: "button", class: "more", hidden: "" });
  const element = h("section", { class: "thread-list", "aria-label": COPY.list.heading, "aria-busy": "false" },
    bar, info, problem, rows, more);

  const make = (summary: Summary): Card => {
    const name = h("span", { class: "name", dir: "auto" });
    const when = h("span", { class: "when" });
    const chip = h("span", { class: "chip", hidden: "" }, COPY.composer.build);
    const note = h("span", { class: "sr" });
    const button = h("button", { type: "button", class: "card" },
      h("span", { class: "orb" }, mark()), name, h("span", { class: "card-meta" }, chip, when), note);
    const li = h("li", {}, button);
    const card: Card = { li, button, name, when, chip, note, summary, title: "\u0000" };
    button.addEventListener("click", () => options.open(card.summary), { signal });
    return card;
  };

  const place = (summary: Summary, now: number, selected: string | null, running: string | null, fresh: ReadonlySet<string>): HTMLLIElement => {
    let card = cards.get(summary.sessionId);
    if (!card) { card = make(summary); cards.set(summary.sessionId, card); }
    card.summary = summary;
    if (card.title !== summary.title) {
      card.title = summary.title;
      card.name.replaceChildren(...neutralize(summary.title || COPY.header.untitled));
    }
    const live = summary.sessionId === running;
    const news = fresh.has(summary.sessionId);
    card.when.textContent = ago(summary.updatedAtMs, now);
    card.when.title = `${COPY.list.created} ${stamp(summary.createdAtMs)}`;
    card.chip.hidden = summary.mode !== "build";
    card.button.title = `${visible(summary.title || COPY.header.untitled)}\n${COPY.list.created} ${stamp(summary.createdAtMs)}`;
    card.button.dataset.running = String(live);
    card.button.dataset.fresh = String(news && !live);
    if (summary.sessionId === selected) card.button.setAttribute("aria-current", "true");
    else card.button.removeAttribute("aria-current");
    card.note.textContent = live ? COPY.list.running : news ? COPY.list.fresh : "";
    return card.li;
  };

  const render = () => {
    const { items, phase, failure, more: capped, stalled, fresh } = list.state;
    const query = input.value.trim().toLocaleLowerCase();
    const matches = query ? items.filter(item => visible(item.title).toLocaleLowerCase().includes(query)) : items;
    const now = Date.now();
    const selected = options.selected();
    const running = options.running();
    clear.hidden = input.value === "";
    element.setAttribute("aria-busy", String(phase === "loading"));
    const wanted = matches.slice(0, limit).map(item => place(item, now, selected, running, fresh));
    // Cards are only moved when the order changed, so a focused card keeps focus while updates arrive.
    if (rows.children.length !== wanted.length || wanted.some((li, at) => rows.children[at] !== li)) {
      const focused = rows.contains(document.activeElement) ? document.activeElement : null;
      rows.replaceChildren(...wanted);
      if (focused instanceof HTMLElement && rows.contains(focused) && document.activeElement !== focused) {
        focused.focus({ preventScroll: true });
      }
    }
    const ids = new Set(items.map(item => item.sessionId));
    for (const id of cards.keys()) if (!ids.has(id)) cards.delete(id);
    if (phase === "loading") info.textContent = COPY.list.reading;
    else if (phase === "failed") info.textContent = "";
    else if (items.length === 0) info.textContent = options.empty;
    else if (matches.length === 0) info.textContent = COPY.list.emptySearch;
    else {
      const count = countText(matches.length, "thread", "threads");
      info.textContent = capped ? `${count}. ${stalled ? COPY.list.stalled : COPY.list.capped}` : count;
    }
    if (failure !== shownFailure) {
      shownFailure = failure;
      if (failure !== null) {
        showServiceState(problem, failure);
        if (serviceState(failure).kind === "failure") {
          const retry = h("button", { type: "button", class: "link" }, COPY.chat.retry);
          retry.addEventListener("click", () => options.reload(), { signal });
          problem.append(" ", retry);
        }
      } else { clearServiceState(problem); problem.replaceChildren(); }
    }
    problem.hidden = failure === null;
    const hidden = matches.length - limit;
    more.hidden = !(hidden > 0);
    if (hidden > 0) more.textContent = options.onMore ? COPY.list.all : `Show ${Math.min(hidden, step)} more`;
  };

  input.addEventListener("input", () => { limit = options.limit ?? Number.POSITIVE_INFINITY; render(); }, { signal });
  input.addEventListener("keydown", event => {
    if (event.key === "Escape" && input.value !== "") { event.preventDefault(); input.value = ""; render(); }
  }, { signal });
  clear.addEventListener("click", () => { input.value = ""; render(); input.focus(); }, { signal });
  reload.addEventListener("click", () => options.reload(), { signal });
  more.addEventListener("click", () => {
    if (options.onMore) { options.onMore(); return; }
    limit += step;
    render();
  }, { signal });
  // Arrow keys move between cards; each card is still an ordinary button for Tab, Enter and Space.
  rows.addEventListener("keydown", event => {
    const buttons = [...rows.querySelectorAll("button")];
    const at = buttons.findIndex(button => button === document.activeElement);
    const to = event.key === "ArrowDown" ? at + 1 : event.key === "ArrowUp" ? at - 1
      : event.key === "Home" ? 0 : event.key === "End" ? buttons.length - 1 : -1;
    if (at < 0 || to < 0 || to >= buttons.length) return;
    event.preventDefault();
    buttons[to].focus();
  }, { signal });
  const clock = window.setInterval(() => {
    if (document.visibilityState !== "visible") return;
    const now = Date.now();
    for (const card of cards.values()) card.when.textContent = ago(card.summary.updatedAtMs, now);
  }, CLOCK_MS);
  signal.addEventListener("abort", () => window.clearInterval(clock), { once: true });

  return { element, render, focus: () => input.focus() };
}
