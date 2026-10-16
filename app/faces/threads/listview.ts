// SPDX-License-Identifier: AGPL-3.0-or-later
import { clearServiceState, serviceState, showServiceState } from "../../core/service-state.js";
import { COPY } from "./copy.js";
import { h, neutralize, visible } from "./dom.js";
import type { List } from "./list.js";
import type { Summary } from "./model.js";
import { spatialMark, threadGlyph } from "./spatial-icons.js";
import { ago, stamp } from "./time.js";

export interface ListViewOptions {
  readonly list: List;
  readonly signal: AbortSignal;
  readonly id: string;
  readonly empty: string;
  readonly open: (summary: Summary) => void;
  readonly selected: () => string | null;
  readonly running: () => string | null;
  readonly reload: () => void;
  readonly limit?: number;
  readonly onMore?: () => void;
  readonly search: boolean;
  readonly filter?: (summary: Summary) => boolean;
  readonly pinned?: (sessionId: string) => boolean;
  readonly togglePin?: (sessionId: string) => void;
}
export interface ListView { readonly element: HTMLElement; render(): void; focus(): void }
interface Card {
  element: HTMLDivElement;
  title: HTMLSpanElement;
  age: HTMLSpanElement;
  image: HTMLImageElement;
  pin: HTMLSpanElement;
  unread: HTMLSpanElement;
  archive: HTMLSpanElement;
  menu: HTMLButtonElement | null;
  summary: Summary;
}

export function createListView(options: ListViewOptions): ListView {
  const { signal, list } = options;
  const cache = new Map<string, Card>();
  let maximum = options.limit ?? Infinity;
  let lastFailure: string | null = null;
  const query = h("input", { class: "searchInput", type: "text", id: `${options.id}-search`, maxlength: "200", autocomplete: "off", spellcheck: "false", placeholder: "Search sessions...", "aria-label": COPY.list.searchLabel, tabindex: "-1" });
  const searchButton = h("button", { class: "searchButton", type: "button", "aria-label": COPY.list.searchLabel, "aria-expanded": "false" }, threadGlyph("search"));
  const clear = h("button", { class: "clearButton", type: "button", "aria-label": COPY.list.clear, hidden: "" }, threadGlyph("close"));
  const search = h("div", { class: "search" }, searchButton, query, clear);
  const slot = h("div", { class: "searchSlot" }, search);
  const header = h("div", { class: "sectionHeader flatThreadHeader" }, slot);
  header.hidden = !options.search;
  const info = h("div", { class: "empty", role: "status" });
  const failure = h("div", { class: "searchWarning", role: "status", hidden: "" });
  const rows = h("div", { class: "flatList", role: "tree", "aria-label": COPY.list.heading });
  const more = h("button", { class: "more", type: "button", hidden: "" });
  const scroll = h("div", { class: "list wide" }, info, failure, rows, more);
  const body = h("div", { class: "treeBody" }, scroll, h("div", { class: "fade", "aria-hidden": "true" }));
  const element = h("div", { class: "root workspaceBrowser", "aria-label": COPY.list.heading, "aria-busy": "false" }, header, h("div", { class: "listArea" }, body));

  const expand = (value: boolean) => {
    search.classList.toggle("searchExpanded", value);
    slot.classList.toggle("searchSlotExpanded", value);
    searchButton.setAttribute("aria-expanded", String(value));
    query.tabIndex = value ? 0 : -1;
    clear.hidden = !value;
    if (value) query.focus();
  };
  const marker = (kind: "pin" | "unread" | "archive", label: string) => h("span", { class: `${kind}Marker`, title: label, hidden: "" }, threadGlyph(kind), h("span", { class: "visuallyHidden" }, label));
  const create = (summary: Summary): Card => {
    const image = spatialMark();
    const title = h("span", { class: "title", dir: "auto" });
    const age = h("span", { class: "time" });
    const pin = marker("pin", "Pinned");
    const unread = marker("unread", "Unread");
    const archive = marker("archive", "Archived");
    const row = h("div", { class: "sessionRow flatSessionRowWithoutStatus", role: "treeitem", "aria-selected": "false", tabindex: "0" },
      h("span", { class: "threadMark", "aria-hidden": "true" }, image), title, pin, unread, archive,
      h("span", { class: "sessionMeta" }, h("span", { class: "workspace" }, "Ungrouped"), age));
    const menu = options.togglePin ? h("button", { class: "iconButton", type: "button", "aria-label": "Pin thread for this view" }, threadGlyph("pin")) : null;
    if (menu) row.append(h("span", { class: "rowActions" }, menu));
    else row.classList.add("withoutActions");
    const card: Card = { element: row, title, age, image, pin, unread, archive, menu, summary };
    row.addEventListener("click", event => { if (event.target instanceof Node && menu?.contains(event.target)) return; options.open(card.summary); }, { signal });
    row.addEventListener("keydown", event => {
      if (event.target !== row || !["Enter", " "].includes(event.key)) return;
      event.preventDefault();
      options.open(card.summary);
    }, { signal });
    menu?.addEventListener("click", event => { event.stopPropagation(); options.togglePin?.(card.summary.sessionId); render(); }, { signal });
    return card;
  };
  const place = (summary: Summary, now: number): HTMLDivElement => {
    let card = cache.get(summary.sessionId);
    if (!card) { card = create(summary); cache.set(summary.sessionId, card); }
    card.summary = summary;
    const title = summary.title || COPY.header.untitled;
    card.title.replaceChildren(...neutralize(title));
    card.element.title = visible(title);
    card.age.textContent = ago(summary.updatedAtMs, now);
    card.age.title = `${COPY.list.created} ${stamp(summary.createdAtMs)}`;
    const selected = summary.sessionId === options.selected();
    card.element.classList.toggle("selected", selected);
    card.element.setAttribute("aria-selected", String(selected));
    if (selected) card.element.setAttribute("aria-current", "true"); else card.element.removeAttribute("aria-current");
    card.image.classList.toggle("turning", summary.sessionId === options.running());
    card.pin.hidden = !options.pinned?.(summary.sessionId);
    card.unread.hidden = !list.state.fresh.has(summary.sessionId);
    card.archive.hidden = !summary.archived;
    card.menu?.setAttribute("aria-pressed", String(!card.pin.hidden));
    card.menu?.setAttribute("aria-label", card.pin.hidden ? "Pin thread for this view" : "Unpin thread for this view");
    return card.element;
  };
  function render(): void {
    if (signal.aborted) return;
    const state = list.state;
    const needle = query.value.trim().toLocaleLowerCase();
    const filtered = state.items.filter(item => (!options.filter || options.filter(item)) && (!needle || visible(item.title).toLocaleLowerCase().includes(needle)));
    const wanted = filtered.slice(0, maximum).map(item => place(item, Date.now()));
    if (rows.children.length !== wanted.length || wanted.some((item, at) => rows.children[at] !== item)) {
      const focused = rows.contains(document.activeElement) ? document.activeElement : null;
      rows.replaceChildren(...wanted);
      if (focused instanceof HTMLElement && rows.contains(focused)) focused.focus({ preventScroll: true });
    }
    const present = new Set(state.items.map(item => item.sessionId));
    for (const id of cache.keys()) if (!present.has(id)) cache.delete(id);
    element.setAttribute("aria-busy", String(state.phase === "loading"));
    info.textContent = state.phase === "loading" ? COPY.list.reading : state.phase === "failed" ? "" : state.items.length === 0 ? options.empty : filtered.length === 0 ? COPY.list.emptySearch : state.more ? state.stalled ? COPY.list.stalled : COPY.list.capped : "";
    info.hidden = info.textContent === "";
    if (lastFailure !== state.failure) {
      lastFailure = state.failure;
      if (state.failure === null) { clearServiceState(failure); failure.replaceChildren(); }
      else {
        showServiceState(failure, state.failure);
        const status = serviceState(state.failure);
        if (status.kind === "failure" || status.retryable) {
          const retry = h("button", { class: "link", type: "button" }, COPY.chat.retry);
          retry.addEventListener("click", options.reload, { signal });
          failure.append(" ", retry);
        }
      }
    }
    failure.hidden = state.failure === null;
    more.hidden = filtered.length <= maximum;
    more.textContent = options.onMore ? COPY.list.all : `Show ${Math.min(filtered.length - maximum, options.limit ?? 100)} more`;
  }
  searchButton.addEventListener("click", () => expand(true), { signal });
  search.addEventListener("click", event => { if (!(event.target instanceof Node) || !clear.contains(event.target)) expand(true); }, { signal });
  query.addEventListener("input", () => { maximum = options.limit ?? Infinity; render(); }, { signal });
  query.addEventListener("keydown", event => { if (event.key === "Escape") { event.preventDefault(); query.value = ""; expand(false); render(); searchButton.focus(); } }, { signal });
  clear.addEventListener("click", event => { event.stopPropagation(); query.value = ""; expand(false); render(); searchButton.focus(); }, { signal });
  more.addEventListener("click", () => { if (options.onMore) options.onMore(); else { maximum += options.limit ?? 100; render(); } }, { signal });
  rows.addEventListener("keydown", event => {
    const items = [...rows.children] as HTMLElement[];
    const current = items.indexOf(document.activeElement as HTMLElement);
    const next = event.key === "ArrowDown" ? current + 1 : event.key === "ArrowUp" ? current - 1 : event.key === "Home" ? 0 : event.key === "End" ? items.length - 1 : -1;
    if (current < 0 || next < 0 || next >= items.length) return;
    event.preventDefault(); items[next].focus();
  }, { signal });
  const clock = window.setInterval(() => {
    if (document.visibilityState === "visible") for (const card of cache.values()) card.age.textContent = ago(card.summary.updatedAtMs, Date.now());
  }, 30_000);
  signal.addEventListener("abort", () => { window.clearInterval(clock); cache.clear(); element.remove(); }, { once: true });
  return { element, render, focus: () => { if (options.search) expand(true); else (rows.firstElementChild as HTMLElement | null)?.focus(); } };
}
