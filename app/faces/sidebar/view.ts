// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { COPY, countText } from "../threads/copy.js";
import { createConversation } from "../threads/conversation.js";
import { h, icon, neutralize } from "../threads/dom.js";
import { listen } from "../threads/events.js";
import { createList } from "../threads/list.js";
import { createListView } from "../threads/listview.js";
import type { Summary } from "../threads/model.js";
import { navigateThread } from "../threads/navigation.js";
import { spatialMark, threadGlyph } from "../threads/spatial-icons.js";
import { createTranscript } from "../threads/transcript.js";

export function mountSidebar(root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>, archived: boolean): void {
  document.documentElement.classList.add("spatialThreadsDocument");
  document.body.setAttribute("data-ds-dark-theme", "");
  document.body.classList.add("spatialThreads");
  let reading = false;
  let selected: string | null = null;
  let connectedBefore = false;
  let paint: number | undefined;
  let quiet: number | undefined;
  const pins = new Set<string>();
  const filters = { pinned: false, unread: false, archived };
  const schedule = () => {
    if (paint !== undefined || signal.aborted) return;
    paint = window.setTimeout(() => { paint = undefined; render(); }, 40);
  };
  const list = createList(client, signal, { archived, changed: schedule });
  const conversation = createConversation(client, signal, { granted, readOnly: true, changed: schedule });
  const transcript = createTranscript({ signal, conversation });
  const problem = h("p", { class: "problem", role: "status", hidden: "" });
  const connection = h("p", { class: "problem", role: "status", hidden: "" });
  const open = (summary: Summary) => {
    selected = summary.sessionId;
    list.seen(summary.sessionId);
    if (!archived) {
      try { navigateThread(summary.sessionId); } catch (error) { showServiceState(connection, error); connection.hidden = false; }
      schedule();
      return;
    }
    reading = true;
    void conversation.open(summary);
    render();
    back.focus();
  };
  const cards = createListView({
    list, signal, id: "sidebar", empty: archived ? COPY.list.emptyArchived : COPY.list.empty, open,
    selected: () => selected, running: () => null, reload: () => { void list.load(); }, search: true, limit: 100,
    filter: summary => (!filters.pinned || pins.has(summary.sessionId)) && (!filters.unread || list.state.fresh.has(summary.sessionId)),
    pinned: id => pins.has(id),
    togglePin: id => { if (pins.has(id)) pins.delete(id); else pins.add(id); schedule(); },
  });
  const action = (name: "plus" | "pin" | "unread" | "archive", label: string, className = "") => h("button", { type: "button", class: `iconButton ${className}`.trim(), "aria-label": label, title: label }, threadGlyph(name));
  const add = action("plus", "New chat");
  const pin = action("pin", "Filter pinned threads", "pinAction");
  const unread = action("unread", "Filter unread threads", "unreadAction");
  const archive = action("archive", "Filter archived threads", "archiveAction");
  const controls = h("span", { class: "actions" }, add, pin, unread, archive);
  const brand = h("div", { class: "brand wide" }, h("span", { class: "brandIdentity" },
    h("span", { class: "brandMark" }, spatialMark(28)), h("span", { class: "brandName" }, h("span", { class: "fallbackBrandName" }, "AUKORA"))));
  const logo = h("div", { class: "logoRow" }, brand, h("div", { class: "headerActions wide" }, controls));
  const listing = h("div", { class: "root spatialSidebar quietBars" },
    archived ? null : logo, connection, h("div", { class: "regionArea" }, cards.element), h("div", { class: "footArea" }, h("div", { class: "footerActions" })));
  const back = h("button", { class: "back", type: "button", "aria-label": COPY.sidebar.back }, icon("back"), h("span", {}, COPY.sidebar.back));
  const title = h("h2", { class: "title" });
  const sub = h("p", { class: "sub" });
  const reader = h("section", { class: "side-reader", hidden: "" }, h("div", { class: "reader-bar" }, back, h("div", { class: "heading-block" }, title, sub)), transcript.element, problem, h("p", { class: "readonly" }, COPY.chat.readOnly));
  const surface = h("div", { class: "side", "data-view": "list" }, listing, reader);
  root.append(surface);

  function render(): void {
    if (signal.aborted) return;
    cards.render();
    pin.setAttribute("aria-pressed", String(filters.pinned));
    unread.setAttribute("aria-pressed", String(filters.unread));
    archive.setAttribute("aria-pressed", String(filters.archived));
    listing.hidden = reading;
    reader.hidden = !reading;
    surface.dataset.view = reading ? "reader" : "list";
    if (!reading) return;
    const { summary, notices } = conversation.state;
    title.replaceChildren(...neutralize(summary?.title || COPY.header.untitled));
    sub.textContent = summary ? `${summary.mode === "build" ? COPY.composer.build : COPY.composer.chat} · ${countText(summary.sequence, COPY.list.message, COPY.list.messages)}` : "";
    const latest = notices.at(-1);
    problem.hidden = latest === undefined;
    if (latest?.code) showServiceState(problem, latest.code);
    else { clearServiceState(problem); problem.textContent = latest?.text ?? ""; }
    transcript.sync();
  }
  add.addEventListener("click", () => {
    try { navigateThread(); } catch (error) { showServiceState(connection, error); connection.hidden = false; }
  }, { signal });
  pin.addEventListener("click", () => { filters.pinned = !filters.pinned; render(); }, { signal });
  unread.addEventListener("click", () => { filters.unread = !filters.unread; render(); }, { signal });
  archive.addEventListener("click", () => { filters.archived = !filters.archived; list.setArchived(filters.archived); render(); }, { signal });
  back.addEventListener("click", () => { reading = false; render(); (cards.element.querySelector<HTMLElement>('[aria-current="true"]') ?? cards.element.querySelector<HTMLElement>('[role="treeitem"]'))?.focus(); }, { signal });
  root.addEventListener("keydown", event => { if (event.key === "Escape" && !event.defaultPrevented && reading) back.click(); }, { signal });
  listing.addEventListener("pointerenter", () => { window.clearTimeout(quiet); quiet = undefined; listing.classList.remove("quietBars"); }, { signal });
  listing.addEventListener("pointerleave", () => { if (quiet === undefined) quiet = window.setTimeout(() => { quiet = undefined; listing.classList.add("quietBars"); }, 2000); }, { signal });
  const live = listen(client, signal, {
    event: value => { list.event(value, selected); conversation.event(value); },
    bad: code => { showServiceState(connection, code); connection.hidden = false; },
    state: (connected, code) => {
      conversation.live(connected);
      if (connected) {
        clearServiceState(connection); connection.hidden = true;
        if (connectedBefore) { void list.load(); if (reading) conversation.resync(); }
        connectedBefore = true;
      } else {
        const retry = h("button", { class: "link", type: "button" }, COPY.notices.liveRetry);
        retry.addEventListener("click", () => live.retry(), { signal });
        showServiceState(connection, code ?? "app:service-unavailable"); connection.append(" ", retry); connection.hidden = false;
      }
    },
  });
  signal.addEventListener("abort", () => { window.clearTimeout(paint); window.clearTimeout(quiet); pins.clear(); surface.remove(); }, { once: true });
  render();
  void list.load();
}
