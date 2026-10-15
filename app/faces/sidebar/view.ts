// SPDX-License-Identifier: AGPL-3.0-or-later
// The Sidebar face: the node's list of chats, and a reader that shows one chat's saved entries. It reads only. It has no
// call that sends a message or creates a chat, so writing happens in Threads. The same view lists archived sessions
// when it is asked to (the Archived sessions face).
import type { FaceClient } from "../../core/index.js";
import { COPY, countText } from "../threads/copy.js";
import { createConversation } from "../threads/conversation.js";
import { h, icon, mark, neutralize } from "../threads/dom.js";
import { listen } from "../threads/events.js";
import { createList } from "../threads/list.js";
import { createListView } from "../threads/listview.js";
import type { Summary } from "../threads/model.js";
import { createTranscript } from "../threads/transcript.js";

const PAINT_MS = 40;
const CARDS = 100;

export function mountSidebar(
  root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>, archived: boolean,
): void {
  let dirtyList = false;
  let dirtyReader = false;
  let paint: number | undefined;
  let reading = false;
  let connectedBefore = false;
  const schedule = (list: boolean, reader: boolean) => {
    dirtyList = dirtyList || list;
    dirtyReader = dirtyReader || reader;
    if (paint !== undefined || signal.aborted) return;
    paint = window.setTimeout(() => { paint = undefined; render(); }, PAINT_MS);
  };
  signal.addEventListener("abort", () => window.clearTimeout(paint), { once: true });

  const list = createList(client, signal, { archived, changed: () => schedule(true, false) });
  const conversation = createConversation(client, signal, {
    granted, readOnly: true, changed: () => schedule(false, true),
  });
  const openId = () => (reading ? conversation.state.summary?.sessionId ?? null : null);
  const transcript = createTranscript({ signal, conversation });

  const choose = (summary: Summary) => {
    reading = true;
    list.seen(summary.sessionId);
    void conversation.open(summary);
    render();
    back.focus();
  };
  const reload = () => { void list.load(); };
  const cards = createListView({
    list, signal, id: "sidebar", empty: archived ? COPY.list.emptyArchived : COPY.list.empty, open: choose,
    selected: openId, running: () => null, reload, search: true, limit: CARDS, onMore: undefined,
  });
  const live = h("p", { class: "problem", role: "status", hidden: "" });

  const brand = h("div", { class: "brand" }, mark(), h("span", {}, COPY.sidebar.brand));
  // Archived sessions has its own page heading; the Sidebar has the brand row and the list's name.
  const listing = h("section", { class: "side-list" },
    archived ? null : brand, archived ? null : h("h2", { class: "side-heading" }, COPY.list.heading), live, cards.element);

  const back = h("button", { type: "button", class: "back", "aria-label": COPY.sidebar.back }, icon("back"), h("span", {}, COPY.sidebar.back));
  const title = h("h2", { class: "title" });
  const sub = h("p", { class: "sub" });
  const problem = h("p", { class: "problem", role: "status", hidden: "" });
  const reader = h("section", { class: "side-reader", hidden: "" },
    h("div", { class: "reader-bar" }, back, h("div", { class: "heading-block" }, title, sub)),
    transcript.element, problem, h("p", { class: "readonly" }, COPY.chat.readOnly));
  const shell = h("div", { class: "side", "data-view": "list" }, listing, reader);
  root.append(shell);

  const renderReader = () => {
    const { summary, notices } = conversation.state;
    title.replaceChildren(...neutralize(summary ? summary.title || COPY.header.untitled : ""));
    sub.textContent = summary
      ? `${summary.mode === "build" ? COPY.composer.build : COPY.composer.chat} · ${countText(summary.sequence, COPY.list.message, COPY.list.messages)}`
      : "";
    const latest = notices[notices.length - 1];
    if (latest) problem.replaceChildren(latest.text, latest.code ? " " : "", latest.code ? h("code", {}, latest.code) : "");
    problem.hidden = latest === undefined;
    transcript.sync();
  };

  function render() {
    if (signal.aborted) return;
    if (dirtyList) cards.render();
    if (dirtyReader && reading) renderReader();
    dirtyList = false;
    dirtyReader = false;
    shell.dataset.view = reading ? "reader" : "list";
    listing.hidden = reading;
    reader.hidden = !reading;
  }

  back.addEventListener("click", () => {
    reading = false;
    render();
    const current = cards.element.querySelector<HTMLElement>('[aria-current="true"]');
    (current ?? cards.element.querySelector<HTMLElement>("button"))?.focus();
  }, { signal });
  root.addEventListener("keydown", event => {
    if (event.key !== "Escape" || event.defaultPrevented || !reading) return;
    back.click();
  }, { signal });

  const link = listen(client, signal, {
    event: event => {
      list.event(event, openId());
      conversation.event(event);
    },
    bad: () => undefined,
    state: (connected, code) => {
      conversation.live(connected);
      if (connected) {
        live.hidden = true;
        if (connectedBefore) { reload(); conversation.resync(); }
        connectedBefore = true;
        return;
      }
      const retry = h("button", { type: "button", class: "link" }, COPY.notices.liveRetry);
      retry.addEventListener("click", () => link.retry(), { signal });
      live.replaceChildren(`${COPY.notices.liveDown} `, code ? h("code", {}, code) : "", " ", retry);
      live.hidden = false;
    },
  });

  schedule(true, false);
  reload();
}
