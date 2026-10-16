// SPDX-License-Identifier: AGPL-3.0-or-later
// The Threads face: the chat with Auma, with the node's list of chats beside it (a drawer on a narrow frame, a column on
// a wide one). The first message of a new chat creates its session. The face reads and writes only through the body
// service calls its manifest grants, and everything it shows from the node is data.
import type { FaceClient } from "../../core/index.js";
import { serviceMessage, serviceState } from "../../core/service-state.js";
import { COPY, countText } from "./copy.js";
import { createComposer } from "./composer.js";
import { createConversation } from "./conversation.js";
import { h, icon, mark, neutralize } from "./dom.js";
import { listen } from "./events.js";
import { createList } from "./list.js";
import { createListView } from "./listview.js";
import type { Summary } from "./model.js";
import { createTranscript } from "./transcript.js";

const PAINT_MS = 40;

export function mountChat(root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>): void {
  let dirtyList = false;
  let dirtyChat = false;
  let paint: number | undefined;
  let drawer = false;
  let connectedBefore = false;
  const schedule = (list: boolean, chat: boolean) => {
    dirtyList = dirtyList || list;
    dirtyChat = dirtyChat || chat;
    if (paint !== undefined || signal.aborted) return;
    paint = window.setTimeout(() => { paint = undefined; render(); }, PAINT_MS);
  };
  signal.addEventListener("abort", () => window.clearTimeout(paint), { once: true });

  const list = createList(client, signal, { archived: false, changed: () => schedule(true, false) });
  const conversation = createConversation(client, signal, {
    granted, readOnly: false, changed: () => schedule(true, true), created: summary => list.upsert(summary),
  });
  const openId = () => (conversation.state.phase === "draft" ? null : conversation.state.summary?.sessionId ?? null);
  // The chat Auma is working on: a turn was sent to it, or a reply for it is streaming.
  const workingId = () => {
    const { turn, stream } = conversation.state;
    if (turn && turn.session !== "") return turn.session;
    return stream?.phase === "streaming" ? stream.session : null;
  };

  const transcript = createTranscript({ signal, conversation });
  const composer = createComposer({ signal, conversation, granted });

  const choose = (summary: Summary) => {
    setDrawer(false);
    list.seen(summary.sessionId);
    composer.setMode(summary.mode);
    void conversation.open(summary);
    composer.focus();
    render();
  };
  const start = () => {
    setDrawer(false);
    conversation.draft();
    composer.setMode("chat");
    composer.focus();
    render();
  };
  const reload = () => { void list.load(); };
  const view = (id: string, limit: number, search: boolean, onMore?: () => void) => createListView({
    list, signal, id, empty: COPY.list.empty, open: choose, selected: openId, running: workingId, reload, search, limit, onMore,
  });

  const toggle = h("button", {
    type: "button", class: "icon-button toggle", "aria-controls": "thread-drawer", "aria-expanded": "false",
    "aria-label": COPY.header.showThreads, title: COPY.header.showThreads,
  }, icon("list"));
  const title = h("h2", { class: "title" });
  const sub = h("p", { class: "sub" });
  const fresh = h("button", { type: "button", class: "new" }, icon("plus"), h("span", {}, COPY.header.newChat));
  const bar = h("header", { class: "bar" }, toggle, h("div", { class: "heading" }, title, sub), fresh);

  const all = view("threads", 100, true);
  const side = h("aside", { class: "drawer", id: "thread-drawer", "aria-label": COPY.list.heading }, all.element);
  const recent = view("recent", 5, false, () => { setDrawer(true); all.focus(); });
  const recents = h("div", { class: "recent", hidden: "" }, h("h3", {}, COPY.list.recent), recent.element);
  const hero = h("div", { class: "hero" },
    h("div", { class: "hero-mark" }, mark()),
    h("h2", { class: "hero-title" }, COPY.hero.headline),
    h("p", { class: "hero-lede" }, COPY.hero.lede),
    recents);
  const stage = h("section", { class: "stage", "aria-label": COPY.names.threads }, hero, transcript.element);
  const chat = h("div", { class: "chat", "data-drawer": "closed", "data-view": "draft" }, bar, side, stage, composer.element);
  root.append(chat);

  const narrow = window.matchMedia("(max-width: 759.98px)");
  const renderHeader = () => {
    const st = conversation.state;
    const draft = st.phase === "draft";
    const summary = st.summary;
    title.replaceChildren(...neutralize(draft || !summary ? COPY.header.newChat : summary.title || COPY.header.untitled));
    sub.textContent = draft ? COPY.header.draftSub : !summary ? ""
      : `${summary.mode === "build" ? COPY.composer.build : COPY.composer.chat} · ${countText(summary.sequence, COPY.list.message, COPY.list.messages)}`;
    toggle.setAttribute("aria-expanded", String(drawer));
    const label = drawer ? COPY.header.hideThreads : COPY.header.showThreads;
    toggle.setAttribute("aria-label", label);
    toggle.title = label;
    chat.dataset.drawer = drawer ? "open" : "closed";
    chat.dataset.view = draft ? "draft" : "chat";
    hero.hidden = !draft;
    transcript.element.hidden = draft;
    const covered = drawer && narrow.matches;
    stage.inert = covered;
    composer.element.inert = covered;
  };

  const setDrawer = (open: boolean) => {
    drawer = open;
    renderHeader();
  };

  function render() {
    if (signal.aborted) return;
    if (dirtyList) {
      all.render();
      recent.render();
      recents.hidden = list.state.items.length === 0 && list.state.failure === null;
    }
    if (dirtyChat) {
      renderHeader();
      if (conversation.state.phase !== "draft") transcript.sync();
      composer.sync();
    }
    dirtyList = false;
    dirtyChat = false;
  }

  toggle.addEventListener("click", () => {
    setDrawer(!drawer);
    if (drawer) all.focus(); else toggle.focus();
  }, { signal });
  narrow.addEventListener("change", renderHeader, { signal });
  fresh.addEventListener("click", start, { signal });
  root.addEventListener("keydown", event => {
    if (event.key !== "Escape" || event.defaultPrevented || !drawer) return;
    setDrawer(false);
    toggle.focus();
  }, { signal });

  const live = listen(client, signal, {
    event: event => {
      list.event(event, openId());
      conversation.event(event);
    },
    bad: code => conversation.notify({ key: "bad", tone: "warn", text: COPY.notices.badEvent, code, action: null }),
    state: (connected, code) => {
      conversation.live(connected);
      if (connected) {
        conversation.dismiss("live");
        // After a gap in the updates, read again what the node has.
        if (connectedBefore) { reload(); conversation.resync(); }
        connectedBefore = true;
        return;
      }
      const state = code === null ? null : serviceState(code);
      if (state?.kind === "unavailable" && !state.retryable) {
        conversation.dismiss("live");
        return;
      }
      conversation.notify({
        key: "live", tone: "warn", text: code ? `${serviceMessage(code)} ${COPY.notices.liveDown}` : COPY.notices.liveDown, code,
        action: { label: COPY.notices.liveRetry, run: () => live.retry() },
      });
    },
  });

  schedule(true, true);
  reload();
}
