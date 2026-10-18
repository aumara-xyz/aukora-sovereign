// SPDX-License-Identifier: AGPL-3.0-or-later
// Messages stays inside its centre lane: a header with the filters and the owner's Aukora ID, search, Add a contact and
// More, then the conversations. Opening one lifts its portal button to the top as the thread's header, with a back
// button, the messages below it and the compose box at the bottom.
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, serviceState, showServiceState } from "../../core/service-state.js";
import { ago } from "../threads/time.js";
import { COPY, sendOutcome } from "./copy.js";
import { threadGlyph } from "../threads/spatial-icons.js";
import { h, untrusted } from "./dom.js";
import { conversationList, moment, readContactPage, readMarks, readMessagePage, readRefusals, shortKey, threadMessages } from "./model.js";
import type { Contact, Conversation, Mark, Message } from "./model.js";
import { addContact, composer, copyId, ownIdentity } from "./actions.js";
import { glyph, portal, portalIcon } from "./portal.js";

const PAGE = 50;
const MAX_ROWS = 1_000;

function stamp(ms: number, compact = false): HTMLElement {
  const at = moment(ms);
  return at ? h("time", { datetime: at.iso, title: at.label }, compact ? ago(ms, Date.now()) : at.label)
    : h("span", {}, "Time unavailable");
}

function messageRow(message: Message, name: string): HTMLElement {
  const inbound = message.direction === "in";
  const sentence = sendOutcome(message);
  const outcome = sentence === null ? null : h("p", { class: `outcome ${message.state ?? ""}` }, sentence);
  if (outcome && message.code !== null && serviceState(message.code).kind === "unavailable") showServiceState(outcome, message.code);
  return h("li", { class: `message ak-row ak-row--static ak-tone-${inbound ? "violet" : "mint"}`, "data-direction": message.direction, "data-message": message.id },
    h("p", { class: "who" }, untrusted("strong", {}, inbound ? name : "You"), inbound && h("span", { class: "ak-pill" }, "Contact")),
    untrusted("p", { class: "words" }, message.text), h("p", { class: "meta" }, stamp(message.at)), outcome);
}

// Per-contact pages arrive newest first; rendering sorts all loaded pages oldest first. A refresh merges the newest
// page while it overlaps the loaded history. A larger burst starts a fresh contiguous window; the compose draft stays.
// No success state claims delivery to the other person.
function threadPanel(client: FaceClient, signal: AbortSignal, contact: Contact, granted: ReadonlySet<string>,
  changed: (messages: readonly Message[]) => void) {
  const address = h("code", { class: "key full" }, contact.npub);
  const copy = h("button", { type: "button", class: "ak-action" }, "Copy Aukora ID");
  const copyStatus = h("p", { role: "status", class: "info" });
  copyId(copy, address, copyStatus, signal);
  const details = h("details", { class: "thread-details" }, h("summary", {}, "Aukora ID and contact details"),
    h("dl", { class: "ak-fields" }, h("dt", {}, "Aukora ID"), h("dd", {}, address)), copy, copyStatus,
    h("p", { class: "aside" }, contact.pairing ? COPY.pairing[contact.pairing.method] : COPY.noPairing));
  const rows = h("ol", { class: "rows transcript", "aria-label": "Messages in time order" });
  const info = h("p", { class: "info", role: "status" });
  const problem = h("p", { class: "problem", role: "alert", hidden: "" });
  const more = h("button", { type: "button", class: "ak-action", hidden: "" }, "Load earlier messages");
  const refresh = h("button", { type: "button", class: "ak-action" }, COPY.refresh);
  const scroll = h("div", { class: "thread-scroll", tabindex: "0", "aria-label": "Conversation history" },
    details, h("div", { class: "button-row" }, more, refresh), info, problem, rows);
  const element = h("div", { class: "thread-panel", "aria-busy": "false" }, scroll);
  const messages = new Map<string, Message>();
  let next: string | null = null;
  let busy = false;
  let started = false;
  let historyStarted = false;
  let capped = false;
  let visible = false;
  let pendingRefresh = false;
  const read = async (restart: boolean): Promise<void> => {
    if (busy) { pendingRefresh ||= restart; return; }
    if (signal.aborted || !granted.has("messages.list")) return;
    busy = true;
    started = true;
    refresh.disabled = more.disabled = true;
    element.setAttribute("aria-busy", "true");
    info.textContent = COPY.reading;
    problem.hidden = true;
    clearServiceState(problem);
    const before = restart ? null : next;
    const bottom = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 48;
    const oldHeight = scroll.scrollHeight;
    const oldTop = scroll.scrollTop;
    try {
      const page = readMessagePage(await client.call("network", "messages.list", { npub: contact.npub, before, limit: PAGE }, { signal }));
      if (page.items.some(message => message.contact !== contact.npub)) throw new Error("app:invalid-reply");
      if (signal.aborted) return;
      // Without overlap, keeping the old cursor would jump over arrivals between the old and newest pages.
      // Restart only the history window so Load earlier follows this page and the compose draft survives.
      const resetWindow = restart && messages.size > 0 && page.next !== null
        && !page.items.some(message => messages.has(message.id));
      if (resetWindow) { messages.clear(); historyStarted = false; capped = false; }
      let added = 0;
      for (const message of page.items) {
        if (!restart && !messages.has(message.id) && messages.size >= MAX_ROWS) continue;
        if (!messages.has(message.id)) added++;
        messages.set(message.id, message);
      }
      // New arrivals still enter a capped thread. Retain the newest window rather than freezing at the cap.
      if (messages.size > MAX_ROWS) {
        const oldest = threadMessages([...messages.values()], contact.npub).slice(0, messages.size - MAX_ROWS);
        for (const message of oldest) messages.delete(message.id);
        capped = true;
      }
      // The older cursor remains valid while the newest page refreshes.
      if (!restart || !historyStarted) next = page.next;
      historyStarted = true;
      const stalled = !restart && page.next !== null && (page.next === before || added === 0);
      if (messages.size >= MAX_ROWS && next !== null) capped = true;
      if (stalled || capped) next = null;
      const ordered = threadMessages([...messages.values()], contact.npub);
      rows.replaceChildren(...ordered.map(message => messageRow(message, contact.label)));
      info.textContent = ordered.length === 0 ? COPY.emptyMessages : stalled ? COPY.stalled
        : capped ? COPY.capped : resetWindow ? "Showing the latest messages. Load earlier messages to continue this conversation." : "";
      if (visible && !document.hidden && element.getClientRects().length > 0) changed(ordered);
      if (restart && (bottom || resetWindow)) scroll.scrollTop = scroll.scrollHeight;
      else if (!restart) scroll.scrollTop = oldTop + scroll.scrollHeight - oldHeight;
    } catch (error) {
      if (!signal.aborted) { info.textContent = ""; showServiceState(problem, error); problem.hidden = false; }
    } finally {
      busy = false;
      if (!signal.aborted) {
        refresh.disabled = more.disabled = false;
        more.hidden = next === null;
        element.setAttribute("aria-busy", "false");
        if (pendingRefresh) { pendingRefresh = false; void read(true); }
      }
    }
  };
  refresh.addEventListener("click", () => { void read(true); }, { signal });
  more.addEventListener("click", () => { void read(false); }, { signal });
  if (granted.has("send")) element.append(composer(client, signal, contact.npub, () => { void read(true); }));
  if (!granted.has("messages.list")) { showServiceState(problem, "app:service-unavailable"); problem.hidden = false; }
  return {
    element,
    show(open: boolean) {
      visible = open;
      if (open) {
        if (element.getClientRects().length > 0) changed([...messages.values()]);
        void read(true);
      }
    },
    refresh() { if (visible && started && element.getClientRects().length > 0) void read(true); },
  };
}

function refusalsPanel(client: FaceClient, signal: AbortSignal): HTMLElement {
  const info = h("p", { role: "status", class: "info" });
  const counts = h("dl", { class: "counts" });
  let busy = false;
  const read = async () => {
    if (busy || signal.aborted) return;
    busy = true;
    clearServiceState(info);
    try {
      const data = readRefusals(await client.call("network", "refusals.counts", {}, { signal }));
      if (signal.aborted) return;
      const pairs: Array<[string, number]> = [[COPY.refusedTotal, data.total], ...COPY.reasons.map(([key, label]): [string, number] => [label, data[key]])];
      counts.replaceChildren(...pairs.flatMap(([label, value]) => [h("dt", {}, label), h("dd", {}, value.toLocaleString())]));
      info.textContent = data.lastAuraSequence > 0 ? `${COPY.lastCounted} #${data.lastAuraSequence}.` : COPY.noneCounted;
    } catch (error) { if (!signal.aborted) { counts.replaceChildren(); showServiceState(info, error); } }
    finally { busy = false; }
  };
  const detail = h("div", {}, h("p", { class: "aside" }, COPY.refusedLead), counts, info);
  return portal("Refused messages", "Only counts are kept", detail, signal, open => { if (open) void read(); }, "shield", "gold").element;
}

type Filter = "all" | "pinned" | "unread" | "archived";
// The same icon toggles, glyphs and pressed colours as Auma's thread list; "all" clears the others.
const FILTERS: ReadonlyArray<readonly [Filter, string]> = [
  ["all", "All conversations"], ["pinned", "Pinned conversations"],
  ["unread", "Unread conversations"], ["archived", "Archived conversations"],
];
const EMPTY: Readonly<Record<Filter, string>> = {
  all: COPY.emptyContacts, pinned: "No pinned conversations.", unread: "No unread conversations.",
  archived: "No archived conversations.",
};
const NO_MARK: Mark = { pinned: false, archived: false };

interface ConversationCard {
  readonly holder: HTMLElement;
  readonly element: HTMLElement;
  update(conversation: Conversation, mark: Mark, failed: boolean): void;
  refresh(): void;
  close(): void;
}

function iconButton(kind: "all" | "pin" | "unread" | "archive", label: string, extra = ""): HTMLButtonElement {
  return h("button", { type: "button", class: `iconButton ${kind}Action ${extra}`.trim(), "aria-label": label, title: label, "aria-pressed": "false" },
    kind === "all" ? glyph("all") : threadGlyph(kind));
}

function marker(kind: "pin" | "unread" | "archive", label: string): HTMLElement {
  return h("span", { class: `marker ${kind}Marker`, title: label, hidden: "" }, threadGlyph(kind), h("span", { class: "visually-hidden" }, label));
}

export function mountMessages(root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>): void {
  const contacts = new Map<string, Contact>();
  const messages = new Map<string, Message>();
  const readIds = new Set<string>();
  const markedUnread = new Set<string>();
  let marks: ReadonlyMap<string, Mark> = new Map();
  const previewed = new Set<string>();
  const previewFailures = new Set<string>();
  const cards = new Map<string, ConversationCard>();
  const canMark = granted.has("conversation.mark");
  let filter: Filter = "all";

  // Header: the title, the filters, then the owner's Aukora ID as a compact blue portal that drops its panel down.
  const filterButtons = new Map(FILTERS.map(([id, label]) => [id, iconButton(id === "pinned" ? "pin" : id === "archived" ? "archive" : id, label)]));
  const idExpander = h("span", { class: "ak-expander", "aria-hidden": "true" }, "+");
  const idToggle = h("button", { type: "button", class: "id-toggle ak-tone-blue", "aria-expanded": "false", "aria-controls": "own-aukora-id" },
    glyph("id"), h("span", {}, "Aukora ID"), idExpander);
  const idPanel = h("div", { class: "id-drop ak-tone-blue", id: "own-aukora-id", hidden: "" }, ownIdentity(client, signal));
  const header = h("header", { class: "ak-header msg-header" },
    h("h1", { class: "ak-header__title" }, "Messages"),
    h("div", { class: "msg-header__tools" }, h("span", { class: "actions msg-filters", role: "group", "aria-label": "Show" }, ...filterButtons.values()), idToggle));

  // Search, then Add a contact beside More (How it works, Refresh and the rarely used).
  const query = h("input", { type: "search", class: "msg-search__input", placeholder: "Search names and messages", "aria-label": "Search conversations", autocomplete: "off", spellcheck: "false", maxlength: "200" });
  const clearSearch = h("button", { type: "button", class: "iconButton msg-search__clear", "aria-label": "Clear search", title: "Clear search", hidden: "" }, threadGlyph("close"));
  const search = h("div", { class: "msg-search" }, threadGlyph("search"), query, clearSearch);
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const rows = h("ul", { class: "rows conversations", "aria-label": "Conversations" });
  const moreContacts = h("button", { type: "button", class: "ak-action", hidden: "" }, "More contacts");
  const refresh = h("button", { type: "button", class: "ak-action" }, COPY.refresh);
  const how = h("div", {},
    h("p", { class: "aside" }, "Your Aukora ID is a Nostr public key. Messages travel through Nostr relays, wrapped so that only the other person can read them."),
    h("p", { class: "aside" }, COPY.contactKey),
    h("p", { class: "aside" }, COPY.relaysSee + " A relay accepting a message does not prove your friend received it."),
    h("p", { class: "aside" }, "Unread marks track incoming messages loaded in this open view. Opening a conversation clears its mark here; this is not a read receipt to your friend. Pinned and archived are your own marks on this node; your friend never sees them."),
    h("p", { class: "aside" }, COPY.inbound), h("p", { class: "aside" }, COPY.footnote));
  if (granted.has("refusals.counts")) how.append(refusalsPanel(client, signal));
  const morePanel = h("div", { class: "more-panel" },
    portal("How it works", "Approvals, privacy and relays", how, signal, () => undefined, "shield", "blue").element,
    h("div", { class: "button-row" }, refresh));
  const tools = h("div", { class: "msg-tools" },
    granted.has("contact.propose") ? addContact(client, signal) : null,
    portal("More", "Help, refresh", morePanel, signal, () => undefined, "more", "blue").element);
  const list = h("div", { class: "list-scene" }, search, tools,
    h("section", { class: "msg-list", "aria-label": "Conversations" }, info, problem, rows, h("div", { class: "button-row" }, moreContacts)));
  const stage = h("div", { class: "thread-stage", hidden: "" });
  const top = h("div", { class: "msg-top" }, header, idPanel);
  const canvas = h("div", { class: "ak-canvas" }, top, list, stage);
  root.dataset.view = "list";
  root.append(canvas);
  let selected: string | null = null;
  let next: string | null = null;
  let busy = false;
  const remember = (items: readonly Message[]) => { for (const message of items) messages.set(message.id, message); };
  const seen = (items: readonly Message[]) => {
    remember(items);
    for (const message of items) if (message.direction === "in") readIds.add(message.id);
    if (selected) markedUnread.delete(selected);
    render();
  };

  idToggle.addEventListener("click", () => {
    const open = idPanel.hidden;
    idPanel.hidden = !open;
    idToggle.setAttribute("aria-expanded", String(open));
    idExpander.textContent = open ? "−" : "+";
  }, { signal });
  for (const [id, button] of filterButtons) button.addEventListener("click", () => { filter = id; render(); }, { signal });
  query.addEventListener("input", () => { clearSearch.hidden = query.value === ""; render(); }, { signal });
  query.addEventListener("keydown", event => { if (event.key === "Escape" && query.value) { event.preventDefault(); query.value = ""; clearSearch.hidden = true; render(); } }, { signal });
  clearSearch.addEventListener("click", () => { query.value = ""; clearSearch.hidden = true; render(); query.focus(); }, { signal });

  const setMark = (npub: string, change: Partial<Mark>) => {
    const before = marks.get(npub) ?? NO_MARK;
    const after = { ...before, ...change };
    const updated = new Map(marks);
    if (after.pinned || after.archived) updated.set(npub, after); else updated.delete(npub);
    marks = updated;
    render();
    void client.call("network", "conversation.mark", { npub, pinned: after.pinned, archived: after.archived }, { signal }).catch(error => {
      if (signal.aborted) return;
      // The node refused: put the mark back as it was and say why.
      const restored = new Map(marks);
      if (before.pinned || before.archived) restored.set(npub, before); else restored.delete(npub);
      marks = restored;
      showServiceState(problem, error);
      problem.hidden = false;
      render();
    });
  };

  const open = (npub: string, card: ConversationCard, show: boolean) => {
    const from = card.element.getBoundingClientRect?.().top;
    selected = show ? npub : null;
    top.hidden = show;
    list.hidden = show;
    stage.hidden = !show;
    root.dataset.view = show ? "thread" : "list";
    (show ? stage : card.holder).append(card.element);
    if (show) markedUnread.delete(npub);
    // The portal button slides up into place as the thread's header (none under reduced motion, see messages.css).
    const to = card.element.getBoundingClientRect?.().top;
    if (show && from !== undefined && to !== undefined && from !== to) {
      card.element.animate?.([{ transform: `translateY(${from - to}px)` }, { transform: "none" }], { duration: 260, easing: "cubic-bezier(.16,1,.3,1)" });
    }
  };

  const create = (conversation: Conversation): ConversationCard => {
    const contact = conversation.contact;
    const title = untrusted("span", { class: "ak-portal__title" }, contact.label);
    const pinMark = marker("pin", "Pinned");
    const unreadMark = marker("unread", "Unread");
    const archiveMark = marker("archive", "Archived");
    const snippet = h("span", { class: "ak-portal__summary conversation-snippet", dir: "auto" });
    const time = h("span", { class: "conversation-time" });
    const expander = h("span", { class: "ak-expander", "aria-hidden": "true" }, "+");
    const head = h("button", { type: "button", class: "ak-portal__head", "aria-expanded": "false" }, portalIcon("message"),
      h("span", { class: "ak-portal__copy" }, h("span", { class: "conversation-title" }, title, pinMark, unreadMark, archiveMark), snippet),
      h("span", { class: "ak-portal__end" }, time, expander));
    const back = h("button", { type: "button", class: "thread-back", "aria-label": "Back to conversations", title: "Back to conversations", hidden: "" }, glyph("back"), h("span", {}, "Back"));
    const pin = iconButton("pin", "Pin conversation");
    const archive = iconButton("archive", "Archive conversation");
    const unread = iconButton("unread", "Mark as unread");
    const actions = h("span", { class: "row-actions" }, ...(canMark ? [pin, archive] : []), unread);
    const panel = threadPanel(client, signal, contact, granted, seen);
    const body = h("div", { class: "ak-portal__body", hidden: "" }, panel.element);
    const element = h("section", { class: "ak-portal ak-tone-mint conversation", "data-open": "no", "data-contact": contact.npub },
      h("div", { class: "conversation-line" }, back, head, actions), body);
    const holder = h("li", {}, element);
    let current = conversation;
    const toggle = (show: boolean) => {
      element.dataset.open = show ? "yes" : "no";
      head.setAttribute("aria-expanded", String(show));
      head.setAttribute("aria-label", show ? `${contact.label}. Back to conversations` : `Open conversation with ${contact.label}`);
      expander.textContent = show ? "−" : "+";
      back.hidden = !show;
      body.hidden = !show;
      open(contact.npub, card, show);
      panel.show(show);
      render();
      (show ? back : head).focus({ preventScroll: true });
    };
    head.addEventListener("click", () => toggle(selected !== contact.npub), { signal });
    back.addEventListener("click", () => toggle(false), { signal });
    element.addEventListener("keydown", event => { if (event.key === "Escape" && selected === contact.npub) { event.preventDefault(); toggle(false); } }, { signal });
    pin.addEventListener("click", () => setMark(contact.npub, { pinned: !(marks.get(contact.npub)?.pinned ?? false) }), { signal });
    archive.addEventListener("click", () => setMark(contact.npub, { archived: !(marks.get(contact.npub)?.archived ?? false) }), { signal });
    unread.addEventListener("click", () => {
      if (current.unread || markedUnread.has(contact.npub)) {
        markedUnread.delete(contact.npub);
        for (const message of messages.values()) if (message.contact === contact.npub && message.direction === "in") readIds.add(message.id);
      } else markedUnread.add(contact.npub);
      render();
    }, { signal });
    const card: ConversationCard = {
      holder, element, refresh: panel.refresh, close: () => toggle(false),
      update(value, mark, failed) {
        current = value;
        const shown = selected === contact.npub;
        const isUnread = !shown && (value.unread || markedUnread.has(contact.npub));
        title.replaceChildren(...untrusted("span", {}, value.contact.label).childNodes);
        snippet.replaceChildren(...untrusted("span", {}, shown ? `Aukora ID ${shortKey(contact.npub)}` : failed ? "Message preview unavailable" : value.snippet || "No messages yet").childNodes);
        time.replaceChildren(...(!shown && value.latest ? [stamp(value.latest.at, true)] : []));
        pinMark.hidden = !mark.pinned;
        archiveMark.hidden = !mark.archived;
        unreadMark.hidden = !isUnread;
        actions.hidden = shown;
        pin.setAttribute("aria-pressed", String(mark.pinned));
        pin.setAttribute("aria-label", mark.pinned ? "Unpin conversation" : "Pin conversation");
        pin.title = pin.getAttribute("aria-label") ?? "";
        archive.setAttribute("aria-pressed", String(mark.archived));
        archive.setAttribute("aria-label", mark.archived ? "Move back from the archive" : "Archive conversation");
        archive.title = archive.getAttribute("aria-label") ?? "";
        unread.setAttribute("aria-pressed", String(isUnread));
        unread.setAttribute("aria-label", isUnread ? "Mark as read" : "Mark as unread");
        unread.title = unread.getAttribute("aria-label") ?? "";
      },
    };
    return card;
  };

  function matches(conversation: Conversation, mark: Mark, needle: string): boolean {
    const isUnread = conversation.unread || markedUnread.has(conversation.contact.npub);
    const shown = filter === "archived" ? mark.archived : !mark.archived
      && (filter === "all" || (filter === "pinned" && mark.pinned) || (filter === "unread" && isUnread));
    if (!shown || needle === "") return shown;
    if (conversation.contact.label.toLocaleLowerCase().includes(needle)) return true;
    for (const message of messages.values()) {
      if (message.contact === conversation.contact.npub && message.text.toLocaleLowerCase().includes(needle)) return true;
    }
    return false;
  }

  function render(): void {
    for (const [id, button] of filterButtons) button.setAttribute("aria-pressed", String(id === filter));
    const needle = query.value.trim().toLocaleLowerCase();
    const all = conversationList([...contacts.values()], [...messages.values()], readIds);
    // Pinned conversations lead; within each group the newest activity comes first.
    const ordered = [...all.filter(value => marks.get(value.contact.npub)?.pinned), ...all.filter(value => !marks.get(value.contact.npub)?.pinned)];
    const wanted: HTMLElement[] = [];
    for (const value of ordered) {
      let card = cards.get(value.contact.npub);
      if (!card) { card = create(value); cards.set(value.contact.npub, card); }
      const mark = marks.get(value.contact.npub) ?? NO_MARK;
      card.update(value, mark, previewFailures.has(value.contact.npub));
      if (matches(value, mark, needle) || selected === value.contact.npub) wanted.push(card.holder);
    }
    // Keep focused portal and action controls in place across polling and unread updates.
    for (let at = 0; at < wanted.length; at++) if (rows.children[at] !== wanted[at]) rows.insertBefore(wanted[at], rows.children[at] ?? null);
    while (rows.children.length > wanted.length) rows.children[wanted.length].remove();
    for (const [id, card] of cards) if (!contacts.has(id) && selected !== id) { card.holder.remove(); cards.delete(id); }
    if (!busy || contacts.size > 0) {
      info.textContent = contacts.size === 0 ? COPY.emptyContacts : wanted.length > 0 ? ""
        : needle ? `No conversation matches “${query.value.trim()}”.` : EMPTY[filter];
    }
  }

  const previews = async () => {
    const missing = [...contacts.values()].filter(contact => !previewed.has(contact.npub));
    // A one-row scoped read also finds the latest message of quiet contacts outside the global inbox page.
    const worker = async () => {
      while (missing.length && !signal.aborted) {
        const contact = missing.shift();
        if (!contact) return;
        try {
          const page = readMessagePage(await client.call("network", "messages.list", { npub: contact.npub, before: null, limit: 1 }, { signal }));
          if (page.items.some(message => message.contact !== contact.npub)) throw new Error("app:invalid-reply");
          if (signal.aborted) return;
          remember(page.items);
          previewed.add(contact.npub);
          previewFailures.delete(contact.npub);
        } catch { if (!signal.aborted) previewFailures.add(contact.npub); }
      }
    };
    await Promise.all([worker(), worker(), worker(), worker()]);
  };

  const readMarksNow = async () => {
    if (!granted.has("conversations.marks")) return;
    try { marks = readMarks(await client.call("network", "conversations.marks", {}, { signal })); }
    catch (error) { if (!signal.aborted) { showServiceState(problem, error); problem.hidden = false; } }
  };

  const read = async (restart: boolean, manual = false): Promise<void> => {
    if (busy || signal.aborted) return;
    if (!granted.has("contacts.list") || !granted.has("messages.list")) {
      showServiceState(problem, "app:service-unavailable"); problem.hidden = false; return;
    }
    busy = true;
    refresh.disabled = moreContacts.disabled = true;
    if (contacts.size === 0) info.textContent = COPY.reading;
    problem.hidden = true;
    clearServiceState(problem);
    const before = restart ? null : next;
    try {
      const page = readContactPage(await client.call("network", "contacts.list", { before, limit: PAGE }, { signal }));
      if (signal.aborted) return;
      if (restart) contacts.clear();
      let added = 0;
      for (const contact of page.items) {
        if (!contacts.has(contact.npub) && contacts.size >= MAX_ROWS) continue;
        if (!contacts.has(contact.npub)) added++;
        contacts.set(contact.npub, contact);
      }
      const advances = page.next !== null && page.next !== before && added > 0;
      next = advances && contacts.size < MAX_ROWS ? page.next : null;
      if (manual || restart) previewed.clear();
      // Incoming rows beyond the latest preview can still mark a conversation unread in this view.
      const recent = readMessagePage(await client.call("network", "messages.list", { before: null, limit: PAGE }, { signal }));
      if (signal.aborted) return;
      remember(recent.items);
      await Promise.all([previews(), restart ? readMarksNow() : Promise.resolve()]);
      if (signal.aborted) return;
      busy = false;
      render();
      if (contacts.size > 0 && !advances && page.next !== null) info.textContent = COPY.stalled;
      else if (contacts.size >= MAX_ROWS && page.next !== null) info.textContent = COPY.capped;
    } catch (error) {
      if (!signal.aborted) { busy = false; render(); info.textContent = ""; showServiceState(problem, error); problem.hidden = false; }
    } finally {
      busy = false;
      if (!signal.aborted) { refresh.disabled = moreContacts.disabled = false; moreContacts.hidden = next === null; }
    }
  };
  refresh.addEventListener("click", () => { void read(true, true); }, { signal });
  moreContacts.addEventListener("click", () => { void read(false); }, { signal });
  const timer = setInterval(() => {
    if (document.hidden || root.getClientRects().length === 0) return;
    if (selected) cards.get(selected)?.refresh();
    else if (contacts.size <= PAGE) void read(true);
  }, 10_000);
  signal.addEventListener("abort", () => { clearInterval(timer); canvas.remove(); }, { once: true });
  render();
  void read(true);
}
