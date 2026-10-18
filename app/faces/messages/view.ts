// SPDX-License-Identifier: AGPL-3.0-or-later
// Messages stays inside its centre lane: a header with the filters and the owner's Aukora ID, search, Add a contact and
// More, then the conversations. Opening one lifts its portal button to the top as the thread's header, with a back
// button, the messages below it and the compose box at the bottom.
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { ago } from "../threads/time.js";
import { COPY, sendOutcome } from "./copy.js";
import { threadGlyph } from "../threads/spatial-icons.js";
import { icon } from "../threads/dom.js";
import { h, untrusted } from "./dom.js";
import { conversationList, moment, readContactPage, readMarks, readMessagePage, readRefusals, threadMessages } from "./model.js";
import type { Contact, Conversation, Mark, Message } from "./model.js";
import { addContact, composer, copyId, ownIdentity, removeContact } from "./actions.js";
import type { Composer } from "./actions.js";
import { glyph, portal, portalIcon } from "./portal.js";
import { readAllPages } from "./paging.js";

const PAGE = 50;
const MAX_ROWS = 1_000;

function stamp(ms: number, compact = false): HTMLElement {
  const at = moment(ms);
  return at ? h("time", { datetime: at.iso, title: at.label }, compact ? ago(ms, Date.now()) : at.label)
    : h("span", {}, "Time unavailable");
}

// A chat bubble (Peter, 2026-10-18): theirs on the left, mine on the right in another colour; no name, pill or notes.
// The time shows only on hover or focus. A failed send carries one small red retry; nothing claims delivery.
function messageRow(message: Message, retry: ((text: string) => void) | null): HTMLElement {
  const at = moment(message.at);
  const failed = message.state === "failed";
  // A send stopped by a contact change says why on the retry control (sendOutcome); other failures keep the short label.
  const why = failed ? sendOutcome(message) : null;
  const label = why !== null && why !== COPY.states.failed ? `${why} Send again` : "Not sent. Send again";
  const again = failed && retry ? h("button", { type: "button", class: "bubble-retry", "aria-label": label, title: label }, icon("refresh")) : null;
  again?.addEventListener("click", () => retry?.(message.text));
  return h("li", { class: `bubble-row ${message.direction === "out" ? "mine" : "theirs"}`, "data-direction": message.direction, "data-message": message.id, "data-state": message.state ?? "" },
    untrusted("p", { class: "bubble" }, message.text), again,
    at ? h("time", { class: "bubble-time", datetime: at.iso }, at.label) : null);
}

// Per-contact pages arrive newest first; rendering sorts all loaded pages oldest first. A refresh merges the newest
// page while it overlaps the loaded history. A larger burst starts a fresh contiguous window; the compose draft stays.
// No success state claims delivery to the other person.
function threadPanel(client: FaceClient, signal: AbortSignal, contact: Contact, granted: ReadonlySet<string>,
  changed: (messages: readonly Message[]) => void, removed: () => void) {
  const address = h("code", { class: "key full" }, contact.npub);
  const copy = h("button", { type: "button", class: "ak-action" }, "Copy Aukora ID");
  const copyStatus = h("p", { role: "status", class: "info" });
  copyId(copy, address, copyStatus, signal);
  // The contact's details open from the name in the thread's header, as in a chat app.
  const details = h("div", { class: "contact-info", hidden: "" },
    h("dl", { class: "ak-fields" }, h("dt", {}, "Aukora ID"), h("dd", {}, address)), copy, copyStatus,
    h("p", { class: "aside" }, contact.pairing ? COPY.pairing[contact.pairing.method] : COPY.noPairing));
  if (granted.has("contact.remove")) details.append(removeContact(client, signal, contact.npub, removed));
  const rows = h("ol", { class: "rows transcript", "aria-label": "Messages in time order" });
  const info = h("p", { class: "info", role: "status" });
  const problem = h("p", { class: "problem", role: "alert", hidden: "" });
  const more = h("button", { type: "button", class: "ak-action", hidden: "" }, "Load earlier messages");
  const scroll = h("div", { class: "thread-scroll", tabindex: "0", "aria-label": "Conversation history" },
    h("div", { class: "button-row" }, more), info, problem, rows);
  const element = h("div", { class: "thread-panel", "aria-busy": "false" }, details, scroll);
  let writer: Composer | null = null;
  const messages = new Map<string, Message>();
  let next: string | null = null;
  let busy = false;
  let started = false;
  let historyStarted = false;
  let capped = false;
  let visible = false;
  let pendingRefresh = false;
  let drawn = "";
  // `quiet` is the live re-read: no Reading line and no busy state, so an open thread does not flicker every poll.
  const read = async (restart: boolean, quiet = false): Promise<boolean> => {
    if (busy) { pendingRefresh ||= restart; return true; }
    if (signal.aborted || !granted.has("messages.list")) return false;
    busy = true;
    started = true;
    more.disabled = true;
    if (!quiet) { element.setAttribute("aria-busy", "true"); info.textContent = COPY.reading; }
    problem.hidden = true;
    clearServiceState(problem);
    const before = restart ? null : next;
    const bottom = scroll.scrollHeight - scroll.scrollTop - scroll.clientHeight < 48;
    const oldHeight = scroll.scrollHeight;
    const oldTop = scroll.scrollTop;
    try {
      const page = readMessagePage(await client.call("network", "messages.list", { npub: contact.npub, before, limit: PAGE }, { signal }));
      if (page.items.some(message => message.contact !== contact.npub)) throw new Error("app:invalid-reply");
      if (signal.aborted) return false;
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
      // Redraw only when a row arrived, left or changed its send state; the reader's place and selection stay.
      const shape = ordered.map(message => `${message.id}:${message.state ?? ""}`).join(",");
      if (shape !== drawn) { drawn = shape; rows.replaceChildren(...ordered.map(message => messageRow(message, writer ? writer.send : null))); }
      info.textContent = ordered.length === 0 ? COPY.emptyMessages : stalled ? COPY.stalled
        : capped ? COPY.capped : resetWindow ? "Showing the latest messages. Load earlier messages to continue this conversation." : "";
      if (visible && client.shown !== false && !document.hidden && element.getClientRects().length > 0) changed(ordered);
      if (restart && (bottom || resetWindow)) scroll.scrollTop = scroll.scrollHeight;
      else if (!restart) scroll.scrollTop = oldTop + scroll.scrollHeight - oldHeight;
      return true;
    } catch (error) {
      if (!signal.aborted) { info.textContent = ""; showServiceState(problem, error); problem.hidden = false; }
      return false;
    } finally {
      busy = false;
      if (!signal.aborted) {
        more.disabled = false;
        more.hidden = next === null;
        element.setAttribute("aria-busy", "false");
        if (pendingRefresh) { pendingRefresh = false; void read(true); }
      }
    }
  };
  more.addEventListener("click", () => { void read(false); }, { signal });
  if (granted.has("send")) {
    writer = composer(client, signal, contact.npub, contact.label, () => { void read(true); });
    element.append(writer.element);
  }
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
    /** Shows or hides the contact's details; returns whether they are shown. */
    toggleInfo(show = details.hidden !== false): boolean { details.hidden = !show; return show; },
    /** The live re-read of the newest page while this thread is open; false when it failed. */
    poll(): Promise<boolean> {
      return visible && started && client.shown !== false && element.getClientRects().length > 0 ? read(true, true) : Promise.resolve(true);
    },
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

type Filter = "pinned" | "unread" | "archived";
type Panel = "contact" | "id" | "more" | "pick";
// The thread list's own icon toggles. No filter selected is "all"; tapping the selected one again clears it.
const FILTERS: ReadonlyArray<readonly [Filter, "pin" | "unread" | "archive", string]> = [
  ["pinned", "pin", "Pinned"], ["unread", "unread", "Unread"], ["archived", "archive", "Archived"],
];
const EMPTY: Readonly<Record<Filter | "all", string>> = {
  all: COPY.emptyContacts, pinned: "No pinned conversations.", unread: "No unread conversations.",
  archived: "No archived conversations.",
};
const NO_MARK: Mark = { pinned: false, archived: false };
/** The live re-read while the face is shown; it backs off to a minute after failures. The node's relay worker
 * fetches every 30 s, so this only re-reads the node's own store. */
const LIVE_MS = 6_000;
const LIVE_MAX_MS = 60_000;

interface ConversationCard {
  readonly holder: HTMLElement;
  readonly element: HTMLElement;
  update(conversation: Conversation, mark: Mark, failed: boolean): void;
  poll(): Promise<boolean>;
  open(): void;
}

function iconButton(kind: "plus" | "pin" | "unread" | "archive", label: string): HTMLButtonElement {
  return h("button", { type: "button", class: `iconButton ${kind}Action`, "aria-label": label, title: label, "aria-pressed": "false" }, threadGlyph(kind));
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
  let filter: Filter | null = null;

  // Row 1: the title, then (inward, clear of both hot corners) New message and the three filters.
  const newMessage = h("button", { type: "button", class: "iconButton plusAction", "aria-label": "New message", title: "New message", "aria-expanded": "false" }, threadGlyph("plus"));
  const filterButtons = new Map(FILTERS.map(([id, glyphName, label]) => [id, iconButton(glyphName, `Show only ${label.toLowerCase()} conversations`)]));
  const header = h("header", { class: "ak-header msg-header" },
    h("h1", { class: "ak-header__title" }, "Messages"),
    h("span", { class: "actions msg-filters", role: "group", "aria-label": "Conversations" }, newMessage, ...filterButtons.values()));

  // Row 2: three thin buttons; each telescopes its own panel down beneath the row, one at a time.
  const how = h("div", {},
    h("p", { class: "aside" }, "Your Aukora ID is a Nostr public key. Messages travel through Nostr relays, wrapped so that only the other person can read them."),
    h("p", { class: "aside" }, COPY.contactKey),
    h("p", { class: "aside" }, COPY.relaysSee + " A relay accepting a message does not prove your friend received it."),
    h("p", { class: "aside" }, COPY.sendSession),
    h("p", { class: "aside" }, "New messages appear here on their own. Unread marks track incoming messages loaded in this open view; opening a conversation clears its mark here, and this is not a read receipt to your friend. Pinned and archived are your own marks on this node; your friend never sees them."),
    h("p", { class: "aside" }, COPY.inbound), h("p", { class: "aside" }, COPY.footnote));
  if (granted.has("refusals.counts")) how.append(refusalsPanel(client, signal));
  const picker = h("ul", { class: "picker", "aria-label": "Choose a contact" });
  const contactStatus = h("p", { role: "status", class: "info", "aria-live": "polite", hidden: "" });
  const contactsChanged = (removed?: string) => {
    if (removed) {
      if (selected === removed) cards.get(removed)?.open();
      contactStatus.textContent = "Contact removed.";
      contactStatus.hidden = false;
    }
    void read(true);
  };
  const panelContent: ReadonlyArray<readonly [Panel, HTMLElement | null]> = [
    ["contact", granted.has("contact.propose") ? addContact(client, signal, contactsChanged) : null],
    ["id", ownIdentity(client, signal)],
    ["more", how],
    ["pick", h("div", {}, h("p", { class: "ak-label" }, "New message to"), picker)],
  ];
  const drawers = new Map<Panel, HTMLElement>();
  for (const [id, content] of panelContent) {
    if (!content) continue;
    drawers.set(id, h("div", { class: `drawer drawer--${id}`, id: `panel-${id}`, "data-open": "no", inert: "" },
      h("div", { class: "drawer__inner" }, h("div", { class: "drawer__body" }, content))));
  }
  const toggles = new Map<Panel, HTMLButtonElement>();
  const expanders = new Map<Panel, HTMLElement>();
  const toggle = (id: Panel, label: string, glyphName: string, tone: string) => {
    if (!drawers.has(id)) return null;
    const expander = h("span", { class: "ak-expander", "aria-hidden": "true" }, "+");
    const button = h("button", { type: "button", class: `panel-toggle ak-tone-${tone}`, "aria-expanded": "false", "aria-controls": `panel-${id}` },
      glyph(glyphName), h("span", { class: "panel-toggle__label" }, label), expander);
    toggles.set(id, button);
    expanders.set(id, expander);
    return button;
  };
  const row = h("div", { class: "panel-row" },
    toggle("contact", "Add contact", "contact", "mint"), toggle("id", "Identity", "id", "blue"), toggle("more", "More", "more", "violet"));
  let openPanel: Panel | null = null;
  const setPanel = (next: Panel | null) => {
    openPanel = next;
    for (const [id, drawer] of drawers) {
      const open = id === next;
      drawer.dataset.open = open ? "yes" : "no";
      if (open) drawer.removeAttribute("inert"); else drawer.setAttribute("inert", "");
    }
    for (const [id, button] of toggles) button.setAttribute("aria-expanded", String(id === next));
    for (const [id, expander] of expanders) expander.textContent = id === next ? "−" : "+";
    newMessage.setAttribute("aria-expanded", String(next === "pick"));
  };
  for (const [id, button] of toggles) button.addEventListener("click", () => setPanel(openPanel === id ? null : id), { signal });

  const query = h("input", { type: "search", class: "msg-search__input", placeholder: "Search names and messages", "aria-label": "Search conversations", autocomplete: "off", spellcheck: "false", maxlength: "200" });
  const clearSearch = h("button", { type: "button", class: "iconButton msg-search__clear", "aria-label": "Clear search", title: "Clear search", hidden: "" }, threadGlyph("close"));
  const search = h("div", { class: "msg-search" }, threadGlyph("search"), query, clearSearch);
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const rows = h("ul", { class: "rows conversations", "aria-label": "Conversations" });
  const moreContacts = h("button", { type: "button", class: "ak-action", hidden: "" }, "More contacts");
  const list = h("div", { class: "list-scene" }, search,
    h("section", { class: "msg-list", "aria-label": "Conversations" }, info, problem, rows, h("div", { class: "button-row" }, moreContacts)));
  const stage = h("div", { class: "thread-stage", hidden: "" });
  const top = h("div", { class: "msg-top" }, header, h("div", { class: "msg-panels" }, row, ...drawers.values()), contactStatus);
  const canvas = h("div", { class: "ak-canvas" }, top, list, stage);
  root.dataset.view = "list";
  root.append(canvas);
  let selected: string | null = null;
  let next: string | null = null;
  let busy = false;
  let pendingRead = false;
  const remember = (items: readonly Message[]) => { for (const message of items) messages.set(message.id, message); };
  const seen = (items: readonly Message[]) => {
    remember(items);
    for (const message of items) if (message.direction === "in") readIds.add(message.id);
    if (selected) markedUnread.delete(selected);
    render();
  };

  newMessage.addEventListener("click", () => {
    // With no contact yet, a new message starts with adding one.
    if (contacts.size === 0) { setPanel(drawers.has("contact") ? "contact" : null); return; }
    setPanel(openPanel === "pick" ? null : "pick");
    render();
  }, { signal });
  for (const [id, button] of filterButtons) button.addEventListener("click", () => { filter = filter === id ? null : id; render(); }, { signal });
  query.addEventListener("input", () => { clearSearch.hidden = query.value === ""; render(); }, { signal });
  clearSearch.addEventListener("click", () => { query.value = ""; clearSearch.hidden = true; render(); query.focus(); }, { signal });
  root.addEventListener("keydown", event => {
    if (event.key !== "Escape" || event.defaultPrevented) return;
    if (selected) { event.preventDefault(); cards.get(selected)?.open(); }
    else if (openPanel) { event.preventDefault(); const was = openPanel; setPanel(null); (was === "pick" ? newMessage : toggles.get(was))?.focus(); }
    else if (query.value) { event.preventDefault(); query.value = ""; clearSearch.hidden = true; render(); }
  }, { signal });

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

  const place = (npub: string, card: ConversationCard, show: boolean) => {
    const from = card.element.getBoundingClientRect?.().top;
    selected = show ? npub : null;
    if (show) setPanel(null);
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
    if (!show) void live(true);
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
    const panel = threadPanel(client, signal, contact, granted, seen, () => contactsChanged(contact.npub));
    const body = h("div", { class: "ak-portal__body", hidden: "" }, panel.element);
    const element = h("section", { class: "ak-portal ak-tone-mint conversation", "data-open": "no", "data-contact": contact.npub },
      h("div", { class: "conversation-line" }, back, head, actions), body);
    const holder = h("li", {}, element);
    let current = conversation;
    const show = (open: boolean) => {
      element.dataset.open = open ? "yes" : "no";
      // Open, the name is the thread's header and shows the contact's details; Back returns to the list.
      head.setAttribute("aria-expanded", "false");
      head.setAttribute("aria-label", open ? `${contact.label}. Show contact details` : `Open conversation with ${contact.label}`);
      panel.toggleInfo(false);
      expander.textContent = open ? "−" : "+";
      back.hidden = !open;
      body.hidden = !open;
      place(contact.npub, card, open);
      panel.show(open);
      render();
      (open ? back : head).focus({ preventScroll: true });
    };
    head.addEventListener("click", () => {
      if (selected !== contact.npub) { show(true); return; }
      const shown = panel.toggleInfo();
      head.setAttribute("aria-expanded", String(shown));
      head.setAttribute("aria-label", `${contact.label}. ${shown ? "Hide" : "Show"} contact details`);
    }, { signal });
    back.addEventListener("click", () => show(false), { signal });
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
      holder, element, poll: panel.poll,
      // Opens the conversation, or closes it when it is the open one (Back, Escape).
      open: () => show(selected !== contact.npub),
      update(value, mark, failed) {
        current = value;
        const shown = selected === contact.npub;
        const isUnread = !shown && (value.unread || markedUnread.has(contact.npub));
        title.replaceChildren(...untrusted("span", {}, value.contact.label).childNodes);
        snippet.replaceChildren(...untrusted("span", {}, shown ? "" : failed ? "Message preview unavailable" : value.snippet || "No messages yet").childNodes);
        time.replaceChildren(...(!shown && value.latest ? [stamp(value.latest.at, true)] : []));
        pinMark.hidden = !mark.pinned;
        archiveMark.hidden = !mark.archived;
        unreadMark.hidden = !isUnread;
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
      && (filter === null || (filter === "pinned" && mark.pinned) || (filter === "unread" && isUnread));
    if (!shown || needle === "") return shown;
    if (conversation.contact.label.toLocaleLowerCase().includes(needle)) return true;
    for (const message of messages.values()) {
      if (message.contact === conversation.contact.npub && message.text.toLocaleLowerCase().includes(needle)) return true;
    }
    return false;
  }

  function renderPicker(ordered: readonly Conversation[]): void {
    const choices = ordered.filter(value => !(marks.get(value.contact.npub)?.archived)).map(value => {
      const choice = h("button", { type: "button", class: "picker__choice" }, portalIcon("message"), untrusted("span", { class: "picker__name" }, value.contact.label));
      choice.addEventListener("click", () => { setPanel(null); const card = cards.get(value.contact.npub); if (card && selected !== value.contact.npub) card.open(); }, { signal });
      return h("li", {}, choice);
    });
    picker.replaceChildren(...choices);
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
    if (openPanel === "pick") renderPicker(ordered);
    // Keep focused portal and action controls in place across live updates.
    for (let at = 0; at < wanted.length; at++) if (rows.children[at] !== wanted[at]) rows.insertBefore(wanted[at], rows.children[at] ?? null);
    while (rows.children.length > wanted.length) rows.children[wanted.length].remove();
    for (const [id, card] of cards) if (!contacts.has(id) && selected !== id) { card.holder.remove(); cards.delete(id); }
    if (!busy || contacts.size > 0) {
      info.textContent = contacts.size === 0 ? COPY.emptyContacts : wanted.length > 0 ? ""
        : needle ? `No conversation matches “${query.value.trim()}”.` : EMPTY[filter ?? "all"];
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

  // `first` is the opening read (previews for every contact and the owner marks); a live re-read takes the newest
  // contacts and messages and previews only contacts it has not seen. Returns false when the read failed.
  const read = async (restart: boolean, first = false): Promise<boolean> => {
    if (signal.aborted) return true;
    if (busy) { pendingRead ||= restart; return true; }
    if (!granted.has("contacts.list") || !granted.has("messages.list")) {
      showServiceState(problem, "app:service-unavailable"); problem.hidden = false; return false;
    }
    busy = true;
    moreContacts.disabled = true;
    if (contacts.size === 0 && first) info.textContent = COPY.reading;
    const before = restart ? null : next;
    try {
      // A refresh is one complete snapshot of the book (all pages) before it replaces the rows shown; a failed later
      // page keeps the previous book. "More contacts" pages only a book that was not refreshed.
      const fetch = async (cursor: string | null) =>
        readContactPage(await client.call("network", "contacts.list", { before: cursor, limit: PAGE }, { signal }));
      const page = restart ? { items: await readAllPages(fetch, contact => contact.npub), next: null } : await fetch(before);
      if (signal.aborted) return false;
      if (restart) contacts.clear();
      let added = 0;
      for (const contact of page.items) {
        if (!restart && !contacts.has(contact.npub) && contacts.size >= MAX_ROWS) continue;
        if (!contacts.has(contact.npub)) added++;
        contacts.set(contact.npub, contact);
      }
      const advances = page.next !== null && page.next !== before && added > 0;
      next = advances && contacts.size < MAX_ROWS ? page.next : null;
      if (first) previewed.clear();
      // Incoming rows beyond the latest preview can still mark a conversation unread in this view.
      const recent = readMessagePage(await client.call("network", "messages.list", { before: null, limit: PAGE }, { signal }));
      if (signal.aborted) return false;
      remember(recent.items);
      await Promise.all([previews(), first ? readMarksNow() : Promise.resolve()]);
      if (signal.aborted) return false;
      busy = false;
      problem.hidden = true;
      clearServiceState(problem);
      render();
      if (contacts.size > 0 && !advances && page.next !== null) info.textContent = COPY.stalled;
      else if (contacts.size >= MAX_ROWS && page.next !== null) info.textContent = COPY.capped;
      // A preview that keeps failing is retried on each live read; count it so the live loop backs off. A contact
      // that left the book takes its failure with it.
      for (const npub of [...previewFailures]) if (!contacts.has(npub)) previewFailures.delete(npub);
      return previewFailures.size === 0;
    } catch (error) {
      if (!signal.aborted) { busy = false; render(); info.textContent = ""; showServiceState(problem, error); problem.hidden = false; }
      return false;
    } finally {
      busy = false;
      if (!signal.aborted) {
        moreContacts.disabled = false; moreContacts.hidden = next === null;
        if (pendingRead) { pendingRead = false; void read(true); }
      }
    }
  };
  moreContacts.addEventListener("click", () => { void read(false); }, { signal });

  // Live: re-read while the face is shown, the open thread when one is open, else the list. Hidden (the tab, or the
  // shell parking this face's slot), it only waits, and showing it again re-reads at once.
  let timer: ReturnType<typeof setTimeout> | undefined;
  let delay = LIVE_MS;
  const schedule = (ms: number) => { if (timer !== undefined) clearTimeout(timer); if (!signal.aborted) timer = setTimeout(() => { void live(); }, ms); };
  async function live(now = false): Promise<void> {
    if (now) { schedule(0); return; }
    timer = undefined;
    if (signal.aborted) return;
    if (document.hidden || client.shown === false || root.getClientRects().length === 0) { schedule(LIVE_MS); return; }
    // The list re-reads the whole book (one snapshot, readAllPages), however many pages it has.
    const ok = selected ? await (cards.get(selected)?.poll() ?? Promise.resolve(true)) : await read(true);
    delay = ok ? LIVE_MS : Math.min(delay * 2, LIVE_MAX_MS);
    schedule(delay);
  }
  document.addEventListener?.("visibilitychange", () => { if (!document.hidden) { delay = LIVE_MS; schedule(0); } }, { signal });
  const unshown = client.onShown?.(shown => { if (shown && !document.hidden) { delay = LIVE_MS; schedule(0); } });
  if (unshown) signal.addEventListener("abort", () => { void unshown(); }, { once: true });
  signal.addEventListener("abort", () => { if (timer !== undefined) clearTimeout(timer); canvas.remove(); }, { once: true });
  render();
  void read(true, true).then(() => schedule(LIVE_MS));
}
