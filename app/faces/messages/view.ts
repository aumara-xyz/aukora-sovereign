// SPDX-License-Identifier: AGPL-3.0-or-later
// Messages stays inside its centre lane. A conversation's own portal header opens and closes its thread.
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, serviceState, showServiceState } from "../../core/service-state.js";
import { ago } from "../threads/time.js";
import { COPY, sendOutcome } from "./copy.js";
import { h, untrusted } from "./dom.js";
import { conversationList, moment, readContactPage, readMessagePage, readRefusals, threadMessages } from "./model.js";
import type { Contact, Conversation, Message } from "./model.js";
import { addContact, composer, copyId, ownIdentity } from "./actions.js";
import { portal, portalIcon } from "./portal.js";

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
    details, h("div", { class: "actions" }, more, refresh), info, problem, rows);
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

interface ConversationCard {
  readonly holder: HTMLElement;
  update(conversation: Conversation, failed: boolean): void;
  refresh(): void;
}

export function mountMessages(root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>): void {
  const contacts = new Map<string, Contact>();
  const messages = new Map<string, Message>();
  const readIds = new Set<string>();
  const previewed = new Set<string>();
  const previewFailures = new Set<string>();
  const cards = new Map<string, ConversationCard>();
  const rows = h("ul", { class: "rows conversations", "aria-label": "Conversations" });
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const more = h("button", { type: "button", class: "ak-action", hidden: "" }, "More contacts");
  const refresh = h("button", { type: "button", class: "ak-action" }, COPY.refresh);
  const how = h("div", {},
    h("p", { class: "aside" }, COPY.contactKey),
    h("p", { class: "aside" }, COPY.relaysSee + " A relay accepting a message does not prove your friend received it."),
    h("p", { class: "aside" }, "Unread marks track incoming messages loaded in this open view. Opening a conversation clears its mark here; this is not a read receipt to your friend."),
    h("p", { class: "aside" }, COPY.inbound), h("p", { class: "aside" }, COPY.footnote));
  if (granted.has("refusals.counts")) how.append(refusalsPanel(client, signal));
  const list = h("div", { class: "list-scene" }, ownIdentity(client, signal),
    granted.has("contact.propose") ? addContact(client, signal) : null,
    h("section", {}, h("h2", { class: "ak-label" }, "Conversations"), info, problem, rows,
      h("div", { class: "actions" }, more, refresh)),
    portal("How it works", "Approvals, privacy and relays", how, signal, () => undefined, "shield", "blue").element);
  const stage = h("div", { class: "thread-stage", hidden: "" });
  const canvas = h("div", { class: "ak-canvas" },
    h("header", { class: "ak-header" }, h("div", { class: "ak-header__copy" },
      h("p", { class: "ak-header__eyebrow" }, "Aukora"), h("h1", { class: "ak-header__title" }, "Messages"))), list, stage);
  root.dataset.view = "list";
  root.append(canvas);
  let selected: string | null = null;
  let next: string | null = null;
  let busy = false;
  const remember = (items: readonly Message[]) => { for (const message of items) messages.set(message.id, message); };
  const seen = (items: readonly Message[]) => {
    remember(items);
    for (const message of items) if (message.direction === "in") readIds.add(message.id);
    render();
  };

  const create = (conversation: Conversation): ConversationCard => {
    const contact = conversation.contact;
    const title = untrusted("span", { class: "ak-portal__title" }, contact.label);
    const snippet = h("span", { class: "ak-portal__summary conversation-snippet", dir: "auto" });
    const time = h("span", { class: "conversation-time" });
    const unread = h("span", { class: "unread", "aria-label": "Unread", title: "Unread in this view", hidden: "" }, "•");
    const mark = portalIcon("message");
    mark.append(unread);
    const expander = h("span", { class: "ak-expander", "aria-hidden": "true" }, "+");
    // The same portal button as every other: icon, title and one-line summary, then the time as its badge and the
    // expander. The contact's Aukora ID and its copy button live inside the open conversation.
    const head = h("button", { type: "button", class: "ak-portal__head", "aria-expanded": "false" }, mark,
      h("span", { class: "ak-portal__copy" }, title, snippet), h("span", { class: "ak-portal__end" }, time, expander));
    const panel = threadPanel(client, signal, contact, granted, seen);
    const body = h("div", { class: "ak-portal__body", hidden: "" }, panel.element);
    const element = h("section", { class: "ak-portal ak-tone-mint conversation", "data-open": "no", "data-contact": contact.npub },
      head, body);
    const holder = h("li", {}, element);
    head.addEventListener("click", () => {
      const open = selected !== contact.npub;
      selected = open ? contact.npub : null;
      element.dataset.open = open ? "yes" : "no";
      head.setAttribute("aria-expanded", String(open));
      head.setAttribute("aria-label", open ? `${contact.label}. Back to conversations` : `Open conversation with ${contact.label}`);
      expander.textContent = open ? "−" : "+";
      body.hidden = !open;
      list.hidden = open;
      stage.hidden = !open;
      root.dataset.view = open ? "thread" : "list";
      (open ? stage : holder).append(element);
      panel.show(open);
      render();
      head.focus({ preventScroll: true });
    }, { signal });
    return {
      holder, refresh: panel.refresh,
      update(value, failed) {
        const open = selected === contact.npub;
        title.replaceChildren(...untrusted("span", {}, value.contact.label).childNodes);
        snippet.replaceChildren(...untrusted("span", {}, open ? "Back to conversations" : failed ? "Message preview unavailable" : value.snippet || "No messages yet").childNodes);
        time.replaceChildren(...(!open && value.latest ? [stamp(value.latest.at, true)] : []));
        unread.hidden = open || !value.unread;
      },
    };
  };

  function render(): void {
    const conversations = conversationList([...contacts.values()], [...messages.values()], readIds);
    const wanted = conversations.map(value => {
      let card = cards.get(value.contact.npub);
      if (!card) { card = create(value); cards.set(value.contact.npub, card); }
      card.update(value, previewFailures.has(value.contact.npub));
      return card.holder;
    });
    // Keep focused portal/copy controls in place across polling and unread updates.
    for (let at = 0; at < wanted.length; at++) if (rows.children[at] !== wanted[at]) rows.insertBefore(wanted[at], rows.children[at] ?? null);
    for (const [id, card] of cards) if (!contacts.has(id) && selected !== id) { card.holder.remove(); cards.delete(id); }
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

  const read = async (restart: boolean, manual = false): Promise<void> => {
    if (busy || signal.aborted) return;
    if (!granted.has("contacts.list") || !granted.has("messages.list")) {
      showServiceState(problem, "app:service-unavailable"); problem.hidden = false; return;
    }
    busy = true;
    refresh.disabled = more.disabled = true;
    info.textContent = COPY.reading;
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
      await previews();
      if (signal.aborted) return;
      render();
      info.textContent = contacts.size === 0 ? COPY.emptyContacts : !advances && page.next !== null ? COPY.stalled
        : contacts.size >= MAX_ROWS && page.next !== null ? COPY.capped : "";
    } catch (error) {
      if (!signal.aborted) { render(); info.textContent = ""; showServiceState(problem, error); problem.hidden = false; }
    } finally {
      busy = false;
      if (!signal.aborted) { refresh.disabled = more.disabled = false; more.hidden = next === null; }
    }
  };
  refresh.addEventListener("click", () => { void read(true, true); }, { signal });
  more.addEventListener("click", () => { void read(false); }, { signal });
  const timer = setInterval(() => {
    if (document.hidden || root.getClientRects().length === 0) return;
    if (selected) cards.get(selected)?.refresh();
    else if (contacts.size <= PAGE) void read(true);
  }, 10_000);
  signal.addEventListener("abort", () => { clearInterval(timer); canvas.remove(); }, { once: true });
  void read(true);
}
