// SPDX-License-Identifier: AGPL-3.0-or-later
// Owner-shell messaging. Contact changes use the existing passkey card flow; sends use the bound owner session.
import type { FaceClient, JsonValue } from "../../core/index.js";
import { clearServiceState, serviceState, showServiceState } from "../../core/service-state.js";
import { COPY, sendOutcome } from "./copy.js";
import { h, untrusted } from "./dom.js";
import { moment, readContactPage, readMessagePage, readRefusals, shortKey } from "./model.js";
import type { Contact, Message, Page, Refusals } from "./model.js";
import { addContact, composer, ownIdentity } from "./actions.js";
import { portal } from "./portal.js";
import { readAllPages } from "./paging.js";

const MAX_ROWS = 1_000;
const PAGE = 50;

interface Panel { readonly element: HTMLElement; show(): void }
interface Feed<T> {
  readonly method: string;
  readonly read: (value: JsonValue) => Page<T>;
  readonly key: (item: T) => string;
  readonly row: (item: T) => HTMLElement;
  readonly empty: string;
  readonly nouns: readonly [string, string];
  readonly params?: Readonly<Record<string, JsonValue>>;
  readonly retain?: boolean;
}

function stamp(ms: number): HTMLElement {
  const at = moment(ms);
  return at ? h("time", { datetime: at.iso }, at.label) : h("span", {}, "time not readable");
}

function messageRow(message: Message, names: ReadonlyMap<string, string>): HTMLElement {
  const inbound = message.direction === "in";
  const name = names.get(message.contact);
  const sentence = sendOutcome(message);
  const outcome = sentence === null ? null : h("p", { class: `outcome ${message.state ?? ""}` }, sentence);
  if (outcome && message.code !== null) {
    const error = new Error(message.code);
    if (serviceState(error).kind === "unavailable") showServiceState(outcome, error);
  }
  return h("li", { class: `message ak-row ak-row--static ak-tone-${inbound ? "violet" : "mint"}`, "data-message": message.id },
    h("p", { class: "who" },
      h("span", { class: "ak-pill" }, inbound ? COPY.inboundBadge : COPY.outboundBadge),
      h("span", {}, inbound ? COPY.from : COPY.to),
      name !== undefined && untrusted("strong", {}, name),
      h("code", { class: "key", title: message.contact }, shortKey(message.contact))),
    untrusted("p", { class: "words" }, message.text),
    h("p", { class: "meta" }, stamp(message.at), h("span", {}, COPY.viaRelays)),
    outcome);
}

function contactRow(contact: Contact, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>): HTMLElement {
  const thread = granted.has("messages.list") ? pagedList<Message>(client, signal, {
    method: "messages.list", read: readMessagePage, key: message => message.id,
    params: { npub: contact.npub }, row: message => messageRow(message, new Map([[contact.npub, contact.label]])),
    empty: COPY.emptyMessages, nouns: ["message", "messages"],
  }) : absent();
  const send = granted.has("send") ? composer(client, signal, contact.npub, () => thread.show()) : null;
  const details = h("div", {},
    h("dl", { class: "ak-fields" }, h("dt", {}, COPY.keyLabel), h("dd", { class: "key full" }, contact.npub)),
    h("p", { class: "aside" }, contact.pairing ? COPY.pairing[contact.pairing.method] : COPY.noPairing),
    thread.element, send);
  const entry = portal(contact.label, shortKey(contact.npub), details, signal, () => thread.show(), "message");
  entry.element.dataset.contact = contact.npub;
  return h("li", {}, entry.element);
}

function tally(count: number, empty: string, nouns: readonly [string, string], more: boolean, advances: boolean): string {
  if (count === 0) return empty;
  const shown = `Showing ${count} ${nouns[count === 1 ? 0 : 1]}.`;
  if (advances && count < MAX_ROWS) return `${shown} There are more.`;
  if (!more) return `${shown} That is all there is.`;
  return `${shown} ${count >= MAX_ROWS ? COPY.capped : COPY.stalled}`;
}

// Messages page newest first; contacts refresh the whole book before pruning retained rows.
function pagedList<T>(client: FaceClient, signal: AbortSignal, feed: Feed<T>): Panel {
  const rows = h("ul", { class: "rows" });
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const more = h("button", { type: "button", class: "ak-action", hidden: "" }, COPY.loadMore);
  const refresh = h("button", { type: "button", class: "ak-action" }, COPY.refresh);
  const element = h("div", { class: "feed", "aria-busy": "false" },
    info, problem, rows, h("div", { class: "actions" }, more, refresh));
  const seen = new Set<string>();
  const retained = new Map<string, HTMLElement>();
  let next: string | null = null;
  let summary = "";
  let busy = false;
  let started = false;

  const read = async (restart: boolean): Promise<void> => {
    if (busy || signal.aborted) return;
    busy = true;
    started = true;
    refresh.disabled = true;
    more.disabled = true;
    element.setAttribute("aria-busy", "true");
    info.textContent = COPY.reading;
    problem.hidden = true;
    clearServiceState(problem);
    const before = restart ? null : next;
    try {
      const fetch = async (cursor: string | null): Promise<Page<T>> => feed.read(
        await client.call("network", feed.method, { before: cursor, limit: PAGE, ...feed.params }, { signal }));
      const page = feed.retain ? { items: await readAllPages(fetch, feed.key), next: null } : await fetch(before);
      if (signal.aborted) return;
      if (restart) { if (!feed.retain) rows.replaceChildren(); seen.clear(); }
      let added = 0;
      for (const item of page.items) {
        const key = feed.key(item);
        if (seen.has(key) || (!feed.retain && seen.size >= MAX_ROWS)) continue;
        seen.add(key);
        const row = (feed.retain && retained.get(key)) || feed.row(item);
        if (feed.retain) retained.set(key, row);
        if (!feed.retain || row.parentElement !== rows) rows.append(row);
        added++;
      }
      if (restart && feed.retain) {
        // A removed contact's row goes for good: one re-added later is drawn afresh with its new label.
        for (const [key, row] of retained) if (!seen.has(key)) { row.remove(); retained.delete(key); }
      }
      const advances = page.next !== null && page.next !== before && added > 0;
      next = advances && seen.size < MAX_ROWS ? page.next : null;
      summary = tally(seen.size, feed.empty, feed.nouns, page.next !== null, advances);
      info.textContent = summary;
    } catch (error) {
      if (signal.aborted) return;
      if (restart) { rows.replaceChildren(); seen.clear(); retained.clear(); next = null; summary = ""; }
      info.textContent = summary;
      showServiceState(problem, error);
      problem.hidden = false;
    } finally {
      busy = false;
      if (!signal.aborted) {
        refresh.disabled = false;
        more.disabled = false;
        more.hidden = next === null;
        element.setAttribute("aria-busy", "false");
      }
    }
  };
  refresh.addEventListener("click", () => { void read(true); }, { signal });
  more.addEventListener("click", () => { void read(false); }, { signal });
  const timer = setInterval(() => {
    if (started && element.isConnected && (feed.retain || seen.size <= PAGE) && !element.closest("[hidden]") && !document.hidden) void read(true);
  }, 10_000);
  signal.addEventListener("abort", () => clearInterval(timer), { once: true });
  return { element, show: () => { void read(true); } };
}

// The refusal counts are one object, not a list. Each reason keeps its own number beside the total.
function refusalsPanel(client: FaceClient, signal: AbortSignal): Panel {
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const counts = h("dl", { class: "counts" });
  const refresh = h("button", { type: "button", class: "ak-action" }, COPY.refresh);
  const element = h("div", { class: "refusals", "aria-busy": "false" },
    h("p", { class: "aside" }, COPY.refusedLead), info, problem, counts, h("div", { class: "actions" }, refresh));
  let busy = false;
  let started = false;

  const show = (data: Refusals) => {
    const rows: Array<[string, number]> = [[COPY.refusedTotal, data.total], ...COPY.reasons.map(([key, label]): [string, number] => [label, data[key]])];
    counts.replaceChildren(...rows.flatMap(([label, value]) => [h("dt", {}, label), h("dd", {}, value.toLocaleString())]));
    info.textContent = data.lastAuraSequence > 0 ? `${COPY.lastCounted} #${data.lastAuraSequence}.` : COPY.noneCounted;
  };
  const read = async (): Promise<void> => {
    if (busy || signal.aborted) return;
    busy = true;
    started = true;
    refresh.disabled = true;
    element.setAttribute("aria-busy", "true");
    info.textContent = COPY.reading;
    problem.hidden = true;
    clearServiceState(problem);
    try {
      const data = readRefusals(await client.call("network", "refusals.counts", {}, { signal }));
      if (!signal.aborted) show(data);
    } catch (error) {
      if (signal.aborted) return;
      counts.replaceChildren();
      info.textContent = "";
      showServiceState(problem, error);
      problem.hidden = false;
    } finally {
      busy = false;
      if (!signal.aborted) {
        refresh.disabled = false;
        element.setAttribute("aria-busy", "false");
      }
    }
  };
  refresh.addEventListener("click", () => { void read(); }, { signal });
  return { element, show: () => { if (!started) void read(); } };
}

function absent(): Panel {
  const element = h("p", { role: "status" });
  showServiceState(element, new Error("app:service-unavailable"));
  return { element, show: () => undefined };
}

// `granted` is the network methods the shell gave this face. It enforces the same list on each call.
export function mountMessages(root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>): void {
  const book = granted.has("contacts.list") ? pagedList<Contact>(client, signal, {
    method: "contacts.list", read: readContactPage, key: contact => contact.npub,
    row: contact => contactRow(contact, client, signal, granted), retain: true,
    empty: COPY.emptyContacts, nouns: ["contact", "contacts"],
  }) : absent();
  const refused = granted.has("refusals.counts") ? refusalsPanel(client, signal) : absent();
  const refusalPortal = portal("Refused", "Only counts are kept", refused.element, signal, refused.show, "shield", "gold");
  const canvas = h("div", { class: "ak-canvas" },
    h("header", { class: "ak-header" }, h("div", { class: "ak-header__copy" },
      h("p", { class: "ak-header__eyebrow" }, "Nostr"), h("h1", { class: "ak-header__title" }, "Messages"))),
    ownIdentity(client, signal),
    granted.has("contact.propose") ? addContact(client, signal) : null,
    h("section", { "aria-label": "Threads" }, h("h2", { class: "ak-label" }, "Threads"), book.element),
    refusalPortal.element,
    h("p", { class: "ak-footnote" }, COPY.footnote));
  root.append(canvas);
  book.show();
}
