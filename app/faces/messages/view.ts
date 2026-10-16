// SPDX-License-Identifier: AGPL-3.0-or-later
// The Messages face: three sections over the network service's read calls. A section whose call this face has not
// been granted shows an unavailable state and makes no call. Nothing here sends, adds a contact or approves anything.
import type { FaceClient, JsonValue } from "../../core/index.js";
import { clearServiceState, serviceState, showServiceState } from "../../core/service-state.js";
import { COPY } from "./copy.js";
import { h, untrusted } from "./dom.js";
import { moment, readContactPage, readMessagePage, readRefusals, shortKey } from "./model.js";
import type { Contact, Message, Page, Refusals } from "./model.js";

const MAX_ROWS = 1_000;
const PAGE = 50;
const NAMES = 100;

interface Panel { readonly element: HTMLElement; show(): void }
interface TabSpec { readonly id: string; readonly label: string; readonly blurb: string; readonly panel: Panel }
interface Feed<T> {
  readonly method: string;
  readonly read: (value: JsonValue) => Page<T>;
  readonly key: (item: T) => string;
  readonly row: (item: T) => HTMLElement;
  readonly empty: string;
  readonly nouns: readonly [string, string];
  readonly prepare?: () => Promise<void>;
}

function stamp(ms: number): HTMLElement {
  const at = moment(ms);
  return at ? h("time", { datetime: at.iso }, at.label) : h("span", {}, "time not readable");
}

function messageRow(message: Message, names: ReadonlyMap<string, string>): HTMLElement {
  const inbound = message.direction === "in";
  const name = names.get(message.contact);
  const sentence = message.state === null ? null : COPY.states[message.state];
  const outcome = sentence === null ? null : h("p", { class: `outcome ${message.state ?? ""}` }, sentence);
  if (outcome && message.code !== null) {
    const error = new Error(message.code);
    if (serviceState(error).kind === "unavailable") showServiceState(outcome, error);
  }
  return h("li", { class: `message ${inbound ? "in" : "out"}`, "data-message": message.id },
    h("p", { class: "who" },
      h("span", { class: "badge" }, inbound ? COPY.inboundBadge : COPY.outboundBadge),
      h("span", {}, inbound ? COPY.from : COPY.to),
      name !== undefined && untrusted("strong", {}, name),
      h("code", { class: "key", title: message.contact }, shortKey(message.contact))),
    untrusted("p", { class: "words" }, message.text),
    h("p", { class: "meta" }, stamp(message.at), h("span", {}, COPY.viaRelays)),
    outcome);
}

function contactRow(contact: Contact): HTMLElement {
  const pairing = contact.pairing;
  return h("li", { class: "contact", "data-contact": contact.npub },
    untrusted("p", { class: "name" }, contact.label),
    h("p", { class: "meta" }, h("span", {}, COPY.keyLabel), h("code", { class: "key full" }, contact.npub)),
    h("p", { class: `meta pairing ${pairing ? pairing.method : "none"}` },
      pairing ? COPY.pairing[pairing.method] : COPY.noPairing,
      pairing && h("span", {}, COPY.verified, " ", stamp(pairing.verifiedAt))));
}

function tally(count: number, empty: string, nouns: readonly [string, string], more: boolean, advances: boolean): string {
  if (count === 0) return empty;
  const shown = `Showing ${count} ${nouns[count === 1 ? 0 : 1]}.`;
  if (advances && count < MAX_ROWS) return `${shown} There are more.`;
  if (!more) return `${shown} That is all there is.`;
  return `${shown} ${count >= MAX_ROWS ? COPY.capped : COPY.stalled}`;
}

// One paged read call, newest first. The cursor is the service's own; a page that adds nothing new ends the paging.
function pagedList<T>(client: FaceClient, signal: AbortSignal, feed: Feed<T>): Panel {
  const rows = h("ul", { class: "rows" });
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const more = h("button", { type: "button", hidden: "" }, COPY.loadMore);
  const refresh = h("button", { type: "button" }, COPY.refresh);
  const element = h("div", { class: "feed", "aria-busy": "false" },
    info, problem, rows, h("div", { class: "actions" }, more, refresh));
  const seen = new Set<string>();
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
      const [value] = await Promise.all([
        client.call("network", feed.method, { before, limit: PAGE }, { signal }),
        restart && feed.prepare ? feed.prepare() : undefined,
      ]);
      const page = feed.read(value);
      if (signal.aborted) return;
      if (restart) { rows.replaceChildren(); seen.clear(); }
      let added = 0;
      for (const item of page.items) {
        const key = feed.key(item);
        if (seen.has(key) || seen.size >= MAX_ROWS) continue;
        seen.add(key);
        rows.append(feed.row(item));
        added++;
      }
      const advances = page.next !== null && page.next !== before && added > 0;
      next = advances && seen.size < MAX_ROWS ? page.next : null;
      summary = tally(seen.size, feed.empty, feed.nouns, page.next !== null, advances);
      info.textContent = summary;
    } catch (error) {
      if (signal.aborted) return;
      if (restart) { rows.replaceChildren(); seen.clear(); next = null; summary = ""; }
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
  return { element, show: () => { if (!started) void read(true); } };
}

// The refusal counts are one object, not a list. Each reason keeps its own number beside the total.
function refusalsPanel(client: FaceClient, signal: AbortSignal): Panel {
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const counts = h("dl", { class: "counts" });
  const refresh = h("button", { type: "button" }, COPY.refresh);
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

function tabs(signal: AbortSignal, specs: readonly TabSpec[]): HTMLElement {
  const bar = h("div", { class: "tabs", role: "tablist", "aria-label": COPY.sections });
  const buttons: HTMLButtonElement[] = [];
  const sections: HTMLElement[] = [];
  const select = (index: number, focus: boolean) => {
    specs.forEach((_, at) => {
      const on = at === index;
      buttons[at].setAttribute("aria-selected", String(on));
      buttons[at].tabIndex = on ? 0 : -1;
      sections[at].hidden = !on;
    });
    if (focus) buttons[index].focus();
    specs[index].panel.show();
  };
  specs.forEach((spec, index) => {
    const button = h("button", {
      type: "button", role: "tab", id: `tab-${spec.id}`, "aria-controls": `panel-${spec.id}`, "aria-selected": "false",
    }, spec.label);
    button.addEventListener("click", () => select(index, false), { signal });
    buttons.push(button);
    bar.append(button);
    sections.push(h("section", {
      role: "tabpanel", id: `panel-${spec.id}`, "aria-labelledby": `tab-${spec.id}`, hidden: "",
    }, h("p", { class: "blurb" }, spec.blurb), spec.panel.element));
  });
  bar.addEventListener("keydown", event => {
    const at = buttons.findIndex(button => button === event.target);
    const last = buttons.length - 1;
    const to = event.key === "ArrowRight" ? (at === last ? 0 : at + 1)
      : event.key === "ArrowLeft" ? (at <= 0 ? last : at - 1)
        : event.key === "Home" ? 0 : event.key === "End" ? last : -1;
    if (at < 0 || to < 0) return;
    event.preventDefault();
    select(to, true);
  }, { signal });
  const whole = h("div", {}, bar, ...sections);
  select(0, false);
  return whole;
}

// `granted` is the list of network calls the shell gave this face. A call outside it is never made.
export function mountMessages(root: HTMLElement, client: FaceClient, signal: AbortSignal, granted: ReadonlySet<string>): void {
  const names = new Map<string, string>();
  // Names are optional: when the contacts cannot be read, a message shows its key alone.
  const learn = async (): Promise<void> => {
    if (!granted.has("contacts.list")) return;
    try {
      const page = readContactPage(await client.call("network", "contacts.list", { before: null, limit: NAMES }, { signal }));
      names.clear();
      for (const contact of page.items) names.set(contact.npub, contact.label);
    } catch { /* Keys are shown instead of names. */ }
  };
  const thread = granted.has("messages.list")
    ? pagedList<Message>(client, signal, {
      method: "messages.list", read: readMessagePage, key: message => message.id,
      row: message => messageRow(message, names), empty: COPY.emptyMessages, nouns: ["message", "messages"], prepare: learn,
    })
    : null;
  const messages: Panel = thread
    ? { element: h("div", {}, h("p", { class: "aside" }, COPY.inbound), thread.element), show: thread.show }
    : absent();
  const book = granted.has("contacts.list")
    ? pagedList<Contact>(client, signal, {
      method: "contacts.list", read: readContactPage, key: contact => contact.npub,
      row: contactRow, empty: COPY.emptyContacts, nouns: ["contact", "contacts"],
    })
    : null;
  const contacts: Panel = book
    ? { element: h("div", {}, h("p", { class: "aside" }, COPY.pairingNote), book.element), show: book.show }
    : absent();
  const refused = granted.has("refusals.counts") ? refusalsPanel(client, signal) : absent();
  root.append(
    h("p", { class: "lede" }, COPY.lede),
    tabs(signal, [
      { id: "messages", label: COPY.tabs.messages, blurb: COPY.blurbs.messages, panel: messages },
      { id: "contacts", label: COPY.tabs.contacts, blurb: COPY.blurbs.contacts, panel: contacts },
      { id: "refused", label: COPY.tabs.refused, blurb: COPY.blurbs.refused, panel: refused },
    ]),
  );
}
