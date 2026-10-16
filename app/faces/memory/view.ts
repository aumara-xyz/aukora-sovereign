// SPDX-License-Identifier: AGPL-3.0-or-later
// The Memory face: four sections over Kira's two read calls. Remembered and Forgotten read memory.list; search reads
// memory.recall; Signed and Proposals have no backend and say so. Nothing here writes, forgets or approves.
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { COPY } from "./copy.js";
import { h, untrusted } from "./dom.js";
import { moment, readNotePage, readRecall } from "./model.js";
import type { Note, Recall, Recalled, Tier } from "./model.js";

const MAX_ROWS = 1_000;
const RECALL_LIMIT = 20;
const QUERY_CHARS = 500;

interface Panel { readonly element: HTMLElement; show(): void }
interface TabSpec { readonly id: string; readonly label: string; readonly blurb: string; readonly panel: Panel }

function stamp(ms: number): HTMLElement {
  const at = moment(ms);
  return at ? h("time", { datetime: at.iso }, at.label) : h("span", {}, "time not readable");
}

function citation(sequence: number, meaning: string): HTMLElement {
  return h("span", { class: "cite", title: meaning }, `Aura record #${sequence}`);
}

function problemFor(error: unknown): HTMLElement {
  const element = h("p", { class: "problem" });
  showServiceState(element, error);
  return element;
}

function rememberedRow(note: Note): HTMLElement {
  return h("li", { class: "note", "data-note": note.noteId },
    untrusted("p", { class: "words" }, note.text ?? ""),
    h("p", { class: "meta" },
      h("span", { class: "chip" }, note.category),
      h("span", {}, "Saved ", stamp(note.at), " ", citation(note.citeSeq, "The Aura receipt for this save"))));
}

function forgottenRow(note: Note): HTMLElement {
  return h("li", { class: "note withheld", "data-note": note.noteId },
    h("p", { class: "words" }, COPY.withheld),
    h("p", { class: "meta" },
      h("span", { class: "chip" }, note.category),
      h("span", {}, "Saved ", stamp(note.at), " ", citation(note.citeSeq, "The Aura receipt for this save")),
      note.demotedAt !== null && note.demotedSeq !== null &&
        h("span", {}, "Forgotten ", stamp(note.demotedAt), " ", citation(note.demotedSeq, "The Aura receipt for this demotion"))));
}

function recalledRow(item: Recalled): HTMLElement {
  return h("li", { class: "note", "data-note": item.noteId },
    untrusted("p", { class: "words" }, item.text),
    h("p", { class: "meta" }, citation(item.citeSeq, "The Aura receipt for this save")));
}

function tally(count: number, tier: Tier, kiraHasMore: boolean, advances: boolean): string {
  if (count === 0) return tier === "remembered" ? COPY.emptyRemembered : COPY.emptyForgotten;
  const shown = `Showing ${count} ${count === 1 ? "note" : "notes"}.`;
  if (advances && count < MAX_ROWS) return `${shown} Kira has more.`;
  if (!kiraHasMore) return `${shown} That is every note Kira lists.`;
  return `${shown} ${count >= MAX_ROWS ? COPY.capped : COPY.stalled}`;
}

// One tier of memory.list, newest first. The cursor is Kira's own; a page that adds nothing new ends the paging.
function noteList(client: FaceClient, signal: AbortSignal, tier: Tier): Panel {
  const rows = h("ul", { class: "notes" });
  const info = h("p", { role: "status", class: "info" });
  const problem = h("p", { role: "alert", class: "problem", hidden: "" });
  const more = h("button", { type: "button", hidden: "" }, COPY.loadMore);
  const refresh = h("button", { type: "button" }, COPY.refresh);
  const element = h("div", { class: "note-list", "aria-busy": "false" },
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
      const page = readNotePage(await client.call("kira", "memory.list", { tier, before }, { signal }), tier);
      if (signal.aborted) return;
      if (restart) { rows.replaceChildren(); seen.clear(); }
      let added = 0;
      for (const note of page.notes) {
        if (seen.has(note.noteId) || seen.size >= MAX_ROWS) continue;
        seen.add(note.noteId);
        rows.append(tier === "remembered" ? rememberedRow(note) : forgottenRow(note));
        added++;
      }
      const advances = page.next !== null && page.next !== before && added > 0;
      next = advances && seen.size < MAX_ROWS ? page.next : null;
      summary = tally(seen.size, tier, page.next !== null, advances);
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

function recallContent(query: string, recall: Recall): Array<Node | string> {
  if (recall.result === "found") {
    const count = recall.items.length;
    return [
      h("p", { role: "status", class: "info" },
        `Recalled ${count} ${count === 1 ? "note" : "notes"} for `, untrusted("q", {}, query), `. ${COPY.recalledData}`),
      h("ul", { class: "notes" }, ...recall.items.map(recalledRow)),
    ];
  }
  if (recall.result === "empty") return [h("p", { role: "status", class: "info" }, COPY.recallEmpty)];
  return [h("div", { role: "status", class: "undetermined" },
    h("p", { class: "info" }, `◌ ${COPY.undeterminedLead}`),
    h("p", {}, COPY.recallUndetermined))];
}

// Search is memory.recall. Its three answers stay apart: found, empty, and not determined. The frame is sandboxed
// without allow-forms, so this is an input and a button, not a form.
function search(client: FaceClient, signal: AbortSignal, list: HTMLElement): HTMLElement {
  const input = h("input", {
    type: "search", id: "memory-query", maxlength: String(QUERY_CHARS), autocomplete: "off", spellcheck: "false",
  });
  const go = h("button", { type: "button" }, COPY.search);
  const clear = h("button", { type: "button", hidden: "" }, COPY.clearSearch);
  const out = h("div", { class: "recall", hidden: "" });
  const box = h("div", { class: "search", role: "search" },
    h("label", { for: "memory-query" }, COPY.searchLabel),
    h("div", { class: "row" }, input, go, clear),
    h("p", { class: "hint" }, COPY.searchHint));
  let pending = false;

  const present = (content: Array<Node | string>) => {
    out.replaceChildren(...content);
    out.hidden = false;
    list.hidden = true;
    clear.hidden = false;
  };
  clear.addEventListener("click", () => {
    out.replaceChildren();
    out.hidden = true;
    list.hidden = false;
    clear.hidden = true;
    input.value = "";
    input.focus();
  }, { signal });
  const run = () => {
    const query = input.value.trim();
    if (pending || signal.aborted) return;
    if (!query) { input.value = ""; input.focus(); return; }
    pending = true;
    go.disabled = true;
    go.textContent = COPY.searching;
    client.call("kira", "memory.recall", { query, limit: RECALL_LIMIT }, { signal })
      .then(value => { if (!signal.aborted) present(recallContent(query, readRecall(value))); })
      .catch((error: unknown) => {
        if (!signal.aborted) present([problemFor(error)]);
      })
      .finally(() => { pending = false; go.disabled = false; go.textContent = COPY.search; });
  };
  go.addEventListener("click", run, { signal });
  input.addEventListener("keydown", event => {
    if (event.key !== "Enter" || event.isComposing) return;
    event.preventDefault();
    run();
  }, { signal });
  return h("div", { class: "lookup" }, box, out);
}

function rememberedPanel(client: FaceClient, signal: AbortSignal): Panel {
  const list = noteList(client, signal, "remembered");
  const lookup = search(client, signal, list.element);
  return { element: h("div", {}, lookup, list.element, h("p", { class: "aside" }, COPY.noForget)), show: list.show };
}

function notice(): Panel {
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

export function mountMemory(root: HTMLElement, client: FaceClient, signal: AbortSignal): void {
  root.append(
    h("p", { class: "lede" }, COPY.lede),
    tabs(signal, [
      { id: "remembered", label: COPY.tabs.remembered, blurb: COPY.blurbs.remembered, panel: rememberedPanel(client, signal) },
      { id: "signed", label: COPY.tabs.signed, blurb: COPY.blurbs.signed, panel: notice() },
      { id: "proposals", label: COPY.tabs.proposals, blurb: COPY.blurbs.proposals, panel: notice() },
      { id: "forgotten", label: COPY.tabs.forgotten, blurb: COPY.blurbs.forgotten, panel: noteList(client, signal, "forgotten") },
    ]),
  );
}
