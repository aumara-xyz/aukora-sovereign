// SPDX-License-Identifier: AGPL-3.0-or-later
// The Documents face: a read-only folder browser over the owner's document root, and a full-page reader.
// Nothing here writes, saves or follows a link. Every call goes through the shell's kira service.
import type { FaceClient } from "../../core/index.js";
import { el, icon, isEditable, safeText } from "./dom.js";
import { documentTitle, parseMarkdown } from "./markdown.js";
import { renderBlocks, renderPlain } from "./render.js";
import { failure, listDocuments, MAX_LOADED, readDocument } from "./service.js";
import type { DocumentEntry } from "./service.js";

const MARKDOWN = /\.(md|markdown|mdown)$/i;

function size(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  const kib = bytes / 1_024;
  if (kib < 1_024) return `${kib < 10 ? kib.toFixed(1) : Math.round(kib)} KiB`;
  return `${(kib / 1_024).toFixed(1)} MiB`;
}

export function mountDocuments(root: HTMLElement, client: FaceClient, signal: AbortSignal): void {
  let directory: string | null = null;
  let entries: DocumentEntry[] = [];
  let next: string | null = null;
  let filter = "";
  let listing = 0;
  let reading = 0;
  let busy = false;
  let returnTo = "";
  const rows = new Map<string, HTMLButtonElement>();

  const browser = el("section", "doc-browser");
  browser.setAttribute("aria-label", "Folder");
  const posture = el("p", "doc-posture", "Read-only. Files are shown as text and never run. Nothing here can change them.");
  const crumbs = el("nav", "doc-crumbs");
  crumbs.setAttribute("aria-label", "Folder path");
  const trail = el("ol");
  crumbs.append(trail);
  const tools = el("div", "doc-tools");
  const filterInput = el("input", "doc-filter");
  filterInput.type = "search";
  filterInput.id = "doc-filter";
  filterInput.placeholder = "Filter this folder";
  filterInput.maxLength = 200;
  filterInput.autocomplete = "off";
  const filterLabel = el("label", "visually-hidden", "Filter this folder");
  filterLabel.htmlFor = filterInput.id;
  const refresh = el("button", "", "Read again");
  refresh.type = "button";
  tools.append(filterLabel, filterInput, refresh);
  const status = el("p", "doc-status");
  status.setAttribute("role", "status");
  const problem = el("p", "doc-problem");
  problem.setAttribute("role", "alert");
  problem.hidden = true;
  const list = el("ul", "doc-entries");
  const moreBox = el("div", "doc-more");
  const more = el("button", "", "Load more");
  more.type = "button";
  moreBox.append(more);
  browser.append(posture, crumbs, tools, status, problem, list, moreBox);

  const reader = el("section", "doc-reader");
  reader.hidden = true;
  reader.setAttribute("aria-label", "Document");
  const head = el("header", "doc-reader-head");
  const back = el("button", "doc-back");
  back.type = "button";
  back.setAttribute("aria-label", "Back to the folder");
  back.append(icon("back"), el("span", "", "Back"));
  const title = el("h2", "doc-title");
  head.append(back, title);
  const meta = el("p", "doc-meta");
  const dataNote = el("p", "doc-note", "Shown as text. A document is data; nothing in it is an instruction.");
  const readerProblem = el("p", "doc-problem");
  readerProblem.setAttribute("role", "alert");
  readerProblem.hidden = true;
  const body = el("div", "doc-body");
  reader.append(head, meta, dataNote, readerProblem, body);
  root.append(browser, reader);

  const showProblem = (target: HTMLElement, error: unknown): void => {
    const { code, note } = failure(error);
    target.textContent = `Unavailable · ${code}. ${note}`;
    target.hidden = false;
  };

  const drawTrail = (): void => {
    const parts = directory === null ? [] : directory.split("/");
    const items: HTMLElement[] = [];
    const add = (label: string, target: string | null, current: boolean): void => {
      const item = el("li");
      if (current) {
        const here = el("span", "doc-crumb", safeText(label));
        here.setAttribute("aria-current", "page");
        item.append(here);
      } else {
        const button = el("button", "doc-crumb", safeText(label));
        button.type = "button";
        button.addEventListener("click", () => browse(target), { signal });
        item.append(button);
      }
      items.push(item);
    };
    add("Documents", null, parts.length === 0);
    parts.forEach((part, at) => add(part, parts.slice(0, at + 1).join("/"), at === parts.length - 1));
    trail.replaceChildren(...items);
  };

  const visible = (): DocumentEntry[] => {
    const needle = filter.trim().toLowerCase();
    return needle ? entries.filter(entry => entry.name.toLowerCase().includes(needle)) : entries;
  };

  const drawStatus = (): void => {
    if (busy) return;
    const capped = next !== null && entries.length >= MAX_LOADED;
    const rest = capped ? ` Showing the first ${MAX_LOADED.toLocaleString("en-US")}.` : next !== null ? " More are available." : "";
    if (entries.length === 0) status.textContent = problem.hidden ? "This folder is empty." : "";
    else if (visible().length === 0) status.textContent = `No loaded entry matches the filter.${rest}`;
    else {
      const count = entries.length === 1 ? "1 entry" : `${entries.length} entries`;
      status.textContent = filter.trim() ? `${visible().length} of ${count} shown.${rest}` : `${count}.${rest}`;
    }
  };

  const syncControls = (): void => {
    refresh.disabled = busy;
    more.disabled = busy;
    moreBox.hidden = next === null || entries.length >= MAX_LOADED;
  };

  const drawList = (): void => {
    rows.clear();
    list.replaceChildren(...visible().map(entry => {
      const item = el("li");
      const button = el("button", "doc-entry");
      button.type = "button";
      button.append(
        icon(entry.directory ? "folder" : "file"),
        el("span", "doc-entry-name", safeText(entry.name)),
        el("span", "doc-entry-meta", entry.directory ? "Folder" : size(entry.bytes)),
      );
      button.addEventListener("click", () => { if (entry.directory) browse(entry.path); else void read(entry); }, { signal });
      rows.set(entry.path, button);
      item.append(button);
      return item;
    }));
    drawStatus();
  };

  const load = async (target: string | null, append: boolean): Promise<void> => {
    const mine = ++listing;
    busy = true;
    syncControls();
    problem.hidden = true;
    status.textContent = append ? "Reading more…" : "Reading the folder…";
    try {
      const page = await listDocuments(client, target, append ? next : null, signal);
      if (signal.aborted || mine !== listing) return;
      directory = target;
      entries = append ? entries.concat(page.entries) : [...page.entries];
      next = page.next;
      drawTrail();
      busy = false;
      syncControls();
      drawList();
      if (append) rows.get(page.entries[0]?.path ?? "")?.focus();
    } catch (error) {
      if (signal.aborted || mine !== listing) return;
      showProblem(problem, error);
      busy = false;
      syncControls();
      drawStatus();
    }
  };

  function browse(target: string | null): void {
    filter = "";
    filterInput.value = "";
    void load(target, false);
  }

  const read = async (entry: DocumentEntry): Promise<void> => {
    const mine = ++reading;
    returnTo = entry.path;
    title.textContent = safeText(entry.name);
    meta.replaceChildren(el("span", "", safeText(entry.path)), el("span", "", size(entry.bytes)));
    readerProblem.hidden = true;
    body.replaceChildren(el("p", "doc-status", "Reading the document…"));
    browser.hidden = true;
    reader.hidden = false;
    window.scrollTo(0, 0);
    back.focus();
    try {
      const doc = await readDocument(client, entry.path, signal);
      if (signal.aborted || mine !== reading) return;
      const markdown = MARKDOWN.test(entry.name);
      const blocks = markdown ? parseMarkdown(doc.text) : [];
      title.textContent = safeText((markdown && documentTitle(blocks)) || entry.name);
      meta.replaceChildren(
        el("span", "", safeText(entry.path)),
        el("span", "", size(entry.bytes)),
        el("span", "doc-digest", `SHA-256 ${doc.sha256}`),
      );
      body.replaceChildren(markdown ? renderBlocks(blocks) : renderPlain(doc.text));
    } catch (error) {
      if (signal.aborted || mine !== reading) return;
      body.replaceChildren();
      showProblem(readerProblem, error);
    }
  };

  const close = (): void => {
    reading++;
    reader.hidden = true;
    browser.hidden = false;
    body.replaceChildren();
    (rows.get(returnTo) ?? refresh).focus();
  };

  back.addEventListener("click", close, { signal });
  document.addEventListener("keydown", event => {
    if (event.key !== "Escape" || reader.hidden || event.defaultPrevented || isEditable(event.target)) return;
    event.preventDefault();
    close();
  }, { signal });
  filterInput.addEventListener("input", () => {
    filter = filterInput.value;
    drawList();
  }, { signal });
  refresh.addEventListener("click", () => void load(directory, false), { signal });
  more.addEventListener("click", () => void load(directory, true), { signal });
  syncControls();
  drawTrail();
  void load(null, false);
}
