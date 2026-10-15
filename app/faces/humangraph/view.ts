// SPDX-License-Identifier: AGPL-3.0-or-later
// The Human Graph face: the owner's approved connections as a map and a list. It reads contacts from the
// node's network service and writes nothing. A pairing mark is evidence about how a contact was paired;
// it grants nothing and nothing here can add, remove or trust a contact.
import type { FaceClient } from "../../core/index.js";
import { el, safeText } from "./dom.js";
import { createGraph, MARKS } from "./graph.js";
import { failure, listConnections, MAX_LOADED } from "./service.js";
import type { Connection, Pairing } from "./service.js";

const TITLES: Readonly<Record<Pairing, string>> = {
  "screen-to-screen": "Met in person",
  remote: "Paired remotely",
  relayed: "Paired through a relay",
  unknown: "Pairing method not known",
  none: "No pairing recorded",
};
const SHORT: Readonly<Record<Pairing, string>> = {
  "screen-to-screen": "Met in person",
  remote: "Remote",
  relayed: "Relay",
  unknown: "Method unknown",
  none: "Unrecorded",
};
const LEGEND: readonly [Pairing, string][] = [
  ["screen-to-screen", "Met in person (solid line)"],
  ["remote", "Paired remotely (dashed line)"],
  ["relayed", "Paired through a relay (dotted line)"],
  ["none", "No pairing recorded, or method unknown (faint dots)"],
];

function nameOf(connection: Connection): string {
  return safeText(connection.label.trim() || connection.key);
}

function when(ms: number | null): string {
  if (ms === null || ms > 8_640_000_000_000_000) return "";
  return `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

export function mountHumanGraph(root: HTMLElement, client: FaceClient, signal: AbortSignal): void {
  let connections: Connection[] = [];
  let next: string | null = null;
  let skipped = 0;
  let selected = -1;
  let generation = 0;
  let busy = true;

  const note = el("p", "graph-note", "Your connections are the contacts you approved with your passkey. A mark shows how a pairing was recorded. It is evidence only and grants nothing.");
  const status = el("p", "graph-status");
  status.setAttribute("role", "status");
  const problem = el("p", "graph-problem");
  problem.setAttribute("role", "alert");
  problem.hidden = true;

  const board = el("section", "graph-board");
  board.setAttribute("aria-label", "Connection map");
  const canvas = el("canvas", "graph-canvas");
  canvas.width = 640;
  canvas.height = 480;
  canvas.setAttribute("role", "img");
  const legend = el("ul", "graph-legend");
  for (const [pairing, text] of LEGEND) {
    const item = el("li");
    const swatch = el("span", `graph-swatch graph-swatch-${pairing}`);
    swatch.style.setProperty("--mark", MARKS[pairing].color);
    swatch.setAttribute("aria-hidden", "true");
    item.append(swatch, el("span", "", text));
    legend.append(item);
  }
  board.append(canvas, legend);

  const side = el("section", "graph-side");
  side.setAttribute("aria-label", "Connections");
  const sideHead = el("div", "graph-side-head");
  const refresh = el("button", "", "Read again");
  refresh.type = "button";
  sideHead.append(el("h2", "graph-heading", "Connections"), refresh);
  const list = el("ul", "graph-people");
  const moreBox = el("div", "graph-more");
  const more = el("button", "", "Load more");
  more.type = "button";
  moreBox.append(more);
  const detail = el("section", "graph-detail");
  detail.setAttribute("aria-label", "Selected connection");
  detail.setAttribute("aria-live", "polite");
  side.append(sideHead, list, moreBox, detail);

  const layout = el("div", "graph-layout");
  layout.append(board, side);
  const media = el("section", "graph-media");
  media.setAttribute("aria-label", "Media");
  media.append(el("h2", "graph-heading", "Media"), el("p", "graph-empty", "No media is attached to any connection."));
  root.append(note, status, problem, layout, media);

  const graph = createGraph(canvas, signal);
  const buttons: HTMLButtonElement[] = [];

  const syncControls = (): void => {
    refresh.disabled = busy;
    more.disabled = busy;
    moreBox.hidden = next === null || connections.length >= MAX_LOADED;
  };

  const drawDetail = (): void => {
    const connection = connections[selected];
    if (!connection) {
      detail.replaceChildren(...(connections.length ? [el("p", "graph-empty", "Select a connection to see how it was paired.")] : []));
      return;
    }
    const facts = el("dl", "graph-facts");
    const fact = (term: string, value: Node | string): void => {
      const row = el("div");
      const description = el("dd");
      description.append(value);
      row.append(el("dt", "", term), description);
      facts.append(row);
    };
    fact("Key", el("code", "graph-key", safeText(connection.key)));
    fact("Pairing", TITLES[connection.pairing]);
    const verified = when(connection.verifiedAtMs);
    if (verified) fact("Verified", verified);
    detail.replaceChildren(el("h3", "graph-name", nameOf(connection)), facts);
  };

  const drawStatus = (): void => {
    if (busy) return;
    const total = connections.length === 1 ? "1 connection" : `${connections.length} connections`;
    const cut = next !== null && connections.length >= MAX_LOADED ? ` Showing the first ${MAX_LOADED.toLocaleString("en-US")}.` : next !== null ? " More are available." : "";
    const odd = skipped ? ` ${skipped === 1 ? "1 entry was" : `${skipped} entries were`} not in a shape this app can read and ${skipped === 1 ? "is" : "are"} not shown.` : "";
    status.textContent = connections.length === 0 && !problem.hidden ? "" : connections.length === 0
      ? `No connections yet. A contact appears here after you approve it with your passkey.${odd}`
      : `${total}.${cut}${odd}`;
  };

  const draw = (): void => {
    buttons.length = 0;
    list.replaceChildren(...connections.map((connection, at) => {
      const item = el("li");
      const button = el("button", "graph-person");
      button.type = "button";
      button.setAttribute("aria-pressed", String(at === selected));
      button.append(el("span", "graph-person-name", nameOf(connection)), el("span", "graph-person-mark", SHORT[connection.pairing]));
      button.addEventListener("click", () => choose(at), { signal });
      buttons.push(button);
      item.append(button);
      return item;
    }));
    const n = connections.length;
    canvas.setAttribute("aria-label", `Connection map: you at the centre and ${n === 1 ? "1 connection" : `${n} connections`}. The list beside it has the same information.`);
    syncControls();
    graph.show(connections, selected);
    drawDetail();
    drawStatus();
  };

  function choose(at: number): void {
    selected = at;
    buttons.forEach((button, index) => button.setAttribute("aria-pressed", String(index === at)));
    graph.show(connections, selected);
    drawDetail();
  }

  const load = async (append: boolean): Promise<void> => {
    const mine = ++generation;
    busy = true;
    syncControls();
    problem.hidden = true;
    status.textContent = append ? "Reading more…" : "Reading your connections…";
    try {
      const page = await listConnections(client, append ? next : null, signal);
      if (signal.aborted || mine !== generation) return;
      const kept = connections[selected]?.key;
      const before = connections.length;
      connections = append ? connections.concat(page.items) : [...page.items];
      skipped = append ? skipped + page.skipped : page.skipped;
      next = page.next;
      selected = kept === undefined ? -1 : connections.findIndex(connection => connection.key === kept);
      busy = false;
      draw();
      if (append) buttons[before]?.focus();
    } catch (error) {
      if (signal.aborted || mine !== generation) return;
      const { code, note: sentence } = failure(error);
      problem.textContent = `Unavailable · ${code}. ${sentence}`;
      problem.hidden = false;
      busy = false;
      syncControls();
      drawStatus();
    }
  };

  canvas.addEventListener("click", event => {
    const at = graph.pick(event.clientX, event.clientY);
    if (at >= 0) {
      choose(at);
      buttons[at]?.focus();
    }
  }, { signal });
  more.addEventListener("click", () => void load(true), { signal });
  refresh.addEventListener("click", () => void load(false), { signal });
  draw();
  void load(false);
}
