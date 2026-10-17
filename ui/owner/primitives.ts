// SPDX-License-Identifier: AGPL-3.0-or-later
// The locked spatial primitives (SPATIAL-DESIGN-RULES rule 10) as plain DOM for the owner origin. The look is
// primitives.css, copied verbatim from the Sovereign face (engine/plugins/aukora-face/layout/src/client/primitives/);
// this file only writes the markup it styles. Measurements are never set here.
export type Tone = "mint" | "blue" | "violet" | "gold" | "red" | "muted";
export type Glyph = "door" | "devices" | "aura" | "aumlok" | "lock" | "out" | "identity" | "sovereignty";

// The face's own hairline glyphs (icons.tsx), 24-unit grid, as shapes: [element, attributes].
type Shape = readonly [string, Readonly<Record<string, string>>];
const path = (d: string): Shape => ["path", { d }];
const GLYPHS: Record<Glyph, readonly Shape[]> = {
  door: [path("M6 20V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v15"), path("M4 20h16"), ["circle", { cx: "14.5", cy: "12.5", r: ".8" }]],
  devices: [["rect", { x: "3", y: "5", width: "13", height: "10", rx: "1.5" }], path("M2 18h15"), ["rect", { x: "17.5", y: "9", width: "4.5", height: "10", rx: "1.2" }]],
  aura: [["circle", { cx: "12", cy: "12", r: "3" }], ["circle", { cx: "12", cy: "12", r: "6" }], ["circle", { cx: "12", cy: "12", r: "9", opacity: ".6" }]],
  aumlok: [["rect", { x: "5", y: "10.5", width: "14", height: "9.5", rx: "2.5" }], path("M8 10.5V8a4 4 0 0 1 8 0v2.5"), path("M12 14v2.5")],
  lock: [["rect", { x: "5", y: "11", width: "14", height: "9", rx: "2.5" }], path("M8 11V8a4 4 0 0 1 8 0v3")],
  out: [path("M9 6h9v9"), path("M18 6 7 17")],
  identity: [["rect", { x: "3.5", y: "5", width: "17", height: "14", rx: "2.5" }], ["circle", { cx: "9", cy: "11", r: "2.2" }],
    path("M5.8 16.2c.7-1.6 1.9-2.4 3.2-2.4s2.5.8 3.2 2.4M14.5 10h3.5M14.5 13.5h3.5")],
  sovereignty: [path("M12 3 5 6v5c0 4.4 2.9 8.2 7 10 4.1-1.8 7-5.6 7-10V6Z"), path("m9 12 2 2 4-4")],
};

function node<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const result = document.createElement(tag);
  if (className) result.className = className;
  if (text) result.textContent = text;
  return result;
}

export function glyph(name: Glyph): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.4");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  for (const [tag, attributes] of GLYPHS[name]) {
    const shape = document.createElementNS("http://www.w3.org/2000/svg", tag);
    for (const [key, value] of Object.entries(attributes)) shape.setAttribute(key, value);
    svg.append(shape);
  }
  return svg;
}

export function iconTile(name: Glyph): HTMLElement {
  const tile = node("span", "ak-icon-tile");
  tile.append(glyph(name));
  return tile;
}

export type Portal = {
  readonly frame: HTMLElement;
  readonly head: HTMLButtonElement;
  /** The opened state's body (PortalDetail); empty for a launcher. */
  readonly body: HTMLElement;
  open(open: boolean): void;
  isOpen(): boolean;
};

/** PortalButton: icon tile, title, one-line summary, expander. With `opens` false it is a launcher or action: no expander. */
export function portalButton(options: {
  tone: Tone; title: string; summary?: string; icon?: Glyph; opens?: boolean; frameClass?: string;
}): Portal {
  const opens = options.opens ?? true;
  const frame = node("div", `ak-portal ak-tone-${options.tone}${options.summary ? "" : " ak-portal--one-line"}${options.frameClass ? ` ${options.frameClass}` : ""}`);
  frame.dataset.open = "no";
  const head = node("button", "ak-portal__head");
  head.type = "button";
  if (options.icon) head.append(iconTile(options.icon));
  const copy = node("span", "ak-portal__copy");
  copy.append(node("span", "ak-portal__title", options.title));
  if (options.summary) copy.append(node("span", "ak-portal__summary", options.summary));
  head.append(copy);
  const expander = node("span", "ak-expander", "+");
  expander.setAttribute("aria-hidden", "true");
  if (opens) { const end = node("span", "ak-portal__end"); end.append(expander); head.append(end); }
  const body = node("div", "ak-portal__body");
  body.hidden = true;
  frame.append(head, body);
  const portal: Portal = {
    frame, head, body,
    isOpen: () => frame.dataset.open === "yes",
    open(open) {
      frame.dataset.open = open ? "yes" : "no";
      expander.textContent = open ? "−" : "+";
      head.setAttribute("aria-expanded", String(open));
      body.hidden = !open;
    },
  };
  if (opens) {
    head.setAttribute("aria-expanded", "false");
    head.addEventListener("click", () => portal.open(!portal.isOpen()));
  }
  return portal;
}

/** An action in the owner origin, in the primitives' button shape: a one-line PortalButton with no expander. */
export function actionButton(label: string, tone: Tone, className = ""): { frame: HTMLElement; button: HTMLButtonElement } {
  const portal = portalButton({ tone, title: label, opens: false, frameClass: `ak-action-frame ${className}`.trim() });
  portal.body.remove();
  return { frame: portal.frame, button: portal.head };
}

export const label = (text: string): HTMLElement => node("p", "ak-label", text);
export const lead = (text: string): HTMLElement => node("p", "ak-lead", text);

/** FieldTable: the little fine lines. */
export function fieldTable(rows: ReadonlyArray<readonly [string, string]>, title?: string): HTMLElement[] {
  const table = node("dl", "ak-fields");
  for (const [key, value] of rows) table.append(node("dt", "", key), node("dd", "", value));
  return title ? [node("p", "ak-fields__title", title), table] : [table];
}

/** StatTiles: name, value in the tile's tone. */
export function statTiles(tiles: ReadonlyArray<{ name: string; value: string; tone?: Tone }>): HTMLElement {
  const grid = node("div", "ak-stats");
  for (const tile of tiles) {
    const stat = node("div", `ak-stat${tile.tone ? ` ak-tone-${tile.tone}` : ""}`);
    stat.append(node("span", "ak-stat__name", tile.name), node("span", "ak-stat__value", tile.value));
    grid.append(stat);
  }
  return grid;
}
