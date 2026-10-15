// SPDX-License-Identifier: AGPL-3.0-or-later
// Element helpers. Text from a session is only ever set as text, and characters that reorder or hide text are shown as
// their code points. No markup is ever built from data: the attribute names below are literals in this face's own code,
// and the page's policy blocks inline styles and handlers, so neither is accepted as an attribute.

export type Attrs = Readonly<Record<string, string>>;
export type Child = Node | string | null | false | undefined;

const SVG_NS = "http://www.w3.org/2000/svg";

function setAttrs(node: Element, attrs: Attrs): void {
  for (const [name, value] of Object.entries(attrs)) {
    if (name === "style" || name.startsWith("on")) throw new Error("app:attribute-refused");
    node.setAttribute(name, value);
  }
}

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K, attrs: Attrs = {}, ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  setAttrs(node, attrs);
  for (const child of children) if (child) node.append(child);
  return node;
}

function svg<K extends keyof SVGElementTagNameMap>(
  tag: K, attrs: Attrs = {}, ...children: Array<SVGElement | null>
): SVGElementTagNameMap[K] {
  const node = document.createElementNS(SVG_NS, tag);
  setAttrs(node, attrs);
  for (const child of children) if (child) node.append(child);
  return node;
}

// Controls other than LF and TAB, bidi controls and isolates, the zero-width space, invisible operators, annotation
// marks, the BOM, Unicode tag characters and the variation selector supplement. A CR that is not part of CRLF counts.
// The joiners U+200C and U+200D stay as they are: scripts and emoji sequences need them and they reorder nothing.
const HIDDEN = new RegExp(
  "[\\u0000-\\u0008\\u000b\\u000c\\u000e-\\u001f\\u007f-\\u009f\\u061c\\u200b\\u200e\\u200f\\u2028-\\u202e" +
  "\\u2060-\\u206f\\ufeff\\ufff9-\\ufffb\\u{e0000}-\\u{e007f}\\u{e0100}-\\u{e01ef}]|\\r(?!\\n)", "gu",
);

function codePoint(character: string): string {
  return `U+${(character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
}

export function neutralize(text: string): Array<Node | string> {
  const parts: Array<Node | string> = [];
  let from = 0;
  for (const match of text.matchAll(HIDDEN)) {
    if (match.index > from) parts.push(text.slice(from, match.index));
    parts.push(h("span", { class: "mark-cp", title: "A hidden character, shown as its code point" }, codePoint(match[0])));
    from = match.index + match[0].length;
  }
  if (from < text.length) parts.push(text.slice(from));
  return parts;
}

// For attributes and labels, where no element can stand in for the hidden character.
export function visible(text: string): string {
  return text.replace(HIDDEN, character => `[${codePoint(character)}]`);
}

export function untrusted<K extends keyof HTMLElementTagNameMap>(
  tag: K, attrs: Attrs, text: string
): HTMLElementTagNameMap[K] {
  const node = h(tag, { ...attrs, dir: "auto" });
  node.append(...neutralize(text));
  return node;
}

const ICONS = {
  plus: "M12 5v14M5 12h14",
  send: "M12 19V5m-6 6 6-6 6 6",
  stop: "M7 7h10v10H7z",
  close: "m6 6 12 12M18 6 6 18",
  search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zm9 16-4.2-4.2",
  list: "M4 7h16M4 12h16M4 17h16",
  back: "m15 6-6 6 6 6",
  refresh: "M20 12a8 8 0 1 1-2.6-5.9M20 4v5h-5",
  down: "m6 9 6 6 6-6",
  chat: "M4 5h16v11H9l-5 4V5Z",
} as const;

export type IconName = keyof typeof ICONS;

export function icon(name: IconName): SVGSVGElement {
  return svg("svg", {
    class: "icon", viewBox: "0 0 24 24", width: "18", height: "18", fill: "none", stroke: "currentColor", "stroke-width": "2",
    "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", focusable: "false",
  }, svg("path", { d: ICONS[name] }));
}

// Three interlaced petals in the design's violet, mint and blue (app/design/tokens.json). Decorative only.
const PETALS = [["#c4aaff", 0], ["#96b4ff", 120], ["#81d4b4", 240]] as const;

export function mark(): SVGSVGElement {
  return svg("svg", {
    class: "mark", viewBox: "0 0 24 24", width: "24", height: "24", fill: "none", "stroke-width": "1.8", "aria-hidden": "true",
    focusable: "false",
  }, ...PETALS.map(([color, turn]) => svg("ellipse", {
    cx: "12", cy: "7.9", rx: "3.7", ry: "7.1", stroke: color, transform: `rotate(${turn} 12 12)`,
  })));
}
