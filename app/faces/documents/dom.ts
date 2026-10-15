// SPDX-License-Identifier: AGPL-3.0-or-later
// Element helpers. Text always enters the page through textContent or text nodes, never as markup.

const SVG_NS = "http://www.w3.org/2000/svg";
const BIDI_CONTROLS = /[‪-‮⁦-⁩]/g;

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

/** Bidirectional overrides and isolates are replaced so text cannot display differently from how it reads. */
export function safeText(text: string): string {
  return text.replace(BIDI_CONTROLS, "�");
}

const ICONS = {
  back: "M15 5 8 12l7 7",
  folder: "M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z",
  file: "M7 3h7l5 5v13H7ZM14 3v5h5",
} as const;

export function icon(name: keyof typeof ICONS): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "doc-icon");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", ICONS[name]);
  svg.append(path);
  return svg;
}

export function isEditable(target: EventTarget | null): boolean {
  return target instanceof HTMLElement && (target.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(target.tagName));
}
