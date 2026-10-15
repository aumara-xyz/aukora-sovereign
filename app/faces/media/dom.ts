// SPDX-License-Identifier: AGPL-3.0-or-later
// Element helpers. Text always enters the page through textContent, never as markup.

const SVG_NS = "http://www.w3.org/2000/svg";

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

const ICONS = {
  image: "M5 4h14a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2ZM3 17l5-5 4 4 3-3 6 6M7.5 8.5a1 1 0 1 0 2 0a1 1 0 1 0-2 0Z",
  video: "M4 5h16a1 1 0 0 1 1 1v12a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1ZM10 9l5 3-5 3Z",
  gallery: "M8 8h12v12H8ZM16 4H5a1 1 0 0 0-1 1v11",
  lock: "M7 11V8a5 5 0 0 1 10 0v3M6 11h12v9H6Z",
} as const;

export function icon(name: keyof typeof ICONS): SVGSVGElement {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("class", "media-icon");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", ICONS[name]);
  svg.append(path);
  return svg;
}
