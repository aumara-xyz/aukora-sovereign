// SPDX-License-Identifier: AGPL-3.0-or-later
// The framework-neutral markup of the shared Spatial portal primitive.
import { h, untrusted } from "./dom.js";

// Glyphs on a 24 grid, drawn with the icon tile's 1.4 stroke and round caps (rule 10).
const PATHS: Readonly<Record<string, string>> = {
  shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M9 12l2 2 4-4",
  contact: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M20 8v6 M17 11h6",
  message: "M4 4h16v12H8l-4 4z M8 8h8 M8 12h5",
  id: "M3 6h18v12H3z M7 10.5a1.5 1.5 0 1 0 3 0 1.5 1.5 0 0 0-3 0 M6 15c.6-1.4 3.4-1.4 4 0 M13 10h5 M13 13h4",
  more: "M6 12h.01 M12 12h.01 M18 12h.01",
  all: "M5 7h14 M5 12h14 M5 17h14",
  back: "M15 5l-7 7 7 7",
};

export function glyph(kind: string): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg") as SVGSVGElement;
  for (const [name, value] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": kind === "more" ? "2.6" : "1.4", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) svg.setAttribute(name, value);
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", PATHS[kind] ?? PATHS.message);
  svg.append(path);
  return svg;
}

export function portalIcon(kind: string): HTMLElement {
  return h("span", { class: "ak-icon-tile" }, glyph(kind));
}

export function portal(title: string, summary: string, content: HTMLElement, signal: AbortSignal,
  changed: (open: boolean) => void = () => undefined, kind = "contact", tone = "mint") {
  const body = h("div", { class: "ak-portal__body", hidden: "" }, content);
  const expander = h("span", { class: "ak-expander", "aria-hidden": "true" }, "+");
  const head = h("button", { type: "button", class: "ak-portal__head", "aria-expanded": "false" },
    portalIcon(kind), h("span", { class: "ak-portal__copy" },
      untrusted("span", { class: "ak-portal__title" }, title),
      untrusted("span", { class: "ak-portal__summary" }, summary)), expander);
  const element = h("section", { class: `ak-portal ak-tone-${tone}`, "data-open": "no" }, head, body);
  const setOpen = (open: boolean) => {
    head.setAttribute("aria-expanded", String(open));
    element.dataset.open = open ? "yes" : "no";
    expander.textContent = open ? "−" : "+";
    body.hidden = !open;
    changed(open);
  };
  head.addEventListener("click", () => setOpen(head.getAttribute("aria-expanded") !== "true"), { signal });
  return { element, head, body, setOpen };
}
