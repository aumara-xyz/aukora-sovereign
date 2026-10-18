// SPDX-License-Identifier: AGPL-3.0-or-later
// The framework-neutral markup of the shared Spatial portal primitive.
import { h, untrusted } from "./dom.js";

function icon(kind: string): HTMLElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  for (const [name, value] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "1.4", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" })) svg.setAttribute(name, value);
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", kind === "shield" ? "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6z M9 12l2 2 4-4"
    : kind === "contact" ? "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M20 8v6 M17 11h6"
      : "M4 4h16v12H8l-4 4z M8 8h8 M8 12h5");
  svg.append(path);
  return h("span", { class: "ak-icon-tile" }, svg);
}

export function portal(title: string, summary: string, content: HTMLElement, signal: AbortSignal,
  opened: () => void = () => undefined, kind = "contact", tone = "mint") {
  const body = h("div", { class: "ak-portal__body", hidden: "" }, content);
  const expander = h("span", { class: "ak-expander", "aria-hidden": "true" }, "+");
  const head = h("button", { type: "button", class: "ak-portal__head", "aria-expanded": "false" },
    icon(kind), h("span", { class: "ak-portal__copy" },
      untrusted("span", { class: "ak-portal__title" }, title),
      untrusted("span", { class: "ak-portal__summary" }, summary)), expander);
  const element = h("section", { class: `ak-portal ak-tone-${tone}`, "data-open": "no" }, head, body);
  head.addEventListener("click", () => {
    const open = head.getAttribute("aria-expanded") !== "true";
    head.setAttribute("aria-expanded", String(open));
    element.dataset.open = open ? "yes" : "no";
    expander.textContent = open ? "−" : "+";
    body.hidden = !open;
    if (open) opened();
  }, { signal });
  return { element, head };
}
