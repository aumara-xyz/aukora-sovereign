// SPDX-License-Identifier: AGPL-3.0-or-later
import glyphs from "../../design/spatial/glyphs.json" with { type: "json" };
import { h } from "./dom.js";

export type ThreadGlyph = "plus" | "pin" | "unread" | "archive" | "search" | "close";
interface Glyph { readonly size: number; readonly viewBox: string; readonly shapes: readonly { readonly tag: string; readonly attributes: Readonly<Record<string, string>> }[] }
const NS = "http://www.w3.org/2000/svg";
const data = glyphs as { readonly icons: Readonly<Record<string, Glyph>> };

export function threadGlyph(name: ThreadGlyph): SVGSVGElement {
  const spec = data.icons[name === "unread" ? "ring" : name];
  if (!spec) throw new Error("app:unknown-operation");
  const node = document.createElementNS(NS, "svg");
  for (const [key, value] of Object.entries({ width: String(spec.size), height: String(spec.size), viewBox: spec.viewBox, fill: "none", "aria-hidden": "true", focusable: "false" })) node.setAttribute(key, value);
  for (const item of spec.shapes) {
    if (!["path", "rect", "circle"].includes(item.tag)) throw new Error("app:invalid-message");
    const shape = document.createElementNS(NS, item.tag);
    for (const [key, value] of Object.entries(item.attributes)) {
      if (!["d", "x", "y", "cx", "cy", "r", "rx", "width", "height", "fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin"].includes(key)) throw new Error("app:invalid-message");
      shape.setAttribute(key, value);
    }
    node.append(shape);
  }
  return node;
}

export function spatialMark(size = 24): HTMLImageElement {
  return h("img", { src: new URL("../../design/brand/aumara-mark-96.png", import.meta.url).href, width: String(size), height: String(size), alt: "" });
}
