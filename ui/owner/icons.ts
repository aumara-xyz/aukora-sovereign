// SPDX-License-Identifier: AGPL-3.0-or-later
import icons from "./icon-paths.json" with { type: "json" };

export function ownerIcon(name: "owner" | "aumlok" | "identity" | "surface"): SVGSVGElement {
  const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  icon.setAttribute("viewBox", icons.viewBox);
  icon.setAttribute("fill", "none");
  icon.setAttribute("stroke", "currentColor");
  icon.setAttribute("stroke-width", String(icons.strokeWidth));
  icon.setAttribute("stroke-linecap", "round");
  icon.setAttribute("stroke-linejoin", "round");
  icon.setAttribute("aria-hidden", "true");
  icon.setAttribute("focusable", "false");
  const line = document.createElementNS("http://www.w3.org/2000/svg", "path");
  line.setAttribute("d", icons.paths[name]);
  icon.append(line);
  return icon;
}
