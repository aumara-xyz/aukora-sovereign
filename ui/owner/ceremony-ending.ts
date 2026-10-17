// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerDisposer } from "./contracts.js";
import { checkAbort } from "./abort.js";
import { brand } from "./brand.js";
import { actionButton } from "./primitives.js";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, text = "", className = ""): HTMLElementTagNameMap[K] {
  const result = document.createElement(tag);
  result.textContent = text;
  result.className = className;
  return result;
}

// The arrival after a verified pairing: the trefoil returns large, one line, and the app opens.
export function mountCeremonyConclusion(host: HTMLElement, signal: AbortSignal, complete: () => void): OwnerDisposer {
  checkAbort(signal);
  brand.show("hero");
  brand.bloom();
  const panel = node("section", "", "ceremony-conclusion owner-scene");
  const textBlock = node("div", "", "owner-text");
  textBlock.append(node("h2", "Welcome to your own space."),
    node("p", "Your two devices met, here and now. Later you will do this with friends and family to grow your human network. More soon.", "owner-detail"));
  const controls = node("div", "", "owner-controls");
  const made = actionButton("Open AUKORA", "mint");
  made.button.classList.add("primary");
  made.button.addEventListener("click", () => { if (!signal.aborted) complete(); }, { signal });
  controls.append(made.frame);
  panel.append(textBlock, controls);
  host.replaceChildren(panel);
  const dispose = (): void => { panel.remove(); signal.removeEventListener("abort", dispose); };
  signal.addEventListener("abort", dispose, { once: true });
  return dispose;
}
