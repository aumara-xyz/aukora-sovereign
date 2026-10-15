// SPDX-License-Identifier: AGPL-3.0-or-later
export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

export function button(label: string, action: () => void, signal: AbortSignal, className = ""): HTMLButtonElement {
  const node = el("button", className, label);
  node.type = "button";
  node.addEventListener("click", action, { signal });
  return node;
}

// Randomness only rearranges learning material; it is never used for identity or authority.
export function shuffled<T>(values: readonly T[]): T[] {
  const result = [...values];
  for (let at = result.length - 1; at > 0; at--) {
    const other = Math.floor(Math.random() * (at + 1));
    [result[at], result[other]] = [result[other], result[at]];
  }
  return result;
}
