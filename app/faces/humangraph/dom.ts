// SPDX-License-Identifier: AGPL-3.0-or-later
// Element helpers. Text always enters the page through textContent, never as markup.

const BIDI_CONTROLS = /[‪-‮⁦-⁩]/g;

export function el<K extends keyof HTMLElementTagNameMap>(tag: K, className = "", text = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text) node.textContent = text;
  return node;
}

/** Bidirectional overrides and isolates are replaced so a label cannot display differently from how it reads. */
export function safeText(text: string): string {
  return text.replace(BIDI_CONTROLS, "�");
}
