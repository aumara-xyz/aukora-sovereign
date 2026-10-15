// SPDX-License-Identifier: AGPL-3.0-or-later
// Element helpers. Message text and contact names are only ever set as text, and characters that reorder or hide text
// are shown as their code points. No markup is ever built from data.

export type Attrs = Readonly<Record<string, string>>;
export type Child = Node | string | null | false | undefined;

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K, attrs: Attrs = {}, ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
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

export function neutralize(text: string): Array<Node | string> {
  const parts: Array<Node | string> = [];
  let from = 0;
  for (const match of text.matchAll(HIDDEN)) {
    if (match.index > from) parts.push(text.slice(from, match.index));
    const code = (match[0].codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0");
    parts.push(h("span", { class: "mark", title: "A hidden character, shown as its code point" }, `U+${code}`));
    from = match.index + match[0].length;
  }
  if (from < text.length) parts.push(text.slice(from));
  return parts;
}

export function untrusted<K extends keyof HTMLElementTagNameMap>(
  tag: K, attrs: Attrs, text: string
): HTMLElementTagNameMap[K] {
  const node = h(tag, { ...attrs, dir: "auto" });
  node.append(...neutralize(text));
  return node;
}
