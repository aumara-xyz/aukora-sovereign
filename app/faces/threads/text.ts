// SPDX-License-Identifier: AGPL-3.0-or-later
// Message text as blocks: plain text and fenced code, with inline code spans. Nothing else is interpreted. There are no
// links, images or markup, so a message that looks like markup or an instruction stays literal text on screen.
import { h, neutralize } from "./dom.js";

interface Block { readonly code: boolean; readonly text: string; readonly lang: string }
interface Fence { readonly mark: string; readonly lang: string }

const LANGUAGE = /^[A-Za-z0-9_+#.-]{1,24}$/;

function opens(line: string): Fence | null {
  const found = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
  if (!found) return null;
  const info = found[2].trim();
  // A backtick fence's info string cannot hold a backtick.
  if (found[1][0] === "`" && info.includes("`")) return null;
  return { mark: found[1], lang: info.split(/\s+/)[0] ?? "" };
}

function closes(line: string, fence: Fence): boolean {
  const found = /^ {0,3}(`{3,}|~{3,})\s*$/.exec(line);
  return found !== null && found[1][0] === fence.mark[0] && found[1].length >= fence.mark.length;
}

// A fence left open by the end of the text runs to the end, which is how a reply looks while it is still streaming.
export function blocks(source: string): Block[] {
  const found: Block[] = [];
  let lines: string[] = [];
  let fence: Fence | null = null;
  const flush = () => {
    const joined = lines.join("\n");
    lines = [];
    if (fence) {
      if (joined.length > 0) found.push({ code: true, text: joined, lang: LANGUAGE.test(fence.lang) ? fence.lang : "" });
    } else {
      const plain = joined.replace(/^\n+|\n+$/g, "");
      if (plain.trim() !== "") found.push({ code: false, text: plain, lang: "" });
    }
  };
  for (const line of source.split("\n")) {
    const bare = line.endsWith("\r") ? line.slice(0, -1) : line;
    if (fence) {
      if (closes(bare, fence)) { flush(); fence = null; } else lines.push(line);
    } else {
      const start = opens(bare);
      if (start) { flush(); fence = start; } else lines.push(line);
    }
  }
  flush();
  return found;
}

function inline(text: string): HTMLElement {
  const node = h("div", { class: "text", dir: "auto" });
  let from = 0;
  for (const match of text.matchAll(/`([^`\n]+)`/g)) {
    if (match.index > from) node.append(...neutralize(text.slice(from, match.index)));
    node.append(h("code", {}, ...neutralize(match[1])));
    from = match.index + match[0].length;
  }
  if (from < text.length) node.append(...neutralize(text.slice(from)));
  return node;
}

function codeBlock(block: Block): HTMLElement {
  const pre = h("pre", { dir: "ltr" }, h("code", {}, ...neutralize(block.text)));
  return h("figure", { class: "code" }, block.lang ? h("figcaption", {}, block.lang) : null, pre);
}

// The elements for one message's text, in order.
export function render(source: string): HTMLElement[] {
  return blocks(source).map(block => (block.code ? codeBlock(block) : inline(block.text)));
}
