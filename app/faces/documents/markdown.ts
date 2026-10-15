// SPDX-License-Identifier: AGPL-3.0-or-later
// A small Markdown reader. It returns plain data and never markup: raw HTML stays text, links and
// images stay text, and nothing here touches the page. The subset is ATX headings, paragraphs,
// emphasis, code spans, fenced code, block quotes, nested lists, pipe tables and rules. Setext
// headings, reference links, footnotes and raw HTML are shown as the text they are.

export type Align = "left" | "center" | "right" | null;

export type Inline =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "code"; readonly text: string }
  | { readonly kind: "strong"; readonly children: readonly Inline[] }
  | { readonly kind: "emphasis"; readonly children: readonly Inline[] }
  | { readonly kind: "link"; readonly url: string; readonly children: readonly Inline[] }
  | { readonly kind: "image"; readonly alt: string; readonly url: string }
  | { readonly kind: "break" };

export type Block =
  | { readonly kind: "heading"; readonly level: number; readonly children: readonly Inline[] }
  | { readonly kind: "paragraph"; readonly children: readonly Inline[] }
  | { readonly kind: "code"; readonly info: string; readonly text: string }
  | { readonly kind: "quote"; readonly children: readonly Block[] }
  | { readonly kind: "list"; readonly ordered: boolean; readonly start: number; readonly items: readonly (readonly Block[])[] }
  | {
    readonly kind: "table";
    readonly align: readonly Align[];
    readonly header: readonly (readonly Inline[])[];
    readonly rows: readonly (readonly (readonly Inline[])[])[];
  }
  | { readonly kind: "rule" };

// Past these bounds the rest is kept as plain text.
const MAX_BLOCK_DEPTH = 6;
const MAX_INLINE_DEPTH = 4;
const MAX_INLINE_CHARS = 8_000;
const MAX_TABLE_COLUMNS = 32;
const ESCAPABLE = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

interface Fence { readonly char: string; readonly length: number; readonly info: string; readonly indent: number }
interface Marker {
  readonly ordered: boolean;
  readonly start: number;
  readonly delimiter: string;
  readonly width: number;
  readonly rest: string;
}

function indentOf(line: string): number {
  let count = 0;
  while (line.charAt(count) === " ") count++;
  return count;
}

function isBlank(line: string): boolean {
  return line.trim() === "";
}

function trimSpaces(text: string): string {
  let end = text.length;
  while (end > 0 && text.charAt(end - 1) === " ") end--;
  return text.slice(0, end);
}

function isSpace(char: string): boolean {
  return char === "" || /^\s$/u.test(char);
}

function isWord(char: string): boolean {
  return /^[\p{L}\p{N}]$/u.test(char);
}

function fenceOf(line: string): Fence | null {
  const indent = indentOf(line);
  const char = line.charAt(indent);
  if (indent > 3 || (char !== "`" && char !== "~")) return null;
  let end = indent;
  while (line.charAt(end) === char) end++;
  const info = line.slice(end).trim();
  if (end - indent < 3 || (char === "`" && info.includes("`"))) return null;
  return { char, length: end - indent, info, indent };
}

function closesFence(line: string, fence: Fence): boolean {
  const indent = indentOf(line);
  if (indent > 3) return false;
  let end = indent;
  while (line.charAt(end) === fence.char) end++;
  return end - indent >= fence.length && line.slice(end).trim() === "";
}

function headingOf(line: string): { level: number; text: string } | null {
  const indent = indentOf(line);
  if (indent > 3 || line.charAt(indent) !== "#") return null;
  let end = indent;
  while (line.charAt(end) === "#") end++;
  const level = end - indent;
  const after = line.charAt(end);
  if (level > 6 || (after !== "" && after !== " " && after !== "\t")) return null;
  let text = line.slice(end).trim();
  let cut = text.length;
  while (cut > 0 && text.charAt(cut - 1) === "#") cut--;
  if (cut < text.length && (cut === 0 || text.charAt(cut - 1) === " ")) text = text.slice(0, cut).trimEnd();
  return { level, text };
}

function isRule(line: string): boolean {
  const indent = indentOf(line);
  const char = line.charAt(indent);
  if (indent > 3 || (char !== "-" && char !== "*" && char !== "_")) return false;
  let count = 0;
  for (let at = indent; at < line.length; at++) {
    const here = line.charAt(at);
    if (here === char) count++;
    else if (here !== " " && here !== "\t") return false;
  }
  return count >= 3;
}

function isQuote(line: string): boolean {
  const indent = indentOf(line);
  return indent <= 3 && line.charAt(indent) === ">";
}

function stripQuote(line: string): string {
  const rest = line.slice(indentOf(line) + 1);
  return rest.startsWith(" ") ? rest.slice(1) : rest;
}

function markerOf(line: string): Marker | null {
  const indent = indentOf(line);
  if (indent > 3) return null;
  const char = line.charAt(indent);
  let end = indent + 1;
  let ordered = false;
  let start = 1;
  let delimiter = char;
  if (char >= "0" && char <= "9") {
    while (line.charAt(end) >= "0" && line.charAt(end) <= "9") end++;
    delimiter = line.charAt(end);
    if (end - indent > 9 || (delimiter !== "." && delimiter !== ")")) return null;
    ordered = true;
    start = Number(line.slice(indent, end));
    end++;
  } else if (char !== "-" && char !== "*" && char !== "+") return null;
  if (end < line.length && line.charAt(end) !== " " && line.charAt(end) !== "\t") return null;
  let spaces = 0;
  while (line.charAt(end + spaces) === " " || line.charAt(end + spaces) === "\t") spaces++;
  const empty = line.slice(end).trim() === "";
  const gap = empty || spaces > 4 ? 1 : spaces;
  return { ordered, start, delimiter, width: end + gap, rest: empty ? "" : line.slice(end + gap) };
}

/** A line that ends the lazy continuation of a list item or the rows of a table. */
function breaksLazy(line: string): boolean {
  return fenceOf(line) !== null || headingOf(line) !== null || isRule(line) || isQuote(line) || markerOf(line) !== null;
}

/** A line that may interrupt a paragraph: an empty or non-initial list item may not. */
function interrupts(line: string): boolean {
  if (fenceOf(line) !== null || headingOf(line) !== null || isRule(line) || isQuote(line)) return true;
  const marker = markerOf(line);
  return marker !== null && marker.rest !== "" && (!marker.ordered || marker.start === 1);
}

function splitRow(line: string): string[] {
  let text = line.trim();
  if (text.startsWith("|")) text = text.slice(1);
  if (text.endsWith("|") && !text.endsWith("\\|")) text = text.slice(0, -1);
  const cells: string[] = [];
  let cell = "";
  for (let at = 0; at < text.length; at++) {
    const char = text.charAt(at);
    if (char === "\\" && text.charAt(at + 1) === "|") {
      cell += "|";
      at++;
    } else if (char === "|") {
      cells.push(cell.trim());
      cell = "";
    } else cell += char;
  }
  cells.push(cell.trim());
  return cells;
}

function closingRun(source: string, from: number, length: number): number {
  let at = from;
  for (;;) {
    at = source.indexOf("`", at);
    if (at < 0) return -1;
    let end = at;
    while (source.charAt(end) === "`") end++;
    if (end - at === length) return at;
    at = end;
  }
}

function matchBracket(source: string, open: number): number {
  let level = 0;
  for (let at = open; at < source.length; at++) {
    const char = source.charAt(at);
    if (char === "\\") at++;
    else if (char === "[") level++;
    else if (char === "]" && --level === 0) return at;
  }
  return -1;
}

function parseDestination(source: string, from: number): { url: string; end: number } | null {
  let at = from;
  while (source.charAt(at) === " ") at++;
  let url: string;
  if (source.charAt(at) === "<") {
    const close = source.indexOf(">", at + 1);
    if (close < 0 || source.slice(at + 1, close).includes("\n")) return null;
    url = source.slice(at + 1, close);
    at = close + 1;
  } else {
    const begin = at;
    let balance = 0;
    while (at < source.length) {
      const char = source.charAt(at);
      if (char === "\\") {
        at += 2;
        continue;
      }
      if (char === " " || char === "\n") break;
      if (char === "(") balance++;
      else if (char === ")" && balance-- === 0) break;
      at++;
    }
    url = source.slice(begin, at);
  }
  while (source.charAt(at) === " " || source.charAt(at) === "\n") at++;
  const quote = source.charAt(at);
  if (quote === "\"" || quote === "'" || quote === "(") {
    const close = source.indexOf(quote === "(" ? ")" : quote, at + 1);
    if (close < 0) return null;
    at = close + 1;
    while (source.charAt(at) === " " || source.charAt(at) === "\n") at++;
  }
  if (source.charAt(at) !== ")") return null;
  return { url: url.replace(/\\([!-/:-@[-`{-~])/g, "$1"), end: at };
}

function findCloser(source: string, from: number, char: string, length: number): number {
  let at = from;
  while (at < source.length) {
    const here = source.charAt(at);
    if (here === "\\") {
      at += 2;
    } else if (here === "`") {
      let end = at;
      while (source.charAt(end) === "`") end++;
      const close = closingRun(source, end, end - at);
      at = close < 0 ? end : close + (end - at);
    } else if (here === char) {
      let end = at;
      while (source.charAt(end) === char) end++;
      if (end - at === length && at > from && !isSpace(source.charAt(at - 1)) && (char === "*" || !isWord(source.charAt(end)))) {
        return at;
      }
      at = end;
    } else at++;
  }
  return -1;
}

function parseInline(source: string, depth: number): Inline[] {
  const out: Inline[] = [];
  let text = "";
  const flush = (): void => {
    if (text) out.push({ kind: "text", text });
    text = "";
  };
  let at = 0;
  while (at < source.length) {
    const char = source.charAt(at);
    if (char === "\\") {
      const next = source.charAt(at + 1);
      if (next === "\n") {
        text = trimSpaces(text);
        flush();
        out.push({ kind: "break" });
        at += 2;
        while (source.charAt(at) === " ") at++;
      } else if (next !== "" && ESCAPABLE.includes(next)) {
        text += next;
        at += 2;
      } else {
        text += char;
        at++;
      }
      continue;
    }
    if (char === "\n") {
      const hard = text.endsWith("  ");
      text = trimSpaces(text);
      if (hard) {
        flush();
        out.push({ kind: "break" });
      } else text += " ";
      at++;
      while (source.charAt(at) === " ") at++;
      continue;
    }
    if (char === "`") {
      let run = 1;
      while (source.charAt(at + run) === "`") run++;
      const close = closingRun(source, at + run, run);
      if (close < 0) {
        text += "`".repeat(run);
        at += run;
        continue;
      }
      flush();
      let code = source.slice(at + run, close).replace(/\n/g, " ");
      if (code.length > 2 && code.startsWith(" ") && code.endsWith(" ") && code.trim() !== "") code = code.slice(1, -1);
      out.push({ kind: "code", text: code });
      at = close + run;
      continue;
    }
    if (char === "*" || char === "_") {
      let run = 1;
      while (source.charAt(at + run) === char) run++;
      if (run <= 3 && depth < MAX_INLINE_DEPTH && !isSpace(source.charAt(at + run)) && (char === "*" || !isWord(source.charAt(at - 1)))) {
        const close = findCloser(source, at + run, char, run);
        if (close > 0) {
          flush();
          const inner = parseInline(source.slice(at + run, close), depth + 1);
          if (run === 1) out.push({ kind: "emphasis", children: inner });
          else if (run === 2) out.push({ kind: "strong", children: inner });
          else out.push({ kind: "strong", children: [{ kind: "emphasis", children: inner }] });
          at = close + run;
          continue;
        }
      }
      text += char.repeat(run);
      at += run;
      continue;
    }
    if (char === "[" || (char === "!" && source.charAt(at + 1) === "[")) {
      const open = char === "[" ? at : at + 1;
      const close = depth < MAX_INLINE_DEPTH ? matchBracket(source, open) : -1;
      const target = close > 0 && source.charAt(close + 1) === "(" ? parseDestination(source, close + 2) : null;
      if (target) {
        flush();
        const label = parseInline(source.slice(open + 1, close), depth + 1);
        if (char === "!") out.push({ kind: "image", alt: plainText(label), url: target.url });
        else out.push({ kind: "link", url: target.url, children: label });
        at = target.end + 1;
        continue;
      }
    }
    text += char;
    at++;
  }
  flush();
  return out;
}

function inlineOf(text: string): Inline[] {
  return text.length > MAX_INLINE_CHARS ? [{ kind: "text", text }] : parseInline(text, 0);
}

function takeList(lines: readonly string[], from: number, first: Marker, depth: number): { block: Block; next: number } {
  const items: Block[][] = [];
  let at = from;
  let marker: Marker | null = first;
  while (marker) {
    const content: string[] = [marker.rest];
    let blanks = 0;
    at++;
    while (at < lines.length) {
      const line = lines[at] ?? "";
      if (isBlank(line)) {
        blanks++;
        at++;
      } else if (indentOf(line) >= marker.width) {
        for (; blanks > 0; blanks--) content.push("");
        content.push(line.slice(marker.width));
        at++;
      } else if (blanks === 0 && !breaksLazy(line)) {
        content.push(line.trim());
        at++;
      } else break;
    }
    items.push(parseBlocks(content, depth + 1));
    const following: Marker | null = at < lines.length && !isRule(lines[at] ?? "") ? markerOf(lines[at] ?? "") : null;
    marker = following !== null && following.ordered === first.ordered && following.delimiter === first.delimiter ? following : null;
  }
  return { block: { kind: "list", ordered: first.ordered, start: first.start, items }, next: at };
}

/** A header row followed by a delimiter row with as many cells. */
function tableAt(lines: readonly string[], from: number): { header: string[]; marks: string[] } | null {
  const head = lines[from] ?? "";
  const divider = lines[from + 1] ?? "";
  if (!head.includes("|") || !divider.includes("|")) return null;
  const header = splitRow(head);
  const marks = splitRow(divider);
  if (header.length !== marks.length || header.length > MAX_TABLE_COLUMNS || !marks.every(mark => /^:?-+:?$/.test(mark))) return null;
  return { header, marks };
}

function takeTable(lines: readonly string[], from: number): { block: Block; next: number } | null {
  const found = tableAt(lines, from);
  if (!found) return null;
  const { header, marks } = found;
  const align = marks.map((mark): Align => (mark.startsWith(":") ? (mark.endsWith(":") ? "center" : "left") : mark.endsWith(":") ? "right" : null));
  const rows: Inline[][][] = [];
  let at = from + 2;
  while (at < lines.length) {
    const line = lines[at] ?? "";
    if (isBlank(line) || breaksLazy(line)) break;
    const cells = splitRow(line);
    rows.push(header.map((_, column) => inlineOf(cells[column] ?? "")));
    at++;
  }
  return { block: { kind: "table", align, header: header.map(cell => inlineOf(cell)), rows }, next: at };
}

function parseBlocks(lines: readonly string[], depth: number): Block[] {
  if (depth >= MAX_BLOCK_DEPTH) {
    const text = lines.map(line => line.trim()).filter(line => line !== "").join(" ");
    return text ? [{ kind: "paragraph", children: [{ kind: "text", text }] }] : [];
  }
  const blocks: Block[] = [];
  let at = 0;
  while (at < lines.length) {
    const line = lines[at] ?? "";
    if (isBlank(line)) {
      at++;
      continue;
    }
    const fence = fenceOf(line);
    if (fence) {
      const body: string[] = [];
      at++;
      while (at < lines.length && !closesFence(lines[at] ?? "", fence)) {
        const inner = lines[at] ?? "";
        body.push(inner.slice(Math.min(fence.indent, indentOf(inner))));
        at++;
      }
      if (at < lines.length) at++;
      blocks.push({ kind: "code", info: fence.info, text: body.join("\n") });
      continue;
    }
    const heading = headingOf(line);
    if (heading) {
      blocks.push({ kind: "heading", level: heading.level, children: inlineOf(heading.text) });
      at++;
      continue;
    }
    if (isRule(line)) {
      blocks.push({ kind: "rule" });
      at++;
      continue;
    }
    if (isQuote(line)) {
      const inner: string[] = [];
      while (at < lines.length && isQuote(lines[at] ?? "")) {
        inner.push(stripQuote(lines[at] ?? ""));
        at++;
      }
      blocks.push({ kind: "quote", children: parseBlocks(inner, depth + 1) });
      continue;
    }
    const marker = markerOf(line);
    if (marker) {
      const list = takeList(lines, at, marker, depth);
      blocks.push(list.block);
      at = list.next;
      continue;
    }
    const table = takeTable(lines, at);
    if (table) {
      blocks.push(table.block);
      at = table.next;
      continue;
    }
    const paragraph: string[] = [];
    while (at < lines.length) {
      const text = lines[at] ?? "";
      if (isBlank(text) || (paragraph.length > 0 && (interrupts(text) || tableAt(lines, at) !== null))) break;
      paragraph.push(text.trimStart());
      at++;
    }
    blocks.push({ kind: "paragraph", children: inlineOf(paragraph.join("\n")) });
  }
  return blocks;
}

export function plainText(nodes: readonly Inline[]): string {
  let text = "";
  for (const node of nodes) {
    if (node.kind === "text" || node.kind === "code") text += node.text;
    else if (node.kind === "image") text += node.alt;
    else if (node.kind === "break") text += " ";
    else text += plainText(node.children);
  }
  return text;
}

/** The first heading with text, which is the document's own name for itself; empty when there is none. */
export function documentTitle(blocks: readonly Block[]): string {
  for (const block of blocks) {
    if (block.kind !== "heading") continue;
    const title = plainText(block.children).trim();
    if (title) return title;
  }
  return "";
}

export function parseMarkdown(source: string): Block[] {
  const lines = source
    .replace(/\r\n?/g, "\n")
    .split("\n")
    .map(line => line.replace(/^[ \t]+/, lead => lead.replace(/\t/g, "    ")));
  return parseBlocks(lines, 0);
}
