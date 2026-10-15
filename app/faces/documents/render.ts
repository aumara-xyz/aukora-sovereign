// SPDX-License-Identifier: AGPL-3.0-or-later
// Builds elements from the Markdown tree. A link is shown as its label and its target as text; it is
// never an anchor, so a document cannot navigate this frame or open anything.
import type { Block, Inline } from "./markdown.js";
import { plainText } from "./markdown.js";
import { el, safeText } from "./dom.js";

const HEADINGS = ["h3", "h4", "h5", "h6"] as const;

function inlineNodes(nodes: readonly Inline[]): Node[] {
  return nodes.map((node): Node => {
    switch (node.kind) {
      case "text":
        return document.createTextNode(safeText(node.text));
      case "code":
        return el("code", "doc-code-inline", safeText(node.text));
      case "strong": {
        const strong = el("strong");
        strong.append(...inlineNodes(node.children));
        return strong;
      }
      case "emphasis": {
        const emphasis = el("em");
        emphasis.append(...inlineNodes(node.children));
        return emphasis;
      }
      case "link": {
        const label = el("span", "doc-link");
        label.append(...inlineNodes(node.children));
        const group = document.createDocumentFragment();
        group.append(label);
        if (node.url && plainText(node.children) !== node.url) group.append(" ", el("span", "doc-url", `(${safeText(node.url)})`));
        return group;
      }
      case "image":
        return el("span", "doc-image", `[image: ${safeText(node.alt || node.url)}]`);
      case "break":
        return document.createElement("br");
    }
  });
}

function blockNode(block: Block): Node {
  switch (block.kind) {
    case "heading": {
      const heading = el(HEADINGS[Math.min(block.level, 4) - 1] ?? "h6", "doc-h");
      heading.dataset.level = String(block.level);
      heading.append(...inlineNodes(block.children));
      return heading;
    }
    case "paragraph": {
      const paragraph = el("p", "doc-p");
      paragraph.append(...inlineNodes(block.children));
      return paragraph;
    }
    case "code": {
      const figure = el("figure", "doc-code");
      if (block.info) figure.append(el("figcaption", "doc-code-info", safeText(block.info)));
      const pre = el("pre");
      pre.append(el("code", "", safeText(block.text)));
      figure.append(pre);
      return figure;
    }
    case "quote": {
      const quote = el("blockquote", "doc-quote");
      quote.append(renderBlocks(block.children));
      return quote;
    }
    case "list": {
      const list = block.ordered ? el("ol", "doc-md-list") : el("ul", "doc-md-list");
      if (block.ordered && block.start !== 1) (list as HTMLOListElement).start = block.start;
      for (const item of block.items) {
        const row = el("li");
        const only = item.length === 1 ? item[0] : undefined;
        if (only?.kind === "paragraph") row.append(...inlineNodes(only.children));
        else row.append(renderBlocks(item));
        list.append(row);
      }
      return list;
    }
    case "table": {
      const wrap = el("div", "doc-table-wrap");
      const table = el("table", "doc-table");
      const head = el("tr");
      block.header.forEach((cell, column) => {
        const th = el("th");
        const align = block.align[column];
        if (align) th.dataset.align = align;
        th.append(...inlineNodes(cell));
        head.append(th);
      });
      table.createTHead().append(head);
      const body = table.createTBody();
      for (const cells of block.rows) {
        const row = el("tr");
        cells.forEach((cell, column) => {
          const td = el("td");
          const align = block.align[column];
          if (align) td.dataset.align = align;
          td.append(...inlineNodes(cell));
          row.append(td);
        });
        body.append(row);
      }
      wrap.append(table);
      return wrap;
    }
    case "rule":
      return el("hr", "doc-rule");
  }
}

export function renderBlocks(blocks: readonly Block[]): DocumentFragment {
  const fragment = document.createDocumentFragment();
  for (const block of blocks) fragment.append(blockNode(block));
  return fragment;
}

/** A file that is not Markdown is shown as the text it is. */
export function renderPlain(text: string): HTMLElement {
  const pre = el("pre", "doc-plain");
  pre.textContent = safeText(text);
  return pre;
}
