// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ApprovalCard, Authorization, JsonObject, JsonValue } from "./codec.js";

function quoted(value: string): string {
  let result = '"';
  for (let offset = 0; offset < value.length; offset += 1) {
    const unit = value.charCodeAt(offset);
    if (unit === 34) result += '\\"';
    else if (unit === 92) result += "\\\\";
    // Controls and everything outside printable ASCII are shown escaped; a plain space is shown as a space (O13).
    else if (unit < 32 || unit >= 127) result += `\\u${unit.toString(16).padStart(4, "0")}`;
    else result += value[offset];
  }
  return `${result}"`;
}

export function visibleJson(value: JsonValue): string {
  if (typeof value === "string") return quoted(value);
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(visibleJson).join(",")}]`;
  const fields = value as JsonObject;
  return `{${Object.keys(fields).sort().map(key => `${quoted(key)}:${visibleJson(fields[key])}`).join(",")}}`;
}

function exact(document: Document, value: JsonValue): HTMLElement {
  const body = document.createElement("pre");
  body.className = "approval-exact-value";
  body.textContent = visibleJson(value);
  return body;
}

/** A fold for exact material (changes, the whole card, the authorization): a static record row of the primitives. */
function fold(document: Document, title: string, value: JsonValue, section: string): HTMLElement {
  const details = document.createElement("details");
  details.className = "ak-row ak-row--static approval-fold";
  details.dataset.section = section;
  const label = document.createElement("summary");
  label.className = "ak-row__head";
  const copy = document.createElement("span");
  copy.className = "ak-row__copy";
  const name = document.createElement("span");
  name.className = "ak-row__title";
  name.textContent = title;
  copy.append(name);
  const expander = document.createElement("span");
  expander.className = "ak-expander";
  expander.setAttribute("aria-hidden", "true");
  label.append(copy, expander);
  const body = document.createElement("div");
  body.className = "ak-row__body";
  body.append(exact(document, value));
  details.append(label, body);
  return details;
}

export function renderAuthorization(document: Document, authorization: Authorization): HTMLElement {
  return fold(document, "Authorization", authorization, "authorization");
}

/** What kind of card this is, by the target the owner's passkey would sign (shown, never trusted for anything). */
export type CardKind = "release" | "plugins" | "key" | "budget" | "contact" | "door" | "grant" | "change";

export function cardKind(target: string, op: Authorization["op"]): CardKind {
  if (op === "grant" || op === "permission" || target === "door/standing-grants.json") return "grant";
  if (target === "release") return "release";
  if (target === "engine/plugin-set.json") return "plugins";
  if (target === "engine/model-key.json") return "key";
  if (target === "engine/model-budget.json") return "budget";
  if (target === "messaging/contacts.json") return "contact";
  if (target.startsWith("door/")) return "door";
  return "change";
}

const KIND_TITLE: Readonly<Record<CardKind, string>> = {
  release: "Release", plugins: "Plugin set", key: "Model key", budget: "Model budget", contact: "Contact", door: "Door ask",
  grant: "Standing grant", change: "Change",
};

// Glyphs on a 24 grid, drawn with the icon tile's 1.4 stroke and round caps (rule 10).
const KIND_GLYPH: Readonly<Record<CardKind, string>> = {
  release: "M12 19V5M6 11l6-6 6 6M5 21h14",
  plugins: "M9 3h6v4a2 2 0 1 0 0 4v4h-4a2 2 0 1 1-4 0H3V9h4a2 2 0 1 0 0-4H3",
  key: "M14.5 9.5a4.5 4.5 0 1 0-4.2 4.5L13 16.5h2.5V19H18v2.5h3v-3.2l-6.6-6.6c.1-.4.1-.8.1-1.2zM8 8h.01",
  budget: "M12 3v18M16.5 7.5c0-1.7-2-3-4.5-3s-4.5 1.3-4.5 3S9.5 10.4 12 11s4.5 1.8 4.5 3.5-2 3-4.5 3-4.5-1.3-4.5-3",
  contact: "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0M20 8v6M17 11h6",
  door: "M6 21V4.5L15 3v18M6 21h12M15 5h3v16M12 12h.01",
  grant: "M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3zM9 12l2 2 4-4",
  change: "M4 20h4L19 9l-4-4L4 16v4zM13.5 6.5l4 4",
};

/**
 * The card's colour by its kind (Peter, 2026-10-18): what changes the node itself (a release, the plugin set, the
 * model key or its budget) is red; a contact, a door ask or a standing grant is blue. Any other change keeps the
 * gate's own rating. The colour never alters the rating: the risk pill still shows it.
 */
export function cardTone(kind: CardKind, risk: ApprovalCard["risk"]): "ak-tone-red" | "ak-tone-blue" {
  if (kind === "release" || kind === "plugins" || kind === "key" || kind === "budget") return "ak-tone-red";
  if (kind === "contact" || kind === "door" || kind === "grant") return "ak-tone-blue";
  return risk === "critical" ? "ak-tone-red" : "ak-tone-blue";
}

function glyph(document: Document, kind: CardKind): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.4");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
  path.setAttribute("d", KIND_GLYPH[kind]);
  svg.append(path);
  return svg;
}

function label(document: Document, text: string, section?: string): HTMLElement {
  const element = document.createElement("p");
  element.className = "ak-label";
  if (section) element.dataset.section = section;
  element.textContent = text;
  return element;
}

/**
 * The card as a portal button opened over the whole site (rule 10). Everything the passkey signs is shown whole:
 * the summary wraps (never an ellipsis), every fact is its exact JSON in a fine-lined field table that wraps anywhere,
 * and the exact changes, card and authorization fold open in place. Every string is set with textContent.
 * `context` (the authorization's target and operation) only chooses the glyph and the one-line kind.
 */
export function renderCard(document: Document, card: ApprovalCard,
  context?: { readonly target: string; readonly op: Authorization["op"] }): HTMLElement {
  const kind = context ? cardKind(context.target, context.op) : "change";
  // The card's kind sets its colour (cardTone): the outline, the summary box and the passkey action share it.
  const tone = cardTone(kind, card.risk);
  const cardView = document.createElement("article");
  cardView.className = `ak-portal ak-portal--free ${tone} approval-card approval-card-${card.risk}`;
  cardView.dataset.open = "yes";
  cardView.dataset.kind = kind;
  cardView.setAttribute("aria-label", `${card.risk} approval`);
  const head = document.createElement("header");
  head.className = "ak-portal__head approval-head";
  const tile = document.createElement("span");
  tile.className = "ak-icon-tile";
  tile.append(glyph(document, kind));
  const copy = document.createElement("span");
  copy.className = "ak-portal__copy";
  const summary = document.createElement("h2");
  summary.className = "ak-portal__title approval-summary";
  summary.tabIndex = -1;
  summary.textContent = card.says;
  const line = document.createElement("span");
  line.className = "ak-portal__summary";
  line.textContent = context ? `${KIND_TITLE[kind]} · ${context.target}` : KIND_TITLE[kind];
  copy.append(summary, line);
  const end = document.createElement("span");
  end.className = "ak-portal__end";
  const risk = document.createElement("span");
  risk.className = `ak-pill approval-risk ${card.risk === "critical" ? "ak-tone-red" : "ak-tone-blue"}`;
  risk.textContent = card.risk.toUpperCase();
  end.append(risk);
  head.append(tile, copy, end);
  const body = document.createElement("div");
  body.className = "ak-portal__body approval-body";
  const facts = document.createElement("dl");
  facts.className = "ak-fields approval-facts";
  facts.dataset.section = "signs";
  for (const [name, value] of card.facts) {
    const term = document.createElement("dt");
    term.textContent = visibleJson(name);
    const detail = document.createElement("dd");
    detail.append(exact(document, value));
    facts.append(term, detail);
  }
  const note = document.createElement("blockquote");
  note.className = "ak-quote ak-tone-muted approval-model-note";
  note.append(exact(document, card.model_note));
  body.append(label(document, "What the passkey signs", "signs"), facts,
    fold(document, "Exact changes", card.from_to, "changes"), fold(document, "Exact card", card, "card"),
    label(document, "Model note · untrusted"), note);
  cardView.append(head, body);
  return cardView;
}
