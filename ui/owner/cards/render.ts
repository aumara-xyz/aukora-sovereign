// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ApprovalCard, Authorization, JsonObject, JsonValue } from "./codec.js";

function quoted(value: string): string {
  let result = '"';
  for (let offset = 0; offset < value.length; offset += 1) {
    const unit = value.charCodeAt(offset);
    if (unit === 34) result += '\\"';
    else if (unit === 92) result += "\\\\";
    else if (unit <= 32 || unit >= 127) result += `\\u${unit.toString(16).padStart(4, "0")}`;
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

export function renderAuthorization(document: Document, authorization: Authorization): HTMLElement {
  const details = document.createElement("details");
  const label = document.createElement("summary");
  label.textContent = "Authorization";
  details.append(label, exact(document, authorization));
  return details;
}

export function renderCard(document: Document, card: ApprovalCard): HTMLElement {
  const cardView = document.createElement("article");
  cardView.className = `approval-card approval-card-${card.risk}`;
  cardView.setAttribute("aria-label", `${card.risk} approval`);
  const risk = document.createElement("span");
  risk.className = "approval-risk";
  risk.textContent = card.risk.toUpperCase();
  const summary = document.createElement("h2");
  summary.className = "approval-summary";
  summary.textContent = card.says;
  const facts = document.createElement("dl");
  facts.className = "approval-facts";
  for (const [label, value] of card.facts) {
    const term = document.createElement("dt");
    term.textContent = visibleJson(label);
    const detail = document.createElement("dd");
    detail.append(exact(document, value));
    facts.append(term, detail);
  }
  const changes = document.createElement("details");
  const changesLabel = document.createElement("summary");
  changesLabel.textContent = "Exact changes";
  changes.append(changesLabel, exact(document, card.from_to));
  const canonical = document.createElement("details");
  canonical.open = true;
  const canonicalLabel = document.createElement("summary");
  canonicalLabel.textContent = "Exact card";
  canonical.append(canonicalLabel, exact(document, card));
  const note = document.createElement("fieldset");
  note.className = "approval-model-note";
  const noteLabel = document.createElement("legend");
  noteLabel.textContent = "Model note · untrusted";
  note.append(noteLabel, exact(document, card.model_note));
  cardView.append(risk, summary, facts, changes, canonical, note);
  return cardView;
}
