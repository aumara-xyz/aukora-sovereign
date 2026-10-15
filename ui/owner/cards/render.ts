// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ApprovalCard, Authorization, JsonObject, JsonValue } from "./codec.js";

function visibleString(value: string): string {
  let output = '"';
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 0x22) output += '\\"';
    else if (code === 0x5c) output += "\\\\";
    else if (code <= 0x20 || code >= 0x7f) output += `\\u${code.toString(16).padStart(4, "0")}`;
    else output += value[index];
  }
  return `${output}"`;
}

// All text becomes printable ASCII. Quotes distinguish strings from JSON values;
// escaped spaces and Unicode preserve distinctions hidden by browser typography.
export function visibleJson(value: JsonValue): string {
  if (typeof value === "string") return visibleString(value);
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(visibleJson).join(",")}]`;
  const record = value as JsonObject;
  return `{${Object.keys(record).sort().map(key => `${visibleString(key)}:${visibleJson(record[key])}`).join(",")}}`;
}

function field(document: Document, label: string, value: JsonValue): HTMLElement {
  const section = document.createElement("section");
  const heading = document.createElement("h3");
  heading.textContent = label;
  const text = document.createElement("pre");
  text.textContent = visibleJson(value);
  text.className = "approval-exact-value";
  section.append(heading, text);
  return section;
}

export function renderAuthorization(document: Document, authorization: Authorization): HTMLElement {
  const details = document.createElement("details");
  const summary = document.createElement("summary");
  summary.textContent = "Exact authorization (C5)";
  const body = field(document, "Authorization fields", authorization);
  details.append(summary, body);
  return details;
}

export function renderCard(document: Document, card: ApprovalCard): HTMLElement {
  const article = document.createElement("article");
  article.className = "approval-card";
  article.setAttribute("aria-label", "Exact approval card");
  article.append(
    field(document, "v", card.v),
    field(document, "risk", card.risk),
    field(document, "says", card.says),
    field(document, "facts", card.facts),
    field(document, "from_to", card.from_to),
  );
  const note = document.createElement("fieldset");
  note.className = "approval-model-note";
  const legend = document.createElement("legend");
  legend.textContent = "model_note — untrusted model text";
  const text = document.createElement("pre");
  text.className = "approval-exact-value";
  text.textContent = visibleJson(card.model_note);
  note.append(legend, text);
  article.append(note);
  return article;
}
