// SPDX-License-Identifier: AGPL-3.0-or-later
import { PHRASE_ENTROPY_BITS } from "../contracts.js";

export function createView(host: HTMLElement) {
  const document = host.ownerDocument;
  const panel = document.createElement("section");
  panel.className = "phrase-pane";
  const css = document.createElement("link");
  css.rel = "stylesheet";
  css.href = new URL("./phrase.css", import.meta.url).href;
  const title = document.createElement("h2");
  title.textContent = "Your seven-word phrase";
  const explanation = document.createElement("p");
  explanation.textContent = "Your phrase seals a random identity root. Your passkey approves changes. Enter your phrase here to refresh it or download a backup.";
  const entropy = document.createElement("p");
  entropy.textContent = `Shipped vocabulary: ${PHRASE_ENTROPY_BITS.minimum} bits minimum, ${PHRASE_ENTROPY_BITS.average} average. Words follow ROOT, ROOT, UNITE, UNITE, RISE, RISE after the anchor.`;
  const entryLabel = document.createElement("label");
  entryLabel.textContent = "Current seven-word phrase";
  const entry = document.createElement("input");
  entry.type = "password";
  entry.autocomplete = "off";
  entry.spellcheck = false;
  entry.maxLength = 1024;
  entry.setAttribute("autocapitalize", "off");
  entryLabel.append(entry);
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  const phrase = document.createElement("p");
  phrase.className = "phrase-words";
  phrase.hidden = true;
  const savedLabel = document.createElement("label");
  const saved = document.createElement("input");
  saved.type = "checkbox";
  savedLabel.append(saved, " I have saved the replacement phrase.");
  savedLabel.hidden = true;
  const review = document.createElement("div");
  const controls = document.createElement("div");
  controls.className = "phrase-controls";
  const button = (text: string) => {
    const result = document.createElement("button");
    result.type = "button";
    result.textContent = text;
    result.hidden = true;
    controls.append(result);
    return result;
  };
  const unlock = button("Unlock phrase locally");
  const draw = button("Generate replacement phrase");
  const prepare = button("Review phrase refresh");
  const approve = button("Approve with passkey");
  const resume = button("Resume from owner service");
  const backup = button("Download passkey-bound backup (v2)");
  const legacyLabel = document.createElement("label");
  const legacy = document.createElement("input");
  legacy.type = "checkbox";
  legacyLabel.append(legacy, " I explicitly request a phrase-only v1 copy without passkey protection.");
  legacyLabel.hidden = true;
  const legacyDownload = button("Download phrase-only copy (v1)");
  const close = button("Finish");
  panel.append(css, title, explanation, entropy, entryLabel, phrase, savedLabel, review,
    legacyLabel, controls, status);
  host.replaceChildren(panel);
  return { document, panel, entry, entryLabel, status, phrase, saved, savedLabel, review,
    controls, unlock, draw, prepare, approve, resume, backup, legacy, legacyLabel, legacyDownload, close };
}
