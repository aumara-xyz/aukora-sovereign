// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { parseCard } from "../identity/card.js";
import { encodeQr } from "../identity/qr.js";
import { COPY } from "./copy.js";
import { icon } from "../threads/dom.js";
import { h } from "./dom.js";

const encoder = new TextEncoder();
const MAX_TEXT_BYTES = 16_384;
const MAX_LABEL_BYTES = 160;
const NPUB = "npub1[02-9ac-hj-np-z]{58}";

// Opaque face frames have no clipboard grant. Keep the public ID selected if copying is unavailable.
export function copyId(button: HTMLButtonElement, address: HTMLElement, status: HTMLElement, signal: AbortSignal): void {
  button.addEventListener("click", () => {
    const range = document.createRange();
    range.selectNodeContents(address);
    const selection = document.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    let copied = false;
    try { copied = document.execCommand("copy"); } catch { /* The selection remains available. */ }
    status.textContent = copied ? "Aukora ID copied." : "Aukora ID selected. Copy it with your keyboard or selection menu.";
  }, { signal });
}

export function ownIdentity(client: FaceClient, signal: AbortSignal): HTMLElement {
  const address = h("code", { "aria-label": "Your Aukora ID", class: "own-id" }, "Reading your Aukora ID…");
  const copy = h("button", { type: "button", class: "ak-action", disabled: "" }, "Copy Aukora ID");
  const status = h("p", { class: "info", role: "status" });
  const qr = h("canvas", { class: "identity-qr", role: "img", "aria-label": "QR code of your Aukora ID", hidden: "" });
  const element = h("section", { "aria-label": "Your Aukora ID", class: "id-panel" },
    h("div", { class: "identity-field" }, qr, h("div", { class: "identity-text" }, address, copy)), status);
  copyId(copy, address, status, signal);
  void client.call("aumlok", "identity", {}, { signal }).then(value => {
    const identity = parseCard(value);
    if (signal.aborted) return;
    address.textContent = identity.nodeNpub ?? "Aukora ID unavailable";
    copy.disabled = identity.nodeNpub === null;
    status.textContent = identity.nodeNpub === null ? "Aukora ID unavailable."
      : !identity.nodeKeyBound ? "This Aukora ID is not yet bound by your passkey. " + COPY.mutual
        : COPY.mutual;
    if (identity.nodeNpub !== null) {
      const symbol = encodeQr(identity.nodeNpub);
      const scale = 4;
      qr.width = qr.height = (symbol.size + 8) * scale;
      const context = qr.getContext("2d");
      if (context) {
        // Drawn light on the screen's own dark background (Peter, 2026-10-18), with the four-module quiet zone left
        // clear: a reflectance-reversed code, which phone cameras read.
        context.clearRect?.(0, 0, qr.width, qr.height);
        context.fillStyle = "rgb(232, 234, 237)";
        for (let y = 0; y < symbol.size; y++) for (let x = 0; x < symbol.size; x++) {
          if (symbol.dark(x, y)) context.fillRect((x + 4) * scale, (y + 4) * scale, scale, scale);
        }
        qr.hidden = false;
      }
    }
  }).catch(error => { if (!signal.aborted) showServiceState(status, error); });
  return element;
}

export function addContact(client: FaceClient, signal: AbortSignal): HTMLFormElement {
  const npub = h("input", { type: "text", name: "npub", required: "", pattern: NPUB, maxlength: "63", placeholder: "npub1…", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "Contact Aukora ID" });
  const name = h("input", { type: "text", name: "label", maxlength: String(MAX_LABEL_BYTES), placeholder: "Name (optional)", autocomplete: "off", "aria-label": "Contact name (optional)" });
  const submit = h("button", { type: "submit", class: "ak-action" }, "Review contact");
  const status = h("p", { role: "status", class: "info", "aria-live": "polite" });
  const form = h("form", { class: "contact-form" },
    h("label", {}, "Aukora ID", npub), h("label", {}, "Name", name),
    h("p", { class: "aside" }, COPY.contactKey),
    h("div", { class: "ak-actionrow" }, submit, h("span", { class: "ak-action__note" }, "One passkey approval")), status);
  form.addEventListener("submit", event => {
    event.preventDefault();
    if (submit.disabled || !form.reportValidity()) return;
    clearServiceState(status);
    if (encoder.encode(name.value).length > MAX_LABEL_BYTES) { status.textContent = "Use a shorter name (160 bytes maximum)."; return; }
    submit.disabled = true;
    status.textContent = "Opening approval…";
    void client.call("network", "contact.propose", { npub: npub.value.trim(), label: name.value.trim() || null }, { signal }).then(() => {
      if (signal.aborted) return;
      status.textContent = COPY.contactReview;
      form.reset();
    }).catch(error => { if (!signal.aborted) showServiceState(status, error); })
      .finally(() => { if (!signal.aborted) submit.disabled = false; });
  }, { signal });
  return form;
}

export interface Composer {
  readonly element: HTMLElement;
  /** Sends this text as a new message (the retry of a failed one). */
  send(text: string): void;
}

// The Auma chat composer: one rounded box, the text, and the round send arrow inside it. Enter sends; Shift+Enter
// starts a new line. What a send records and what relays see is explained once, under More, How it works.
export function composer(client: FaceClient, signal: AbortSignal, npub: string, name: string, sent: () => void): Composer {
  const text = h("textarea", { name: "text", class: "draft", rows: "1", required: "", maxlength: String(MAX_TEXT_BYTES), placeholder: `Message ${name}`, "aria-label": `Message ${name}` });
  const submit = h("button", { type: "submit", class: "send", "aria-label": "Send", title: "Send" }, icon("send"));
  const status = h("p", { role: "status", class: "info composer-status", "aria-live": "polite" });
  const form = h("form", { class: "composer" }, h("div", { class: "composer-card" }, text, h("div", { class: "composer-row" }, submit)), status);
  const deliver = (value: string) => {
    if (submit.disabled) return;
    clearServiceState(status);
    if (value.trim().length === 0) { status.textContent = "Write a message first."; return; }
    if (encoder.encode(value).length > MAX_TEXT_BYTES) { status.textContent = "Use a shorter message (16,384 bytes maximum)."; return; }
    submit.disabled = true;
    text.disabled = true;
    status.textContent = "Sending…";
    void client.call("network", "send", { npub, text: value }, { signal }).then(() => {
      if (signal.aborted) return;
      if (text.value === value) text.value = "";
      status.textContent = "";
      sent();
    }).catch(error => { if (!signal.aborted) showServiceState(status, error); })
      .finally(() => { if (!signal.aborted) { submit.disabled = false; text.disabled = false; } });
  };
  form.addEventListener("submit", event => { event.preventDefault(); deliver(text.value); }, { signal });
  text.addEventListener("keydown", event => {
    if (event.key !== "Enter" || event.shiftKey || event.isComposing) return;
    event.preventDefault();
    deliver(text.value);
  }, { signal });
  return { element: form, send: deliver };
}
