// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { parseCard } from "../identity/card.js";
import { encodeQr } from "../identity/qr.js";
import { COPY } from "./copy.js";
import { h } from "./dom.js";
import { portal } from "./portal.js";

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
  const element = h("section", { "aria-label": "Your Aukora ID" },
    h("h2", { class: "ak-label" }, "Your Aukora ID"),
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
        // QR contrast and four-module quiet zone match the existing Identity encoder's requirements.
        context.fillStyle = "white";
        context.fillRect(0, 0, qr.width, qr.height);
        context.fillStyle = "black";
        for (let y = 0; y < symbol.size; y++) for (let x = 0; x < symbol.size; x++) {
          if (symbol.dark(x, y)) context.fillRect((x + 4) * scale, (y + 4) * scale, scale, scale);
        }
        qr.hidden = false;
      }
    }
  }).catch(error => { if (!signal.aborted) showServiceState(status, error); });
  return element;
}

export function addContact(client: FaceClient, signal: AbortSignal): HTMLElement {
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
  return portal("Add a contact", "Aukora ID and name", form, signal).element;
}

export function composer(client: FaceClient, signal: AbortSignal, npub: string, sent: () => void): HTMLElement {
  const text = h("textarea", { name: "text", rows: "3", required: "", maxlength: String(MAX_TEXT_BYTES), placeholder: "Write a message…", "aria-label": "Message" });
  const submit = h("button", { type: "submit", class: "ak-action" }, "Send");
  const status = h("p", { role: "status", class: "info", "aria-live": "polite" });
  const form = h("form", { class: "composer" }, h("label", { class: "ak-label" }, "Message", text),
    h("div", { class: "ak-actionrow" }, submit, h("span", { class: "ak-action__note" }, "Sent by you · recorded in Aura")),
    h("p", { class: "info" }, COPY.sendSession), h("p", { class: "info" }, COPY.relaysSee), status);
  form.addEventListener("submit", event => {
    event.preventDefault();
    if (submit.disabled || !form.reportValidity()) return;
    clearServiceState(status);
    if (text.value.trim().length === 0) { status.textContent = "Write a message first."; return; }
    if (encoder.encode(text.value).length > MAX_TEXT_BYTES) { status.textContent = "Use a shorter message (16,384 bytes maximum)."; return; }
    submit.disabled = true;
    text.disabled = true;
    status.textContent = "Sending…";
    void client.call("network", "send", { npub, text: text.value }, { signal }).then(() => {
      if (signal.aborted) return;
      text.value = "";
      status.textContent = "Queued for the relays.";
      sent();
    }).catch(error => { if (!signal.aborted) showServiceState(status, error); })
      .finally(() => { if (!signal.aborted) { submit.disabled = false; text.disabled = false; } });
  }, { signal });
  return form;
}
