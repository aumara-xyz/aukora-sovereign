// SPDX-License-Identifier: AGPL-3.0-or-later
import type { FaceClient } from "../../core/index.js";
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import { parseCard } from "../identity/card.js";
import { COPY } from "./copy.js";
import { h } from "./dom.js";
import { portal } from "./portal.js";

const encoder = new TextEncoder();
const MAX_TEXT_BYTES = 16_384;
const MAX_LABEL_BYTES = 160;
const NPUB = "npub1[02-9ac-hj-np-z]{58}";

export function ownIdentity(client: FaceClient, signal: AbortSignal): HTMLElement {
  const address = h("code", { "aria-label": "Your node npub", class: "own-npub" }, "Reading your node address…");
  const copy = h("button", { type: "button", class: "ak-action", disabled: "" }, "Copy npub");
  const status = h("p", { class: "info", role: "status" });
  const element = h("section", { "aria-label": "Your node address" },
    h("h2", { class: "ak-label" }, "Your npub"),
    h("div", { class: "identity-field" }, address, copy), status);
  copy.addEventListener("click", () => {
    // The face has an opaque origin. Copy the selected public key in this gesture without broad clipboard grants.
    const range = document.createRange();
    range.selectNodeContents(address);
    const selection = document.getSelection();
    selection?.removeAllRanges();
    selection?.addRange(range);
    let copied = false;
    try { copied = document.execCommand("copy"); } catch { /* The selected address remains available to copy. */ }
    status.textContent = copied ? "Copied." : "Address selected. Copy it with your keyboard or selection menu.";
  }, { signal });
  void client.call("aumlok", "identity", {}, { signal }).then(value => {
    const identity = parseCard(value);
    if (signal.aborted) return;
    address.textContent = identity.nodeNpub ?? "Node address unavailable";
    copy.disabled = identity.nodeNpub === null;
    status.textContent = identity.nodeNpub === null ? "Node address unavailable."
      : !identity.nodeKeyBound ? "Node key is not yet bound by an owner-approved Nostr identity record. " + COPY.mutual
        : "Node key · " + COPY.mutual;
  }).catch(error => { if (!signal.aborted) showServiceState(status, error); });
  return element;
}

export function addContact(client: FaceClient, signal: AbortSignal): HTMLElement {
  const npub = h("input", { type: "text", name: "npub", required: "", pattern: NPUB, maxlength: "63", placeholder: "npub1…", autocomplete: "off", autocapitalize: "off", spellcheck: "false", "aria-label": "Contact npub" });
  const name = h("input", { type: "text", name: "label", maxlength: String(MAX_LABEL_BYTES), placeholder: "Name (optional)", autocomplete: "off", "aria-label": "Contact name (optional)" });
  const submit = h("button", { type: "submit", class: "ak-action" }, "Review contact");
  const status = h("p", { role: "status", class: "info", "aria-live": "polite" });
  const form = h("form", { class: "contact-form" },
    h("label", {}, "Nostr address", npub), h("label", {}, "Name", name),
    h("p", { class: "info" }, COPY.contactKey),
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
  return portal("Add contact", "Nostr address and optional name", form, signal).element;
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
