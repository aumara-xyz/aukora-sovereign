// SPDX-License-Identifier: AGPL-3.0-or-later
// The Identity screen: the public card, the contact code as a picture of the text the node issued, and the safety numbers
// to compare. Everything on it is public and display-only. The code is drawn on a canvas (this page allows no data
// images), and a code past its expiry is removed rather than left to be photographed. No key, signature or secret is
// ever held here, and nothing on the page can sign, approve or open anything.
import { clearServiceState, showServiceState } from "../../core/service-state.js";
import type { IdentityCard } from "./card.js";
import { encodeQr } from "./qr.js";

export interface IdentityView {
  show(card: IdentityCard, now: number): void;
  unavailable(reason: unknown): void;
  /** Re-evaluates expiry; returns whole seconds left on the shown code, 0 once it has expired, or null without one. */
  tick(now: number): number | null;
  dispose(): void;
}

const QUIET_ZONE = 4;
const TARGET_PIXELS = 320;
const LIGHT = "#f4f3f8";
const DARK = "#151322";

function make<K extends keyof HTMLElementTagNameMap>(tag: K, className?: string, text?: string): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function fact(list: HTMLElement, term: string): HTMLElement {
  const row = make("div", "fact");
  const value = make("dd");
  row.append(make("dt", undefined, term), value);
  list.append(row);
  return value;
}

/** Digits in groups of five, the way they are read aloud. */
export function groupDigits(digits: string): string {
  return digits.match(/.{1,5}/g)?.join(" ") ?? digits;
}

function drawCode(canvas: HTMLCanvasElement, text: string) {
  const symbol = encodeQr(text);
  const modules = symbol.size + QUIET_ZONE * 2;
  const scale = Math.max(2, Math.floor(TARGET_PIXELS / modules));
  canvas.width = modules * scale;
  canvas.height = modules * scale;
  const context = canvas.getContext("2d");
  if (!context) throw new Error("identity:canvas-unavailable");
  context.fillStyle = LIGHT;
  context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = DARK;
  for (let y = 0; y < symbol.size; y++) {
    for (let x = 0; x < symbol.size; x++) {
      if (symbol.dark(x, y)) context.fillRect((x + QUIET_ZONE) * scale, (y + QUIET_ZONE) * scale, scale, scale);
    }
  }
}

export function createIdentityView(root: HTMLElement): IdentityView {
  const card = make("section", "card");
  card.setAttribute("aria-labelledby", "card-title");
  const head = make("div", "card-head");
  const title = make("h2", undefined, "Public contact card");
  title.id = "card-title";
  const badge = make("p", "badge", "CHECKING");
  badge.setAttribute("role", "status");
  head.append(title, badge);
  const name = make("p", "name");
  const facts = make("dl", "facts");
  const subject = fact(facts, "Aumlok ID");
  const node = fact(facts, "Node address");
  const agent = fact(facts, "Agent address");
  const lead = make("p", "note");
  card.append(head, name, facts, lead);

  const code = make("section", "code");
  code.setAttribute("aria-labelledby", "code-title");
  const codeTitle = make("h2", undefined, "Contact code");
  codeTitle.id = "code-title";
  const canvas = make("canvas", "qr");
  canvas.setAttribute("role", "img");
  const expiry = make("p", "expiry");
  const asText = make("details", "as-text");
  const asTextTitle = make("summary", undefined, "Code as text");
  const codeText = make("pre", "code-text");
  asText.append(asTextTitle, codeText);
  code.append(codeTitle, canvas, expiry, asText, make("p", "note", "A contact code introduces this node. It grants nothing to whoever scans it: the owner still approves every contact on this node."));

  const safety = make("section", "safety");
  safety.setAttribute("aria-labelledby", "safety-title");
  const safetyTitle = make("h2", undefined, "Safety numbers");
  safetyTitle.id = "safety-title";
  const safetyList = make("ul", "numbers");
  safety.append(
    safetyTitle,
    make("p", "note", "Read these digits aloud, or compare them side by side with your contact's own screen. If any digit differs, do not trust that contact. A safety number compares keys; it does not show who holds them."),
    safetyList,
  );
  root.append(card, code, safety);

  let expiresAt: number | null = null;
  // Stays set from the moment a code lapses until the next read replaces it, so the flow keeps asking for a fresh one.
  let lapsed = false;
  const hideCode = (message: string) => {
    canvas.hidden = true;
    asText.hidden = true;
    expiry.textContent = message;
  };

  const view: IdentityView = {
    show(next, now) {
      clearServiceState(badge);
      facts.hidden = false;
      code.hidden = false;
      safety.hidden = false;
      badge.textContent = next.subject === null ? "UNBOUND" : "PUBLIC";
      badge.dataset.state = next.subject === null ? "unbound" : "public";
      name.textContent = next.label;
      subject.textContent = next.subject ?? "None yet. Bind a phrase in the AUMLOK pane first.";
      node.textContent = next.nodeNpub ?? "None yet.";
      agent.textContent = next.agentNpub ?? "None yet.";
      lead.textContent = next.nodeNpub !== null && !next.nodeKeyBound
        ? "Node key is not yet bound by an owner-approved Nostr identity record."
        : "Public keys only. Nothing on this page can sign, approve or open anything.";
      expiresAt = null;
      lapsed = false;
      if (next.contact === null) {
        hideCode(next.subject === null ? "No contact code until this node is bound." : "The node has not issued a contact code.");
      } else {
        try {
          drawCode(canvas, next.contact.text);
          canvas.setAttribute("aria-label", "Contact code as a QR picture");
          codeText.textContent = next.contact.text;
          canvas.hidden = false;
          asText.hidden = false;
          expiresAt = next.contact.expiresAt;
        } catch {
          hideCode("The contact code cannot be drawn.");
        }
        view.tick(now);
      }
      safetyList.replaceChildren();
      if (next.safety.length === 0) safetyList.append(make("li", undefined, "No safety numbers yet."));
      for (const entry of next.safety) {
        const item = make("li");
        item.dataset.kind = entry.kind;
        item.append(
          make("strong", undefined, entry.kind === "own" ? `${entry.label} (this node)` : entry.label),
          make("span", "digits", groupDigits(entry.digits)),
        );
        safetyList.append(item);
      }
    },
    unavailable(reason) {
      showServiceState(badge, reason);
      badge.dataset.state = "unavailable";
      name.textContent = "";
      for (const part of [subject, node, agent]) part.textContent = "—";
      facts.hidden = true;
      lead.textContent = "";
      expiresAt = null;
      lapsed = false;
      hideCode("");
      codeText.textContent = "";
      code.hidden = true;
      safety.hidden = true;
      safetyList.replaceChildren();
    },
    tick(now) {
      if (lapsed) return 0;
      if (expiresAt === null) {
        if (!canvas.hidden) expiry.textContent = "This code does not expire.";
        return null;
      }
      const left = Math.max(0, Math.floor(expiresAt - now / 1000));
      if (left === 0) {
        hideCode("This code has expired. Refresh for a new one.");
        expiresAt = null;
        lapsed = true;
        return 0;
      }
      expiry.textContent = `Valid for ${left} more second${left === 1 ? "" : "s"}.`;
      return left;
    },
    dispose() {
      card.remove();
      code.remove();
      safety.remove();
    },
  };
  hideCode("Reading the contact code.");
  return view;
}
