// SPDX-License-Identifier: AGPL-3.0-or-later
// The AUMLOK screen: one layout that never changes, an anchor card above six tiles in three bands, with the state shown
// by what fills them. The words themselves never appear here. The phrase is generated, shown, checked and derived only
// in the owner pane, and this page has no input that could take one. The panes open from the shell's own buttons; this
// face has no way to open them.
import type { AumlokStatus } from "./status.js";
import { icon } from "../../design/index.js";

export interface AumlokView {
  show(status: AumlokStatus): void;
  unavailable(reason: string): void;
  dispose(): void;
}

// The phrase's shape: a six-letter anchor, then two words from each themed list.
const BANDS = [
  { id: "root", name: "ROOT", detail: "nature", tone: "green" },
  { id: "unite", name: "UNITE", detail: "people and connection", tone: "blue" },
  { id: "rise", name: "RISE", detail: "spirit, space and technology", tone: "purple" },
] as const;
const ANCHOR_LETTERS = 6;

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

export function createAumlokView(root: HTMLElement): AumlokView {
  const witness = make("section", "witness");
  witness.setAttribute("aria-labelledby", "witness-title");
  const head = make("div", "witness-head");
  const title = make("h2", undefined, "Seven-word binding");
  title.prepend(icon("aumlok"));
  title.id = "witness-title";
  const badge = make("p", "badge");
  badge.setAttribute("role", "status");
  head.append(title, badge);

  const phrase = make("figure", "phrase");
  phrase.setAttribute("role", "img");
  const anchor = make("div", "anchor");
  anchor.append(make("span", "label", "Anchor"));
  const boxes = make("span", "boxes");
  for (let at = 0; at < ANCHOR_LETTERS; at++) boxes.append(make("span", "box"));
  anchor.append(boxes);
  const bands = make("div", "bands");
  for (const band of BANDS) {
    const item = make("div", "band");
    item.dataset.tone = band.tone;
    const tiles = make("span", "tiles");
    tiles.append(make("span", "tile"), make("span", "tile"));
    item.append(make("span", "label", band.name), make("span", "detail", band.detail), tiles);
    bands.append(item);
  }
  phrase.append(anchor, bands);
  const lead = make("p", "lead");
  witness.append(head, phrase, lead);

  const facts = make("dl", "facts");
  const passkeys = fact(facts, "Passkeys");
  const refresh = fact(facts, "Phrase refresh");
  passkeys.textContent = "—";
  refresh.textContent = "—";
  const panesOrigin = fact(facts, "Owner pane");
  panesOrigin.parentElement?.setAttribute("hidden", "");

  const panes = make("p", "note", "Your seven words never appear here.");
  panes.prepend(icon("owner"));
  root.append(witness, facts, panes);

  const set = (state: "bound" | "unbound" | "unavailable" | "checking", label: string, text: string, filled: boolean) => {
    witness.dataset.state = state;
    badge.dataset.state = state;
    badge.textContent = label;
    phrase.dataset.filled = String(filled);
    phrase.setAttribute("aria-label", state === "bound"
      ? "Seven words: one anchor and six themed words, bound. The words are not shown here."
      : state === "unbound" ? "Seven words: one anchor and six themed words, none bound yet."
        : `Seven words: binding status ${state === "checking" ? "being read" : "unavailable"}.`);
    lead.textContent = text;
  };
  set("checking", "CHECKING", "Reading binding status…", false);

  return {
    show(status) {
      if (status.bound) {
        set("bound", "BOUND", "Your identity root is sealed.", true);
      } else {
        set("unbound", "UNBOUND", "Open Phrase in the app bar to bind your identity.", false);
      }
      passkeys.textContent = status.passkeys === 0
        ? (status.bound ? "None · open Passkey" : "None yet")
        : String(status.passkeys);
      refresh.textContent = status.refreshDue ? "Due · open Phrase"
        : status.bound ? "Not due" : "Unbound";
      panesOrigin.textContent = status.ownerOrigin ?? "";
      panesOrigin.parentElement?.toggleAttribute("hidden", status.ownerOrigin === null);
    },
    unavailable(reason) {
      set("unavailable", "UNAVAILABLE", reason, false);
      passkeys.textContent = "Unknown";
      refresh.textContent = "Unknown";
      panesOrigin.parentElement?.setAttribute("hidden", "");
    },
    dispose() {
      witness.remove();
      facts.remove();
      panes.remove();
    },
  };
}
