// SPDX-License-Identifier: AGPL-3.0-or-later
// The AUMLOK screen: one layout that never changes, an anchor card above six tiles in three bands, with the state shown
// by what fills them. The words themselves never appear here. The phrase is generated, shown, checked and derived only
// in the owner pane, and this page has no input that could take one. The panes open from the shell's own buttons; this
// face has no way to open them.
import type { AumlokStatus } from "./status.js";

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
// The shipped word lists' honest strength, in bits (crates/aumlok SHIPPED_ENTROPY).
const MINIMUM_BITS = "41.5";
const AVERAGE_BITS = "43.1";

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
  const title = make("h2", undefined, "Seven-word binding witness");
  title.id = "witness-title";
  const badge = make("p", "badge");
  badge.setAttribute("role", "status");
  head.append(title, badge);

  const phrase = make("figure", "phrase");
  phrase.setAttribute("role", "img");
  const anchor = make("div", "anchor");
  anchor.append(make("span", "label", "Word zero · anchor"));
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
  const passkeys = fact(facts, "Passkeys enrolled");
  const refresh = fact(facts, "Phrase refresh");
  passkeys.textContent = "—";
  refresh.textContent = "—";
  const strength = fact(facts, "Phrase strength");
  strength.textContent = `${MINIMUM_BITS} bits at minimum, ${AVERAGE_BITS} on average, over the shipped word lists. Owner authority is the passkey, never the phrase.`;
  const panesOrigin = fact(facts, "Trusted panes served from");
  panesOrigin.parentElement?.setAttribute("hidden", "");

  const panes = make("section", "panes");
  panes.setAttribute("aria-labelledby", "panes-title");
  const panesTitle = make("h2", undefined, "Opening the trusted panes");
  panesTitle.id = "panes-title";
  panes.append(
    panesTitle,
    make("p", undefined, "Passkey and Phrase open from the buttons in the bar at the top of the app. They are served from a separate owner origin and appear only framed inside this app. This screen cannot open them and never asks for the words."),
    make("p", "note", "A passkey approval shows that a passkey signed exact bytes after its user check. It does not show which person pressed it."),
  );
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
  set("checking", "CHECKING", "Reading the binding status from the node.", false);

  return {
    show(status) {
      if (status.bound) {
        set("bound", "BOUND", "A seven-word phrase seals this node's identity root. The words were checked in the Phrase pane; this app has never seen them and cannot show them.", true);
      } else {
        set("unbound", "UNBOUND", "No seven-word phrase seals this node's identity root yet. Open Phrase in the bar at the top of the app to bind one: the words are shown and checked there, never here.", false);
      }
      passkeys.textContent = status.passkeys === 0
        ? (status.bound ? "None. Open Passkey in the bar at the top of the app to enrol one." : "None yet.")
        : String(status.passkeys);
      refresh.textContent = !status.bound ? "Not applicable until a phrase is bound."
        : status.refreshDue ? "Due. Open Phrase and choose a new phrase; the same identity root is rewrapped under it."
          : "Not due.";
      panesOrigin.textContent = status.ownerOrigin ?? "";
      panesOrigin.parentElement?.toggleAttribute("hidden", status.ownerOrigin === null);
    },
    unavailable(reason) {
      set("unavailable", "UNAVAILABLE", `Binding status is not available (${reason}). Nothing here is shown as bound.`, false);
      passkeys.textContent = "Unknown.";
      refresh.textContent = "Unknown.";
      panesOrigin.parentElement?.setAttribute("hidden", "");
    },
    dispose() {
      witness.remove();
      facts.remove();
      panes.remove();
    },
  };
}
