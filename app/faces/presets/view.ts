// SPDX-License-Identifier: AGPL-3.0-or-later
// The Agent presets screen: one card per preset the node reports, with the model Auma asks, the longest reply, and each
// built-in operation marked allowed or not allowed in words as well as colour, then a card on what the two modes are and
// what a preset can never do. A failed read replaces the preset cards with an unavailable card. Nothing here edits, adds,
// copies or removes a preset, and a preset is only ever a choice among operations the node already has.
import { showServiceState } from "../../core/service-state.js";
import { card, count, facts, make, mark, note } from "../general/kit.js";
import { OPERATIONS } from "./presets.js";
import type { Operation, Preset } from "./presets.js";

export interface PresetsView {
  show(presets: readonly Preset[]): void;
  unavailable(reason: unknown): void;
}

const TITLES = { chat: "Chat", build: "Build" } as const;
const OPERATION_TEXT: Record<Operation, readonly [string, string]> = {
  chat: ["Chat", "Talk with you and ask the model for a reply."],
  threads: ["Threads", "Keep conversations in threads."],
  sessions: ["Sessions", "Create, open and list saved sessions, and add to them."],
  streaming: ["Streaming replies", "Show a reply as it arrives."],
  compaction: ["Compaction", "Shorten a long session so it still fits the model's context."],
  proposals: ["Proposals", "Read a target and propose a change to it. A proposal only asks."],
  memory_read: ["Memory, read", "Recall your notes, each with its source."],
  memory_propose: ["Memory, propose", "Ask to add a note. It waits for your approval."],
};

function operations(parent: HTMLElement, allowed: ReadonlySet<Operation>): void {
  const list = make("ul", "ops");
  for (const operation of OPERATIONS) {
    const [label, detail] = OPERATION_TEXT[operation];
    const item = make("li", "op");
    const yes = allowed.has(operation);
    const verdict = make("span", "state", yes ? "Allowed" : "Not allowed");
    verdict.dataset.tone = yes ? "ok" : "unknown";
    const words = make("span", "op-words");
    words.append(make("strong", undefined, label), make("span", "op-detail", detail));
    item.append(words, verdict);
    list.append(item);
  }
  parent.append(list);
}

export function createPresetsView(root: HTMLElement): PresetsView {
  const stage = make("div", "presets");
  root.append(stage);
  const modes = card(root, "modes", "Chat and Build");
  note(modes.body, "In Chat, Auma talks. In Build she may also propose changes, but a proposal only asks: nothing runs until you approve its exact bytes with your passkey.", "lead");
  note(modes.body, "A preset only selects among operations already in the node. It never loads code, runs a command or opens a network connection.", "lead");

  // One card in place of the presets: while they are being read, when there are none, and when they cannot be read.
  const instead = (label: string, text: string) => {
    stage.replaceChildren();
    const only = card(stage, "presets", "Presets");
    mark(only.badge, "unknown", label);
    note(only.body, text, "lead");
  };
  instead("CHECKING", "Reading the presets from the node.");

  return {
    show(presets) {
      stage.replaceChildren();
      if (presets.length === 0) {
        instead("NONE", "The node reports no presets.");
        return;
      }
      for (const preset of presets) {
        const one = card(stage, `preset-${preset.id}`, TITLES[preset.id]);
        mark(one.badge, "plain", `${TITLES[preset.id].toUpperCase()} MODE`);
        const row = facts(one.body);
        row("Model").textContent = preset.model;
        row("Longest reply").textContent = `${count(preset.maxOutputTokens)} tokens`;
        one.body.append(make("h3", undefined, "Built-in operations"));
        operations(one.body, preset.operations);
      }
    },
    unavailable(reason) {
      stage.replaceChildren();
      const only = card(stage, "presets", "Presets");
      showServiceState(only.badge, reason);
    },
  };
}
