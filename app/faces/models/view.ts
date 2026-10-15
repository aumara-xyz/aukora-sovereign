// SPDX-License-Identifier: AGPL-3.0-or-later
// The Models screen, three cards: the model in the slot and whether the node holds a key for it, the spend grant and what
// is left of it, and how the last reply's model identity stands. It prints what the broker reports and nothing more; there
// is no field for a key and no control that signs, raises, freezes or revokes a grant. A failed read empties all three.
import { card, count, explain, facts, make, mark, moment, note, since, usd } from "../general/kit.js";
import type { Card } from "../general/kit.js";
import type { LastReply, ModelSlot, ModelsReport, SpendGrant } from "./broker.js";

export interface ModelsView {
  show(report: ModelsReport, now: number): void;
  unavailable(reason: string): void;
}

const PROVIDERS = { deepseek: "DeepSeek", openrouter: "OpenRouter" } as const;
const OUTCOMES = {
  completed: "Completed.",
  cancelled: "Cancelled.",
  refused: "Refused.",
  unknown: "Unknown. The broker did not see how it ended.",
} as const;
const KEY_NOTE = "The key never reaches Auma or this page. The node's broker holds it and makes each call, and this page has no field for one.";
const GRANT_NOTE = "A grant is signed with your passkey over exact bytes. It sets how much can be spent, per call and in total, how many calls are allowed, and when it ends. This page cannot sign, raise, freeze or revoke one.";
const IDENTITY_NOTE = "These are three separate claims: what was asked for, what the provider said it was, and whether anything independent checked. A provider's report is evidence about a model, not proof of it.";

function pending(target: Card, text: string): void {
  target.body.replaceChildren();
  mark(target.badge, "unknown", "CHECKING");
  note(target.body, text, "lead");
}

function failed(target: Card, reason: string): void {
  target.body.replaceChildren();
  mark(target.badge, "unknown", "UNAVAILABLE");
  note(target.body, `${explain(reason)} Nothing here is shown as current.`, "lead");
}

function showModel(target: Card, slot: ModelSlot | null, keyPresent: boolean): void {
  target.body.replaceChildren();
  if (slot === null) {
    mark(target.badge, "attention", "NO MODEL");
    note(target.body, "No model is set. Auma cannot answer until the node has one.", "lead");
    facts(target.body)("Provider key").textContent = keyPresent ? "Held by the node." : "Not held.";
  } else {
    const row = facts(target.body);
    mark(target.badge, "ok", "MODEL SET");
    row("Model").textContent = slot.name;
    const origin = row("Source");
    if (slot.source.kind === "provider") {
      origin.textContent = `Hosted by ${PROVIDERS[slot.source.provider]}`;
    } else {
      origin.append("A model file on this node", make("div", "mono digest", slot.source.artifact));
    }
    row("Provider key").textContent = keyPresent ? "Held by the node."
      : slot.source.kind === "local" ? "Not needed for a local model."
        : "Not held. A hosted model cannot answer without one.";
  }
  note(target.body, KEY_NOTE);
}

function showGrant(target: Card, grant: SpendGrant | null, now: number): void {
  target.body.replaceChildren();
  if (grant === null) {
    mark(target.badge, "attention", "NO GRANT");
    note(target.body, "No spend grant is in place. The broker makes no paid model call without one.", "lead");
    note(target.body, GRANT_NOTE);
    return;
  }
  mark(target.badge, grant.frozen ? "failed" : "ok", grant.frozen ? "FROZEN" : "GRANT SET");
  if (grant.frozen) note(target.body, "The broker has frozen this grant.", "lead");
  const used = grant.spent + grant.reserved;
  const gauge = make("div", "gauge");
  const meter = make("meter");
  meter.min = 0;
  meter.max = grant.totalCap;
  meter.value = Math.min(used, grant.totalCap);
  meter.dataset.tone = used >= grant.totalCap ? "failed" : used / grant.totalCap >= 0.8 ? "attention" : "ok";
  meter.setAttribute("aria-label", "Part of the cap that is spent or held");
  const percent = Math.min(100, Math.floor((used / grant.totalCap) * 100));
  gauge.append(meter, make("p", "gauge-text", `${usd(used)} of ${usd(grant.totalCap)} used (${percent}%)${used > grant.totalCap ? ", over the cap" : ""}`));
  target.body.append(gauge);
  const row = facts(target.body);
  row("Spent").textContent = usd(grant.spent);
  row("Held for calls in flight").textContent = usd(grant.reserved);
  row("Left to spend").textContent = usd(Math.max(0, grant.totalCap - used));
  row("Most for one call").textContent = usd(grant.perRequestCap);
  row("Model calls").textContent = `${count(grant.requests)} of ${count(grant.maxRequests)}`;
  row("Price").textContent = `${perMillion(grant.promptPrice)} per million prompt tokens, ${perMillion(grant.completionPrice)} per million reply tokens`;
  const ends = moment(grant.expiresAt);
  row("Ends").textContent = ends === null ? "At a time this page cannot read." : `${ends} (${since(grant.expiresAt, now)}, by this browser's clock)`;
  note(target.body, GRANT_NOTE);
}

/** A price in millionths of a dollar per token is the same number of dollars per million tokens. */
function perMillion(microusdPerToken: number): string {
  const micro = microusdPerToken * 1_000_000;
  return Number.isSafeInteger(micro) ? usd(micro) : `${count(microusdPerToken)} millionths of a dollar a token`;
}

function showLast(target: Card, last: LastReply | null): void {
  target.body.replaceChildren();
  mark(target.badge, last === null ? "unknown" : "plain", last === null ? "NONE YET" : "RECORDED");
  if (last === null) {
    note(target.body, "No model reply has been recorded yet.", "lead");
    note(target.body, IDENTITY_NOTE);
    return;
  }
  const row = facts(target.body);
  row("Asked for").textContent = last.requested;
  row("Provider reported").textContent = last.reported ?? "Nothing reported.";
  row("Independently checked").textContent = last.verification.verified
    ? `Verified as ${last.verification.model} by ${last.verification.verifier}.` : "Not verified.";
  row("How it ended").textContent = OUTCOMES[last.outcome];
  row("Charged").textContent = `${usd(last.charged)}${last.costUnknown ? " (the real cost could not be determined)" : ""}`;
  note(target.body, IDENTITY_NOTE);
}

export function createModelsView(root: HTMLElement): ModelsView {
  const model = card(root, "model", "Model");
  const grant = card(root, "grant", "Spend grant");
  const last = card(root, "last", "Last reply");
  pending(model, "Reading the model route from the node.");
  pending(grant, "Reading the spend grant from the node.");
  pending(last, "Reading the last reply from the node.");
  return {
    show(report, now) {
      showModel(model, report.model, report.keyPresent);
      showGrant(grant, report.grant, now);
      showLast(last, report.last);
    },
    unavailable(reason) {
      for (const target of [model, grant, last]) failed(target, reason);
    },
  };
}
