// SPDX-License-Identifier: AGPL-3.0-or-later
// The General screen. The first card is the release the node reports serving, the only part that comes from the node; a
// failed read empties it and says so. The other cards are plain facts about this release (language, appearance, the
// limits the app keeps, how a setting changes) and are printed whether or not the node answers, because none of them is a
// claim about the node. The owner slider is mounted separately and reads the door's current policy.
import { FD4_LIMITS, MAX_RPC_BYTES, RPC_DEADLINE_MS } from "../../core/index.js";
import { showServiceState } from "../../core/service-state.js";
import { card, count, facts, groups, make, mark, note, plural } from "./kit.js";
import type { ReleaseReport } from "./release.js";

export interface GeneralView {
  show(report: ReleaseReport): void;
  unavailable(reason: unknown): void;
}

export function createGeneralView(root: HTMLElement): GeneralView {
  const release = card(root, "release", "Release the node serves");
  const lead = note(release.body, "Reading the release from the node.", "lead");
  const field = facts(release.body);
  const digest = field("Release digest");
  digest.classList.add("mono", "digest");
  digest.textContent = "—";
  const assets = field("Files in the release");
  assets.textContent = "—";
  mark(release.badge, "unknown", "CHECKING");

  const language = card(root, "language", "Language and appearance");
  const look = facts(language.body);
  look("Language").textContent = "English. This release has one set of words, so there is nothing to switch.";
  look("Appearance").textContent = "Dark. The colours are the design tokens pinned with this release; there is no light theme.";
  look("Lanes").textContent = "Threads, App, and Apps and System share the window in thirds. Choose the split with the Lanes control at the top; on a phone one lane shows at a time.";

  const limits = card(root, "limits", "Limits this release keeps");
  note(limits.body, "Past one of these bounds a request is refused or dropped.", "lead");
  const bound = facts(limits.body);
  bound("A message to Auma").textContent = `${count(FD4_LIMITS.textBytes)} bytes at most`;
  bound("A session title").textContent = `${count(FD4_LIMITS.titleBytes)} bytes at most`;
  bound("One page of sessions or entries").textContent = `${count(FD4_LIMITS.pageItems)} at most`;
  bound("One reply from the node").textContent = `${count(MAX_RPC_BYTES)} bytes at most`;
  bound("Waiting for a reply").textContent = `${plural(RPC_DEADLINE_MS / 1_000, "second", "seconds")}, then the request is dropped`;

  const change = card(root, "change", "How settings change");
  change.body.append(make("p", "lead",
    "The Laya slider above tightens immediately; loosening requires your passkey in the owner pane. Other protected changes are proposed as exact bytes for your passkey to approve."));

  return {
    show(report) {
      release.body.hidden = false;
      mark(release.badge, "ok", "REPORTED");
      lead.textContent = "The node reports serving this release. The digest identifies the exact set of files the app was built from.";
      digest.textContent = groups(report.manifestSha256);
      assets.textContent = plural(report.assets, "file", "files");
    },
    unavailable(reason) {
      showServiceState(release.badge, reason);
      release.body.hidden = true;
      lead.textContent = "";
      digest.textContent = "—";
      assets.textContent = "—";
    },
  };
}
