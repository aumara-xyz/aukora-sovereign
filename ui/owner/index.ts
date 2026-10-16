// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountOwner } from "./router.js";
import { configuration, takeClaimFragment } from "./bootstrap.js";
import { createOnboarding } from "./onboarding.js";
export { mountOwner } from "./router.js";
export { OWNER_PROTOCOL, PHRASE_ENTROPY_BITS } from "./contracts.js";
export type {
  OwnerModules, OwnerPane, OwnerPaneContext, OwnerRoute, OwnerWitness,
  PasskeyPaneService, PhrasePaneService, ApprovalPaneService, SupervisorCards,
} from "./contracts.js";

const root = document.getElementById("owner-root");
if (root) {
  void (async () => {
    const claim = takeClaimFragment();
    const config = await configuration();
    const onboarding = createOnboarding(config, claim);
    mountOwner(root, {
      shellOrigin: config.shellOrigin,
      panes: { claim: onboarding, passkey: onboarding, phrase: onboarding },
      witness: { async observeVisit() { return { state: "alarm", reason: "unavailable" }; } },
    });
  })().catch(error => {
    root.textContent = error instanceof Error && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(error.message)
      ? error.message : "owner:startup-refused";
    root.setAttribute("role", "alert");
  });
}
