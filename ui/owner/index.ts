// SPDX-License-Identifier: AGPL-3.0-or-later
import { mountOwner } from "./router.js";
import { configuration, takeClaimFragment } from "./bootstrap.js";
import { createOnboarding } from "./onboarding.js";
import { createClaimService } from "./claim/index.js";
import { createLivePhraseService } from "./phrase/index.js";
import { createApprovalServices } from "./cards/index.js";
import { createPasskeyService } from "./passkey/index.js";
import { disabledOwnerWitness, witnessPane } from "./witness/index.js";
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
    const onboarding = createOnboarding(config, "");
    const joining = createOnboarding(config, "", "enrol");
    const claims = createClaimService({ ...config, mode: "host-token-v1", initialToken: claim,
      joining: context => joining({ ...context, route: { pane: "passkey" } }),
      signin: context => onboarding({ ...context, route: { pane: "passkey" } }) });
    const refresh = createLivePhraseService(config);
    const { approval, supervisor } = createApprovalServices();
    const passkey = createPasskeyService({ ...config, ceremonies: {
      async current() { throw new Error("owner:unknown-operation"); },
      async advance() { throw new Error("owner:unknown-operation"); },
    } });
    const witness = disabledOwnerWitness();
    mountOwner(root, {
      shellOrigin: config.shellOrigin,
      panes: { claim: context => claims.mount(context), passkey: onboarding,
        phrase: context => context.route.pane === "phrase" && context.route.refresh
          ? refresh.mount(context) : onboarding(context),
        approval: context => approval.mount(context, supervisor, passkey),
        witness: witnessPane(witness) },
      witness,
    });
  })().catch(() => {
    root.textContent = "Owner services could not open. Close this pane and try again.";
    root.setAttribute("role", "alert");
  });
}
