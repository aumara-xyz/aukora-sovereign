// SPDX-License-Identifier: AGPL-3.0-or-later
import type {
  ApprovalPaneService, OwnerDisposer, OwnerPaneContext, PasskeyPaneService, SupervisorCards,
} from "../contracts.js";
import { domainDigest, parseAuthorization, parseCard, refuse, verifyCommitments } from "./codec.js";
import type { Authorization } from "./codec.js";
import { renderAuthorization, renderCard } from "./render.js";

export interface SupervisorApprovalActions {
  // Only selectors and the opaque assertion cross this port; C5 bytes stay private.
  submitAuthorization(
    proposalId: string,
    action: Authorization["op"],
    assertion: Uint8Array,
    signal: AbortSignal,
  ): Promise<void>;
}

function errorCode(error: unknown): string {
  return error instanceof Error && /^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$/.test(error.message)
    ? error.message : "card:unavailable";
}

export class ApprovalCards implements ApprovalPaneService {
  private readonly actions: SupervisorApprovalActions;

  constructor(actions: SupervisorApprovalActions) {
    this.actions = actions;
  }

  mount(context: OwnerPaneContext, supervisor: SupervisorCards, passkey: PasskeyPaneService): OwnerDisposer {
    if (context.route.pane !== "approval" || !/^[0-9a-f]{32}$/.test(context.route.proposalId)) refuse("route");
    const proposalId = context.route.proposalId;
    const lifetime = new AbortController();
    const signal = lifetime.signal;
    const document = context.host.ownerDocument;
    const panel = document.createElement("section");
    panel.className = "approval-review";
    const stylesheet = document.createElement("link");
    stylesheet.rel = "stylesheet";
    stylesheet.href = new URL("./cards.css", import.meta.url).href;
    panel.append(stylesheet);
    const status = document.createElement("p");
    status.setAttribute("role", "status");
    status.textContent = "Loading the proposal from the supervisor.";
    panel.append(status);
    context.host.replaceChildren(panel);
    let disposed = false;
    let started = false;

    const dispose = (): void => {
      if (disposed) return;
      disposed = true;
      lifetime.abort();
      context.signal.removeEventListener("abort", dispose);
      panel.remove();
    };
    context.signal.addEventListener("abort", dispose, { once: true });
    if (context.signal.aborted) { dispose(); return dispose; }

    const showFailure = (error: unknown): void => {
      if (signal.aborted) return;
      status.setAttribute("role", "alert");
      status.textContent = errorCode(error);
    };

    const load = async (): Promise<void> => {
      const loaded = await supervisor.loadByProposalId(proposalId, signal);
      if (signal.aborted) return;
      if (loaded.proposalId !== proposalId || !(loaded.canonicalCard instanceof Uint8Array)
        || !(loaded.canonicalAuthorization instanceof Uint8Array)) refuse("supervisor-response");
      const cardBytes = new Uint8Array(loaded.canonicalCard);
      const authorizationBytes = new Uint8Array(loaded.canonicalAuthorization);
      const card = parseCard(cardBytes);
      const authorization = parseAuthorization(authorizationBytes, proposalId);
      await verifyCommitments(cardBytes, authorization);
      const challenge = await domainDigest("aukora:owner-authorization:v1", authorizationBytes);
      if (signal.aborted) return;
      const explanation = document.createElement("p");
      explanation.textContent = "Strings show quotes and visible escapes, including spaces and Unicode. The passkey authorizes these exact card and operation commitments.";
      const controls = document.createElement("div");
      const authorize = document.createElement("button");
      authorize.type = "button";
      const labels = {
        apply: "Approve application", retire: "Approve retirement", release: "Approve release",
        grant: "Approve grant", permission: "Approve permission",
      };
      authorize.textContent = labels[authorization.op];
      const cancel = document.createElement("button");
      cancel.type = "button";
      cancel.textContent = "Cancel";
      controls.append(authorize, cancel);
      panel.append(explanation, renderAuthorization(document, authorization), renderCard(document, card), controls);
      status.textContent = "Card and operation commitments match the supervisor's authorization. Review every field before using your passkey.";

      const approve = async (): Promise<void> => {
        if (started || signal.aborted) return;
        started = true;
        authorize.disabled = true;
        cancel.disabled = true;
        status.textContent = "Waiting for your passkey.";
        try {
          const assertion = await passkey.assertExact(new Uint8Array(challenge), context.shellOrigin, signal);
          if (signal.aborted) return;
          if (!(assertion instanceof Uint8Array) || assertion.length === 0) refuse("assertion-empty");
          status.textContent = "Submitting your assertion to the supervisor.";
          await this.actions.submitAuthorization(proposalId, authorization.op, new Uint8Array(assertion), signal);
          if (signal.aborted) return;
          status.textContent = "The supervisor accepted your authorization.";
          context.complete();
        } catch (error) {
          showFailure(error);
          if (!signal.aborted) {
            cancel.disabled = false;
            cancel.textContent = "Close review";
          }
        }
      };
      authorize.addEventListener("click", () => { void approve(); }, { signal });
      cancel.addEventListener("click", () => {
        authorize.disabled = true;
        cancel.disabled = true;
        status.textContent = "Review cancelled. Use Close to return to the app.";
        lifetime.abort();
      }, { signal });
    };
    void load().catch(showFailure);
    return dispose;
  }
}

export function createApprovalPane(actions: SupervisorApprovalActions): ApprovalPaneService {
  return new ApprovalCards(actions);
}

export { renderCard, visibleJson } from "./render.js";
export type { ApprovalCard, Authorization, JsonValue } from "./codec.js";
