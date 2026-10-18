// SPDX-License-Identifier: AGPL-3.0-or-later
import type {
  ApprovalPaneService, OwnerDisposer, OwnerPaneContext, PasskeyPaneService, SupervisorCards,
} from "../contracts.js";
import { domainDigest, parseAuthorization, parseCard, refuse, verifyCommitments } from "./codec.js";
import type { Authorization } from "./codec.js";
import { renderAuthorization, renderCard } from "./render.js";
import { createApprovalTransport } from "./transport.js";
import type { ApprovalServiceOptions } from "./transport.js";
import { ownerIcon } from "../icons.js";
import { abortScope, checkAbort } from "../abort.js";
import { renderBrowserAdvice } from "../passkey/browser.js";
import { closedState, retryTarget } from "./state.js";

export interface SupervisorApprovalActions {
  submitAuthorization(proposalId: string, action: Authorization["op"], assertion: Uint8Array, signal: AbortSignal): Promise<void>;
  decline(proposalId: string, signal: AbortSignal): Promise<void>;
  again(proposalId: string, signal: AbortSignal): Promise<string>;
}

function failure(error: unknown): string {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "Passkey cancelled or expired. Review again when ready.";
  }
  if (error instanceof Error && /(?:spent|expired|stale|conflict|already|closed|not-pending)/.test(error.message)) {
    return "This approval is no longer available.";
  }
  return "Approval unavailable. Review again to check its current state.";
}

function needsReview(error: unknown): boolean {
  return error instanceof Error
    && /^[a-z][a-z0-9_-]*:(?:review-required|ceremony-expired)$/.test(error.message);
}

export class ApprovalCards implements ApprovalPaneService {
  private readonly actions: SupervisorApprovalActions;

  constructor(actions: SupervisorApprovalActions) { this.actions = actions; }

  mount(context: OwnerPaneContext, supervisor: SupervisorCards, passkey: PasskeyPaneService): OwnerDisposer {
    if (context.route.pane !== "approval" || !/^[0-9a-f]{32}$/.test(context.route.proposalId)) refuse("route");
    const proposalId = context.route.proposalId;
    const lifetime = new AbortController();
    const signal = lifetime.signal;
    const document = context.host.ownerDocument;
    const review = document.createElement("section");
    // The stage: the card centred like a portal popping open; the dim over the whole site is the shell's backdrop.
    review.className = "approval-review approval-stage";
    const stylesheet = document.createElement("link");
    stylesheet.rel = "stylesheet";
    stylesheet.href = new URL("./cards.css", import.meta.url).href;
    const status = document.createElement("p");
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "ak-action ak-tone-blue";
    retry.textContent = "Review again";
    retry.hidden = true;
    const again = document.createElement("button");
    again.type = "button";
    again.className = "ak-action ak-tone-blue approval-again";
    again.textContent = "Ask again";
    again.hidden = true;
    status.setAttribute("role", "status");
    status.textContent = "Loading approval…";
    review.append(stylesheet, status, retry, again);
    context.host.replaceChildren(review);
    let disposed = false;
    let started = false;
    let loading = false;
    let renewed = false;

    const dispose = (): void => {
      if (disposed) return;
      disposed = true;
      lifetime.abort();
      context.signal.removeEventListener("abort", dispose);
      review.remove();
    };
    context.signal.addEventListener("abort", dispose, { once: true });
    if (context.signal.aborted) { dispose(); return dispose; }
    const showFailure = (error: unknown): void => {
      if (signal.aborted) return;
      const closed = closedState(error);
      if (closed) {
        review.replaceChildren(stylesheet, status, again);
        status.setAttribute("role", "status");
        status.classList.remove("owner-status");
        status.textContent = closed.message;
        again.hidden = !closed.again;
        again.disabled = false;
        if (closed.again) again.focus();
        return;
      }
      status.setAttribute("role", "alert");
      if (!renderBrowserAdvice(status, error)) {
        status.classList.remove("owner-status");
        status.textContent = failure(error);
      }
      retry.hidden = false;
      retry.focus();
    };

    const recover = async (error: unknown): Promise<void> => {
      if (signal.aborted) return;
      if (!renewed && needsReview(error)) {
        renewed = true;
        await load(true).catch(showFailure);
      } else showFailure(error);
    };

    const load = async (refresh = false): Promise<void> => {
      if (loading || signal.aborted) return;
      loading = true;
      started = true;
      retry.hidden = true;
      retry.disabled = true;
      review.replaceChildren(stylesheet, status, retry, again);
      again.hidden = true;
      status.setAttribute("role", "status");
      status.classList.remove("owner-status");
      status.classList.toggle("approval-renewed", refresh);
      status.textContent = refresh ? "Renewing review…" : "Loading approval…";
      try {
        const loaded = await supervisor.loadByProposalId(proposalId, signal);
        checkAbort(signal);
        if (loaded.proposalId !== proposalId || !(loaded.canonicalCard instanceof Uint8Array)
          || !(loaded.canonicalAuthorization instanceof Uint8Array)) refuse("response");
        const timeoutMs = loaded.relativeTimeoutMs;
        if (typeof timeoutMs !== "number" || !Number.isSafeInteger(timeoutMs)
          || timeoutMs <= 0 || timeoutMs > 300_000) refuse("ceremony-expired");
        const expires = performance.now() + timeoutMs;
        const cardBytes = new Uint8Array(loaded.canonicalCard);
        const authBytes = new Uint8Array(loaded.canonicalAuthorization);
        const card = parseCard(cardBytes);
        const auth = parseAuthorization(authBytes, proposalId);
        await verifyCommitments(cardBytes, auth);
        const challenge = await domainDigest("aukora:owner-authorization:v1", authBytes);
        checkAbort(signal);
        const cardView = renderCard(document, card, { target: auth.target, op: auth.op });
        const body = cardView.querySelector<HTMLElement>(".approval-body");
        if (!body) refuse("render");
        // The SHA-256 of the exact new bytes, first and whole: the passkey signs an authorization naming it.
        const digestLabel = document.createElement("p");
        digestLabel.className = "ak-label";
        digestLabel.textContent = "Exact bytes · SHA-256";
        const digest = document.createElement("dl");
        digest.className = "ak-fields approval-digest";
        const digestKey = document.createElement("dt");
        digestKey.textContent = "new_sha256";
        const digestValue = document.createElement("dd");
        const digestCode = document.createElement("code");
        digestCode.textContent = auth.new_sha256;
        digestValue.append(digestCode);
        digest.append(digestKey, digestValue);
        body.prepend(digestLabel, digest);
        const authorize = document.createElement("button");
        authorize.type = "button";
        // Unmistakable: the card's tone, ringed as an opened portal, with the owner mark and the passkey cue.
        authorize.className = `ak-action ${card.risk === "critical" ? "ak-tone-red" : "ak-tone-blue"} approval-passkey`;
        const labels = { apply: "Approve", retire: "Retire", release: "Approve release",
          grant: "Approve grant", permission: "Approve permission" };
        const actionLabel = document.createElement("span");
        actionLabel.textContent = labels[auth.op];
        const passkeyCue = document.createElement("small");
        passkeyCue.textContent = "Touch ID / passkey";
        authorize.append(ownerIcon("owner"), actionLabel, passkeyCue);
        const decline = document.createElement("button");
        decline.type = "button";
        decline.className = "ak-action ak-tone-muted approval-decline";
        decline.textContent = "Decline";
        const controls = document.createElement("div");
        controls.className = "ak-actionrow approval-actions";
        controls.append(decline, authorize);
        body.append(renderAuthorization(document, auth), controls);
        review.append(cardView);
        if (refresh) {
          const message = document.createElement("span");
          message.textContent = "Review renewed. Check the card, then approve.";
          status.replaceChildren(ownerIcon("owner"), message);
        } else status.textContent = "Review the exact bytes, then use your passkey.";
        started = false;
        cardView.querySelector<HTMLElement>(".approval-summary")?.focus();
        authorize.addEventListener("click", () => {
          if (started || loading || signal.aborted) return;
          started = true;
          authorize.disabled = true;
          status.textContent = "Waiting for your passkey…";
          void (async () => {
            const remaining = Math.floor(expires - performance.now());
            if (remaining <= 0 || remaining > 300_000) refuse("ceremony-expired");
            const ceremony = abortScope(signal, remaining);
            try {
              const assertion = await passkey.assertExact(new Uint8Array(challenge), context.shellOrigin,
                ceremony.signal, remaining);
              checkAbort(ceremony.signal);
              if (!(assertion instanceof Uint8Array) || assertion.length === 0) refuse("assertion-empty");
              status.textContent = "Applying approval…";
              await this.actions.submitAuthorization(proposalId, auth.op, new Uint8Array(assertion), ceremony.signal);
              checkAbort(signal);
              status.textContent = "Approved.";
              context.complete();
            } catch (error) {
              if (!signal.aborted && ceremony.signal.aborted) refuse("ceremony-expired");
              throw error;
            } finally { ceremony.dispose(); }
          })().catch(recover);
        }, { signal });
        decline.addEventListener("click", () => {
          if (started || loading || signal.aborted) return;
          started = true;
          decline.disabled = true;
          authorize.disabled = true;
          status.textContent = "Declining…";
          void (async () => {
            await this.actions.decline(proposalId, signal);
            checkAbort(signal);
            // A deliberate no. Supported supervisor requests can be asked for again here or under Approvals.
            review.replaceChildren(stylesheet, status, again);
            status.textContent = retryTarget(auth.target) ? "Declined. Nothing changes until you ask again." : "Declined.";
            again.hidden = !retryTarget(auth.target);
            again.disabled = false;
          })().catch(error => { started = false; decline.disabled = false; authorize.disabled = false; showFailure(error); });
        }, { signal });
      } finally { loading = false; retry.disabled = false; }
    };
    retry.addEventListener("click", () => { void load().catch(recover); }, { signal });
    again.addEventListener("click", () => {
      if (signal.aborted || again.disabled) return;
      again.disabled = true;
      status.setAttribute("role", "status");
      status.textContent = "Asking again…";
      void (async () => {
        await this.actions.again(proposalId, signal);
        checkAbort(signal);
        status.textContent = "Asked again. The new card opens next.";
        again.hidden = true;
        context.complete();
      })().catch(error => {
        if (signal.aborted) return;
        again.hidden = true;
        status.setAttribute("role", "alert");
        status.textContent = failure(error);
        retry.hidden = false;
      });
    }, { signal });
    void load().catch(recover);
    return dispose;
  }
}

export function createApprovalPane(actions: SupervisorApprovalActions): ApprovalPaneService {
  return new ApprovalCards(actions);
}

export function createApprovalServices(options: ApprovalServiceOptions = {}): {
  readonly approval: ApprovalPaneService; readonly supervisor: SupervisorCards;
} {
  const transport = createApprovalTransport(options);
  return { approval: new ApprovalCards(transport), supervisor: transport };
}

export { renderCard, visibleJson } from "./render.js";
export type { ApprovalCard, Authorization, JsonValue } from "./codec.js";
export type { ApprovalRequest, ApprovalServiceOptions } from "./transport.js";
