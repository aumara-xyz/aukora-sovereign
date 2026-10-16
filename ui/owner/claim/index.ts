// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerDisposer, OwnerPane, OwnerPaneContext } from "../contracts.js";
import { claimBody, claimToken, httpsOrigin } from "./codec.js";
import type { ClaimMode } from "./codec.js";
import { consumeClaim } from "./transport.js";

export interface ClaimConfiguration {
  readonly ownerOrigin: string;
  readonly shellOrigin: string;
  readonly mode: ClaimMode;
  readonly initialToken?: string;
  // Trusted release composition continues inside the same owner frame.
  readonly joining: OwnerPane;
}

export interface ClaimService { mount(context: OwnerPaneContext): OwnerDisposer }

function frame(ownerOrigin: string, shellOrigin: string, context: OwnerPaneContext): void {
  if (!window.isSecureContext || location.origin !== ownerOrigin || context.shellOrigin !== shellOrigin
    || window.parent === window || window.top !== window.parent || context.route.pane !== "claim"
    || document.referrer !== `${shellOrigin}/`) {
    throw new Error("owner:frame-required");
  }
  if (context.signal.aborted) throw new DOMException("Claim closed", "AbortError");
}

export function createClaimService(configuration: ClaimConfiguration): ClaimService {
  const ownerOrigin = httpsOrigin(configuration.ownerOrigin);
  const shellOrigin = httpsOrigin(configuration.shellOrigin);
  const mode = configuration.mode;
  const joining = configuration.joining;
  let initialToken = configuration.initialToken ?? "";
  if (ownerOrigin === shellOrigin || !["invite-v2", "host-token-v1"].includes(mode)
    || typeof joining !== "function") throw new Error("invites:claim-configuration");
  return { mount(context) {
    frame(ownerOrigin, shellOrigin, context);
    const lifetime = new AbortController();
    let busy = false;
    let claimed = false;
    let entering = false;
    let continuation: OwnerDisposer | undefined;
    const form = document.createElement("form");
    form.className = "owner-claim";
    const title = document.createElement("h2");
    title.textContent = "Claim your node";
    const explanation = document.createElement("p");
    explanation.textContent = mode === "invite-v2"
      ? "Enter your node's claim link and the private secret you kept for this invite. Then use your two devices to join."
      : "Open your node with its claim link.";
    const tokenLabel = document.createElement("label");
    tokenLabel.textContent = "Node claim link or token";
    const token = document.createElement("input");
    token.type = "password";
    token.required = true;
    token.maxLength = 2048;
    token.autocomplete = "off";
    token.spellcheck = false;
    token.value = initialToken;
    initialToken = "";
    tokenLabel.append(token);
    const secretLabel = document.createElement("label");
    secretLabel.textContent = "Invite secret (64 lowercase hexadecimal characters)";
    const secret = document.createElement("input");
    secret.type = "password";
    secret.required = mode === "invite-v2";
    secret.maxLength = 64;
    secret.pattern = "[0-9a-f]{64}";
    secret.autocomplete = "off";
    secret.spellcheck = false;
    secretLabel.append(secret);
    const submit = document.createElement("button");
    submit.type = "submit";
    submit.textContent = "Claim node";
    const resume = document.createElement("button");
    resume.type = "button";
    resume.textContent = "Resume an opened setup session";
    const status = document.createElement("p");
    status.setAttribute("role", "status");
    const next = document.createElement("section");
    const back = document.createElement("button");
    back.type = "button";
    back.textContent = "Back to claim";
    back.hidden = true;
    form.append(title, explanation, tokenLabel);
    if (mode === "invite-v2") form.append(secretLabel);
    form.append(submit, resume, status);
    context.host.replaceChildren(form, next, back);

    function dispose(): void {
      if (lifetime.signal.aborted) return;
      lifetime.abort();
      token.value = "";
      secret.value = "";
      try { continuation?.(); } finally {
        context.signal.removeEventListener("abort", dispose);
        context.host.replaceChildren();
      }
    }

    async function enterJoining(): Promise<void> {
      if (entering || lifetime.signal.aborted) return;
      entering = true;
      submit.disabled = true;
      resume.disabled = true;
      token.value = "";
      secret.value = "";
      try {
        frame(ownerOrigin, shellOrigin, context);
        const cleanup = await joining({ ...context, host: next, signal: lifetime.signal });
        if (typeof cleanup !== "function") throw new Error("invites:joining-adapter");
        if (lifetime.signal.aborted) cleanup();
        else { continuation = cleanup; form.hidden = true; back.hidden = false; }
      } catch {
        if (!lifetime.signal.aborted) {
          status.textContent = claimed
            ? "The claim opened a setup session. Joining is unavailable; you can retry without sending the secret again."
            : "Joining could not resume. An authenticated setup session is required.";
          if (claimed) submit.textContent = "Continue joining";
          submit.disabled = false;
        }
      } finally { entering = false; resume.disabled = false; }
    }

    resume.addEventListener("click", () => {
      if (!busy) void enterJoining();
    }, { signal: lifetime.signal });
    back.addEventListener("click", () => {
      const cleanup = continuation;
      continuation = undefined;
      try { cleanup?.(); } finally {
        next.replaceChildren();
        form.hidden = false;
        back.hidden = true;
        submit.disabled = false;
        if (claimed) submit.textContent = "Continue joining";
      }
    }, { signal: lifetime.signal });

    form.addEventListener("submit", event => {
      event.preventDefault();
      if (busy || lifetime.signal.aborted) return;
      if (claimed) { void enterJoining(); return; }
      let body: string;
      try {
        frame(ownerOrigin, shellOrigin, context);
        body = claimBody(mode, claimToken(token.value, shellOrigin), secret.value);
      } catch {
        status.textContent = "Use the claim link for this node and the exact invite secret. Nothing was sent.";
        return;
      }
      token.value = "";
      secret.value = "";
      busy = true;
      submit.disabled = true;
      resume.disabled = true;
      status.textContent = "Claiming this node…";
      void consumeClaim(body, lifetime.signal).then(async () => {
        if (lifetime.signal.aborted) return;
        claimed = true;
        token.disabled = true;
        token.required = false;
        secret.disabled = true;
        secret.required = false;
        status.textContent = mode === "invite-v2" ? "Setup opened. Continue joining."
          : "Setup opened. Create your passkey.";
        await enterJoining();
      }).catch(() => {
        if (!lifetime.signal.aborted) {
          status.textContent = "The node has not confirmed this claim. It may have been consumed if the reply was interrupted. Re-enter the private claim details to retry.";
        }
      }).finally(() => {
        busy = false;
        if (!lifetime.signal.aborted && !form.hidden) { submit.disabled = false; resume.disabled = false; }
      });
    }, { signal: lifetime.signal });
    context.signal.addEventListener("abort", dispose, { once: true });
    return dispose;
  } };
}
