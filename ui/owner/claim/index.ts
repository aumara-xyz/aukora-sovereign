// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerDisposer, OwnerPane, OwnerPaneContext } from "../contracts.js";
import { claimBody, claimToken, httpsOrigin } from "./codec.js";
import type { ClaimMode } from "./codec.js";
import { consumeClaim } from "./transport.js";
import { brand } from "../brand.js";
import { actionButton, iconTile } from "../primitives.js";
import { renderBrowserAdvice } from "../passkey/browser.js";

export interface ClaimConfiguration {
  readonly ownerOrigin: string;
  readonly shellOrigin: string;
  readonly mode: ClaimMode;
  readonly initialToken?: string;
  // Trusted release composition continues inside the same owner frame.
  readonly joining: OwnerPane;
  readonly signin?: OwnerPane;
  // "I already have a Sovereign ID": the onboarding pane reads this after the passkey.
  readonly intent?: { sovereignId: boolean };
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
    const stage = document.createElement("div");
    stage.className = "claim-stage";
    // The opening portal is the primitives' PortalButton (tone mint): icon tile, title, one-line summary, "+" / "−".
    const portal = document.createElement("section");
    portal.className = "claim-portal ak-portal ak-tone-mint";
    portal.dataset.open = "no";
    const portalButton = document.createElement("button");
    portalButton.type = "button";
    portalButton.className = "claim-portal-button ak-portal__head";
    portalButton.setAttribute("aria-expanded", "false");
    portalButton.setAttribute("aria-controls", "claim-portal-content");
    const portalCopy = document.createElement("span");
    portalCopy.className = "ak-portal__copy";
    const portalTitle = document.createElement("span");
    portalTitle.className = "ak-portal__title";
    portalTitle.textContent = "Exit the Matrix";
    const portalSummary = document.createElement("span");
    portalSummary.className = "ak-portal__summary";
    portalSummary.textContent = "Claim your node";
    portalCopy.append(portalTitle, portalSummary);
    const portalEnd = document.createElement("span");
    portalEnd.className = "ak-portal__end";
    const depth = document.createElement("span");
    depth.className = "ak-expander";
    depth.textContent = "+";
    depth.setAttribute("aria-hidden", "true");
    portalEnd.append(depth);
    portalButton.append(iconTile("door"), portalCopy, portalEnd);
    const portalContent = document.createElement("div");
    portalContent.id = "claim-portal-content";
    portalContent.className = "claim-portal-content";
    portalContent.inert = true;
    portalContent.setAttribute("aria-hidden", "true");
    const portalBody = document.createElement("div");
    portalBody.className = "claim-portal-body ak-portal__body";
    const explanation = document.createElement("p");
    explanation.className = "owner-detail";
    const tokenLabel = document.createElement("label");
    tokenLabel.className = "owner-input";
    tokenLabel.textContent = "Claim code or link";
    const token = document.createElement("input");
    token.type = "password";
    token.required = true;
    token.maxLength = 2048;
    token.autocomplete = "off";
    token.spellcheck = false;
    token.placeholder = "Claim code or link";
    token.setAttribute("autocapitalize", "off");
    token.value = initialToken;
    initialToken = "";
    tokenLabel.append(token);
    // A claim link already carries the code: the field stays out of sight and the portal says so in one line.
    const prefilled = token.value !== "";
    const secretLabel = document.createElement("label");
    secretLabel.className = "owner-input";
    secretLabel.textContent = "Invite secret";
    const secret = document.createElement("input");
    secret.type = "password";
    secret.required = mode === "invite-v2";
    secret.maxLength = 64;
    secret.pattern = "[0-9a-f]{64}";
    secret.autocomplete = "off";
    secret.spellcheck = false;
    secret.placeholder = "Invite secret";
    secret.setAttribute("autocapitalize", "off");
    secretLabel.append(secret);
    // The key from a claim link is already in: say so with a check and a masked code (only its last four characters), never the code.
    const keyIsIn = (): HTMLElement[] => {
      const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      svg.setAttribute("viewBox", "0 0 16 16");
      svg.setAttribute("class", "claim-check");
      svg.setAttribute("aria-hidden", "true");
      const tick = document.createElementNS("http://www.w3.org/2000/svg", "path");
      tick.setAttribute("d", "M3.2 8.6l3.1 3.1 6.5-7.2");
      tick.setAttribute("fill", "none");
      svg.append(tick);
      const line = document.createElement("span");
      line.className = "claim-key-line";
      line.append(svg, document.createTextNode("Your claim key is in"));
      const tail = token.value.replace(/[^A-Za-z0-9]/g, "").slice(-4).toUpperCase().padStart(4, "•");
      const mask = document.createElement("span");
      mask.className = "claim-mask";
      mask.textContent = `••••-••••-${tail}`;
      mask.setAttribute("aria-label", "ends in " + tail);
      return [line, mask];
    };
    const showDetail = (): void => {
      tokenLabel.hidden = prefilled && !retyping;
      const extra = configuration.intent?.sovereignId ? "After your passkey, bring your Sovereign ID." : "";
      if (!tokenLabel.hidden) {
        explanation.textContent = (mode === "invite-v2" ? "Enter your claim link and private invite secret." : "Enter your claim code or link.")
          + (extra ? ` ${extra}` : "");
        return;
      }
      explanation.replaceChildren(...keyIsIn());
      if (extra) explanation.append(document.createElement("br"), document.createTextNode(extra));
    };
    let retyping = false;
    // The owner frame is sandboxed without allow-forms, so a form submission is dropped before any submit event fires;
    // the button and Enter call the handler directly (found on t2 at 5cacca0: "Claim node" did nothing).
    const begin = actionButton("Begin your journey", "mint");
    const submit = begin.button;
    submit.classList.add("primary");
    const submitLabel = submit.querySelector<HTMLElement>(".ak-portal__title")!;
    const signin = document.createElement("button");
    signin.type = "button";
    signin.className = "quiet-link";
    signin.textContent = "Recover my account";
    const status = document.createElement("p");
    status.className = "owner-status";
    status.setAttribute("role", "status");
    renderBrowserAdvice(status);
    const next = document.createElement("section");
    next.className = "claim-continuation";
    next.hidden = true;
    const inputs = document.createElement("div");
    inputs.className = "owner-content";
    inputs.append(tokenLabel);
    if (mode === "invite-v2") inputs.append(secretLabel);
    const controls = document.createElement("div");
    controls.className = "owner-controls";
    controls.append(begin.frame);
    const foot = document.createElement("div");
    foot.className = "claim-foot";
    if (configuration.signin) foot.append(signin);
    const sovereign = document.createElement("button");
    sovereign.type = "button";
    sovereign.className = "quiet-link";
    sovereign.textContent = "I already have a Sovereign ID";
    if (configuration.intent) foot.append(sovereign);
    const textBlock = document.createElement("div");
    textBlock.className = "owner-text";
    textBlock.append(explanation);
    portalBody.append(textBlock, inputs, controls);
    portalContent.append(portalBody);
    portal.append(portalButton, portalContent);
    stage.append(portal, status);
    form.append(stage, foot);
    context.host.replaceChildren(form, next);
    showDetail();
    brand.show("hero");

    function openPortal(open: boolean): void {
      portal.dataset.open = open ? "yes" : "no";
      depth.textContent = open ? "−" : "+";
      portalButton.setAttribute("aria-expanded", String(open));
      portalContent.setAttribute("aria-hidden", String(!open));
      portalContent.inert = !open;
      if (open) (tokenLabel.hidden ? submit : token).focus({ preventScroll: true });
    }

    sovereign.addEventListener("click", () => {
      if (busy || entering || !configuration.intent) return;
      configuration.intent.sovereignId = !configuration.intent.sovereignId;
      sovereign.textContent = configuration.intent.sovereignId ? "Start with a new identity instead" : "I already have a Sovereign ID";
      showDetail();
      openPortal(true);
    }, { signal: lifetime.signal });

    portalButton.addEventListener("click", () => {
      if (!busy && !entering) openPortal(portal.dataset.open !== "yes");
    }, { signal: lifetime.signal });

    async function dissolve(): Promise<void> {
      form.classList.add("claim-leaving");
      openPortal(false);
      if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      await new Promise<void>(resolve => {
        const finish = () => {
          clearTimeout(timer);
          lifetime.signal.removeEventListener("abort", finish);
          resolve();
        };
        const timer = setTimeout(finish, 780);
        lifetime.signal.addEventListener("abort", finish, { once: true });
      });
    }

    function dispose(): void {
      if (lifetime.signal.aborted) return;
      lifetime.abort();
      token.value = "";
      secret.value = "";
      try { continuation?.(); } finally {
        brand.hide();
        context.signal.removeEventListener("abort", dispose);
        context.host.replaceChildren();
      }
    }

    async function enterJoining(pane: OwnerPane = joining): Promise<void> {
      if (entering || lifetime.signal.aborted) return;
      entering = true;
      submit.disabled = true;
      signin.disabled = true;
      sovereign.disabled = true;
      portalButton.disabled = true;
      token.value = "";
      secret.value = "";
      try {
        frame(ownerOrigin, shellOrigin, context);
        const cleanup = await pane({ ...context, host: next, signal: lifetime.signal });
        if (typeof cleanup !== "function") throw new Error("invites:joining-adapter");
        if (lifetime.signal.aborted) cleanup();
        else {
          continuation = cleanup;
          await dissolve();
          if (!lifetime.signal.aborted) {
            form.hidden = true;
            next.hidden = false;
            next.querySelector<HTMLElement>("h2[tabindex]")?.focus({ preventScroll: true });
          }
        }
      } catch {
        if (!lifetime.signal.aborted) {
          status.textContent = claimed
            ? "Setup opened. Retry without sending the claim again."
            : "Sign-in is not available yet. Try again shortly.";
          if (claimed) submitLabel.textContent = "Continue setup";
          submit.disabled = false;
          form.classList.remove("claim-leaving");
          openPortal(true);
        }
      } finally {
        entering = false;
        signin.disabled = false;
        sovereign.disabled = false;
        portalButton.disabled = false;
      }
    }

    signin.addEventListener("click", () => {
      if (!busy && configuration.signin) void enterJoining(configuration.signin);
    }, { signal: lifetime.signal });
    const onSubmit = (event: Event) => {
      event.preventDefault();
      if (busy || lifetime.signal.aborted) return;
      if (claimed) { void enterJoining(); return; }
      let body: string;
      try {
        frame(ownerOrigin, shellOrigin, context);
        body = claimBody(mode, claimToken(token.value, shellOrigin), secret.value);
      } catch {
        status.textContent = mode === "invite-v2" ? "Use this node’s claim link and exact invite secret."
          : "Use this node’s exact claim code or link.";
        return;
      }
      token.value = "";
      secret.value = "";
      busy = true;
      submit.disabled = true;
      signin.disabled = true;
      sovereign.disabled = true;
      portalButton.disabled = true;
      status.textContent = "";
      brand.working(true);
      void consumeClaim(body, lifetime.signal).then(async () => {
        if (lifetime.signal.aborted) return;
        claimed = true;
        token.disabled = true;
        token.required = false;
        secret.disabled = true;
        secret.required = false;
        await enterJoining();
      }).catch(async error => {
        if (!lifetime.signal.aborted) {
          if (error instanceof Error && error.message === "aumlok:claim-spent" && configuration.signin) {
            await enterJoining(configuration.signin);
          } else if (!renderBrowserAdvice(status, error)) {
            status.textContent = "That did not open. Check your claim link and try again.";
            retyping = true;
            showDetail();
          }
        }
      }).finally(() => {
        busy = false;
        brand.working(false);
        if (!lifetime.signal.aborted && !form.hidden) {
          submit.disabled = false;
          signin.disabled = false;
          sovereign.disabled = false;
          portalButton.disabled = false;
        }
      });
    };
    submit.addEventListener("click", onSubmit, { signal: lifetime.signal });
    for (const field of [token, secret]) {
      field.addEventListener("keydown", event => {
        if (event.key === "Enter") onSubmit(event);
      }, { signal: lifetime.signal });
    }
    context.signal.addEventListener("abort", dispose, { once: true });
    return dispose;
  } };
}
