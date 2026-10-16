// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerConfiguration } from "./bootstrap.js";
import type { OwnerPane, OwnerPaneContext } from "./contracts.js";
import { createPasskeyService } from "./passkey/index.js";
import { claimToken } from "./claim/codec.js";
import { consumeClaim } from "./claim/transport.js";
import { deadline, exact, handle, options, post, state, text } from "./transport.js";
import type { Options, RecordValue } from "./transport.js";
import { loadAumlok } from "./aumlok.js";
import { ownerIcon } from "./icons.js";
import { explainOwnerError, phraseAcknowledgement, phraseInputs, renderPhrase } from "./phrase-layout.js";

const ICONS = { claim: "owner", passkey: "aumlok", phrase: "identity", signin: "surface" } as const;

function element<K extends keyof HTMLElementTagNameMap>(tag: K, content = "", className = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = content;
  node.className = className;
  return node;
}

export function createOnboarding(
  config: OwnerConfiguration, initialClaim: string, initialStage: "signin" | "enrol" = "signin",
): OwnerPane {
  let claim = initialClaim;
  return (context: OwnerPaneContext) => {
    if (!["claim", "passkey", "phrase"].includes(context.route.pane)) throw new Error("owner:unknown-route");
    if (context.shellOrigin !== config.shellOrigin || location.origin !== config.ownerOrigin
      || window.parent === window || window.top !== window.parent) throw new Error("owner:frame-required");
    context.signal.throwIfAborted();
    const lifetime = new AbortController();
    const signal = lifetime.signal;
    let stepLifetime = new AbortController();
    let wasm: Awaited<ReturnType<typeof loadAumlok>> | undefined;
    let busy = false;
    let active: "claim" | "passkey" | "phrase" | "signin" = context.route.pane === "claim" ? "claim"
      : context.route.pane === "phrase" ? "phrase" : "signin";
    let ceremony: Options | undefined;
    let submission: RecordValue | undefined;
    let bindingId: string | undefined;
    let phrase: string[] = [];
    let strength = "";
    const fields: HTMLInputElement[] = [];
    const panel = element("section", "", "onboarding");
    const progress = element("ol", "", "owner-steps");
    progress.setAttribute("aria-label", "Owner setup");
    const heading = element("h2");
    heading.tabIndex = -1;
    const detail = element("p", "", "owner-detail");
    const content = element("div", "", "owner-content");
    const status = element("p", "", "owner-status");
    status.setAttribute("role", "status");
    const controls = element("div", "", "owner-controls");
    panel.append(progress, heading, detail, content, controls, status);
    context.host.replaceChildren(panel);
    const passkey = createPasskeyService({ ...config, ceremonies: {
      async current() { throw new Error("owner:unknown-operation"); },
      async advance() { throw new Error("owner:unknown-operation"); },
    } });

    function live(): void { signal.throwIfAborted(); }

    function clearFields(): void {
      fields.forEach(field => { field.value = ""; });
      fields.length = 0;
    }

    function screen(stage: typeof active, title: string, description: string): void {
      live();
      stepLifetime.abort();
      stepLifetime = new AbortController();
      active = stage;
      clearFields();
      content.replaceChildren();
      controls.replaceChildren();
      status.textContent = "";
      heading.textContent = title;
      detail.textContent = description;
      heading.focus({ preventScroll: true });
      progress.replaceChildren();
      for (const name of ["claim", "passkey", "phrase", "signin"] as const) {
        const step = element("li");
        step.append(ownerIcon(ICONS[name]));
        step.title = name === "phrase" ? "Seven words" : name === "signin" ? "Sign in" : name;
        step.setAttribute("aria-label", step.title);
        if (name === stage) step.setAttribute("aria-current", "step");
        progress.append(step);
      }
    }

    async function run(action: () => Promise<void>): Promise<void> {
      if (busy || signal.aborted) return;
      busy = true;
      controls.querySelectorAll("button").forEach(button => { button.disabled = true; });
      status.textContent = "Working…";
      try { await action(); }
      catch (error) { if (!signal.aborted) status.textContent = explainOwnerError(error); }
      finally {
        busy = false;
        if (!signal.aborted) controls.querySelectorAll("button").forEach(button => {
          button.disabled = button.dataset.locked === "true";
        });
      }
    }

    function button(label: string, action: () => Promise<void> | void, secondary = false): HTMLButtonElement {
      const node = element("button", "", secondary ? "secondary" : "primary");
      node.append(ownerIcon(ICONS[active]), element("span", label));
      node.type = "button";
      node.addEventListener("click", () => { void run(async () => { await action(); }); }, { signal });
      controls.append(node);
      return node;
    }

    function input(label: string, band = ""): HTMLInputElement {
      const wrapper = element("label", label, `owner-input ${band}`);
      const entry = element("input");
      entry.type = "password";
      entry.autocomplete = "off";
      entry.spellcheck = false;
      entry.maxLength = 2048;
      entry.setAttribute("autocapitalize", "off");
      entry.setAttribute("autocorrect", "off");
      entry.setAttribute("data-1p-ignore", "true");
      wrapper.append(entry);
      content.append(wrapper);
      fields.push(entry);
      return entry;
    }

    function claimScreen(): void {
      screen("claim", "Your node", claim ? "Your claim link is ready." : "Open your claim link, or paste it here.");
      const entry = claim ? undefined : input("Claim link");
      button("Claim", async () => {
        const token = claimToken(claim || entry?.value || "", config.shellOrigin);
        claim = "";
        clearFields();
        try { await consumeClaim(JSON.stringify({ token }), signal); }
        catch (error) {
          if (!signal.aborted) claimScreen();
          throw error;
        }
        live();
        enrolScreen();
      });
      button("Resume setup", () => { enrolScreen(); }, true);
      button("Sign in", () => { signinScreen(); }, true);
    }

    function enrolScreen(): void {
      ceremony = undefined;
      screen("passkey", "Your passkey", "Create it, then confirm possession on your device.");
      button("Create passkey", async () => {
        if (ceremony && ceremony.expires <= performance.now()) ceremony = undefined;
        ceremony ??= options(await post("/api/enrol/start", {}, signal), true, config.relyingParty);
        live();
        if (!ceremony.registration) { possessionScreen(); return; }
        deadline(ceremony.expires);
        const material = await passkey.register(ceremony.registration, signal);
        const current = ceremony;
        // An uncertain submission resumes the durable ceremony before another browser prompt.
        ceremony = undefined;
        const reply = await post("/api/enrol/finish", { enrolment_id: current.id, attestation: material }, signal);
        ceremony = options(reply, true, config.relyingParty);
        if (!ceremony.assertion || ceremony.id !== current.id) throw new Error("aumlok:ceremony-state");
        possessionScreen();
      });
      button("Sign in with an existing passkey", () => { signinScreen(); }, true);
    }

    function possessionScreen(): void {
      screen("passkey", "Confirm your passkey", "One more device check completes enrolment.");
      button("Confirm passkey", async () => {
        if (ceremony && ceremony.expires <= performance.now()) ceremony = undefined;
        if (!ceremony) ceremony = options(await post("/api/enrol/start", {}, signal), true, config.relyingParty);
        if (ceremony.registration) { enrolScreen(); return; }
        if (!ceremony.assertion) throw new Error("aumlok:ceremony-state");
        deadline(ceremony.expires);
        const current = ceremony;
        const assertion = await passkey.assert(current.assertion, signal);
        ceremony = undefined;
        const reply = await post("/api/enrol/finish", { enrolment_id: current.id, assertion }, signal);
        if (state(reply) !== "enrolled") throw new Error("aumlok:ceremony-state");
        bindingScreen();
      });
      button("Resume with sign-in", () => { signinScreen(); }, true);
    }

    function bindingScreen(): void {
      ceremony = undefined;
      bindingId = undefined;
      phrase.fill("");
      phrase = [];
      screen("phrase", "Seven words", "An anchor, then ROOT · UNITE · RISE.");
      button("Reveal my words", async () => {
        await prepareBinding();
        if (!wasm) {
          const loaded = await loadAumlok(signal);
          if (signal.aborted) { loaded.dispose(); return; }
          wasm = loaded;
        }
        live();
        await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
        live();
        const draw = wasm.call({ op: "prepare", owner_origin: config.ownerOrigin, shell_origin: config.shellOrigin });
        phrase = text(draw.phrase, 256).split(" ");
        if (phrase.length !== 7 || phrase.some(word => !/^[a-z]+$/.test(word))
          || draw.minimum_entropy_bits !== 41.5 || draw.average_entropy_bits !== 43.1) throw new Error("aumlok:phrase-invalid");
        strength = `${draw.minimum_entropy_bits} bits at the weakest, ${draw.average_entropy_bits} on average`;
        showWords();
      });
      button("Sign in", () => { signinScreen(); }, true);
    }

    function showWords(): void {
      screen("phrase", "Keep these seven words", "Build a story in your own head that walks through these seven words, in order.");
      content.append(renderPhrase(phrase, stepLifetime.signal), element("p", strength, "phrase-strength"),
        element("p", "Never type these words into an AI.", "phrase-warning"));
      button("Continue", () => { confirmationScreen(); });
    }

    function confirmationScreen(): void {
      screen("phrase", "Your words, once more", "Type all seven in order.");
      const { element: entries, inputs } = phraseInputs(stepLifetime.signal);
      fields.push(...inputs);
      const acknowledgement = phraseAcknowledgement(stepLifetime.signal);
      content.append(entries, element("p", "Never type these words into an AI.", "phrase-warning"), acknowledgement.element);
      const seal = button("Seal my identity", async () => {
        if (!wasm || phrase.length !== 7) throw new Error("aumlok:phrase-locked");
        if (!acknowledgement.checked()) return;
        const wrong: number[] = [];
        inputs.forEach((entry, at) => {
          const mismatch = entry.value.trim().toLowerCase() !== phrase[at];
          entry.toggleAttribute("aria-invalid", mismatch);
          if (mismatch) { entry.setAttribute("aria-invalid", "true"); wrong.push(at + 1); }
        });
        if (wrong.length) {
          status.textContent = `Check word${wrong.length === 1 ? "" : "s"} ${wrong.join(", ")}.`;
          inputs[wrong[0] - 1].focus();
          return;
        }
        let entered = inputs.map(entry => entry.value.trim()).join(" ");
        try { submission = wasm.call({ op: "confirm", entered }); }
        finally { entered = ""; }
        exact(submission, ["v", "envelope", "identity_public_key", "subject"]);
        if (submission.v !== 2 || !/^aukora:1:[0-9a-f]{64}$/.test(text(submission.subject))) throw new Error("aumlok:binding-input");
        phrase.fill("");
        phrase = [];
        wasm.call({ op: "discard" });
        approvalScreen();
      });
      seal.disabled = true;
      seal.dataset.locked = "true";
      acknowledgement.onChange(() => {
        seal.dataset.locked = String(!acknowledgement.checked());
        seal.disabled = busy || !acknowledgement.checked();
      });
      button("See my words again", () => { showWords(); }, true);
    }

    async function prepareBinding(): Promise<void> {
      const prepare = await post("/api/binding/prepare", {}, signal);
      exact(prepare, ["ceremony_id", "expires_at", "schema"]);
      if (prepare.schema !== "aukora-owner-binding-v2") throw new Error("aumlok:ceremony-kind");
      if (!Number.isSafeInteger(prepare.expires_at) || (prepare.expires_at as number) < 0) {
        throw new Error("owner:response-invalid");
      }
      bindingId = handle(prepare.ceremony_id);
    }

    function approvalScreen(): void {
      screen("phrase", "Bind your identity", "Your passkey approves this sealed identity.");
      button("Bind with Touch ID / passkey", async () => {
        if (!submission) throw new Error("aumlok:binding-input");
        await prepareBinding();
        const prepared = options(await post("/api/binding/confirm", { ceremony_id: bindingId, submission }, signal), false, config.relyingParty);
        if (prepared.id !== bindingId || !prepared.assertion) throw new Error("aumlok:ceremony-state");
        const assertion = await passkey.assert(prepared.assertion, signal);
        const reply = await post("/api/binding/confirm", { ceremony_id: bindingId, assertion }, signal);
        if (state(reply) !== "bound" || reply.subject !== submission.subject) throw new Error("aumlok:binding-input");
        submission = undefined;
        bindingId = undefined;
        signinScreen();
      });
      button("Resume with sign-in", () => { signinScreen(); }, true);
    }

    function signinScreen(): void {
      if (wasm) wasm.call({ op: "discard" });
      phrase.fill("");
      phrase = [];
      submission = undefined;
      ceremony = undefined;
      bindingId = undefined;
      screen("signin", "Welcome home", "Sign in with your passkey.");
      button("Sign in", async () => {
        if (ceremony && ceremony.expires <= performance.now()) ceremony = undefined;
        try { ceremony ??= options(await post("/api/signin/start", {}, signal), false, config.relyingParty); }
        catch (error) {
          // Claimed but no passkey yet (a reload after the claim): continue the setup, never strand the owner.
          if (error instanceof Error && error.message === "aumlok:enrolment-required") { enrolScreen(); return; }
          throw error;
        }
        if (!ceremony.assertion) throw new Error("aumlok:ceremony-state");
        deadline(ceremony.expires);
        const current = ceremony;
        const assertion = await passkey.assert(current.assertion, signal);
        ceremony = undefined;
        const reply = await post("/api/signin/finish", { ceremony_id: current.id, assertion }, signal);
        if (state(reply) === "enrolled") bindingScreen();
        else { live(); context.complete(); }
      });
    }

    function dispose(): void {
      if (signal.aborted) return;
      lifetime.abort();
      stepLifetime.abort();
      clearFields();
      phrase.fill("");
      phrase = [];
      claim = "";
      submission = undefined;
      ceremony = undefined;
      wasm?.dispose();
      wasm = undefined;
      context.signal.removeEventListener("abort", dispose);
      context.host.replaceChildren();
    }
    context.signal.addEventListener("abort", dispose, { once: true });
    if (context.signal.aborted) dispose();
    else if (active === "claim") claimScreen();
    else if (active === "phrase") bindingScreen();
    else if (initialStage === "enrol") enrolScreen();
    else signinScreen();
    return dispose;
  };
}
