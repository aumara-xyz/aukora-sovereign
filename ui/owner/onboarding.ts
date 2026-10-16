// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerConfiguration } from "./bootstrap.js";
import type { OwnerPane, OwnerPaneContext } from "./contracts.js";
import { createPasskeyService } from "./passkey/index.js";
import { claimToken } from "./claim/codec.js";
import { consumeClaim } from "./claim/transport.js";
import { deadline, exact, handle, options, post, state, text } from "./transport.js";
import type { Options, RecordValue } from "./transport.js";
import { loadAumlok } from "./aumlok.js";

const BANDS = ["ANCHOR", "ROOT", "ROOT", "UNITE", "UNITE", "RISE", "RISE"] as const;
const SYMBOLS = { claim: "◇", passkey: "⌘", phrase: "✦", signin: "↗" };

function element<K extends keyof HTMLElementTagNameMap>(tag: K, content = "", className = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = content;
  node.className = className;
  return node;
}

function explanation(error: unknown): string {
  const code = error instanceof Error ? error.message : typeof error === "string" ? error : "owner:request-refused";
  if (error instanceof DOMException && ["NotAllowedError", "AbortError"].includes(error.name)) {
    return "Passkey cancelled. Try again when ready.";
  }
  if (code === "aumlok:word-mismatch" || code === "aumlok:phrase-invalid") return "Check all seven words, in order.";
  if (code === "aumlok:enrolment-closed") return "A passkey is enrolled. Sign in to continue.";
  if (code === "aumlok:ceremony-expired") return "This request expired. Start the step again.";
  return /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(code) ? code : "owner:request-unconfirmed";
}

export function createOnboarding(config: OwnerConfiguration, initialClaim: string): OwnerPane {
  let claim = initialClaim;
  return (context: OwnerPaneContext) => {
    if (!["claim", "passkey", "phrase"].includes(context.route.pane)) throw new Error("owner:unknown-route");
    if (context.shellOrigin !== config.shellOrigin || location.origin !== config.ownerOrigin
      || window.parent === window || window.top !== window.parent) throw new Error("owner:frame-required");
    context.signal.throwIfAborted();
    const lifetime = new AbortController();
    const signal = lifetime.signal;
    let wasm: Awaited<ReturnType<typeof loadAumlok>> | undefined;
    let busy = false;
    let active: "claim" | "passkey" | "phrase" | "signin" = context.route.pane === "claim" ? "claim"
      : context.route.pane === "phrase" ? "phrase" : "signin";
    let ceremony: Options | undefined;
    let submission: RecordValue | undefined;
    let bindingId: string | undefined;
    let bindingExpires: number | undefined;
    let phraseShown = false;
    const fields: HTMLInputElement[] = [];
    const panel = element("section", "", "onboarding");
    const progress = element("ol", "", "owner-steps");
    progress.setAttribute("aria-label", "Owner setup");
    const heading = element("h2");
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
      active = stage;
      clearFields();
      content.replaceChildren();
      controls.replaceChildren();
      status.textContent = "";
      heading.textContent = title;
      detail.textContent = description;
      progress.replaceChildren();
      for (const name of ["claim", "passkey", "phrase", "signin"] as const) {
        const step = element("li", SYMBOLS[name]);
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
      catch (error) { if (!signal.aborted) status.textContent = explanation(error); }
      finally {
        busy = false;
        if (!signal.aborted) controls.querySelectorAll("button").forEach(button => { button.disabled = false; });
      }
    }

    function button(label: string, action: () => Promise<void> | void, secondary = false): void {
      const node = element("button", label, secondary ? "secondary" : "primary");
      node.type = "button";
      node.addEventListener("click", () => { void run(async () => { await action(); }); }, { signal });
      controls.append(node);
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
      button("◇  Claim", async () => {
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
      button("⌘  Create passkey", async () => {
        if (ceremony && ceremony.expires <= Date.now()) ceremony = undefined;
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
      button("⌘  Confirm passkey", async () => {
        if (ceremony && ceremony.expires <= Date.now()) ceremony = undefined;
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
      bindingExpires = undefined;
      screen("phrase", "Seven words", "An anchor, then ROOT · UNITE · RISE.");
      button("✦  Reveal my words", async () => {
        if (!wasm) {
          const loaded = await loadAumlok(signal);
          if (signal.aborted) { loaded.dispose(); return; }
          wasm = loaded;
        }
        live();
        await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
        live();
        const draw = wasm.call({ op: "prepare", owner_origin: config.ownerOrigin, shell_origin: config.shellOrigin });
        const phrase = text(draw.phrase, 256).split(" ");
        if (phrase.length !== 7 || phrase.some(word => !/^[a-z]+$/.test(word))
          || draw.minimum_entropy_bits !== 41.5 || draw.average_entropy_bits !== 43.1) throw new Error("aumlok:phrase-invalid");
        phraseShown = true;
        screen("phrase", "Keep these seven words", "Picture one place for each pair.");
        const bands = element("ol", "", "phrase-bands");
        phrase.forEach((word, index) => {
          const row = element("li", "", `word-band band-${BANDS[index].toLowerCase()}`);
          row.append(element("span", BANDS[index], "word-label"), element("strong", word));
          bands.append(row);
        });
        phrase.fill("");
        content.append(bands, element("p", "never type these words into an AI", "phrase-warning"),
          element("p", "41.5 bits minimum · 43.1 average", "phrase-entropy"));
        button("I saved them · continue", () => { confirmationScreen(); });
      });
      button("Sign in", () => { signinScreen(); }, true);
    }

    function confirmationScreen(): void {
      screen("phrase", "Your words, once more", "Enter all seven in order. They stay on this owner page.");
      const inputs = BANDS.map((band, index) => {
        const entry = input(`${index + 1} · ${band}`, `band-${band.toLowerCase()}`);
        entry.maxLength = 64;
        return entry;
      });
      content.append(element("p", "never type these words into an AI", "phrase-warning"));
      button("✦  Seal my identity", async () => {
        if (!wasm || !phraseShown) throw new Error("aumlok:phrase-locked");
        let entered = inputs.map(entry => entry.value.trim()).join(" ");
        try { submission = wasm.call({ op: "confirm", entered }); }
        finally { entered = ""; inputs.forEach(entry => { entry.value = ""; }); }
        exact(submission, ["v", "envelope", "identity_public_key", "subject"]);
        if (submission.v !== 2 || !/^aukora:1:[0-9a-f]{64}$/.test(text(submission.subject))) throw new Error("aumlok:binding-input");
        phraseShown = false;
        wasm.call({ op: "discard" });
        approvalScreen();
      });
      inputs[0].focus();
    }

    function approvalScreen(): void {
      screen("phrase", "Bind your identity", "Your passkey approves this sealed identity.");
      button("⌘  Bind with passkey", async () => {
        if (!submission) throw new Error("aumlok:binding-input");
        if (!bindingId || !bindingExpires || bindingExpires <= Date.now()) {
          const prepare = await post("/api/binding/prepare", {}, signal);
          exact(prepare, ["ceremony_id", "expires_at", "schema"]);
          if (prepare.schema !== "aukora-owner-binding-v2") throw new Error("aumlok:ceremony-kind");
          bindingId = handle(prepare.ceremony_id);
          bindingExpires = deadline(prepare.expires_at);
        }
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
      phraseShown = false;
      submission = undefined;
      ceremony = undefined;
      bindingId = undefined;
      bindingExpires = undefined;
      screen("signin", "Welcome home", "Sign in with your passkey.");
      button("↗  Sign in", async () => {
        if (ceremony && ceremony.expires <= Date.now()) ceremony = undefined;
        ceremony ??= options(await post("/api/signin/start", {}, signal), false, config.relyingParty);
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
      clearFields();
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
    else signinScreen();
    return dispose;
  };
}
