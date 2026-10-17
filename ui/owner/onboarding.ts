// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerConfiguration } from "./bootstrap.js";
import type { OwnerPane, OwnerPaneContext } from "./contracts.js";
import { createPasskeyService } from "./passkey/index.js";
import { renderBrowserAdvice } from "./passkey/browser.js";
import { checkAbort } from "./abort.js";
import { claimToken } from "./claim/codec.js";
import { consumeClaim } from "./claim/transport.js";
import { deadline, exact, handle, options, post, record, state, text } from "./transport.js";
import type { Options, RecordValue } from "./transport.js";
import { loadAumlok } from "./aumlok.js";
import { explainOwnerError, normaliseWord, phraseForm, recoveryInput, renderPhrase } from "./phrase-layout.js";
import { mountPairing } from "./pairing.js";
import { pairingPort } from "./pairing-port.js";
import { brand } from "./brand.js";
import { actionButton } from "./primitives.js";

function element<K extends keyof HTMLElementTagNameMap>(tag: K, content = "", className = ""): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.textContent = content;
  node.className = className;
  return node;
}

export function createOnboarding(
  config: OwnerConfiguration, initialClaim: string, initialStage: "signin" | "enrol" = "signin",
  // Set on the opening screen by "I already have a Sovereign ID": after the passkey, the ceremony goes to the import.
  intent: { sovereignId: boolean } = { sovereignId: false },
): OwnerPane {
  let claim = initialClaim;
  return (context: OwnerPaneContext) => {
    if (!["claim", "passkey", "phrase"].includes(context.route.pane)) throw new Error("owner:unknown-route");
    if (context.shellOrigin !== config.shellOrigin || location.origin !== config.ownerOrigin
      || window.parent === window || window.top !== window.parent) throw new Error("owner:frame-required");
    checkAbort(context.signal);
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
    let username = "";
    let newlyBound = false;
    let handoffDispose: (() => void) | undefined;
    let recoveryFile = "";
    const fields: HTMLInputElement[] = [];
    const panel = element("section", "", "onboarding");
    const heading = element("h2");
    heading.tabIndex = -1;
    // The line under a headline is never wider than the headline.
    const textBlock = element("div", "", "owner-text");
    const detail = element("p", "", "owner-detail");
    textBlock.append(heading, detail);
    const content = element("div", "", "owner-content");
    const status = element("p", "", "owner-status");
    status.setAttribute("role", "status");
    const controls = element("div", "", "owner-controls");
    panel.append(textBlock, content, controls, status);
    context.host.replaceChildren(panel);
    const passkey = createPasskeyService({ ...config, ceremonies: {
      async current() { throw new Error("owner:unknown-operation"); },
      async advance() { throw new Error("owner:unknown-operation"); },
    } });

    function live(): void { checkAbort(signal); }

    function clearFields(): void {
      fields.forEach(field => { field.value = ""; });
      fields.length = 0;
    }

    // The scene being left stays for a moment as a ghost and drifts away while the next one rises in.
    function leaveScene(): void {
      if (!heading.textContent || !panel.isConnected) return;
      const ghost = panel.cloneNode(true) as HTMLElement;
      ghost.classList.remove("owner-scene");
      ghost.classList.add("owner-ghost");
      ghost.inert = true;
      ghost.setAttribute("aria-hidden", "true");
      ghost.querySelectorAll("[id]").forEach(node => node.removeAttribute("id"));
      ghost.querySelectorAll("input, textarea").forEach(node => { (node as HTMLInputElement).value = ""; });
      context.host.append(ghost);
      const remove = (): void => ghost.remove();
      setTimeout(remove, 650);
      signal.addEventListener("abort", remove, { once: true });
    }

    function screen(stage: typeof active, title: string, description: string): void {
      live();
      leaveScene();
      stepLifetime.abort();
      stepLifetime = new AbortController();
      handoffDispose?.();
      handoffDispose = undefined;
      active = stage;
      panel.removeAttribute("data-scene");
      textBlock.replaceChildren(heading, detail);
      panel.append(textBlock, content, controls, status);
      panel.querySelector(".claim-portal")?.remove();
      clearFields();
      content.replaceChildren();
      controls.replaceChildren();
      status.textContent = "";
      heading.textContent = title;
      detail.textContent = description;
      detail.hidden = description === "";
      panel.classList.remove("owner-scene");
      void panel.offsetWidth;
      panel.classList.add("owner-scene");
      renderBrowserAdvice(status);
      heading.focus({ preventScroll: true });
      brand.show(stage === "claim" ? "hero" : "mark");
    }

    async function run(action: () => Promise<void>): Promise<void> {
      if (busy || signal.aborted) return;
      busy = true;
      controls.querySelectorAll("button").forEach(button => { button.disabled = true; });
      renderBrowserAdvice(status);
      brand.working(true);
      try { await action(); }
      catch (error) {
        if (!signal.aborted) {
          if (error instanceof Error && ["aumlok:claim-spent", "aumlok:enrolment-closed"].includes(error.message)) {
            signinScreen();
          } else if (!renderBrowserAdvice(status, error)) status.textContent = explainOwnerError(error);
        }
      }
      finally {
        busy = false;
        brand.working(false);
        if (!signal.aborted) controls.querySelectorAll("button").forEach(button => {
          button.disabled = button.dataset.locked === "true";
        });
      }
    }

    // An action is the primitives' button shape (mint for the one primary, blue for a visible second); a plain
    // secondary is a quiet line of text.
    function button(label: string, action: () => Promise<void> | void, secondary = false, visible = false): HTMLButtonElement {
      let node: HTMLButtonElement;
      if (secondary && !visible) {
        node = element("button", label, "secondary");
        controls.append(node);
      } else {
        const made = actionButton(label, secondary ? "blue" : "mint");
        node = made.button;
        controls.append(made.frame);
      }
      node.classList.add(secondary ? "secondary" : "primary");
      node.type = "button";
      node.addEventListener("click", () => { void run(async () => { await action(); }); }, { signal });
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
      entry.addEventListener("input", () => { entry.removeAttribute("aria-invalid"); }, { signal: stepLifetime.signal });
      wrapper.append(entry);
      content.append(wrapper);
      fields.push(entry);
      return entry;
    }

    function claimScreen(): void {
      screen("claim", "Claim your node", claim ? "Using your claim link" : "Enter your claim code or link.");
      const portal = element("section", "", "claim-portal");
      portal.dataset.open = "no";
      const trigger = element("button", "", "claim-portal-button");
      trigger.append(element("span", "Exit the Matrix"));
      trigger.type = "button";
      trigger.setAttribute("aria-expanded", "false");
      trigger.setAttribute("aria-controls", "onboarding-claim-portal");
      const depth = element("span", "⌄", "claim-portal-depth");
      depth.setAttribute("aria-hidden", "true");
      trigger.append(depth);
      const layer = element("div", "", "claim-portal-content");
      layer.id = "onboarding-claim-portal";
      layer.inert = true;
      layer.setAttribute("aria-hidden", "true");
      const body = element("div", "", "claim-portal-body");
      body.append(textBlock, content, controls);
      layer.append(body);
      portal.append(trigger, layer);
      panel.prepend(portal);
      const entry = input("Claim code or link");
      entry.value = claim;
      entry.placeholder = "Claim code or link";
      const prefilled = claim !== "";
      if (prefilled) entry.closest("label")?.setAttribute("hidden", "");
      trigger.addEventListener("click", () => {
        if (busy) return;
        const open = portal.dataset.open !== "yes";
        portal.dataset.open = open ? "yes" : "no";
        trigger.setAttribute("aria-expanded", String(open));
        layer.inert = !open;
        layer.setAttribute("aria-hidden", String(!open));
        if (open && !prefilled) entry.focus({ preventScroll: true });
      }, { signal: stepLifetime.signal });
      button("Begin your journey", async () => {
        const token = claimToken(entry.value, config.shellOrigin);
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
      const recover = button("Recover my account", () => { signinScreen(); }, true);
      recover.classList.add("quiet-link");
      panel.append(recover);
    }

    function enrolScreen(): void {
      ceremony = undefined;
      screen("passkey", "Create your passkey", "It lives on your device.\nIt unlocks with your face, fingerprint or device PIN.");
      button("Create passkey", async () => {
        if (ceremony && ceremony.expires <= performance.now()) ceremony = undefined;
        ceremony ??= options(await post("/api/enrol/start", {}, signal), true, config.relyingParty);
        live();
        if (!ceremony.registration) { possessionScreen(); return; }
        deadline(ceremony.expires);
        const material = await passkey.register(ceremony.registration, signal);
        live();
        brand.bloom();
        brand.door();
        const current = ceremony;
        // An uncertain submission resumes the durable ceremony before another browser prompt.
        ceremony = undefined;
        const reply = await post("/api/enrol/finish", { enrolment_id: current.id, attestation: material }, signal);
        ceremony = options(reply, true, config.relyingParty);
        if (!ceremony.assertion || ceremony.id !== current.id) throw new Error("aumlok:ceremony-state");
        possessionScreen();
      });
    }

    function possessionScreen(): void {
      screen("passkey", "Confirm your passkey", "One more touch and it is yours.");
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
        brand.bloom();
        bindingScreen();
      });
    }

    function bindingScreen(): void {
      ceremony = undefined;
      bindingId = undefined;
      submission = undefined;
      if (wasm) wasm.call({ op: "discard" });
      phrase.fill("");
      phrase = [];
      username = "";
      recoveryFile = "";
      if (intent.sovereignId) { intent.sovereignId = false; importScreen(); return; }
      screen("phrase", "Enter your username", "A public name. It is not saved to your identity yet.");
      const entry = nameInput();
      const next = button("Next", () => {
        const value = entry.value.trim();
        if (!validName(value)) return;
        username = value;
        phraseIntroScreen();
      });
      next.disabled = true;
      next.dataset.locked = "true";
      entry.addEventListener("input", () => {
        next.dataset.locked = String(!validName(entry.value.trim()));
        next.disabled = busy || next.dataset.locked === "true";
      }, { signal: stepLifetime.signal });
    }

    function validName(value: string): boolean {
      return value.length > 0 && value.length <= 64 && !/[\u0000-\u001f\u007f]/u.test(value);
    }

    function nameInput(): HTMLInputElement {
      const entry = input("Username", "band-anchor");
      entry.type = "text";
      entry.maxLength = 64;
      entry.placeholder = "Username";
      return entry;
    }

    // AUMLOK is always capitalised and in its accent (the gold of the anchor).
    function accent(line: HTMLElement, label: string): void {
      const [before, after] = line.textContent?.split(label) ?? [];
      if (after === undefined) return;
      line.replaceChildren(before, element("span", label, "aumlok"), after);
    }

    // One short paragraph per sentence; some words carry their colour.
    function line(...parts: Array<string | readonly [string, string]>): void {
      const paragraph = element("p", "", "owner-detail");
      for (const part of parts) paragraph.append(typeof part === "string" ? part : element("span", part[0], part[1]));
      textBlock.append(paragraph);
    }

    // The three groups as three boxes: the label on top in its colour, what it is beneath. Side by side, or stacked on a phone.
    function themes(...rows: Array<readonly [string, string, string, string]>): void {
      const list = element("ul", "", "owner-themes");
      for (const [word, band, tone, theme] of rows) {
        const box = element("li", "", `owner-themebox ak-portal ${tone}`);
        box.append(element("span", word, `band-word ${band}`), element("span", theme, "owner-theme"));
        list.append(box);
      }
      textBlock.append(list);
    }

    function phraseIntroScreen(): void {
      screen("phrase", "Your seven words", "");
      line(["Your first word is your anchor.", "aumlok"]);
      line("Six more words follow, in three themed pairs:");
      themes(["ROOT", "band-root", "ak-tone-mint", "the earth"], ["UNITE", "band-unite", "ak-tone-blue", "the people"],
        ["RISE", "band-rise", "ak-tone-violet", "the above"]);
      line("Keep them offline. Give them to no one, and to no AI.");
      button("I understand", () => drawWords(false));
      button("Back", () => { bindingScreen(); }, true);
    }

    async function drawWords(rotate = false): Promise<void> {
      phrase.fill("");
      phrase = [];
      if (!rotate) content.replaceChildren();
      try {
        wasm?.call({ op: "discard" });
        try { await prepareBinding(); }
        catch (error) {
          if (error instanceof Error && error.message === "aumlok:enrolment-required") { enrolScreen(); return; }
          throw error;
        }
        await readyWasm();
        if (!wasm) throw new Error("aumlok:wasm-abi");
        await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
        live();
        const draw = wasm.call({ op: "prepare", owner_origin: config.ownerOrigin, shell_origin: config.shellOrigin });
        phrase = text(draw.phrase, 256).split(" ");
        if (phrase.length !== 7 || phrase.some(word => !/^[a-z]+$/.test(word))
          || draw.minimum_entropy_bits !== 41.5 || draw.average_entropy_bits !== 43.1) throw new Error("aumlok:phrase-invalid");
        if (rotate) await swapWords();
        else showWords();
      } catch (error) {
        // A failed draw never leaves old words on screen over a new (or emptied) phrase: start the step again.
        if (!signal.aborted) phraseIntroScreen();
        throw error;
      }
    }

    // Rotating keeps the screen where it is: only the words change, with a soft crossfade.
    async function swapWords(): Promise<void> {
      try {
        const old = content.querySelector<HTMLElement>(".phrase-display");
        const fresh = renderPhrase(phrase, stepLifetime.signal);
        const fade = (target: HTMLElement | null, from: number, to: number, duration: number): Promise<void> =>
          target?.animate ? target.animate([{ opacity: from }, { opacity: to }], { duration, easing: "ease", fill: "forwards" }).finished.then(() => {}, () => {}) : Promise.resolve();
        await fade(old, 1, 0, 260);
        live();
        if (old) old.replaceWith(fresh); else content.append(fresh);
        await fade(fresh, 0, 1, 700);
      } catch (error) {
        // The words on screen must be the words that will be checked: if the soft swap fails, draw the whole screen again.
        if (signal.aborted) throw error;
        showWords();
      }
    }

    async function readyWasm(): Promise<void> {
      if (!wasm) {
        const loaded = await loadAumlok(signal);
        if (signal.aborted) { loaded.dispose(); live(); }
        wasm = loaded;
      }
      live();
    }

    function importScreen(): void {
      submission = undefined;
      recoveryFile = "";
      screen("phrase", "Your Sovereign ID", "Your recovery file and seven words open the same identity.");
      const recovery = recoveryInput(stepLifetime.signal);
      content.append(recovery.element);
      button("Next · enter my words", async () => {
        recoveryFile = await recovery.read();
        live();
        recovery.clear();
        importWordsScreen();
      });
      button("Back", () => { bindingScreen(); }, true);
    }

    function importWordsScreen(): void {
      screen("phrase", "Your Sovereign ID words", "Enter the seven words that seal your recovery file.");
      panel.dataset.scene = "confirmation";
      const form = phraseForm(stepLifetime.signal);
      fields.push(...form.all());
      content.append(form.element,
        element("p", "Never type these words into an AI.", "phrase-warning"));
      const open = button("Open my Sovereign ID", async () => {
        try { await prepareBinding(); }
        catch (error) {
          if (error instanceof Error && error.message === "aumlok:enrolment-required") { enrolScreen(); return; }
          throw error;
        }
        await readyWasm();
        if (!wasm) throw new Error("aumlok:wasm-abi");
        let entered = "";
        let imported: RecordValue;
        try {
          if (!recoveryFile) throw new Error("aumlok:envelope-json");
          live();
          await new Promise<void>(resolve => requestAnimationFrame(() => resolve()));
          live();
          entered = form.values().join(" ");
          imported = wasm.call({ op: "import", owner_origin: config.ownerOrigin,
            shell_origin: config.shellOrigin, recovery: recoveryFile, entered });
        } finally {
          entered = "";
          form.all().forEach(field => { field.value = ""; });
        }
        exact(imported, ["submission", "person_nostr_public_key", "person_nostr_npub"]);
        const candidate = record(imported.submission);
        validateSubmission(candidate);
        if (!/^[0-9a-f]{64}$/.test(text(imported.person_nostr_public_key, 64))) throw new Error("aumlok:binding-input");
        const npub = text(imported.person_nostr_npub, 63);
        if (!/^npub1[023456789acdefghjklmnpqrstuvwxyz]{58}$/.test(npub)) throw new Error("aumlok:binding-input");
        wasm.call({ op: "discard" });
        recoveryFile = "";
        submission = candidate;
        compareIdentityScreen(npub);
      });
      button("Use another recovery file", () => { importScreen(); }, true);
      open.disabled = true;
      open.dataset.locked = "true";
      form.onChange(() => {
        open.dataset.locked = String(!form.complete());
        open.disabled = busy || !form.complete();
      });
    }

    function compareIdentityScreen(npub: string): void {
      screen("phrase", "Compare with AUKORA Light", "Compare this person-nostr address with your address in Light before binding this node.");
      const address = element("code", npub);
      address.style.overflowWrap = "anywhere";
      content.append(element("p", "Your person-nostr address"), address);
      button("It matches my Light address", () => { approvalScreen(); });
      button("Use another recovery file", () => { importScreen(); }, true);
    }

    function validateSubmission(value: RecordValue): void {
      exact(value, ["v", "envelope", "identity_public_key", "subject"]);
      if (value.v !== 2 || !/^aukora:1:[0-9a-f]{64}$/.test(text(value.subject))) throw new Error("aumlok:binding-input");
      const envelope = record(value.envelope);
      exact(envelope, ["ciphertext", "kdf", "nonce", "salt", "version"]);
      if (envelope.version !== 1) throw new Error("aumlok:binding-input");
      if (!/^[A-Za-z0-9+/]{43}=$/.test(text(value.identity_public_key, 44))) throw new Error("aumlok:binding-input");
    }

    function showWords(): void {
      screen("phrase", "Write them down", "Your seven words, in order.");
      panel.dataset.scene = "words";
      content.append(renderPhrase(phrase, stepLifetime.signal));
      button("Rotate phrase", () => drawWords(true), true);
      button("Bind this phrase", () => { bindWarningScreen(); });
    }

    // One step: the headline says what is at stake, the two buttons sit side by side.
    function bindWarningScreen(): void {
      screen("phrase", "You won’t see these words again.", "");
      panel.dataset.scene = "confirm";
      line("The first word is your ", ["anchor", "aumlok"], ".");
      const names = element("p", "", "owner-detail owner-names");
      names.append(element("span", "ROOT", "band-word band-root"), element("span", "UNITE", "band-word band-unite"), element("span", "RISE", "band-word band-rise"));
      textBlock.append(names);
      line("built for your own memory palace.");
      line("Right now, make up a story that binds all seven.");
      line("Close your eyes. Walk through it.");
      line("Then see if you can recall them first try.");
      line("The next step is that test.");
      line(["YOUR MIND HOLDS THE KEYS TO FREEDOM.", "owner-motto"]);
      button("Back to my words", () => { showWords(); }, true, true);
      button("I have them", () => { confirmationScreen(); });
    }

    // The words screen, blank: the name on top, the anchor into its six gold boxes, then the words by group.
    function confirmationScreen(): void {
      screen("phrase", "Seal your AUMLOK", "Write your name and the seven words back, as you wrote them.");
      accent(heading, "AUMLOK");
      panel.dataset.scene = "confirmation";
      const name = nameInput();
      const form = phraseForm(stepLifetime.signal);
      fields.push(...form.all());
      content.append(form.element);
      button("Back to my words", () => { showWords(); }, true, true);
      const seal = button("Seal my identity", async () => {
        if (!wasm || phrase.length !== 7) throw new Error("aumlok:phrase-locked");
        if (name.value.trim() !== username) {
          name.setAttribute("aria-invalid", "true");
          status.textContent = "Use the same username.";
          name.focus();
          return;
        }
        // Only the rows that do not match are marked. The phrase shown is the phrase checked.
        const typed = form.values();
        const wrongAnchor = typed[0] !== normaliseWord(phrase[0]);
        const wrong = typed.slice(1).flatMap((word, at) => word === normaliseWord(phrase[at + 1]) ? [] : [at]);
        form.flagAnchor(wrongAnchor);
        wrong.forEach(at => form.flagWord(at, true));
        if (wrongAnchor || wrong.length) {
          status.textContent = wrongAnchor && wrong.length === 6
            ? "These are not the words you were shown. Go back to your words and copy them exactly."
            : "Check the marked words.";
          if (wrongAnchor) form.focusAnchor(); else form.focusWord(wrong[0]);
          return;
        }
        let entered = typed.join(" ");
        try { submission = wasm.call({ op: "confirm", entered }); }
        finally { entered = ""; }
        validateSubmission(submission);
        phrase.fill("");
        phrase = [];
        wasm.call({ op: "discard" });
        approvalScreen();
      });
      seal.disabled = true;
      seal.dataset.locked = "true";
      const ready = (): void => {
        const complete = name.value.trim() !== "" && form.complete();
        seal.dataset.locked = String(!complete);
        seal.disabled = busy || !complete;
        status.textContent = "";
      };
      name.addEventListener("input", ready, { signal: stepLifetime.signal });
      form.onChange(ready);
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
        newlyBound = true;
        username = "";
        brand.bloom();
        brand.door();
        screen("phrase", "Your identity is bound", "One final connection awaits.");
        // The node asks for one more touch to open the session; it is part of going on, not a separate sign-in screen.
        button("Continue to the final part of the ceremony", async () => { await continueSession(); });
      });
    }

    // The sign-in ceremony. Returns false when the owner was sent back into setup.
    async function signinCeremony(): Promise<boolean> {
      if (ceremony && ceremony.expires <= performance.now()) ceremony = undefined;
      try { ceremony ??= options(await post("/api/signin/start", {}, signal), false, config.relyingParty); }
      catch (error) {
        // Claimed but no passkey yet (a reload after the claim): continue the setup, never strand the owner.
        if (error instanceof Error && error.message === "aumlok:enrolment-required") { enrolScreen(); return false; }
        throw error;
      }
      if (!ceremony.assertion) throw new Error("aumlok:ceremony-state");
      deadline(ceremony.expires);
      const current = ceremony;
      const assertion = await passkey.assert(current.assertion, signal);
      ceremony = undefined;
      const reply = await post("/api/signin/finish", { ceremony_id: current.id, assertion }, signal);
      if (state(reply) === "enrolled") { bindingScreen(); return false; }
      live();
      return true;
    }

    // Is the first pairing still due? Decided by the node, never by what this page remembers: an owner who is bound but has no paired
    // device resumes at pairing after any sign-in, including after a reload. If the node cannot say, it is treated as still due.
    async function pairingDue(): Promise<boolean> {
      if (newlyBound) return true;
      if (!pairingPort?.pairedCount) return false;            // this node does not serve co-presence: there is nothing to resume
      try { return await pairingPort.pairedCount(signal) === 0; } catch { return true; }
    }

    async function continueSession(): Promise<void> {
      if (!await signinCeremony()) return;
      brand.bloom();
      if (await pairingDue()) {
        clearFields();
        stepLifetime.abort();
        handoffDispose = mountPairing(context.host, signal, () => context.complete());
      } else context.complete();
    }

    // "Recover my account": the existing sign-in, for an owner who is already set up.
    function signinScreen(): void {
      if (wasm) wasm.call({ op: "discard" });
      phrase.fill("");
      phrase = [];
      submission = undefined;
      ceremony = undefined;
      bindingId = undefined;
      recoveryFile = "";
      screen("signin", "Welcome back", "Sign in with your passkey.");
      button("Sign in", continueSession);
    }

    function dispose(): void {
      if (signal.aborted) return;
      lifetime.abort();
      stepLifetime.abort();
      brand.hide();
      handoffDispose?.();
      clearFields();
      phrase.fill("");
      phrase = [];
      claim = "";
      username = "";
      recoveryFile = "";
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
