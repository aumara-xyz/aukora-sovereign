// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerConfiguration } from "../bootstrap.js";
import type { OwnerPane, OwnerPaneContext } from "../contracts.js";
import { loadAumlok } from "../aumlok.js";
import { createPasskeyService } from "../passkey/index.js";
import { renderBrowserAdvice } from "../passkey/browser.js";
import { checkAbort } from "../abort.js";
import { exact, handle, options, post, record, state, text } from "../transport.js";
import type { RecordValue } from "../transport.js";
import { explainOwnerError, phraseAcknowledgement, phraseInputs, renderPhrase } from "../phrase-layout.js";

function node<K extends keyof HTMLElementTagNameMap>(tag: K, value = "", className = ""): HTMLElementTagNameMap[K] {
  const result = document.createElement(tag);
  result.textContent = value;
  result.className = className;
  return result;
}

type Current = {
  ceremony: string; subject: string; digest: string; envelope: RecordValue; publicKey: string;
};

function current(reply: RecordValue): Current {
  exact(reply, ["ceremony_id", "expires_at", "schema", "subject", "envelope", "revision",
    "identity_public_key", "previous_envelope_sha256"]);
  if (reply.schema !== "aukora-owner-refresh-v2" || !Number.isSafeInteger(reply.expires_at)
    || (reply.expires_at as number) < 0 || !Number.isSafeInteger(reply.revision) || (reply.revision as number) < 1
    || !/^aukora:1:[0-9a-f]{64}$/.test(text(reply.subject))
    || !/^[0-9a-f]{64}$/.test(text(reply.previous_envelope_sha256))) throw new Error("aumlok:refresh-input");
  return { ceremony: handle(reply.ceremony_id), subject: text(reply.subject),
    digest: text(reply.previous_envelope_sha256), envelope: record(reply.envelope),
    publicKey: text(reply.identity_public_key) };
}

export function createLivePhraseService(config: OwnerConfiguration): { mount: OwnerPane } {
  return { mount(context: OwnerPaneContext) {
    if (context.route.pane !== "phrase" || !context.route.refresh || context.shellOrigin !== config.shellOrigin
      || location.origin !== config.ownerOrigin) throw new Error("owner:frame-required");
    const lifetime = new AbortController();
    const signal = lifetime.signal;
    let stepLifetime = new AbortController();
    let wasm: Awaited<ReturnType<typeof loadAumlok>> | undefined;
    let bound: Current | undefined;
    let words: string[] = [];
    let fields: HTMLInputElement[] = [];
    let busy = false;
    let submitted = false;
    let replacement: RecordValue | undefined;
    const panel = node("section", "", "onboarding phrase-pane");
    const title = node("h2", "Refresh your seven words");
    title.tabIndex = -1;
    const content = node("div", "", "owner-content");
    const controls = node("div", "", "owner-controls");
    const status = node("p", "", "owner-status");
    status.setAttribute("role", "status");
    panel.append(title, content, controls, status);
    context.host.replaceChildren(panel);
    title.focus({ preventScroll: true });
    const passkey = createPasskeyService({ ...config, ceremonies: {
      async current() { throw new Error("owner:unknown-operation"); },
      async advance() { throw new Error("owner:unknown-operation"); },
    } });

    function live(): void { checkAbort(signal); }
    function clear(heading = title.textContent ?? ""): void {
      stepLifetime.abort();
      stepLifetime = new AbortController();
      fields.forEach(field => { field.value = ""; }); fields = [];
      content.replaceChildren(); controls.replaceChildren(); status.textContent = "";
      renderBrowserAdvice(status);
      title.textContent = heading;
      title.focus({ preventScroll: true });
    }
    async function run(action: () => Promise<void> | void): Promise<void> {
      if (busy || signal.aborted) return;
      busy = true;
      controls.querySelectorAll("button").forEach(button => { button.disabled = true; });
      try { live(); await action(); }
      catch (error) {
        if (!signal.aborted && !renderBrowserAdvice(status, error)) status.textContent = explainOwnerError(error);
      }
      finally {
        busy = false;
        if (!signal.aborted) controls.querySelectorAll("button").forEach(button => {
          button.disabled = button.dataset.locked === "true";
        });
      }
    }
    function button(label: string, action: () => Promise<void> | void): HTMLButtonElement {
      const result = node("button", label, "primary");
      result.type = "button";
      result.addEventListener("click", () => { void run(action); }, { signal });
      controls.append(result);
      return result;
    }
    async function load(): Promise<void> {
      if (submitted) throw new Error("aumlok:refresh-unsettled");
      words.fill(""); words = [];
      replacement = undefined;
      wasm?.dispose(); wasm = undefined;
      bound = current(await post("/api/binding/refresh", {}, signal));
      const loaded = await loadAumlok(signal);
      if (signal.aborted) { loaded.dispose(); return; }
      wasm = loaded;
      unlock();
    }
    function unlock(): void {
      clear("Your current seven words");
      const entry = phraseInputs(stepLifetime.signal);
      fields = entry.inputs;
      content.append(entry.element, node("p", "Never type these words into an AI.", "phrase-warning"));
      button("Unlock locally", async () => {
        if (!wasm || !bound) throw new Error("aumlok:phrase-locked");
        let entered = fields.map(field => field.value.trim()).join(" ");
        let result: RecordValue;
        try { result = wasm.call({ op: "refresh_open", owner_origin: config.ownerOrigin,
          shell_origin: config.shellOrigin, envelope: JSON.stringify(bound.envelope), entered }); }
        finally { entered = ""; }
        exact(result, ["subject"]);
        if (result.subject !== bound.subject) throw new Error("aumlok:refresh-corrupt");
        clear("Choose new words");
        button("Reveal replacement", () => {
          if (!wasm || !bound) throw new Error("aumlok:phrase-locked");
          const draft = wasm.call({ op: "refresh_prepare", ceremony: bound.ceremony });
          exact(draft, ["phrase"]);
          words = text(draft.phrase).split(" ");
          reveal();
        });
      });
    }
    function reveal(): void {
      clear("Keep these seven words");
      content.append(node("p", "Build a story in your own head that walks through these seven words, in order.", "owner-detail"),
        renderPhrase(words, stepLifetime.signal), node("p", "Never type these words into an AI.", "phrase-warning"));
      button("Continue", confirm);
    }
    function confirm(): void {
      clear("Your new words, once more");
      const entry = phraseInputs(stepLifetime.signal);
      fields = entry.inputs;
      const acknowledgement = phraseAcknowledgement(stepLifetime.signal, true);
      content.append(entry.element, node("p", "Never type these words into an AI.", "phrase-warning"), acknowledgement.element);
      const approve = button("Refresh with Touch ID / passkey", async () => {
        if (!acknowledgement.checked() || !bound || !wasm || submitted) throw new Error("aumlok:refresh-input");
        const wrong: number[] = [];
        fields.forEach((field, at) => {
          if (field.value.trim().toLowerCase() !== words[at]) {
            field.setAttribute("aria-invalid", "true"); wrong.push(at + 1);
          } else field.removeAttribute("aria-invalid");
        });
        if (wrong.length) { status.textContent = `Check word${wrong.length > 1 ? "s" : ""} ${wrong.join(", ")}.`; fields[wrong[0] - 1].focus(); return; }
        let entered = fields.map(field => field.value.trim()).join(" ");
        try { replacement = wasm.call({ op: "refresh_confirm", entered }); }
        finally { entered = ""; }
        await submitReplacement();
      });
      approve.dataset.locked = "true"; approve.disabled = true;
      acknowledgement.onChange(() => {
        approve.dataset.locked = String(!acknowledgement.checked());
        approve.disabled = busy || !acknowledgement.checked();
      });
      button("See my words again", reveal);
    }

    function pending(message: string): void {
      clear("Check your refresh");
      status.textContent = message;
      button("Check refresh", checkRefresh);
    }

    async function submitReplacement(): Promise<void> {
      if (!bound || !wasm || !replacement) throw new Error("aumlok:refresh-input");
      const submission = { v: 2, subject: bound.subject, identity_public_key: bound.publicKey,
        envelope: replacement, previous_envelope_sha256: bound.digest };
      const prepared = options(await post("/api/binding/refresh/prepare", {
        ceremony_id: bound.ceremony, submission,
      }, signal), false, config.relyingParty);
      if (prepared.id !== bound.ceremony || !prepared.assertion) throw new Error("aumlok:ceremony-state");
      const assertion = await passkey.assert(prepared.assertion, signal);
      live(); submitted = true;
      pending("Confirming your refresh…");
      try {
        const reply = await post("/api/binding/refresh/prepare", { ceremony_id: bound.ceremony, assertion }, signal);
        if (state(reply) !== "bound" || reply.subject !== bound.subject) throw new Error("aumlok:refresh-corrupt");
        await checkRefresh();
      } catch {
        if (!signal.aborted) pending("Refresh not confirmed. Check before continuing.");
      }
    }

    async function checkRefresh(): Promise<void> {
      if (!submitted || !bound || !wasm || !replacement) throw new Error("aumlok:refresh-input");
      const committed = current(await post("/api/binding/refresh", {}, signal));
      live();
      if (committed.subject !== bound.subject || committed.publicKey !== bound.publicKey) {
        throw new Error("aumlok:refresh-corrupt");
      }
      const observed = JSON.stringify(committed.envelope);
      if (observed === JSON.stringify(replacement) && committed.digest !== bound.digest) {
        const identity = wasm.call({ op: "open", owner_origin: config.ownerOrigin,
          shell_origin: config.shellOrigin, envelope: observed, entered: words.join(" "), person_epoch: 1 });
        if (identity.subject !== bound.subject || identity.identity_public_key !== bound.publicKey) {
          throw new Error("aumlok:refresh-corrupt");
        }
        words.fill(""); words = []; replacement = undefined; clear();
        wasm.call({ op: "refresh_discard" });
        status.textContent = "Seven words refreshed.";
        context.complete();
        return;
      }
      pending("A different refresh is current. Close and reopen Phrase.");
      if (observed !== JSON.stringify(bound.envelope) || committed.digest !== bound.digest) return;
      if (committed.ceremony !== bound.ceremony) {
        status.textContent = "Your current words still apply. This request expired; close and reopen Phrase.";
        return;
      }
      status.textContent = "Your current words still apply. You can retry the same refresh.";
      button("Retry with passkey", submitReplacement);
    }

    function dispose(): void {
      if (signal.aborted) return;
      lifetime.abort(); words.fill(""); words = [];
      stepLifetime.abort();
      replacement = undefined;
      fields.forEach(field => { field.value = ""; }); fields = [];
      try { wasm?.call({ op: "refresh_discard" }); } finally { wasm?.dispose(); wasm = undefined; }
      context.signal.removeEventListener("abort", dispose);
      context.host.replaceChildren();
    }
    context.signal.addEventListener("abort", dispose, { once: true });
    if (context.signal.aborted) dispose();
    else {
      button("Open refresh", load);
      void run(load);
    }
    return dispose;
  } };
}
