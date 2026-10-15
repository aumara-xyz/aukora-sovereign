// SPDX-License-Identifier: AGPL-3.0-or-later
import { ALLOCATE_PATH, AllocationRefusal, REQUEST_SCHEMA, decodeHandoff, encodeRequest,
  hex, readBody, refuse, shellOrigin } from "./contracts.js";

function requestKey(): string {
  const random = crypto.getRandomValues(new Uint8Array(32));
  const key = btoa(String.fromCharCode(...random)).replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "");
  random.fill(0);
  return key;
}

function element<K extends keyof HTMLElementTagNameMap>(tag: K, text?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  return node;
}

export function mountGoSovereign(root: HTMLElement): () => void {
  if (window.top !== window.self || !isSecureContext) refuse("page-context");
  const origin = shellOrigin(window.location.origin);
  const controller = new AbortController();
  let pending: { code: string; key: string } | null = null;
  let busy = false;
  let disposed = false;
  const title = element("h1", "Go Sovereign");
  const introduction = element("p", "Paste your invitation code to get your own AUKORA node.");
  const form = element("form");
  const label = element("label", "Invitation code");
  const code = element("input");
  code.id = "invite-code";
  code.name = "code";
  code.type = "text";
  code.autocomplete = "off";
  code.spellcheck = false;
  code.maxLength = 128;
  code.required = true;
  code.setAttribute("autocapitalize", "none");
  code.setAttribute("aria-describedby", "invite-hint");
  label.htmlFor = code.id;
  const hint = element("p", "Your code has 32 characters: 0–9 and a–f. Keep your separate invite secret private.");
  hint.id = "invite-hint";
  hint.className = "hint";
  const submit = element("button", "Get my node");
  submit.type = "submit";
  const status = element("p", "After allocation, your node opens at its one link. Joining and claiming happen there.");
  status.setAttribute("role", "status");
  status.setAttribute("aria-live", "polite");
  form.append(label, code, hint, submit);
  root.replaceChildren(title, introduction, form, status);

  async function allocate(event: SubmitEvent): Promise<void> {
    event.preventDefault();
    if (busy || disposed) return;
    const candidate = code.value.trim();
    if (!hex(candidate, 32)) {
      status.textContent = "Enter the 32-character invitation code exactly as you received it.";
      code.focus();
      return;
    }
    if (pending && pending.code !== candidate) {
      status.textContent = "The earlier allocation may still be completing. Retry its original code.";
      code.value = pending.code;
      return;
    }
    pending ??= { code: candidate, key: requestKey() };
    busy = true;
    submit.disabled = true;
    code.disabled = true;
    status.textContent = "Preparing your node. Keep this page open.";
    const attempt = new AbortController();
    const cancelAttempt = (): void => attempt.abort();
    controller.signal.addEventListener("abort", cancelAttempt, { once: true });
    const timer = setTimeout(cancelAttempt, 190000);
    try {
      const response = await fetch(new URL(ALLOCATE_PATH, origin), {
        method: "POST", mode: "same-origin", credentials: "omit", redirect: "error", cache: "no-store",
        referrerPolicy: "no-referrer", headers: { "content-type": "application/json" },
        body: encodeRequest({ code: pending.code, request_key: pending.key, schema: REQUEST_SCHEMA }),
        signal: attempt.signal,
      });
      if (response.url !== new URL(ALLOCATE_PATH, origin).href ||
          response.headers.get("content-type")?.split(";", 1)[0] !== "application/json") refuse("response-invalid");
      if (!response.ok) {
        await response.body?.cancel();
        refuse("allocation-unavailable");
      }
      const handoff = decodeHandoff(await readBody(response.body, attempt.signal));
      if (disposed) return;
      const target = new URL("/", handoff.shell_origin);
      if (target.origin === origin) refuse("shell-invalid");
      target.hash = `claim=${handoff.claim_token}`;
      code.value = "";
      status.textContent = "Your node is ready. Opening your Spatial app.";
      window.location.assign(target.href);
    } catch (error) {
      if (disposed) return;
      status.textContent = error instanceof AllocationRefusal && error.code === "go-sovereign:handoff-invalid"
        ? "The allocation response could not be verified. Retry uses the same request."
        : "The allocation was not confirmed. Retry uses the same request for this invitation.";
      submit.textContent = "Retry this allocation";
      if (pending) code.value = pending.code;
      submit.disabled = false;
      code.disabled = false;
      busy = false;
    } finally {
      clearTimeout(timer);
      controller.signal.removeEventListener("abort", cancelAttempt);
    }
  }

  form.addEventListener("submit", allocate, { signal: controller.signal });
  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    controller.abort();
    pending = null;
    code.value = "";
    root.replaceChildren();
  };
  window.addEventListener("pagehide", dispose, { once: true, signal: controller.signal });
  return dispose;
}

const root = document.querySelector<HTMLElement>("[data-go-sovereign]");
if (root) {
  try { mountGoSovereign(root); }
  catch { root.textContent = "Go Sovereign requires its secure top-level deployment page."; }
}
