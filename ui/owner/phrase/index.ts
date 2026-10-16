// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerPaneContext, OwnerDisposer, PhrasePaneService } from "../contracts.js";
import { domainDigest, hex, parseAuthorization, parseCard, sha256, verifyCommitments } from "../cards/codec.js";
import { renderAuthorization, renderCard } from "../cards/render.js";
import type { PhraseConfiguration, PhraseWasmSession, RefreshSnapshot, RefreshSubmission } from "./services.js";
import { bytes, copyCurrent, copySubmission, id, refuse, sameCurrent, sameSubmission, snapshot } from "./validate.js";
import { createView } from "./view.js";
import { explainOwnerError } from "../phrase-layout.js";
export { createLivePhraseService } from "./live.js";

export type * from "./services.js";

export function createPhraseService(configuration: PhraseConfiguration): PhrasePaneService {
  const { ownerOrigin, shellOrigin, refreshTarget, wasm, ceremonies, passkey } = configuration;
  if (typeof refreshTarget !== "string" || !refreshTarget || refreshTarget.length > 256) refuse("refresh-input");
  return { mount };

  function mount(context: OwnerPaneContext): OwnerDisposer {
    if (context.route.pane !== "phrase" || context.shellOrigin !== shellOrigin) refuse("owner-frame");
    if (context.signal.aborted) return () => {};
    let local: PhraseWasmSession | undefined = wasm.OwnerPhraseSession.verify(ownerOrigin, shellOrigin);
    const view = createView(context.host);
    const lifetime = new AbortController();
    const signal = lifetime.signal;
    let state: RefreshSnapshot | undefined;
    let submission: RefreshSubmission | undefined;
    let unlocked = false;
    let busy = false;
    let uncertain = false;
    let approval: { phase: "prepare" | "finish"; proposalId: string; challenge: Uint8Array; expires: number } | undefined;
    const downloads = new Set<string>();

    function live(): void {
      if (signal.aborted) throw new DOMException("Phrase pane closed", "AbortError");
      const check = wasm.OwnerPhraseSession.verify(ownerOrigin, shellOrigin);
      check.free();
    }

    function secret(): PhraseWasmSession {
      live();
      if (!local) refuse("owner-frame");
      return local;
    }

    function resetSecret(): void {
      local?.free();
      local = signal.aborted ? undefined : wasm.OwnerPhraseSession.verify(ownerOrigin, shellOrigin);
      unlocked = false;
      view.entry.value = "";
      view.phrase.textContent = "";
      view.saved.checked = false;
      view.legacy.checked = false;
      submission = undefined;
      approval = undefined;
      view.review.replaceChildren();
    }

    function controls(): void {
      const pending = state?.pending;
      const blocked = pending?.state === "in-doubt";
      const refreshing = !!submission || pending?.state === "prepared" || blocked;
      view.entryLabel.hidden = unlocked || !state || uncertain;
      view.unlock.hidden = unlocked || !state || uncertain;
      view.draw.hidden = !unlocked || refreshing || uncertain;
      view.prepare.hidden = !unlocked || !submission || !!approval || blocked || uncertain;
      view.approve.hidden = !approval || uncertain;
      view.savedLabel.hidden = !submission || blocked || uncertain;
      view.phrase.hidden = !unlocked || !submission || uncertain;
      view.backup.hidden = !unlocked || refreshing || uncertain;
      view.legacyLabel.hidden = view.backup.hidden;
      view.legacyDownload.hidden = view.backup.hidden || !view.legacy.checked;
      view.resume.hidden = false;
      view.close.hidden = !unlocked || refreshing || uncertain;
      for (const button of view.controls.querySelectorAll("button")) button.disabled = busy;
      view.entry.disabled = busy;
      view.saved.disabled = busy;
      view.legacy.disabled = busy;
      view.prepare.disabled ||= !view.saved.checked;
      view.approve.disabled ||= !view.saved.checked;
    }

    function fail(error: unknown): void {
      if (signal.aborted) return;
      view.status.textContent = explainOwnerError(error);
      view.status.setAttribute("role", "alert");
    }

    async function run(action: () => void | Promise<void>): Promise<void> {
      if (busy || signal.aborted) return;
      busy = true; controls();
      view.status.setAttribute("role", "status");
      try { live(); await action(); }
      catch (error) { fail(error); }
      finally {
        busy = false;
        if (signal.aborted) { local?.free(); local = undefined; }
        else controls();
      }
    }

    function showPending(): void {
      const pending = state?.pending;
      if (!pending || pending.state === "cancelled" || pending.state === "expired") return;
      if (pending.state === "in-doubt") {
        view.status.textContent = "The owner service has not resolved this refresh. Resume to read its durable state.";
        return;
      }
      if (pending.state === "committed") return;
      const s = pending.submission;
      secret().resume(s.ceremony, s.protectedNonce, s.protectedCiphertext, s.replacement);
      submission = s;
      view.phrase.textContent = secret().phrase();
      view.prepare.textContent = "Review final phrase replacement";
      view.status.textContent = "Prepared refresh resumed. Save the replacement phrase before approving retirement of the old online envelope.";
    }

    async function resume(): Promise<void> {
      uncertain = true;
      view.status.textContent = "Reading the current envelope and refresh state.";
      const next = await snapshot(await ceremonies.resume(signal));
      live();
      const old = state;
      const draft = submission;
      if (next.pending?.state === "committed" && draft && unlocked
        && sameSubmission(next.pending.submission, draft)) {
        secret().adopt_replacement(next.current.envelope);
        submission = undefined; approval = undefined;
        view.phrase.textContent = ""; view.review.replaceChildren(); view.saved.checked = false;
      } else if (!old || !sameCurrent(old.current, next.current)) resetSecret();
      state = next;
      uncertain = false;
      approval = undefined;
      view.review.replaceChildren();
      if (unlocked) {
        secret().discard_draft();
        submission = undefined;
        view.phrase.textContent = "";
        view.saved.checked = false;
        showPending();
      }
      view.status.textContent = next.pending?.state === "committed"
        ? "The owner service confirms the replacement is current. Previously downloaded copies remain decryptable."
        : next.pending?.state === "in-doubt" ? "Refresh outcome unresolved. Resume before taking another action."
        : next.pending?.state === "prepared" && unlocked
          ? "Prepared refresh resumed. Save the replacement phrase before its final approval."
          : unlocked ? "Current envelope confirmed. Choose refresh or backup."
          : "Current envelope loaded. Enter its phrase to continue locally.";
    }

    async function unlock(): Promise<void> {
      if (!state) refuse("refresh-input");
      view.status.textContent = "Opening the envelope on the owner origin.";
      try {
        if (secret().unlock(state.current.envelope, view.entry.value) !== state.current.subject) {
          resetSecret(); refuse("refresh-corrupt");
        }
        unlocked = true;
      } finally { view.entry.value = ""; }
      view.status.textContent = "Phrase unlocked locally. Choose refresh or backup.";
      showPending();
    }

    async function draw(): Promise<void> {
      if (!state || !unlocked || submission || uncertain
        || state.pending?.state === "prepared" || state.pending?.state === "in-doubt") refuse("refresh-input");
      const current = state.current;
      const started = await ceremonies.begin(copyCurrent(current), signal);
      live(); id(started.ceremony); id(started.session);
      secret().prepare(started.ceremony);
      submission = { ceremony: started.ceremony, session: started.session, subject: current.subject,
        expectedEpoch: current.ownerEpoch, expectedRevision: current.revision, previousDigest: current.digest,
        replacement: secret().replacement_envelope(), protectedNonce: secret().protected_nonce(),
        protectedCiphertext: secret().protected_ciphertext() };
      view.phrase.textContent = secret().phrase();
      view.saved.checked = false;
      view.prepare.textContent = "Review phrase refresh";
      view.status.textContent = "Save all seven replacement words. The current online envelope has not changed.";
    }

    async function review(): Promise<void> {
      if (!submission || !view.saved.checked || uncertain) refuse("refresh-input");
      const phase = state?.pending?.state === "prepared" ? "finish" : "prepare";
      const loaded = await ceremonies.review(phase, copySubmission(submission), signal);
      if (!Number.isInteger(loaded.relativeTimeoutMs) || loaded.relativeTimeoutMs! < 100
        || loaded.relativeTimeoutMs! > 300_000) refuse("refresh-proof");
      const expires = performance.now() + loaded.relativeTimeoutMs!;
      live();
      bytes(loaded.canonicalCard, 1, 65536); bytes(loaded.canonicalAuthorization, 1, 65536);
      const cardBytes = Uint8Array.from(loaded.canonicalCard);
      const authBytes = Uint8Array.from(loaded.canonicalAuthorization);
      const card = parseCard(cardBytes);
      const auth = parseAuthorization(authBytes, loaded.proposalId);
      if (auth.subject !== submission.subject || BigInt(auth.epoch) !== submission.expectedEpoch
        || auth.op !== "apply" || auth.cell !== null || auth.target !== refreshTarget
        || auth.base_sha256 !== submission.previousDigest
        || auth.new_sha256 !== hex(await sha256(submission.replacement))) refuse("refresh-proof");
      await verifyCommitments(cardBytes, auth);
      const challenge = await domainDigest("aukora:owner-authorization:v1", authBytes);
      live();
      view.review.replaceChildren(renderAuthorization(view.document, auth), renderCard(view.document, card));
      approval = { phase, proposalId: loaded.proposalId, challenge, expires };
      view.status.textContent = phase === "prepare"
        ? "Review the exact preparation authorization, then approve with your passkey."
        : "Review the exact replacement authorization. This retires the previous online envelope; old downloads still work offline.";
    }

    async function approve(): Promise<void> {
      const selected = approval;
      const draft = submission;
      if (!selected || !draft || !view.saved.checked || selected.expires <= performance.now()) refuse("refresh-proof");
      const assertion = await passkey.assertExact(Uint8Array.from(selected.challenge), shellOrigin, signal,
        Math.floor(selected.expires - performance.now()));
      live(); bytes(assertion, 1, 65536);
      if (selected.expires <= performance.now()) refuse("refresh-expired");
      uncertain = true;
      approval = undefined;
      view.review.replaceChildren();
      const next = await snapshot(selected.phase === "prepare"
        ? await ceremonies.prepare(copySubmission(draft), selected.proposalId, assertion, signal)
        : await ceremonies.finish(draft.ceremony, selected.proposalId, assertion, signal));
      live();
      if (!next.pending || !sameSubmission(next.pending.submission, draft)) refuse("refresh-corrupt");
      if (selected.phase === "prepare" && next.pending.state !== "prepared") refuse("refresh-unsettled");
      if (selected.phase === "finish" && next.pending.state !== "committed") refuse("refresh-unsettled");
      // Read back durable status before enabling another change or backup.
      await resume();
    }

    function download(content: Uint8Array, version: 1 | 2): void {
      live();
      const url = URL.createObjectURL(new Blob([Uint8Array.from(content)], { type: "application/json" }));
      downloads.add(url);
      const anchor = view.document.createElement("a");
      anchor.href = url;
      anchor.download = `aukora-backup-v${version}.json`;
      view.panel.append(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => { URL.revokeObjectURL(url); downloads.delete(url); }, 1000);
    }

    async function backup(): Promise<void> {
      if (!state || !unlocked || submission || uncertain
        || state.pending?.state === "prepared" || state.pending?.state === "in-doubt") refuse("refresh-input");
      const request = await ceremonies.beginBackup(copyCurrent(state.current), signal);
      live(); id(request.ceremony); bytes(request.credential, 1, 1024); bytes(request.challenge, 32, 32);
      if (request.expectedEpoch !== state.current.ownerEpoch) refuse("refresh-stale");
      view.status.textContent = "Use the original passkey to protect this backup.";
      const encrypted = await secret().backup_v2(request.credential, request.originalRpId, request.ceremony,
        request.challenge, request.expectedEpoch, request.expiresAtMs, signal);
      live();
      await ceremonies.finishBackup(request.ceremony, secret().backup_assertion(), signal);
      live(); download(encrypted, 2);
      view.status.textContent = "Passkey-bound v2 backup offered for download. Keep your phrase and the original passkey.";
    }

    function dispose(): void {
      if (signal.aborted) return;
      lifetime.abort();
      context.signal.removeEventListener("abort", dispose);
      window.removeEventListener("pagehide", dispose);
      view.entry.value = ""; view.phrase.textContent = "";
      view.panel.remove();
      for (const url of downloads) URL.revokeObjectURL(url);
      downloads.clear();
      if (!busy) { local?.free(); local = undefined; }
    }

    const bind = (button: HTMLButtonElement, action: () => void | Promise<void>) => {
      button.addEventListener("click", () => { void run(action); }, { signal });
    };
    bind(view.unlock, unlock); bind(view.draw, draw); bind(view.prepare, review);
    bind(view.approve, approve); bind(view.resume, resume); bind(view.backup, backup);
    bind(view.legacyDownload, () => {
      if (!view.legacy.checked || !unlocked || submission || uncertain) refuse("backup-prf-required");
      download(secret().backup_v1(), 1);
      view.status.textContent = "Explicitly requested phrase-only v1 copy offered for download.";
    });
    bind(view.close, () => { context.complete(); dispose(); });
    view.saved.addEventListener("change", controls, { signal });
    view.legacy.addEventListener("change", controls, { signal });
    context.signal.addEventListener("abort", dispose, { once: true });
    window.addEventListener("pagehide", dispose, { once: true });
    if (context.signal.aborted) dispose();
    else void run(resume);
    return dispose;
  }
}
