// SPDX-License-Identifier: AGPL-3.0-or-later
import { CONTEXT_CORE_DOMAIN, PORTAL_LABELS, type ExchangeMethod, type PortalExchange, type PortalPage, type PortalServices, type ReceiptVerdict } from "./contracts.js";
import { checkAbort, hex, utf8 } from "./bytes.js";
import { receiptCode, receiptVerdict } from "./verdict.js";

// The pinned fixture text has exactly one trailing LF removed.
export const APPROVED_TEXT = "buzz-grant:abababababababababababababababababababababababababababababababab:cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd";
export type PageOptions = {
  readonly prepare?: (method: ExchangeMethod) => Promise<void>;
  readonly release?: () => void;
};
type Active = { controller: AbortController; attempt: string | null; terminal: boolean; publishing: boolean; exchange: PortalExchange | null; unsubscribe: (() => void) | null; scanStop: (() => void) | null };
function element<K extends keyof HTMLElementTagNameMap>(name: K, content?: string): HTMLElementTagNameMap[K] {
  const node = document.createElement(name);
  if (content !== undefined) node.textContent = content;
  return node;
}
function control(label: string, input: HTMLElement): HTMLLabelElement {
  const node = element("label"); node.append(element("span", label), input); return node;
}

export function createPortalPage(options: PageOptions = {}): PortalPage {
  return {
    mount(host: HTMLElement, services: PortalServices): () => void {
      const root = element("section"); root.className = "copresence-portal";
      const title = element("h1", "Point and Bloom"), description = element("p", "Face the two screens toward each other. Use the same context on both devices.");
      const evidence = element("p", PORTAL_LABELS.evidence), claimed = element("p", PORTAL_LABELS.claimed);
      claimed.hidden = true;
      const context = element("textarea"); context.maxLength = 2048; context.value = "Meet in person"; context.rows = 2;
      const method = element("select");
      for (const [value, label] of [["optical", "Screens"], ["optical-audio", "Screens and sound"], ["optical-audio-motion", "Screens, sound and motion"]]) {
        const option = element("option", label); option.value = value; method.append(option);
      }
      const intent = element("input"); intent.type = "checkbox";
      const approved = element("pre", APPROVED_TEXT); approved.className = "approved-text";
      const approval = control("Acknowledge this exact text on the device for this exchange", intent);
      const start = element("button", "Point screens"), stop = element("button", "Stop");
      start.type = stop.type = "button"; stop.disabled = true;
      const phase = element("output", "FACE"); phase.setAttribute("aria-live", "polite");
      const digest = element("p");
      const download = element("a", "Export private receipt"); download.hidden = true; download.download = "copresence-receipt.v1.json";
      const sensor = element("p", "Sound uses the microphone. For motion, gently move each screen during the exchange. These observations remain device claims.");
      root.append(title, description, control("Shared context", context), control("Method fixed before exchange", method), sensor, approval, approved, start, stop, phase, digest, evidence, claimed, download);
      host.append(root);
      let active: Active | null = null, disposed = false, receiptUrl: string | null = null;
      const freshSignal = (): AbortSignal => new AbortController().signal;
      const finish = async (session: Active, outcome: "bloom" | "refused" | "cancelled"): Promise<boolean> => {
        if (session.terminal || session.attempt === null) return true;
        session.terminal = true;
        try { await services.attempts.finish(session.attempt, outcome, freshSignal()); return true; }
        catch { phase.value = "copresence:attempt-storage"; return false; }
      };
      const release = (session: Active): void => {
        session.controller.abort(); session.scanStop?.(); session.unsubscribe?.(); session.exchange?.stop(); options.release?.();
      };
      const resetControls = (): void => { method.disabled = context.disabled = intent.disabled = false; start.disabled = false; stop.disabled = true; };
      const cancel = (): void => {
        const session = active;
        if (!session) return;
        active = null; release(session); services.optical.clear(); void finish(session, "cancelled"); resetControls();
      };
      const run = async (): Promise<void> => {
        if (active || disposed) return;
        const session: Active = { controller: new AbortController(), attempt: null, terminal: false, publishing: false, exchange: null, unsubscribe: null, scanStop: null };
        active = session;
        services.optical.clear();
        method.disabled = context.disabled = intent.disabled = true; start.disabled = true; stop.disabled = false;
        download.hidden = true; claimed.hidden = true; digest.textContent = ""; phase.value = "FACE";
        if (receiptUrl) { URL.revokeObjectURL(receiptUrl); receiptUrl = null; }
        const selected = method.value as ExchangeMethod;
        const contextBytes = utf8.encode(context.value), approvedText = intent.checked ? utf8.encode(APPROVED_TEXT) : null;
        try {
          const reservation = services.attempts.reserve(selected, session.controller.signal);
          const preparation = Promise.resolve(options.prepare?.(selected)).then(() => ({ error: null }), error => ({ error }));
          session.attempt = await reservation;
          if (session.controller.signal.aborted) { await finish(session, "cancelled"); return; }
          const prepared = await preparation;
          if (prepared.error !== null) throw prepared.error;
          checkAbort(session.controller.signal);
          session.exchange = await services.engine.begin({ domain: CONTEXT_CORE_DOMAIN, attemptId: session.attempt, method: selected, contextBytes, approvedText }, session.controller.signal);
          checkAbort(session.controller.signal);
          session.unsubscribe = session.exchange.subscribe(observation => {
            if (active !== session || disposed) return;
            if (observation.phase !== "BLOOM") {
              phase.value = observation.phase;
              if (observation.frameBytes) services.optical.showFrame(observation.frameBytes);
            }
            if (observation.phase === "BLOOM" && observation.receiptBytes) {
              const receiptBytes = observation.receiptBytes;
              let verdict: ReceiptVerdict | null = null;
              try { verdict = receiptVerdict(observation.verdict); } catch { /* Refused below. */ }
              if (verdict === null || receiptCode(verdict) !== null) {
                phase.value = "copresence:receipt-verdict";
                void finish(session, "refused"); active = null; release(session); services.optical.clear(); resetControls(); return;
              }
              claimed.hidden = verdict.verdict !== "CONSISTENT_CLAIMED";
              if (receiptUrl) {
                if (observation.frameBytes) services.optical.showFrame(observation.frameBytes);
                return;
              }
              if (session.publishing) return;
              session.publishing = true;
              void finish(session, "bloom").then(async persisted => {
                if (active !== session || disposed) return;
                if (!persisted) {
                  active = null; release(session); services.optical.clear(); download.hidden = true; resetControls(); return;
                }
                phase.value = "BLOOM";
                if (observation.frameBytes) services.optical.showFrame(observation.frameBytes);
                if (!receiptUrl) {
                  receiptUrl = URL.createObjectURL(new Blob([new Uint8Array(receiptBytes)], { type: "application/json" }));
                  download.href = receiptUrl; download.hidden = false;
                  // Keep the confirmation visible long enough for the other screen to read it.
                  setTimeout(() => {
                    if (active === session) { active = null; release(session); resetControls(); }
                  }, 10000);
                }
                let displayDigest: Uint8Array | null = null;
                let displayUnavailable = false;
                try { displayDigest = await services.optical.showBloom(observation.personNostrKeys, session.controller.signal); }
                catch { displayUnavailable = true; }
                if (active !== session || disposed) return;
                digest.textContent = displayDigest ? `${PORTAL_LABELS.bloom}: ${hex(displayDigest)}`
                  : displayUnavailable ? `${PORTAL_LABELS.bloom}: unavailable.`
                  : `${PORTAL_LABELS.bloom}: nothing shown; both person keys are required.`;
              }).catch(error => {
                if (active !== session || disposed) return;
                phase.value = error instanceof Error && /^(copresence|pentora):[a-z0-9-]+$/.test(error.message) ? error.message : "copresence:bloom-expansion";
                active = null; release(session); services.optical.clear(); download.hidden = true; resetControls();
              }).finally(() => { session.publishing = false; });
            } else if (observation.phase === "REFUSED") {
              try { phase.value = receiptCode(receiptVerdict(observation.verdict)) ?? "copresence:receipt-verdict"; }
              catch { phase.value = "copresence:receipt-verdict"; }
              void finish(session, "refused"); active = null; release(session); services.optical.clear(); resetControls();
            }
          });
          if (active !== session) return;
          session.scanStop = await services.optical.scan(bytes => { void session.exchange?.receive(bytes); }, session.controller.signal);
          if (active !== session) session.scanStop();
        } catch (error) {
          const outcome = session.controller.signal.aborted ? "cancelled" : "refused";
          session.exchange?.stop(); session.unsubscribe?.(); session.scanStop?.();
          if (active === session) {
            phase.value = error instanceof Error && error.message.startsWith("copresence:") ? error.message : "copresence:device-unavailable";
            active = null; release(session); services.optical.clear(); resetControls();
          }
          await finish(session, outcome);
        }
      };
      const onStart = (): void => { void run(); };
      const onVisibility = (): void => { if (document.visibilityState === "hidden") cancel(); };
      start.addEventListener("click", onStart); stop.addEventListener("click", cancel);
      document.addEventListener("visibilitychange", onVisibility); window.addEventListener("pagehide", cancel);
      return () => {
        disposed = true; cancel();
        document.removeEventListener("visibilitychange", onVisibility); window.removeEventListener("pagehide", cancel);
        start.removeEventListener("click", onStart); stop.removeEventListener("click", cancel);
        if (receiptUrl) URL.revokeObjectURL(receiptUrl);
        root.remove();
      };
    },
  };
}
export const portalPage = createPortalPage();
