// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  CONTEXT_CORE_DOMAIN, type PortalExchange, type PortalObservation, type PortalServices,
} from "../contracts.js";
import { APPROVED_TEXT } from "../page.js";
import { equal } from "../bytes.js";
import type { JoiningConfiguration, PreparedJoiningExchange } from "./services.js";
import { live, methodForLayers, refuse } from "./validate.js";

type Outcome = "bloom" | "refused" | "cancelled";

function requireJoiningOptical(): void {
  // The current optical protocol is disabled for joining.
  refuse("joining-optical");
}

function reason(error: unknown): string {
  return error instanceof Error && /^[a-z][a-z0-9-]*:[a-z0-9-]+$/.test(error.message)
    ? error.message : "invites:joining-optical";
}

function bytes(value: unknown): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length < 1 || value.length > 65_536) {
    refuse("joining-optical-bytes");
  }
  return Uint8Array.from(value);
}

export function mountJoiningExchange(host: HTMLElement, preparedExchange: PreparedJoiningExchange,
  configuration: JoiningConfiguration, parentSignal: AbortSignal,
  receiptCallback: (receipt: Uint8Array) => void,
  errorCallback: (error: unknown) => void): () => void {
  live(parentSignal);
  requireJoiningOptical();
  const method = methodForLayers(preparedExchange.context.requiredLayers);
  const controller = new AbortController(), signal = controller.signal;
  const root = document.createElement("section"), surface = document.createElement("div");
  const status = document.createElement("output"), start = document.createElement("button");
  const acknowledgement = document.createElement("input");
  acknowledgement.type = "checkbox";
  status.setAttribute("aria-live", "polite");
  status.textContent = "Ready for your two-device exchange.";
  start.type = "button"; start.textContent = "Start optical exchange";
  const needsAcknowledgement = preparedExchange.context.requiredLayers.intentAcknowledgement;
  if (needsAcknowledgement) {
    const approved = document.createElement("pre"), label = document.createElement("label");
    approved.textContent = APPROVED_TEXT;
    label.append(acknowledgement, document.createTextNode("I acknowledge this exact text for this exchange."));
    root.append(approved, label);
    start.disabled = true;
  }
  root.append(start, status, surface); host.append(root);

  let services: PortalServices | null = null, exchange: PortalExchange | null = null;
  let unsubscribe: (() => void) | null = null, scanStop: (() => void) | null = null;
  let attempt: string | null = null, finishing: Promise<void> | null = null;
  let started = false, stopped = false, disposed = false, reported = false, delivered = false;
  let confirmationClosed = false;
  let acceptedReceipt: Uint8Array | null = null;
  let failure: unknown = null;
  let queue: Promise<void> = Promise.resolve();
  let ready: () => void = () => {};
  const initialization = new Promise<void>(resolve => { ready = resolve; });
  const expiry = setTimeout(() => {
    if (delivered) closeConfirmation();
    else fail(new Error("invites:joining-expired"));
  }, Math.max(0, preparedExchange.context.expiresAtMs - Date.now()));

  function closeConfirmation(): void {
    confirmationClosed = true;
    release();
  }

  function active(): void {
    if (delivered && Date.now() >= preparedExchange.context.expiresAtMs) closeConfirmation();
    live(signal);
    if (stopped || disposed) refuse("joining-cancelled");
    if (!delivered && Date.now() >= preparedExchange.context.expiresAtMs) refuse("joining-expired");
  }

  function report(error: unknown): void {
    if (reported || disposed || parentSignal.aborted || confirmationClosed) return;
    reported = true;
    status.textContent = reason(error);
    try {
      void Promise.resolve(errorCallback(error)).catch(callbackError => {
        status.textContent = reason(callbackError);
      });
    }
    catch (callbackError) { status.textContent = reason(callbackError); }
  }

  function finish(outcome: Outcome): Promise<void> {
    if (attempt === null || services === null) return Promise.resolve();
    // Persist the first terminal outcome once; later observations cannot replace it.
    finishing ??= Promise.resolve().then(() => services!.attempts.finish(attempt!, outcome,
      new AbortController().signal));
    return finishing;
  }

  function release(): void {
    stopped = true; start.disabled = true; acknowledgement.disabled = true;
    clearTimeout(expiry); controller.abort(); ready();
    const stopScan = scanStop, stopSubscription = unsubscribe, stopExchange = exchange;
    scanStop = unsubscribe = null; exchange = null;
    for (const stop of [stopScan, stopSubscription, stopExchange ? () => stopExchange.stop() : null,
      services ? () => services!.optical.clear() : null]) {
      try {
        void Promise.resolve(stop?.()).catch(error => { failure ??= error; report(error); });
      } catch (error) { failure ??= error; }
    }
  }

  function fail(error: unknown): void {
    failure ??= error;
    release();
    const cancelled = disposed || parentSignal.aborted || confirmationClosed;
    void finish(cancelled ? "cancelled" : "refused").then(() => {
      if (!cancelled) report(failure);
    }, persistenceError => report(persistenceError));
  }

  function cancel(): void {
    release();
    void finish("cancelled").catch(report);
  }

  async function observe(observation: PortalObservation): Promise<void> {
    await initialization;
    if (stopped || disposed) return;
    active();
    if (observation.attemptId !== attempt || observation.method !== method
      || !["FACE", "SEENYOU", "HANDSHAKE", "BLOOM", "REFUSED"].includes(observation.phase)) {
      refuse("joining-observation");
    }
    if (observation.phase === "REFUSED") {
      const verdict = observation.verdict;
      if (verdict?.accepted !== false || !/^copresence:[A-Za-z0-9_-]+$/.test(verdict.code)) {
        refuse("joining-optical-refused");
      }
      throw new Error(verdict.code);
    }
    if (observation.frameBytes !== null) {
      await services!.optical.showFrame(bytes(observation.frameBytes));
      active();
    }
    status.textContent = observation.phase;
    if (observation.phase !== "BLOOM") {
      if (observation.receiptBytes !== null) refuse("joining-observation");
      return;
    }
    if (observation.verdict?.accepted !== true || observation.verdict.code !== null) {
      refuse("joining-optical-verdict");
    }
    const receipt = bytes(observation.receiptBytes);
    if (delivered) {
      if (!acceptedReceipt || !equal(receipt, acceptedReceipt)) refuse("joining-receipt-changed");
      return;
    }
    await finish("bloom");
    active();
    acceptedReceipt = receipt.slice();
    delivered = true;
    await receiptCallback(receipt);
  }

  function observation(value: PortalObservation): void {
    if (stopped || disposed) return;
    try {
      const copied = { ...value,
        frameBytes: value.frameBytes === null ? null : bytes(value.frameBytes),
        receiptBytes: value.receiptBytes === null ? null : bytes(value.receiptBytes),
        verdict: value.verdict === null ? null : { ...value.verdict },
      };
      queue = queue.then(() => observe(copied)).catch(fail);
    } catch (error) { fail(error); }
  }

  async function run(): Promise<void> {
    active();
    const approvedText = needsAcknowledgement ? new TextEncoder().encode(APPROVED_TEXT) : null;
    if (needsAcknowledgement && !acknowledgement.checked) refuse("joining-intent-required");
    services = await configuration.portal(surface, method, signal);
    active();
    await services.optical.clear();
    attempt = await services.attempts.reserve(method, signal);
    active();
    if (typeof attempt !== "string" || attempt.length < 1) refuse("joining-attempt");
    exchange = await services.engine.begin({ domain: CONTEXT_CORE_DOMAIN, attemptId: attempt,
      method, contextBytes: Uint8Array.from(preparedExchange.canonicalContext), approvedText }, signal);
    active();
    unsubscribe = exchange.subscribe(observation);
    if (typeof unsubscribe !== "function") refuse("joining-optical-subscription");
    active();
    scanStop = await services.optical.scan(input => {
      if (stopped || disposed) return;
      try {
        active();
        const incoming = bytes(input), current = exchange;
        if (!current) refuse("joining-optical-exchange");
        void Promise.resolve(current.receive(incoming)).catch(fail);
      } catch (error) { fail(error); }
    }, signal);
    if (typeof scanStop !== "function") refuse("joining-optical-scan");
    active();
    ready();
  }

  const onStart = (): void => {
    if (started || stopped || disposed || (needsAcknowledgement && !acknowledgement.checked)) return;
    started = true; start.disabled = true; acknowledgement.disabled = true;
    status.textContent = "Preparing the optical exchange.";
    void run().catch(fail);
  };
  const onAcknowledgement = (): void => {
    if (!started && !stopped && !disposed) start.disabled = !acknowledgement.checked;
  };
  start.addEventListener("click", onStart);
  acknowledgement.addEventListener("change", onAcknowledgement);
  parentSignal.addEventListener("abort", cancel, { once: true });
  if (parentSignal.aborted) cancel();
  return () => {
    if (disposed) return;
    disposed = true; cancel();
    parentSignal.removeEventListener("abort", cancel);
    start.removeEventListener("click", onStart);
    acknowledgement.removeEventListener("change", onAcknowledgement);
    root.remove();
  };
}
