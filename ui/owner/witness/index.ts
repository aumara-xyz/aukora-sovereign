// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerPane, OwnerWitness, WitnessObservation } from "../contracts.js";
import { assertActive } from "./contracts.js";
import type { BrowserCheckpoint, PresentedHead, WitnessServices } from "./contracts.js";
import { checkpoint, checkpointFor, presented } from "./codec.js";
import { consistency } from "./proof.js";

export { createBrowserWitnessStore } from "./store.js";
export type {
  BrowserCheckpoint, PresentedHead, WitnessHeadSource, WitnessPrimitives,
  WitnessServices, WitnessStore,
} from "./contracts.js";

export function disabledOwnerWitness(): OwnerWitness {
  return { async observeVisit(signal) {
    assertActive(signal);
    return { state: "alarm", reason: "unavailable" };
  } };
}

export function witnessPane(witness: OwnerWitness): OwnerPane {
  return context => {
    const status = document.createElement("p");
    status.className = "owner-witness-status";
    status.setAttribute("role", "status");
    status.textContent = "Browser witness not enabled";
    context.host.replaceChildren(status);
    void witness.observeVisit(context.signal).then(observation => {
      if (context.signal.aborted) return;
      status.textContent = observation.state === "first" || observation.state === "extension"
        ? `Browser head retained · ${observation.treeSize}`
        : observation.reason === "rollback" ? "History is older than this browser's head."
          : observation.reason === "fork" ? "History conflicts with this browser's head."
            : observation.reason === "unavailable" ? "Browser witness not enabled" : "History not yet verified.";
    }).catch(() => {});
    return () => status.remove();
  };
}

function alarm(reason: "rollback" | "fork" | "unavailable" | "undetermined"): WitnessObservation {
  return { state: "alarm", reason };
}

async function observe(services: WitnessServices, signal: AbortSignal): Promise<WitnessObservation> {
  for (let attempt = 0; attempt < 2; attempt++) {
    assertActive(signal);
    const stored = await services.store.load(signal);
    assertActive(signal);
    let previous: BrowserCheckpoint | null = null;
    if (stored !== null) {
      try { previous = checkpoint(stored); } catch { return alarm("undetermined"); }
    }
    const response = await services.source.present(previous?.treeSize ?? null, signal);
    assertActive(signal);
    let head: PresentedHead;
    try { head = await presented(response, services.primitives, signal); }
    catch (error) {
      if (error instanceof Error && error.message === "witness:head-invalid") return alarm("undetermined");
      throw error;
    }
    assertActive(signal);
    if (previous) {
      if (head.treeSize < previous.treeSize) return alarm("rollback");
      if (head.treeSize === previous.treeSize && head.root !== previous.root) return alarm("fork");
      const finding = await consistency(previous, head, services.primitives, signal);
      if (finding !== "extension") return alarm(finding);
    } else if (head.retainedTreeSize !== 0 || head.proofFromPrevious.length !== 0) {
      return alarm("undetermined");
    }
    assertActive(signal);
    const replacement = await services.store.replace(previous, checkpointFor(head), signal);
    assertActive(signal);
    if (replacement === "stored") {
      return { state: previous === null ? "first" : "extension", treeSize: head.treeSize };
    }
    if (replacement !== "changed") return alarm("unavailable");
  }
  return alarm("undetermined");
}

function untilAborted<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const aborted = (): void => reject(new Error("witness:aborted"));
    signal.addEventListener("abort", aborted, { once: true });
    if (signal.aborted) aborted();
    operation.then(resolve, reject).finally(() => signal.removeEventListener("abort", aborted));
  });
}

export function createOwnerWitness(services: WitnessServices): OwnerWitness {
  const timeoutMs = services.timeoutMs ?? 10_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60_000) {
    throw new Error("witness:invalid-timeout");
  }
  const configuration: WitnessServices = Object.freeze({
    store: services.store, source: services.source, primitives: services.primitives,
  });
  return Object.freeze({
    async observeVisit(signal: AbortSignal): Promise<WitnessObservation> {
      const visit = new AbortController();
      const cancel = (): void => visit.abort();
      signal.addEventListener("abort", cancel, { once: true });
      if (signal.aborted) cancel();
      const deadline = setTimeout(cancel, timeoutMs);
      try {
        return await untilAborted(observe(configuration, visit.signal), visit.signal);
      } catch {
        return alarm("unavailable");
      } finally {
        clearTimeout(deadline);
        signal.removeEventListener("abort", cancel);
      }
    },
  });
}
