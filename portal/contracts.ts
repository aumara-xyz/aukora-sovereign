// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Guide } from "./guide.js";
export const LEGACY_CORE_DOMAIN = "copresence.v0" as const;
export const CONTEXT_CORE_DOMAIN = "copresence.v1" as const;
export const INTENT_DOMAINS = Object.freeze({
  text: "copresence.intent.v1",
  nonce: "copresence.intent-nonce.v1",
  acknowledgement: "copresence.intent-ack.v1",
});

export const PORTAL_TIMING = Object.freeze({
  rotationMs: 1000,
  idleScanHz: 2,
  exchangeScanHz: 10,
  legacyWindowSeconds: 10,
});

export type PortalPhase = "FACE" | "SEENYOU" | "HANDSHAKE" | "BLOOM" | "REFUSED";
export type ExchangeMethod = "optical" | "optical-audio" | "optical-audio-motion";
export type RefusalCode = `copresence:${string}`;

export type ReceiptVerdict =
  | { readonly verdict: "CONSISTENT_CLAIMED"; readonly positionSource: "SELF_REPORTED_UNVERIFIABLE" }
  | { readonly verdict: "SUSPICIOUS"; readonly code: RefusalCode }
  // A verified receipt may carry no position assessment.
  | { readonly verdict: "UNDETERMINED"; readonly code: RefusalCode | null };

export type PortalObservation = {
  readonly phase: PortalPhase;
  readonly attemptId: string;
  readonly method: ExchangeMethod;
  readonly frameBytes: Uint8Array | null;
  // Pairing root from both person keys; absent until the host resolves both bindings.
  readonly bloomDigest: Uint8Array | null;
  readonly personNostrKeys: PersonNostrKeys | null;
  readonly verdict: ReceiptVerdict | null;
  readonly receiptBytes: Uint8Array | null;
};

export type PersonNostrKeys = {
  readonly local: Uint8Array | null;
  readonly peer: Uint8Array | null;
};

export type PersonNostrKeysForReceipt = (receiptBytes: Uint8Array) => PersonNostrKeys | null;

export type ContextExchange = {
  readonly domain: typeof CONTEXT_CORE_DOMAIN;
  readonly attemptId: string;
  readonly method: ExchangeMethod;
  readonly contextBytes: Uint8Array;
  readonly approvedText: Uint8Array | null;
};

export interface AttemptStore {
  reserve(method: ExchangeMethod, signal: AbortSignal): Promise<string>;
  finish(attemptId: string, outcome: "bloom" | "refused" | "cancelled", signal: AbortSignal): Promise<void>;
}

export interface PortalExchange {
  receive(frameBytes: Uint8Array): Promise<void>;
  subscribe(listener: (observation: PortalObservation) => void): () => void;
  stop(): void;
}

export interface CopresenceEngine {
  begin(exchange: ContextExchange, signal: AbortSignal): Promise<PortalExchange>;
  verifyLegacyReceipt(receiptBytes: Uint8Array, approvedText: Uint8Array | null, signal: AbortSignal): Promise<ReceiptVerdict>;
  verifyContextReceipt(receiptBytes: Uint8Array, approvedText: Uint8Array | null, signal: AbortSignal): Promise<ReceiptVerdict>;
}

export interface OpticalSurface {
  /** What the camera sees while nothing reads (the hint for the person), when the decoder can say. */
  readonly guide?: Guide;
  showFrame(bytes: Uint8Array): void;
  scan(consume: (bytes: Uint8Array) => void, signal: AbortSignal): Promise<() => void>;
  showBloom(keys: PersonNostrKeys | null, signal?: AbortSignal): Promise<Uint8Array | null>;
  clear(): void;
}

export type PortalServices = {
  readonly engine: CopresenceEngine;
  readonly attempts: AttemptStore;
  readonly optical: OpticalSurface;
};

export type PortalPage = {
  mount(host: HTMLElement, services: PortalServices): () => void;
};

export const PORTAL_LABELS = Object.freeze({
  bloom: "Relationship bloom",
  evidence: "Co-presence is evidence and grants no authority.",
  claimed: "Position is self-reported and unverifiable.",
  remote: "Remote or relayed pairing",
  inPerson: "Met in person",
});
