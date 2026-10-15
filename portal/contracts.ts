// SPDX-License-Identifier: AGPL-3.0-or-later
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
  | { readonly verdict: "UNDETERMINED"; readonly code: RefusalCode };

export type PortalObservation = {
  readonly phase: PortalPhase;
  readonly attemptId: string;
  readonly method: ExchangeMethod;
  readonly frameBytes: Uint8Array | null;
  readonly bloomDigest: Uint8Array | null;
  readonly verdict: ReceiptVerdict | null;
  readonly receiptBytes: Uint8Array | null;
};

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
  showFrame(bytes: Uint8Array): void;
  scan(consume: (bytes: Uint8Array) => void, signal: AbortSignal): Promise<() => void>;
  showBloom(digest: Uint8Array): void;
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
