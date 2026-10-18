// SPDX-License-Identifier: AGPL-3.0-or-later
// The seam between the pairing scene (pairing.ts) and the co-presence engine. The scene draws and drives; the engine
// is the shared portal engine (portal/engine.ts, optical.ts), composed here with the node: the owner device's durable key,
// the node's pinned context, the node's verdict and the one-time link the phone opens (portal/COPRESENCE-NODE.md).

import { createNodePairingPort } from "../../portal/node/pairing-port.js";
import type { OpticalSurface } from "../../portal/contracts.js";

export type PairingMethod = "optical";

export type PairingExchangeRequest = {
  readonly domain: "copresence.v1";
  readonly attemptId: string;
  readonly method: PairingMethod;
  readonly contextBytes: Uint8Array;
  readonly approvedText: null;
};

export type PairingObservation = {
  readonly phase: "FACE" | "SEENYOU" | "HANDSHAKE" | "BLOOM" | "REFUSED";
  readonly frameBytes: Uint8Array | null;
  readonly personNostrKeys: { readonly local: Uint8Array | null; readonly peer: Uint8Array | null } | null;
  readonly verdict: { readonly verdict: string; readonly code?: string | null } | null;
  readonly receiptBytes: Uint8Array | null;
};

export interface PairingExchange {
  receive(frameBytes: Uint8Array): Promise<void>;
  subscribe(listener: (observation: PairingObservation) => void): () => void;
  stop(): void;
}

// These are the portal's own PortalServices, structurally.
export interface PairingServices {
  readonly engine: { begin(request: PairingExchangeRequest, signal: AbortSignal): Promise<PairingExchange> };
  readonly attempts: {
    reserve(method: PairingMethod, signal: AbortSignal): Promise<string>;
    finish(attemptId: string, outcome: "bloom" | "refused" | "cancelled", signal: AbortSignal): Promise<void>;
  };
  readonly optical: OpticalSurface;
}

export type PairingCanvases = {
  readonly frame: HTMLCanvasElement;
  readonly video: HTMLVideoElement;
  readonly bloom: HTMLCanvasElement;
};

export type PairingPort = {
  /** Called when pairing starts; the port binds the canvases to the engine's optical surface. */
  open(canvases: PairingCanvases, signal: AbortSignal): Promise<PairingServices>;
  /** An address a phone can open to be the second device, when the host offers one. */
  /** How many devices the node has paired with this owner. Zero means the first pairing is still due, whatever this page remembers. */
  pairedCount?(signal: AbortSignal): Promise<number>;
  readonly phoneLink?: { readonly url: string; readonly caption?: string; draw(canvas: HTMLCanvasElement): void };
};

export const pairingPort: PairingPort | null = createNodePairingPort();
