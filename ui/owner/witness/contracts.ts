// SPDX-License-Identifier: AGPL-3.0-or-later
export const CHECKPOINT_SCHEMA = "aukora-owner-browser-head-v1" as const;
export const PRESENTED_SCHEMA = "aukora-aura-presented-head-v1" as const;
export const LEAF_CONVENTION = "rfc6962-leaf-sha256-0x00-prefixed-v1" as const;
export const MAX_HEAD_BYTES = 65_536;
export const MAX_PROOF_HASHES = 64;

export type BrowserCheckpoint = {
  readonly schema: typeof CHECKPOINT_SCHEMA;
  readonly leafConvention: typeof LEAF_CONVENTION;
  readonly treeSize: number;
  readonly root: string;
};

export type PresentedHead = {
  readonly schema: typeof PRESENTED_SCHEMA;
  readonly leafConvention: typeof LEAF_CONVENTION;
  readonly treeSize: number;
  readonly root: string;
  readonly retainedTreeSize: number;
  readonly proofFromPrevious: readonly string[];
};

export interface WitnessStore {
  load(signal: AbortSignal): Promise<unknown | null>;
  replace(expected: BrowserCheckpoint | null, next: BrowserCheckpoint, signal: AbortSignal): Promise<"stored" | "changed">;
}

export interface WitnessHeadSource {
  present(retainedTreeSize: number | null, signal: AbortSignal): Promise<Uint8Array>;
}

// These callbacks have no JavaScript implementation or fallback in this module.
export interface WitnessPrimitives {
  canonicalize(bytes: Uint8Array, signal: AbortSignal): Promise<Uint8Array>;
  sha256(bytes: Uint8Array, signal: AbortSignal): Promise<Uint8Array>;
}

export type WitnessServices = {
  readonly store: WitnessStore;
  readonly source: WitnessHeadSource;
  readonly primitives: WitnessPrimitives;
  readonly timeoutMs?: number;
};

export function assertActive(signal: AbortSignal): void {
  if (signal.aborted) throw new Error("witness:aborted");
}
