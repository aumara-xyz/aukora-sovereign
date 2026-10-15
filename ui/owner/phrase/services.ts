// SPDX-License-Identifier: AGPL-3.0-or-later
import type { PasskeyPaneService, ProposalCardBytes, PhrasePaneService } from "../contracts.js";

// This module is composed by the trusted owner release, never from frame messages.
export interface PhraseWasmSession {
  unlock(envelope: Uint8Array, entered: string): string;
  prepare(ceremony: string): void;
  resume(ceremony: string, nonce: Uint8Array, ciphertext: Uint8Array, replacement: Uint8Array): void;
  phrase(): string;
  replacement_envelope(): Uint8Array;
  protected_nonce(): Uint8Array;
  protected_ciphertext(): Uint8Array;
  adopt_replacement(envelope: Uint8Array): void;
  discard_draft(): void;
  backup_v2(credential: Uint8Array, rp: string, ceremony: string, challenge: Uint8Array,
    epoch: bigint, expires: bigint, signal: AbortSignal): Promise<Uint8Array>;
  backup_assertion(): string;
  backup_v1(): Uint8Array;
  free(): void;
}

export interface PhraseWasm {
  readonly OwnerPhraseSession: {
    verify(ownerOrigin: string, shellOrigin: string): PhraseWasmSession;
  };
}

export interface CurrentEnvelope {
  readonly subject: string;
  readonly ownerEpoch: bigint;
  readonly revision: bigint;
  readonly digest: string;
  readonly envelope: Uint8Array;
}

export interface RefreshSubmission {
  readonly ceremony: string;
  readonly session: string;
  readonly subject: string;
  readonly expectedEpoch: bigint;
  readonly expectedRevision: bigint;
  readonly previousDigest: string;
  readonly replacement: Uint8Array;
  readonly protectedNonce: Uint8Array;
  readonly protectedCiphertext: Uint8Array;
}

export interface RefreshRecord {
  readonly submission: RefreshSubmission;
  readonly replacementDigest: string;
  readonly state: "prepared" | "in-doubt" | "committed" | "cancelled" | "expired";
}

export interface RefreshSnapshot {
  readonly current: CurrentEnvelope;
  readonly pending: RefreshRecord | null;
}

export interface BackupCeremony {
  readonly ceremony: string;
  readonly credential: Uint8Array;
  readonly originalRpId: string;
  readonly challenge: Uint8Array;
  readonly expectedEpoch: bigint;
  readonly expiresAtMs: bigint;
}

// The node adapter resolves the authenticated session, rechecks every proof in
// its authority transaction, and returns ciphertext only. These are local port
// types, not additions to a v1 wire schema.
// review binds the full submission AND phase to its proposal and challenge;
// prepare/finish reread that association before consuming the exact-byte proof.
// C5 uses apply, cell=null, refreshTarget, the current envelope digest as base,
// and SHA-256 of replacement bytes as new_sha256. Preparation does not commit it.
export interface PhraseCeremonies {
  resume(signal: AbortSignal): Promise<RefreshSnapshot>;
  begin(current: CurrentEnvelope, signal: AbortSignal): Promise<{ ceremony: string; session: string }>;
  review(phase: "prepare" | "finish", submission: RefreshSubmission,
    signal: AbortSignal): Promise<ProposalCardBytes>;
  prepare(submission: RefreshSubmission, proposalId: string, assertion: Uint8Array,
    signal: AbortSignal): Promise<RefreshSnapshot>;
  finish(ceremony: string, proposalId: string, assertion: Uint8Array,
    signal: AbortSignal): Promise<RefreshSnapshot>;
  beginBackup(current: CurrentEnvelope, signal: AbortSignal): Promise<BackupCeremony>;
  finishBackup(ceremony: string, assertion: string, signal: AbortSignal): Promise<void>;
}

export interface PhraseConfiguration {
  readonly ownerOrigin: string;
  readonly shellOrigin: string;
  readonly refreshTarget: string;
  readonly wasm: PhraseWasm;
  readonly ceremonies: PhraseCeremonies;
  readonly passkey: PasskeyPaneService;
}

export type { PhrasePaneService };
