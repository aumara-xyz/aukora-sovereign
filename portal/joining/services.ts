// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerDisposer, OwnerPaneContext } from "../../ui/owner/contracts.js";

export const JOINING_CONTEXT_SCHEMA = "aukora.joining-context.v1" as const;

export type JoiningParticipant = {
  readonly ownerCredential: string;
  // Lowercase hex of the credential's exact COSE public-key bytes.
  readonly ownerPublicKey: string;
  readonly ownerEpoch: number;
  readonly devicePublicKey: string;
  readonly deviceEpoch: number;
  readonly sessionContribution: string;
};

// These local ports do not add fields to a frozen receipt or HTTP request.
export type JoiningContext = {
  readonly schema: typeof JOINING_CONTEXT_SCHEMA;
  readonly ceremony: string;
  readonly node: string;
  readonly claimDigest: string;
  readonly purpose: "join-own-devices";
  readonly participants: readonly [JoiningParticipant, JoiningParticipant];
  readonly scopes: readonly string[];
  readonly method: "screen-to-screen";
  readonly requiredLayers: {
    readonly sound: boolean;
    readonly motion: boolean;
    readonly intentAcknowledgement: boolean;
  };
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
};

export type PreparedJoiningExchange = {
  readonly context: JoiningContext;
  readonly canonicalContext: Uint8Array;
  readonly contextDigest: string;
};

export type JoiningEvidence = {
  readonly exchange: PreparedJoiningExchange;
  // SHA-256 of the exact opaque receipt bytes accepted by recordEvidence.
  readonly receiptDigest: string;
};

export type JoiningPhrase = {
  readonly subject: string;
  readonly envelopeDigest: string;
};

type JoiningBase = {
  readonly ceremony: string;
  readonly node: string;
  readonly claimDigest: string;
  readonly revision: number;
};

export type JoiningSnapshot = JoiningBase & (
  | { readonly stage: "copresence" }
  | { readonly stage: "phrase"; readonly evidence: JoiningEvidence }
  | { readonly stage: "passkey"; readonly evidence: JoiningEvidence; readonly phrase: JoiningPhrase }
  | {
    readonly stage: "bound";
    readonly evidence: JoiningEvidence;
    readonly phrase: JoiningPhrase;
    readonly binding: {
      readonly subject: string;
      readonly credential: string;
      readonly ownerPublicKey: string;
      readonly ownerEpoch: number;
      readonly receiptSequence: number;
    };
  }
);

// The authenticated node adapter resolves the claim session, reserves durable
// attempts before optical input and verifies exact context, both signatures,
// timestamps, nonce commitments, fixed method and single-use receipt evidence.
// Only its separate passkey transaction can return the bound checkpoint.
export interface JoiningCeremonies {
  resume(signal: AbortSignal): Promise<JoiningSnapshot>;
  prepare(ceremony: string, revision: number, signal: AbortSignal): Promise<PreparedJoiningExchange>;
  recordEvidence(ceremony: string, revision: number, contextDigest: string,
    receipt: Uint8Array, signal: AbortSignal): Promise<JoiningSnapshot>;
}

export type JoiningOpticalContext = {
  readonly host: HTMLElement;
  readonly signal: AbortSignal;
  readonly exchange: PreparedJoiningExchange;
  receipt(bytes: Uint8Array): void;
};

export interface JoiningOptical {
  mount(context: JoiningOpticalContext): OwnerDisposer | Promise<OwnerDisposer>;
}

export type JoiningEnrolmentContext = {
  readonly owner: OwnerPaneContext;
  readonly snapshot: JoiningSnapshot;
  // A pane calls settled after its own service commits; this only triggers a
  // fresh authenticated read. Calling it cannot advance a joining checkpoint.
  settled(): void;
};

export interface JoiningEnrolment {
  mountPhrase(context: JoiningEnrolmentContext): OwnerDisposer | Promise<OwnerDisposer>;
  mountPasskey(context: JoiningEnrolmentContext): OwnerDisposer | Promise<OwnerDisposer>;
}

export interface JoiningContextCodec {
  // C1 bytes; SHA-256("aukora:joining-context:v1", NUL, those bytes).
  // The returned bytes and digest are recomputed, never taken from a face.
  encode(context: JoiningContext, signal: AbortSignal): Promise<{
    readonly canonical: Uint8Array;
    readonly digest: string;
  }>;
}

export type JoiningConfiguration = {
  readonly ownerOrigin: string;
  readonly shellOrigin: string;
  readonly node: string;
  readonly ceremonies: JoiningCeremonies;
  readonly optical: JoiningOptical;
  readonly enrolment: JoiningEnrolment;
  readonly codec: JoiningContextCodec;
  readonly contextFormatPinned: (schema: typeof JOINING_CONTEXT_SCHEMA) => boolean;
};
