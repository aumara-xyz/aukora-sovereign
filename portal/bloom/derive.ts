// SPDX-License-Identifier: AGPL-3.0-or-later
// The host supplies the Rust pairing derivation; this module validates its inputs and output.

export const BLOOM_LABEL = "Relationship bloom — display only";
export const IDENTITY_BYTES = 32;
export const DIGEST_BYTES = 32;
export const TRIT_COUNT = 110;
export const CENTRE_CELL = 55;

export type PairingExpansion = {
  readonly digest: Uint8Array;
  readonly trits: Uint8Array;
};

export interface PentoraPairingExpansion {
  pairing_expansion(firstPersonKey: Uint8Array, secondPersonKey: Uint8Array): PairingExpansion | Promise<PairingExpansion>;
}

export interface PentoraPairingDigest {
  pairing_digest(firstPersonKey: Uint8Array, secondPersonKey: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export function refuse(reason: string): never {
  throw new Error(`pentora:${reason}`);
}

export function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

function personKey(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== IDENTITY_BYTES) refuse("identity-invalid");
  return value.slice();
}

/** The sorted person-key root is computed by Rust, independently of receipt bytes. */
export async function pairingDigest(
  first: Uint8Array,
  second: Uint8Array,
  pentora: PentoraPairingDigest | undefined,
): Promise<Uint8Array> {
  const a = personKey(first), b = personKey(second);
  if (a.every((byte, at) => byte === b[at])) refuse("identities-equal");
  if (!pentora || typeof pentora.pairing_digest !== "function") refuse("pairing-expansion-unavailable");
  const digest = await pentora.pairing_digest(a, b);
  if (!(digest instanceof Uint8Array) || digest.length !== DIGEST_BYTES) refuse("pairing-expansion-invalid");
  return digest.slice();
}

/** Two person-nostr x-only public keys are required; node or receipt identifiers are not inputs. */
export async function pairingExpansion(
  first: Uint8Array,
  second: Uint8Array,
  pentora: PentoraPairingExpansion | undefined,
): Promise<PairingExpansion> {
  const a = personKey(first), b = personKey(second);
  if (a.every((byte, at) => byte === b[at])) refuse("identities-equal");
  if (!pentora || typeof pentora.pairing_expansion !== "function") refuse("pairing-expansion-unavailable");
  const result = await pentora.pairing_expansion(a, b);
  if (!result || !(result.digest instanceof Uint8Array) || result.digest.length !== DIGEST_BYTES
    || !(result.trits instanceof Uint8Array) || result.trits.length !== TRIT_COUNT) refuse("pairing-expansion-invalid");
  const digest = result.digest.slice(), trits = result.trits.slice();
  if (trits.some(trit => trit > 2)) refuse("pairing-expansion-invalid");
  return { digest, trits };
}
