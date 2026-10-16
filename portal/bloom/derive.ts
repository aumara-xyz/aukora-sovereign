// SPDX-License-Identifier: AGPL-3.0-or-later
// The host supplies the Rust pairing derivation; this module validates its inputs and output.
import type { PersonNostrPublicKey, RelationshipBloomDigest } from "../contracts.js";

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

/** The host resolves this role from its person bindings; optical bytes cannot supply it. */
export function copyPersonNostrKey(value: PersonNostrPublicKey): PersonNostrPublicKey {
  if (!value || typeof value !== "object" || value.role !== "person-nostr" || value.encoding !== "x-only"
    || !(value.bytes instanceof Uint8Array) || value.bytes.length !== IDENTITY_BYTES) refuse("identity-invalid");
  return { role: "person-nostr", encoding: "x-only", bytes: value.bytes.slice() };
}

function personPair(first: PersonNostrPublicKey, second: PersonNostrPublicKey): [Uint8Array, Uint8Array] {
  const a = copyPersonNostrKey(first).bytes, b = copyPersonNostrKey(second).bytes;
  for (let index = 0; index < IDENTITY_BYTES; index++) {
    if (a[index]! < b[index]!) return [a, b];
    if (a[index]! > b[index]!) return [b, a];
  }
  refuse("identities-equal");
}

/** The sorted person-key root is computed by Rust, independently of receipt bytes. */
export async function pairingDigest(
  first: PersonNostrPublicKey,
  second: PersonNostrPublicKey,
  pentora: PentoraPairingDigest | undefined,
): Promise<RelationshipBloomDigest> {
  const [a, b] = personPair(first, second);
  if (!pentora || typeof pentora.pairing_digest !== "function") refuse("pairing-expansion-unavailable");
  const digest = await pentora.pairing_digest(a, b);
  if (!(digest instanceof Uint8Array) || digest.length !== DIGEST_BYTES) refuse("pairing-expansion-invalid");
  return { domain: "pentora.bloom.v1", bytes: digest.slice() };
}

/** Two person-nostr x-only public keys are required; node or receipt identifiers are not inputs. */
export async function pairingExpansion(
  first: PersonNostrPublicKey,
  second: PersonNostrPublicKey,
  pentora: PentoraPairingExpansion | undefined,
): Promise<PairingExpansion> {
  const [a, b] = personPair(first, second);
  if (!pentora || typeof pentora.pairing_expansion !== "function") refuse("pairing-expansion-unavailable");
  const result = await pentora.pairing_expansion(a, b);
  if (!result || !(result.digest instanceof Uint8Array) || result.digest.length !== DIGEST_BYTES
    || !(result.trits instanceof Uint8Array) || result.trits.length !== TRIT_COUNT) refuse("pairing-expansion-invalid");
  const digest = result.digest.slice(), trits = result.trits.slice();
  if (trits.some(trit => trit > 2)) refuse("pairing-expansion-invalid");
  return { digest, trits };
}
