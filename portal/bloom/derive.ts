// SPDX-License-Identifier: AGPL-3.0-or-later
// The pairing derivation of crates/pentora/src/bloom.rs. Both follow the vectors in
// crates/pentora/vectors/bloom-v1.json. A bloom is a picture: it proves no meeting, carries no
// consent and grants nothing.

export const BLOOM_DOMAIN = "pentora.bloom.v1";
export const BLOOM_LABEL = "Relationship bloom — display only";
export const IDENTITY_BYTES = 32;
export const DIGEST_BYTES = 32;
export const TRIT_COUNT = 110;
export const CENTRE_CELL = 55;

/** Refusals carry the organ's code, as the Rust side does: `pentora:<reason>`. */
export function refuse(reason: string): never {
  throw new Error(`pentora:${reason}`);
}

export function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

/** Trit `at` is drawn on the `at`-th non-centre cell: cell `at` below 55, cell `at + 1` from 55. */
export function cellOfTrit(at: number): number {
  if (!Number.isInteger(at) || at < 0 || at >= TRIT_COUNT) refuse("cell-index");
  return at < CENTRE_CELL ? at : at + 1;
}

/** The inverse of `cellOfTrit`. The centre cell has no trit and refuses. */
export function tritOfCell(cell: number): number {
  if (!Number.isInteger(cell) || cell < 0 || cell > TRIT_COUNT || cell === CENTRE_CELL) refuse("cell-index");
  return cell < CENTRE_CELL ? cell : cell - 1;
}

function identity(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length !== IDENTITY_BYTES) refuse("identity-invalid");
  return value;
}

/** Bytewise order of two byte strings of one length: -1, 0 or 1. */
function compare(left: Uint8Array, right: Uint8Array): number {
  for (let at = 0; at < left.length; ++at) {
    const a = left[at] ?? 0, b = right[at] ?? 0;
    if (a !== b) return a < b ? -1 : 1;
  }
  return 0;
}

/**
 * sha256("pentora.bloom.v1" || 0x00 || low || high) for two different 32-byte identities, `low`
 * being the lower one bytewise. Either argument order gives the same digest. Both lengths are
 * checked before the two are compared, as in the Rust derivation.
 */
export async function pairingDigest(first: Uint8Array, second: Uint8Array): Promise<Uint8Array> {
  const a = identity(first), b = identity(second);
  const order = compare(a, b);
  if (order === 0) refuse("identities-equal");
  const [low, high] = order < 0 ? [a, b] : [b, a];
  const domain = new TextEncoder().encode(BLOOM_DOMAIN);
  const preimage = new Uint8Array(domain.length + 1 + 2 * IDENTITY_BYTES);
  preimage.set(domain);
  preimage.set(low, domain.length + 1);
  preimage.set(high, domain.length + 1 + IDENTITY_BYTES);
  const subtle = typeof crypto === "object" && crypto !== null ? crypto.subtle : undefined;
  if (!subtle) refuse("crypto-unavailable");
  return new Uint8Array(await subtle.digest("SHA-256", preimage));
}

/**
 * The 110 trits (each 0, 1 or 2) of a 32-byte commitment drawn as it is: N is its big-endian
 * integer and trit `at` is floor(N / 3^at) mod 3. An all-zero commitment is a missing one.
 */
export function bloomTrits(digest: Uint8Array): Uint8Array {
  if (!(digest instanceof Uint8Array) || digest.length !== DIGEST_BYTES) refuse("digest-invalid");
  if (digest.every(byte => byte === 0)) refuse("commitment-empty");
  let rest = 0n;
  for (const byte of digest) rest = (rest << 8n) | BigInt(byte);
  const trits = new Uint8Array(TRIT_COUNT);
  for (let at = 0; at < TRIT_COUNT; ++at) {
    trits[at] = Number(rest % 3n);
    rest /= 3n;
  }
  return trits;
}
