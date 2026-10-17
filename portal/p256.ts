// SPDX-License-Identifier: AGPL-3.0-or-later
// SEC1 point compression for P-256, the only arithmetic the compact frames add. WebCrypto signs, verifies and checks that a point is
// on the curve; this module only converts a 33-byte compressed key (02/03 || x) to the 65-byte uncompressed form WebCrypto imports.
// Decompression is the textbook step (SEC1 2.3.4): y = (x^3 - 3x + b)^((p+1)/4) mod p, valid because p = 3 mod 4, then the root with
// the right parity; the result is rejected unless it satisfies the curve equation, and WebCrypto's import checks it again.
import { refuse } from "./bytes.js";

const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function power(base: bigint, exponent: bigint): bigint {
  let result = 1n;
  base %= P;
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) result = (result * base) % P;
    base = (base * base) % P;
  }
  return result;
}

export function compressKey(raw: Uint8Array): Uint8Array {
  if (raw.length !== 65 || raw[0] !== 4) refuse("key");
  const out = new Uint8Array(33);
  out[0] = 2 + (raw[64]! & 1);
  out.set(raw.subarray(1, 33), 1);
  return out;
}

const cache = new Map<string, Uint8Array>();
export function decompressKey(compressed: Uint8Array): Uint8Array {
  if (compressed.length !== 33 || (compressed[0] !== 2 && compressed[0] !== 3)) refuse("key");
  const label = Array.from(compressed, byte => byte.toString(16).padStart(2, "0")).join("");
  const known = cache.get(label);
  if (known) return known.slice();
  let x = 0n;
  for (const byte of compressed.subarray(1)) x = (x << 8n) | BigInt(byte);
  if (x >= P) refuse("key");
  const right = ((((x * x) % P) * x - 3n * x + B) % P + P) % P;
  let y = power(right, (P + 1n) / 4n);
  if ((y * y) % P !== right) refuse("key");
  if ((y & 1n) !== BigInt(compressed[0]! & 1)) y = P - y;
  const out = new Uint8Array(65);
  out[0] = 4;
  out.set(compressed.subarray(1), 1);
  for (let i = 64, value = y; i >= 33; --i, value >>= 8n) out[i] = Number(value & 255n);
  if (cache.size > 64) cache.clear();
  cache.set(label, out);
  return out.slice();
}
