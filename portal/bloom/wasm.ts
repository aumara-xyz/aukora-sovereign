// SPDX-License-Identifier: AGPL-3.0-or-later
// Binds an already instantiated Rust module. No receipt digest or JavaScript derivation is accepted.
import { DIGEST_BYTES, IDENTITY_BYTES, TRIT_COUNT, refuse } from "./derive.ts";
import type { PairingExpansion, PentoraPairingExpansion } from "./derive.ts";

type WasmCall = (...args: number[]) => number;

function callable(value: unknown, arity: number): WasmCall {
  if (typeof value !== "function" || value.length !== arity) refuse("pairing-expansion-unavailable");
  return value as WasmCall;
}

function offset(value: number): number {
  if (!Number.isInteger(value) || value < -0x80000000 || value > 0xffffffff) refuse("pairing-expansion-invalid");
  return value >>> 0;
}

/** The host supplies exports of the Rust Pentora WASM module. Every output is copied before release. */
export function bindPairingPentora(exports: WebAssembly.Exports): PentoraPairingExpansion {
  const memory = exports.memory;
  if (!(memory instanceof WebAssembly.Memory)) refuse("pairing-expansion-unavailable");
  const reserve = callable(exports.pentora_allocate_root32, 0);
  const expand = callable(exports.pentora_pairing_expand, 2);
  const freeKey = callable(exports.pentora_release_root32, 1);
  const freeResult = callable(exports.pentora_release_result, 1);

  const range = (start: number, count: number): Uint8Array => {
    const buffer = memory.buffer;
    if (!Number.isInteger(start) || start <= 0 || !Number.isInteger(count) || count <= 0
      || start + count > buffer.byteLength) refuse("pairing-expansion-invalid");
    return new Uint8Array(buffer, start, count);
  };

  return Object.freeze({
    pairing_expansion(firstPersonKey: Uint8Array, secondPersonKey: Uint8Array): PairingExpansion {
      if (!(firstPersonKey instanceof Uint8Array) || firstPersonKey.length !== IDENTITY_BYTES
        || !(secondPersonKey instanceof Uint8Array) || secondPersonKey.length !== IDENTITY_BYTES) refuse("identity-invalid");
      const first = firstPersonKey.slice(), second = secondPersonKey.slice();
      if (first.every((byte, at) => byte === second[at])) refuse("identities-equal");
      let firstSlot = 0, secondSlot = 0, resultSlot = 0;
      try {
        firstSlot = offset(reserve());
        range(firstSlot, IDENTITY_BYTES).set(first);
        secondSlot = offset(reserve());
        if (Math.abs(firstSlot - secondSlot) < IDENTITY_BYTES) refuse("pairing-expansion-invalid");
        range(secondSlot, IDENTITY_BYTES).set(second);
        resultSlot = offset(expand(firstSlot, secondSlot));
        if (resultSlot % 4 !== 0) refuse("pairing-expansion-invalid");
        const descriptor = range(resultSlot, 16);
        const words = new DataView(descriptor.buffer, descriptor.byteOffset, descriptor.byteLength);
        const version = words.getUint32(0, true), status = words.getUint32(4, true);
        const payloadSlot = words.getUint32(8, true), length = words.getUint32(12, true);
        if (version !== 1 || (status !== 0 && status !== 1)) refuse("pairing-expansion-invalid");
        if (status === 1) {
          if (length > 96) refuse("pairing-expansion-invalid");
          const bytes = range(payloadSlot, length).slice();
          let reason: string;
          try { reason = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
          catch { refuse("pairing-expansion-invalid"); }
          if (!/^pentora:[a-z0-9-]{1,64}$/.test(reason)) refuse("pairing-expansion-invalid");
          throw new Error(reason);
        }
        if (length !== DIGEST_BYTES + TRIT_COUNT) refuse("pairing-expansion-invalid");
        const payload = range(payloadSlot, length).slice();
        const trits = payload.slice(DIGEST_BYTES);
        if (trits.some(trit => trit > 2)) refuse("pairing-expansion-invalid");
        return { digest: payload.slice(0, DIGEST_BYTES), trits };
      } finally {
        let released = true;
        for (const [release, slot] of [[freeResult, resultSlot], [freeKey, secondSlot], [freeKey, firstSlot]] as const) {
          if (slot === 0) continue;
          try { if (release(slot) !== 0) released = false; }
          catch { released = false; }
        }
        if (!released) refuse("pairing-expansion-invalid");
      }
    },
  });
}
