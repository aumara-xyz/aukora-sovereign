// SPDX-License-Identifier: AGPL-3.0-or-later
// Binds the browser export of crates/pentora (the Rust derivation compiled to WASM) and nothing else: there is no
// JavaScript expansion to fall back on. The module takes the 32 raw bytes of the Aura display head and returns the
// display digest, sha256("pentora.display.v1" || 0x00 || head), followed by 110 trits. If the module cannot be loaded,
// does not match the ABI, or fails its known answer, every call refuses and the fingerprint canvas stays empty.
import { toHex } from "./bytes.js";

export const ABI_VERSION = 1;
export const DIGEST_BYTES = 32;
export const TRIT_COUNT = 110;
export const EXPANSION_BYTES = DIGEST_BYTES + TRIT_COUNT;
export const MAX_MODULE_BYTES = 4 * 1024 * 1024;

export interface FingerprintExpansion {
  readonly digest: Uint8Array;
  readonly trits: Uint8Array;
}
export interface PentoraModule {
  /** Exactly 32 head bytes in; the digest and the 110 base-three digits out. */
  expand(head: Uint8Array): FingerprintExpansion;
}

// Pinned vector 0 of crates/pentora/vectors/expansion_vectors_1006.json: an all-zero head.
const KNOWN_DIGEST = "64601047ff85ffa5fae9d7219c28781e9e21b5ea055ce05a629b0fda3c753889";
const KNOWN_TRITS = "0000000001000000020101010102010001000001000100020100000201000202000001000101020200020201020202010002010100000102000000010101010200010202000001020002000202010201000202020200000002020101000001010101000100020202000000010200";

const REFUSAL = /^pentora:[a-z0-9-]{1,64}$/;

type Exported = (...args: number[]) => number;

function exported(value: unknown, arity: number): Exported {
  if (typeof value !== "function" || value.length !== arity) throw new Error("coherence:pentora-exports");
  return value as Exported;
}

/** Offsets are linear-memory positions the module handed out; every read is bounds-checked against current memory. */
export function bindPentora(exports: WebAssembly.Exports): PentoraModule {
  const memory = exports.memory;
  if (!(memory instanceof WebAssembly.Memory)) throw new Error("coherence:pentora-exports");
  const allocate = exported(exports.pentora_allocate_root32, 0);
  const run = exported(exports.pentora_expand, 1);
  const releaseRoot = exported(exports.pentora_release_root32, 1);
  const releaseResult = exported(exports.pentora_release_result, 1);
  const fits = (offset: number, length: number) =>
    Number.isSafeInteger(offset) && offset > 0 && offset + length <= memory.buffer.byteLength;

  const bound: PentoraModule = {
    expand(head) {
      if (!(head instanceof Uint8Array) || head.length !== DIGEST_BYTES) throw new Error("coherence:head-length");
      const root = allocate() >>> 0;
      if (!fits(root, DIGEST_BYTES)) throw new Error("coherence:pentora-allocation");
      let descriptor = 0;
      let outcome: FingerprintExpansion | Error;
      try {
        new Uint8Array(memory.buffer, root, DIGEST_BYTES).set(head);
        descriptor = run(root) >>> 0;
        if (!fits(descriptor, 16)) {
          descriptor = 0;
          throw new Error("coherence:pentora-expand");
        }
        const view = new DataView(memory.buffer);
        const version = view.getUint32(descriptor, true);
        const status = view.getUint32(descriptor + 4, true);
        const pointer = view.getUint32(descriptor + 8, true);
        const length = view.getUint32(descriptor + 12, true);
        if (version !== ABI_VERSION || !fits(pointer, length)) throw new Error("coherence:pentora-descriptor");
        const data = new Uint8Array(memory.buffer, pointer, length).slice();
        if (status === 1) {
          const reason = new TextDecoder("utf-8").decode(data.subarray(0, 96));
          throw new Error(REFUSAL.test(reason) ? reason : "coherence:pentora-refused");
        }
        if (status !== 0 || length !== EXPANSION_BYTES) throw new Error("coherence:pentora-descriptor");
        const trits = data.slice(DIGEST_BYTES);
        if (trits.some(trit => trit > 2)) throw new Error("coherence:pentora-trits");
        outcome = { digest: data.slice(0, DIGEST_BYTES), trits };
      } catch (error) {
        outcome = error instanceof Error ? error : new Error("coherence:pentora-expand");
      }
      const released = (descriptor === 0 || releaseResult(descriptor) === 0) && releaseRoot(root) === 0;
      if (outcome instanceof Error) throw outcome;
      if (!released) throw new Error("coherence:pentora-release");
      return outcome;
    },
  };
  const known = bound.expand(new Uint8Array(DIGEST_BYTES));
  if (toHex(known.digest) !== KNOWN_DIGEST || toHex(known.trits) !== KNOWN_TRITS) {
    throw new Error("coherence:pentora-mismatch");
  }
  return Object.freeze(bound);
}

/** Fetches the pinned module, requires that it imports nothing, instantiates it with no imports and binds it. */
export async function loadPentora(source: URL, signal: AbortSignal): Promise<PentoraModule> {
  let bytes: ArrayBuffer;
  try {
    const response = await fetch(source, { credentials: "omit", redirect: "error", referrerPolicy: "no-referrer", signal });
    const declared = Number(response.headers.get("content-length") ?? 0);
    if (!response.ok || declared > MAX_MODULE_BYTES) throw new Error("fetch");
    bytes = await response.arrayBuffer();
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_MODULE_BYTES) throw new Error("fetch");
  } catch {
    throw new Error("coherence:pentora-unavailable");
  }
  let compiled: WebAssembly.Module;
  try { compiled = await WebAssembly.compile(bytes); }
  catch { throw new Error("coherence:pentora-compile"); }
  if (WebAssembly.Module.imports(compiled).length !== 0) throw new Error("coherence:pentora-imports");
  let instance: WebAssembly.Instance;
  try { instance = await WebAssembly.instantiate(compiled, {}); }
  catch { throw new Error("coherence:pentora-compile"); }
  return bindPentora(instance.exports);
}
