// SPDX-License-Identifier: AGPL-3.0-or-later
// Only canon's health decoder decides which evidence cells the face may display.
// This adapter projects its validated output; it never paints the input arrays directly.
import { decodeData } from "../../core/index.js";
import type { JsonValue } from "../../core/index.js";
import type { DecodedHealth, HealthCell, HealthDecoder } from "./views.js";

export const PRIVATE_CELLS = 90;
export const CORNER_CELLS = 20;
export const MAX_SNAPSHOT_BYTES = 65_536;
const MAX_MODULE_BYTES = 4 * 1024 * 1024;
const ABI_VERSION = 1;
const STATES: ReadonlySet<string> = new Set<HealthCell>(["verified", "undetermined", "failed"]);
const REFUSAL = /^[a-z][a-z0-9-]*:[a-z0-9-]{1,64}$/;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
type AbiFunction = (...args: number[]) => number;

function exported(value: unknown, arity: number): AbiFunction {
  if (typeof value !== "function" || value.length !== arity) throw new Error("coherence:health-exports");
  return value as AbiFunction;
}

function cells(value: JsonValue | undefined, count: number): HealthCell[] {
  if (!Array.isArray(value) || value.length !== count) throw new Error("coherence:snapshot-cells");
  return value.map(cell => {
    if (typeof cell !== "string" || !STATES.has(cell)) throw new Error("coherence:snapshot-cells");
    return cell as HealthCell;
  });
}

function context(value: JsonValue | undefined): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new Error("coherence:snapshot-context");
  return value;
}

// Called only with success bytes copied from canon's health_decode_snapshot result.
function displayCells(bytes: Uint8Array): DecodedHealth {
  const value = decodeData(utf8.decode(bytes));
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("coherence:snapshot-format");
  return {
    private_cells: cells(value.private_cells, PRIVATE_CELLS),
    corner_cells: cells(value.corner_cells, CORNER_CELLS),
    meta: {
      epoch: context(value.epoch),
      sequence: context(value.sequence),
      observed_at_ms: context(value.observed_at_ms),
    },
  };
}

/** Uses canon's v1 descriptor ABI and its allocation ownership checks. */
export function bindHealthDecoder(exports: WebAssembly.Exports): HealthDecoder {
  const memory = exports.memory;
  if (!(memory instanceof WebAssembly.Memory)) throw new Error("coherence:health-exports");
  const allocate = exported(exports.allocate_input, 1);
  const decode = exported(exports.health_decode_snapshot, 2);
  const releaseInput = exported(exports.release_input, 2);
  const releaseResult = exported(exports.release_result, 1);
  const fits = (offset: number, length: number) => Number.isSafeInteger(offset) && offset > 0
    && Number.isSafeInteger(length) && length > 0 && offset + length <= memory.buffer.byteLength;

  return Object.freeze({
    decode_snapshot(bytes: Uint8Array): DecodedHealth {
      if (!(bytes instanceof Uint8Array) || bytes.length === 0 || bytes.length > MAX_SNAPSHOT_BYTES) {
        throw new Error("coherence:snapshot-bounds");
      }
      const input = allocate(bytes.length) >>> 0;
      if (input === 0) throw new Error("coherence:health-allocation");
      let descriptor = 0;
      let output: Uint8Array | undefined;
      let failure: unknown;
      try {
        if (!fits(input, bytes.length)) throw new Error("coherence:health-allocation");
        new Uint8Array(memory.buffer, input, bytes.length).set(bytes);
        descriptor = decode(input, bytes.length) >>> 0;
        if (!fits(descriptor, 16)) throw new Error("coherence:health-descriptor");
        const view = new DataView(memory.buffer);
        const version = view.getUint32(descriptor, true);
        const status = view.getUint32(descriptor + 4, true);
        const pointer = view.getUint32(descriptor + 8, true);
        const length = view.getUint32(descriptor + 12, true);
        if (version !== ABI_VERSION || length > MAX_SNAPSHOT_BYTES || !fits(pointer, length)) {
          throw new Error("coherence:health-descriptor");
        }
        const data = new Uint8Array(memory.buffer, pointer, length).slice();
        if (status === 1) {
          const reason = length <= 96 ? utf8.decode(data) : "";
          throw new Error(REFUSAL.test(reason) ? reason : "coherence:health-refused");
        }
        if (status !== 0) throw new Error("coherence:health-descriptor");
        output = data;
      } catch (error) {
        failure = error;
      } finally {
        // Each release is attempted even if the other release refuses or traps.
        try {
          if (descriptor !== 0 && releaseResult(descriptor) !== 0) failure = new Error("coherence:health-release");
        } catch { failure = new Error("coherence:health-release"); }
        try {
          if (releaseInput(input, bytes.length) !== 0) failure = new Error("coherence:health-release");
        } catch { failure = new Error("coherence:health-release"); }
      }
      if (failure !== undefined) throw failure;
      if (output === undefined) throw new Error("coherence:health-decode");
      return displayCells(output);
    },
  });
}

/** Loads the release's canon module without imports; no JavaScript decoder substitutes for it. */
export async function loadHealthDecoder(source: URL, signal: AbortSignal): Promise<HealthDecoder> {
  let bytes: ArrayBuffer;
  try {
    const response = await fetch(source, { credentials: "omit", redirect: "error", referrerPolicy: "no-referrer", signal });
    const declared = Number(response.headers.get("content-length") ?? 0);
    if (!response.ok || declared > MAX_MODULE_BYTES) throw new Error("coherence:health-unavailable");
    bytes = await response.arrayBuffer();
    if (bytes.byteLength === 0 || bytes.byteLength > MAX_MODULE_BYTES) throw new Error("coherence:health-unavailable");
  } catch { throw new Error("coherence:health-unavailable"); }
  let compiled: WebAssembly.Module;
  try { compiled = await WebAssembly.compile(bytes); }
  catch { throw new Error("coherence:health-compile"); }
  if (WebAssembly.Module.imports(compiled).length !== 0) throw new Error("coherence:health-imports");
  let instance: WebAssembly.Instance;
  try { instance = await WebAssembly.instantiate(compiled, {}); }
  catch { throw new Error("coherence:health-compile"); }
  return bindHealthDecoder(instance.exports);
}
