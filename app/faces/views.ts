// SPDX-License-Identifier: AGPL-3.0-or-later
import { createCoherenceViews as createCanvases } from "./coherence/views.js";
import type { CoherenceViews as CanvasViews } from "./coherence/views.js";

export type { HealthDecoder } from "./coherence/views.js";

export interface PentoraExpansion {
  // Raw Aura head in; copied display digest followed by 110 trits out.
  pentora_expand(head32: Uint8Array): Uint8Array;
}

export interface CoherenceViews extends Omit<CanvasViews, "fingerprint"> {
  fingerprint(head32: Uint8Array, pentora: PentoraExpansion): void;
}

function requireHead(head: Uint8Array): void {
  if (!(head instanceof Uint8Array) || head.length !== 32) throw new Error("coherence:head-invalid");
}

function expansionBytes(bytes: Uint8Array): Uint8Array {
  if (!(bytes instanceof Uint8Array) || bytes.length !== 142) throw new Error("coherence:expansion");
  const copy = bytes.slice();
  if (copy.subarray(32).some(trit => trit > 2)) throw new Error("coherence:expansion");
  return copy;
}

function pointer(value: number): number {
  if (!Number.isInteger(value) || value < -0x80000000 || value > 0xffffffff) {
    throw new Error("coherence:pentora-pointer");
  }
  return value >>> 0;
}

function memoryBytes(memory: WebAssembly.Memory, offset: number, length: number): Uint8Array {
  const buffer = memory.buffer;
  if (!offset || offset > buffer.byteLength || length > buffer.byteLength - offset) {
    throw new Error("coherence:pentora-bounds");
  }
  return new Uint8Array(buffer, offset, length);
}

export function bindPentora(exports: WebAssembly.Exports): PentoraExpansion {
  const memory = exports.memory;
  const allocate = exports.pentora_allocate_root32;
  const expand = exports.pentora_expand;
  const releaseRoot = exports.pentora_release_root32;
  const releaseResult = exports.pentora_release_result;
  if (!(memory instanceof WebAssembly.Memory) || typeof allocate !== "function" ||
      typeof expand !== "function" || typeof releaseRoot !== "function" || typeof releaseResult !== "function") {
    throw new Error("coherence:pentora-abi");
  }
  return {
    pentora_expand(head) {
      requireHead(head);
      const input = head.slice();
      let root = 0;
      let result = 0;
      try {
        root = pointer(allocate());
        if (!root) throw new Error("coherence:pentora-allocation");
        memoryBytes(memory, root, 32).set(input);
        result = pointer(expand(root));
        if (!result) throw new Error("coherence:pentora-result");
        const descriptorBytes = memoryBytes(memory, result, 16);
        const descriptor = new DataView(descriptorBytes.buffer, descriptorBytes.byteOffset, 16);
        const version = descriptor.getUint32(0, true);
        const status = descriptor.getUint32(4, true);
        const offset = descriptor.getUint32(8, true);
        const length = descriptor.getUint32(12, true);
        if (version !== 1 || (status !== 0 && status !== 1)) throw new Error("coherence:pentora-abi");
        if (status === 1) {
          if (!length || length > 128) throw new Error("coherence:pentora-refusal");
          const reason = new TextDecoder("utf-8", { fatal: true }).decode(memoryBytes(memory, offset, length));
          if (!/^pentora:[a-z0-9-]+$/.test(reason)) throw new Error("coherence:pentora-refusal");
          throw new Error(reason);
        }
        if (length !== 142) throw new Error("coherence:expansion");
        return expansionBytes(memoryBytes(memory, offset, length));
      } finally {
        try {
          if (result && releaseResult(result) !== 0) throw new Error("coherence:pentora-release");
        } finally {
          if (root && releaseRoot(root) !== 0) throw new Error("coherence:pentora-release");
        }
      }
    },
  };
}

export function createCoherenceViews(root: HTMLElement): CoherenceViews {
  const canvases = createCanvases(root);
  let disposed = false;
  return {
    ...canvases,
    fingerprint(head, pentora) {
      if (disposed) throw new Error("coherence:disposed");
      canvases.clearFingerprint("Loading fingerprint");
      try {
        requireHead(head);
        const bytes = expansionBytes(pentora.pentora_expand(head.slice()));
        const digest = bytes.slice(0, 32);
        const trits = bytes.slice(32);
        // The canvas consumes the returned digest and trits without another derivation.
        canvases.fingerprint(digest, { pentora_expand: () => trits });
      } catch (error) {
        canvases.clearFingerprint("Unavailable");
        throw error;
      }
    },
    dispose() {
      disposed = true;
      canvases.dispose();
    },
  };
}
