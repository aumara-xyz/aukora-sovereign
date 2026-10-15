// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  CHECKPOINT_SCHEMA, LEAF_CONVENTION, MAX_HEAD_BYTES, MAX_PROOF_HASHES,
  PRESENTED_SCHEMA, assertActive,
} from "./contracts.js";
import type { BrowserCheckpoint, PresentedHead, WitnessPrimitives } from "./contracts.js";

function record(value: unknown, keys: string): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).sort().join(",") === keys;
}

export function digest(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

function size(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

export function checkpoint(value: unknown): BrowserCheckpoint {
  if (!record(value, "leafConvention,root,schema,treeSize")
    || value.schema !== CHECKPOINT_SCHEMA || value.leafConvention !== LEAF_CONVENTION
    || !size(value.treeSize) || !digest(value.root)) throw new Error("witness:retained-invalid");
  return Object.freeze({
    schema: CHECKPOINT_SCHEMA, leafConvention: LEAF_CONVENTION,
    treeSize: value.treeSize, root: value.root,
  });
}

export async function presented(
  input: Uint8Array, primitives: WitnessPrimitives, signal: AbortSignal,
): Promise<PresentedHead> {
  assertActive(signal);
  if (!(input instanceof Uint8Array) || input.byteLength === 0 || input.byteLength > MAX_HEAD_BYTES) {
    throw new Error("witness:head-invalid");
  }
  const bytes = input.slice();
  const canonical = await primitives.canonicalize(bytes.slice(), signal);
  assertActive(signal);
  if (!(canonical instanceof Uint8Array) || canonical.length !== bytes.length
    || !bytes.every((byte, index) => byte === canonical[index])) throw new Error("witness:head-invalid");
  let value: unknown;
  try { value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("witness:head-invalid"); }
  if (!record(value, "leafConvention,proofFromPrevious,retainedTreeSize,root,schema,treeSize")
    || value.schema !== PRESENTED_SCHEMA || value.leafConvention !== LEAF_CONVENTION
    || !size(value.treeSize) || !digest(value.root)
    || typeof value.retainedTreeSize !== "number" || !Number.isSafeInteger(value.retainedTreeSize)
    || value.retainedTreeSize < 0 || !Array.isArray(value.proofFromPrevious)
    || value.proofFromPrevious.length > MAX_PROOF_HASHES || !value.proofFromPrevious.every(digest)) {
    throw new Error("witness:head-invalid");
  }
  return Object.freeze({
    schema: PRESENTED_SCHEMA, leafConvention: LEAF_CONVENTION,
    treeSize: value.treeSize, root: value.root, retainedTreeSize: value.retainedTreeSize,
    proofFromPrevious: Object.freeze([...value.proofFromPrevious]),
  });
}

export function checkpointFor(head: PresentedHead): BrowserCheckpoint {
  return Object.freeze({
    schema: CHECKPOINT_SCHEMA, leafConvention: LEAF_CONVENTION,
    treeSize: head.treeSize, root: head.root,
  });
}
