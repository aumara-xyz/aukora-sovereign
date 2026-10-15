// SPDX-License-Identifier: AGPL-3.0-or-later
import { assertActive } from "./contracts.js";
import type { BrowserCheckpoint, PresentedHead, WitnessPrimitives } from "./contracts.js";

export type ConsistencyFinding = "extension" | "fork" | "undetermined";

function rawDigest(hex: string): Uint8Array {
  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function parent(
  left: string, right: string, primitives: WitnessPrimitives, signal: AbortSignal,
): Promise<string> {
  assertActive(signal);
  const bytes = new Uint8Array(65);
  bytes[0] = 1;
  bytes.set(rawDigest(left), 1);
  bytes.set(rawDigest(right), 33);
  const hash = await primitives.sha256(bytes, signal);
  assertActive(signal);
  if (!(hash instanceof Uint8Array) || hash.length !== 32) throw new Error("witness:hash-unavailable");
  return Array.from(hash, byte => byte.toString(16).padStart(2, "0")).join("");
}

// Both inputs have passed codec validation. Only a proof connected to the new
// root can establish that an independently reconstructed old root conflicts.
export async function consistency(
  previous: BrowserCheckpoint, next: PresentedHead,
  primitives: WitnessPrimitives, signal: AbortSignal,
): Promise<ConsistencyFinding> {
  assertActive(signal);
  if (next.retainedTreeSize !== previous.treeSize || next.treeSize < previous.treeSize) return "undetermined";
  if (next.treeSize === previous.treeSize) {
    if (next.root !== previous.root) return "fork";
    return next.proofFromPrevious.length === 0 ? "extension" : "undetermined";
  }
  const path = next.proofFromPrevious;
  if (path.length === 0) return "undetermined";
  let oldIndex = BigInt(previous.treeSize) - 1n;
  let newIndex = BigInt(next.treeSize) - 1n;
  while ((oldIndex & 1n) === 1n) {
    oldIndex >>= 1n;
    newIndex >>= 1n;
  }
  const anchored = oldIndex === 0n;
  let cursor = anchored ? 0 : 1;
  let oldRoot = anchored ? previous.root : path[0];
  let newRoot = oldRoot;
  while (cursor < path.length) {
    if (newIndex === 0n) return "undetermined";
    const sibling = path[cursor++];
    if ((oldIndex & 1n) === 1n || oldIndex === newIndex) {
      oldRoot = await parent(sibling, oldRoot, primitives, signal);
      newRoot = await parent(sibling, newRoot, primitives, signal);
      while (oldIndex !== 0n && (oldIndex & 1n) === 0n) {
        oldIndex >>= 1n;
        newIndex >>= 1n;
      }
    } else {
      newRoot = await parent(newRoot, sibling, primitives, signal);
    }
    oldIndex >>= 1n;
    newIndex >>= 1n;
  }
  if (newIndex !== 0n || newRoot !== next.root) return "undetermined";
  if (oldRoot === previous.root) return "extension";
  return anchored ? "undetermined" : "fork";
}
