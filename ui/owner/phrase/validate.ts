// SPDX-License-Identifier: AGPL-3.0-or-later
import { hex, sha256 } from "../cards/codec.js";
import type { CurrentEnvelope, RefreshSnapshot, RefreshSubmission } from "./services.js";

export function refuse(reason: string): never { throw new Error(`aumlok:${reason}`); }

export function id(value: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{32}$/.test(value)) refuse("ceremony-id");
}

export function bytes(value: Uint8Array, minimum: number, maximum: number): void {
  if (!(value instanceof Uint8Array) || value.length < minimum || value.length > maximum) {
    refuse("refresh-input");
  }
}

export function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function counter(value: bigint): void {
  if (typeof value !== "bigint" || value < 0n || value > 0xffffffffffffffffn) refuse("refresh-input");
}

function digest(value: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) refuse("refresh-input");
}

function subject(value: string): void {
  if (typeof value !== "string" || !/^aukora:1:[0-9a-f]{64}$/.test(value)) refuse("refresh-input");
}

export function sameSubmission(a: RefreshSubmission, b: RefreshSubmission): boolean {
  return a.ceremony === b.ceremony && a.session === b.session && a.subject === b.subject
    && a.expectedEpoch === b.expectedEpoch && a.expectedRevision === b.expectedRevision
    && a.previousDigest === b.previousDigest && sameBytes(a.replacement, b.replacement)
    && sameBytes(a.protectedNonce, b.protectedNonce) && sameBytes(a.protectedCiphertext, b.protectedCiphertext);
}

export function sameCurrent(a: CurrentEnvelope, b: CurrentEnvelope): boolean {
  return a.subject === b.subject && a.ownerEpoch === b.ownerEpoch && a.revision === b.revision
    && a.digest === b.digest && sameBytes(a.envelope, b.envelope);
}

export function copyCurrent(value: CurrentEnvelope): CurrentEnvelope {
  return { ...value, envelope: Uint8Array.from(value.envelope) };
}

export function copySubmission(value: RefreshSubmission): RefreshSubmission {
  return { ...value, replacement: Uint8Array.from(value.replacement),
    protectedNonce: Uint8Array.from(value.protectedNonce), protectedCiphertext: Uint8Array.from(value.protectedCiphertext) };
}

export async function snapshot(input: RefreshSnapshot): Promise<RefreshSnapshot> {
  const c = input.current;
  subject(c.subject); counter(c.ownerEpoch); counter(c.revision); digest(c.digest);
  bytes(c.envelope, 1, 1024);
  const current = copyCurrent(c);
  if (hex(await sha256(current.envelope)) !== current.digest) refuse("refresh-corrupt");
  if (input.pending === null) return { current, pending: null };
  const record = input.pending;
  if (!["prepared", "in-doubt", "committed", "cancelled", "expired"].includes(record.state)) {
    refuse("refresh-state");
  }
  const s = record.submission;
  id(s.ceremony); id(s.session); subject(s.subject); counter(s.expectedEpoch); counter(s.expectedRevision);
  digest(s.previousDigest); digest(record.replacementDigest);
  bytes(s.replacement, 1, 1024); bytes(s.protectedNonce, 24, 24); bytes(s.protectedCiphertext, 17, 1040);
  const submission = copySubmission(s);
  if (hex(await sha256(submission.replacement)) !== record.replacementDigest
    || record.replacementDigest === submission.previousDigest) refuse("refresh-corrupt");
  if (current.subject !== submission.subject || current.ownerEpoch !== submission.expectedEpoch) refuse("refresh-stale");
  if (record.state === "committed") {
    if (current.revision !== submission.expectedRevision + 1n || current.digest !== record.replacementDigest
      || !sameBytes(current.envelope, submission.replacement)) refuse("refresh-unsettled");
  } else if (record.state === "prepared" || record.state === "in-doubt") {
    if (current.revision !== submission.expectedRevision || current.digest !== submission.previousDigest) {
      refuse("refresh-stale");
    }
  }
  return { current, pending: { ...record, submission } };
}
