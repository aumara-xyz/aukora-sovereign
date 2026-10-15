// SPDX-License-Identifier: AGPL-3.0-or-later
// The public contact card as the aumlok identity service reports it: who this node is to others (a label, the AUMLOK ID
// and the two delegated Nostr addresses), the contact code the node issued, and the safety numbers to compare. Public keys
// and digits only; no key material, signature or secret can be in it. The face never creates, signs or verifies any of it.
// Any other shape refuses, and a label written by someone else is shown only after it passes the same readability rules.
import type { JsonValue } from "../../core/index.js";

export interface ContactCode {
  readonly text: string;
  /** Unix seconds after which the node no longer honours the code, or null when it does not expire. */
  readonly expiresAt: number | null;
}
export interface SafetyNumber {
  readonly kind: "own" | "contact";
  readonly label: string;
  readonly digits: string;
}
export interface IdentityCard {
  readonly label: string;
  readonly subject: string | null;
  readonly nodeNpub: string | null;
  readonly agentNpub: string | null;
  readonly contact: ContactCode | null;
  readonly safety: readonly SafetyNumber[];
}

export const MAX_LABEL = 64;
export const MAX_CODE = 1_000;
export const MAX_SAFETY = 101;
export const OWN_DIGITS = 35;
export const PAIR_DIGITS = 70;
export const UNREADABLE = "Unreadable name";

const KEYS = ["agent_npub", "contact_code", "label", "node_npub", "safety", "subject"];
const SUBJECT = /^aukora:1:[0-9a-f]{64}$/;
const NPUB = /^npub1[a-z0-9]{1,123}$/;
const PRINTABLE = /^[\x20-\x7e]+$/;
// Control characters, and the characters that reorder or hide text.
const UNREADABLE_CHARACTERS = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁩﻿]/;

function invalid(): never {
  throw new Error("identity:card-invalid");
}

function plain(value: JsonValue | undefined, keys: readonly string[]): { [key: string]: JsonValue } {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) invalid();
  const wanted = [...keys].sort();
  const present = Object.keys(value).sort();
  if (present.length !== wanted.length || present.some((key, at) => key !== wanted[at])) invalid();
  return value;
}

/** A label of 1 to 64 characters with nothing in it that hides or reorders text, or null. */
export function readableLabel(value: JsonValue | undefined): string | null {
  if (typeof value !== "string" || value.length === 0 || [...value].length > MAX_LABEL) return null;
  return UNREADABLE_CHARACTERS.test(value) || value.trim() !== value ? null : value;
}

function nullable(value: JsonValue | undefined, pattern: RegExp): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || !pattern.test(value) || value.length > 128) invalid();
  return value;
}

function contact(value: JsonValue | undefined): ContactCode | null {
  if (value === null) return null;
  const row = plain(value, ["expires_at", "text"]);
  const { text, expires_at: expiresAt } = row;
  if (typeof text !== "string" || text.length > MAX_CODE || !PRINTABLE.test(text)) invalid();
  if (expiresAt !== null && (typeof expiresAt !== "number" || !Number.isSafeInteger(expiresAt) || expiresAt < 0)) invalid();
  return { text, expiresAt };
}

function safety(value: JsonValue | undefined, ownLabel: string): SafetyNumber[] {
  if (!Array.isArray(value) || value.length > MAX_SAFETY) invalid();
  let own = 0;
  return value.map(item => {
    const row = plain(item, ["digits", "kind", "label"]);
    const { digits, kind } = row;
    if (kind !== "own" && kind !== "contact") invalid();
    const length = kind === "own" ? OWN_DIGITS : PAIR_DIGITS;
    if (typeof digits !== "string" || digits.length !== length || !/^[0-9]+$/.test(digits)) invalid();
    if (kind === "own" && ++own > 1) invalid();
    // A contact chose its own name, so an unreadable one is replaced rather than refusing the whole card.
    return { kind, digits, label: kind === "own" ? ownLabel : (readableLabel(row.label) ?? UNREADABLE) };
  });
}

export function parseCard(value: JsonValue): IdentityCard {
  const row = plain(value, KEYS);
  const label = readableLabel(row.label);
  if (label === null) invalid();
  const subject = nullable(row.subject, SUBJECT);
  const code = contact(row.contact_code);
  // A node that is not bound has no identity to introduce, so it can have no contact code.
  if (subject === null && code !== null) invalid();
  return {
    label, subject, nodeNpub: nullable(row.node_npub, NPUB), agentNpub: nullable(row.agent_npub, NPUB),
    contact: code, safety: safety(row.safety, label),
  };
}
