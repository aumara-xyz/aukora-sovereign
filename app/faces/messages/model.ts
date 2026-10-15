// SPDX-License-Identifier: AGPL-3.0-or-later
// Readers for the three network replies this face shows. A reply that breaks its shape is refused whole: nothing is
// repaired, defaulted or partly shown. The shapes follow crates/messaging (ApprovedContact, PairingMethod,
// OutboxState, RefusalCounts) and are not yet pinned by a vector file:
//   messages.list   {before, limit} -> {items:[{id, direction:"in"|"out", contact:npub, at, text, transport,
//                    state:null|"queued"|"published"|"unconfirmed"|"failed", code:null|refusal}], next}
//   contacts.list   {before, limit} -> {items:[{npub, label, pairing:null|{method, verified_at}}], next}
//   refusals.counts {}              -> {envelope, signature, recipient, stranger, replay, payload, stale_contact,
//                    total, last_aura_sequence}
// An inbound row has no state and no code. An outbound row has a state, and a code exactly when it failed.
import type { JsonValue } from "../../core/index.js";

export type Direction = "in" | "out";
export type SendState = "queued" | "published" | "unconfirmed" | "failed";
export type PairingMethod = "screen-to-screen" | "remote" | "relayed" | "unknown";

export interface Message {
  readonly id: string;
  readonly direction: Direction;
  readonly contact: string;
  readonly at: number;
  readonly text: string;
  readonly state: SendState | null;
  readonly code: string | null;
}
export interface Contact {
  readonly npub: string;
  readonly label: string;
  readonly pairing: { readonly method: PairingMethod; readonly verifiedAt: number } | null;
}
export interface Refusals {
  readonly envelope: number;
  readonly signature: number;
  readonly recipient: number;
  readonly stranger: number;
  readonly replay: number;
  readonly payload: number;
  readonly staleContact: number;
  readonly total: number;
  readonly lastAuraSequence: number;
}
export interface Page<T> { readonly items: readonly T[]; readonly next: string | null }

const PAGE_ITEMS = 100;
const MAX_MESSAGE_BYTES = 16_384;
const MAX_LABEL_BYTES = 160;
const encoder = new TextEncoder();
const clock = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

function invalid(): Error { return new Error("app:invalid-reply"); }

function object(value: unknown): { readonly [key: string]: JsonValue } {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid();
  return value as { readonly [key: string]: JsonValue };
}

function handle(value: unknown): string {
  if (typeof value !== "string" || /[\u0000-\u001f\u007f-\u009f]/.test(value)) throw invalid();
  const bytes = encoder.encode(value).length;
  if (bytes < 1 || bytes > 128) throw invalid();
  return value;
}

function npub(value: unknown): string {
  if (typeof value !== "string" || !/^npub1[02-9ac-hj-np-z]{58}$/.test(value)) throw invalid();
  return value;
}

function bounded(value: unknown, maximum: number, allowControls: boolean): string {
  if (typeof value !== "string" || (!allowControls && /[\u0000-\u001f\u007f-\u009f]/.test(value))) throw invalid();
  const bytes = encoder.encode(value).length;
  if (bytes < 1 || bytes > maximum) throw invalid();
  return value;
}

function refusal(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/.test(value)) throw invalid();
  return value;
}

function whole(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw invalid();
  return value;
}

function nullable<T>(value: unknown, read: (item: unknown) => T): T | null {
  return value === null ? null : read(value);
}

function sendState(value: unknown): SendState {
  if (value !== "queued" && value !== "published" && value !== "unconfirmed" && value !== "failed") throw invalid();
  return value;
}

function readMessage(value: unknown): Message {
  const row = object(value);
  const direction = row.direction;
  if (direction !== "in" && direction !== "out") throw invalid();
  if (row.transport !== "nostr-relays") throw invalid();
  const state = nullable(row.state, sendState);
  const code = nullable(row.code, refusal);
  const shaped = direction === "in" ? state === null && code === null : state !== null && (state === "failed") === (code !== null);
  if (!shaped) throw invalid();
  return {
    id: handle(row.id), direction, contact: npub(row.contact), at: whole(row.at),
    text: bounded(row.text, MAX_MESSAGE_BYTES, true), state, code,
  };
}

function readPairing(value: unknown): NonNullable<Contact["pairing"]> {
  const row = object(value);
  const method = row.method;
  if (method !== "screen-to-screen" && method !== "remote" && method !== "relayed" && method !== "unknown") throw invalid();
  return { method, verifiedAt: whole(row.verified_at) };
}

function readContact(value: unknown): Contact {
  const row = object(value);
  return { npub: npub(row.npub), label: bounded(row.label, MAX_LABEL_BYTES, false), pairing: nullable(row.pairing, readPairing) };
}

// A page names its own continuation: no items means no continuation, and a key never repeats within a page.
function readPage<T>(value: JsonValue, read: (item: unknown) => T, key: (item: T) => string): Page<T> {
  const reply = object(value);
  if (!Array.isArray(reply.items) || reply.items.length > PAGE_ITEMS) throw invalid();
  const items = reply.items.map(read);
  if (new Set(items.map(key)).size !== items.length) throw invalid();
  const next = nullable(reply.next, handle);
  if (next !== null && items.length === 0) throw invalid();
  return { items, next };
}

export function readMessagePage(value: JsonValue): Page<Message> {
  return readPage(value, readMessage, message => message.id);
}

export function readContactPage(value: JsonValue): Page<Contact> {
  return readPage(value, readContact, contact => contact.npub);
}

// The total must equal the buckets; counts that disagree with themselves are not shown.
export function readRefusals(value: JsonValue): Refusals {
  const row = object(value);
  const counts: Refusals = {
    envelope: whole(row.envelope), signature: whole(row.signature), recipient: whole(row.recipient),
    stranger: whole(row.stranger), replay: whole(row.replay), payload: whole(row.payload),
    staleContact: whole(row.stale_contact), total: whole(row.total), lastAuraSequence: whole(row.last_aura_sequence),
  };
  const sum = counts.envelope + counts.signature + counts.recipient + counts.stranger + counts.replay
    + counts.payload + counts.staleContact;
  if (!Number.isSafeInteger(sum) || sum !== counts.total) throw invalid();
  return counts;
}

export function shortKey(key: string): string {
  return `${key.slice(0, 12)}…${key.slice(-6)}`;
}

export function moment(ms: number): { readonly label: string; readonly iso: string } | null {
  const date = new Date(ms);
  return Number.isFinite(date.getTime()) ? { label: clock.format(date), iso: date.toISOString() } : null;
}
