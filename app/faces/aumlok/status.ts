// SPDX-License-Identifier: AGPL-3.0-or-later
// AUMLOK's public binding status, in the shape the pinned organs reply gives it: whether the identity root is sealed under
// a seven-word phrase, how many passkeys are enrolled, and whether a phrase refresh is due. Nothing secret is in it, and
// nothing in it authorizes anything. Any other shape refuses; an absent status is never shown as bound.
import type { JsonValue } from "../../core/index.js";

export interface AumlokStatus {
  readonly bound: boolean;
  readonly passkeys: number;
  readonly refreshDue: boolean;
  /** The owner origin the trusted panes are served from, when the service names it. */
  readonly ownerOrigin: string | null;
}

export const MAX_PASSKEYS = 1_000;
const REQUIRED = ["bound", "passkeys", "refresh_due"];
const LOOPBACK = new Set(["localhost", "127.0.0.1", "[::1]"]);

function origin(value: JsonValue | undefined): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.length > 253) throw new Error("aumlok:status-invalid");
  let url: URL;
  try { url = new URL(value); }
  catch { throw new Error("aumlok:status-invalid"); }
  const secure = url.protocol === "https:" || (url.protocol === "http:" && LOOPBACK.has(url.hostname));
  if (!secure || url.origin !== value) throw new Error("aumlok:status-invalid");
  return value;
}

export function parseStatus(value: JsonValue): AumlokStatus {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("aumlok:status-invalid");
  const keys = Object.keys(value);
  const allowed = [...REQUIRED, "owner_origin"];
  if (keys.some(key => !allowed.includes(key)) || REQUIRED.some(key => !keys.includes(key))) {
    throw new Error("aumlok:status-invalid");
  }
  const { bound, passkeys, refresh_due: refreshDue } = value;
  if (typeof bound !== "boolean" || typeof refreshDue !== "boolean" || typeof passkeys !== "number"
    || !Number.isSafeInteger(passkeys) || passkeys < 0 || passkeys > MAX_PASSKEYS) {
    throw new Error("aumlok:status-invalid");
  }
  // A refresh is a property of a bound root; an unbound node cannot owe one.
  if (refreshDue && !bound) throw new Error("aumlok:status-invalid");
  return { bound, passkeys, refreshDue, ownerOrigin: origin(value.owner_origin) };
}
