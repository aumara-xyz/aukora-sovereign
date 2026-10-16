// SPDX-License-Identifier: AGPL-3.0-or-later
// The one call this face makes, and the checks on what comes back. It asks the node's network service
// for the owner's approved contacts, a page at a time. Replies are data: a page that does not have the
// shape below is refused as app:invalid-reply, and a single malformed contact is counted, not shown.
import type { FaceClient } from "../../core/index.js";

export const PAGE_LIMIT = 100;
export const MAX_LOADED = 1_000;

/** How a contact was paired. "none" means the node recorded no pairing evidence at all. */
export type Pairing = "screen-to-screen" | "remote" | "relayed" | "unknown" | "none";

export interface Connection {
  readonly key: string;
  readonly label: string;
  readonly pairing: Pairing;
  readonly verifiedAtMs: number | null;
}
export interface ConnectionPage { readonly items: readonly Connection[]; readonly skipped: number; readonly next: string | null }

const METHODS: ReadonlySet<string> = new Set(["screen-to-screen", "remote", "relayed", "unknown"]);

const invalid = (): Error => new Error("app:invalid-reply");

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function connectionOf(row: unknown): Connection | null {
  if (!isObject(row) || typeof row.key !== "string" || typeof row.label !== "string") return null;
  if (row.key === "" || row.key.length > 256 || row.label.length > 1_024) return null;
  const evidence = row.pairing;
  if (evidence === null || evidence === undefined) return { key: row.key, label: row.label, pairing: "none", verifiedAtMs: null };
  if (!isObject(evidence) || typeof evidence.method !== "string") return null;
  const method = evidence.method.toLowerCase().replaceAll("_", "-");
  const at = evidence.verified_at_ms;
  return {
    key: row.key,
    label: row.label,
    pairing: METHODS.has(method) ? (method as Pairing) : "unknown",
    verifiedAtMs: typeof at === "number" && Number.isSafeInteger(at) && at >= 0 ? at : null,
  };
}

export async function listConnections(client: FaceClient, before: string | null, signal: AbortSignal): Promise<ConnectionPage> {
  const reply: unknown = await client.call("network", "contacts.list", { before, limit: PAGE_LIMIT }, { signal });
  if (!isObject(reply) || !Array.isArray(reply.items) || reply.items.length > PAGE_LIMIT) throw invalid();
  const next = reply.next;
  if (next !== null && (typeof next !== "string" || next === "" || next.length > 128 || next === before)) throw invalid();
  const items: Connection[] = [];
  let skipped = 0;
  for (const row of reply.items as unknown[]) {
    const connection = connectionOf(row);
    if (connection) items.push(connection);
    else skipped++;
  }
  return { items, skipped, next };
}
