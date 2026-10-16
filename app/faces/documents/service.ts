// SPDX-License-Identifier: AGPL-3.0-or-later
// The two calls this face makes, and the checks on what comes back. Both go to the shell's kira
// service. Replies are data: anything that does not have the exact shape below is refused as
// app:invalid-reply.
import type { FaceClient } from "../../core/index.js";

export const PAGE_LIMIT = 100;
export const MAX_LOADED = 1_000;
export const MAX_READ_BYTES = 32_768;

export interface DocumentEntry {
  readonly path: string;
  readonly name: string;
  readonly bytes: number;
  readonly directory: boolean;
}
export interface DocumentPage { readonly entries: readonly DocumentEntry[]; readonly next: string | null }
export interface DocumentText { readonly path: string; readonly text: string; readonly sha256: string }

const FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\\%:]/;

const invalid = (): Error => new Error("app:invalid-reply");

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The same rules the node applies, so a reply naming a path the node would refuse is itself refused. */
export function validPath(path: string): boolean {
  return path.length > 0 && path.length <= 1_024 && !FORBIDDEN.test(path)
    && path.split("/").every(part => part !== "" && part !== "." && part !== "..");
}

function childOf(prefix: string, path: string): boolean {
  return validPath(path) && path.startsWith(prefix) && !path.slice(prefix.length).includes("/");
}

export async function listDocuments(client: FaceClient, directory: string | null, after: string | null, signal: AbortSignal): Promise<DocumentPage> {
  const reply: unknown = await client.call("kira", "documents.list", { directory, after, limit: PAGE_LIMIT }, { signal });
  if (!isObject(reply) || !Array.isArray(reply.entries) || reply.entries.length > PAGE_LIMIT) throw invalid();
  const prefix = directory === null ? "" : `${directory}/`;
  const entries: DocumentEntry[] = [];
  for (const row of reply.entries as unknown[]) {
    if (!isObject(row) || typeof row.path !== "string" || typeof row.directory !== "boolean"
        || typeof row.bytes !== "number" || !Number.isSafeInteger(row.bytes) || row.bytes < 0
        || !childOf(prefix, row.path)) throw invalid();
    entries.push({ path: row.path, name: row.path.slice(prefix.length), bytes: row.bytes, directory: row.directory });
  }
  const next = reply.next;
  if (next !== null && (typeof next !== "string" || next === after || !childOf(prefix, next))) throw invalid();
  return { entries, next };
}

export async function readDocument(client: FaceClient, path: string, signal: AbortSignal): Promise<DocumentText> {
  const reply: unknown = await client.call("kira", "documents.read", { path }, { signal });
  if (!isObject(reply) || reply.path !== path || typeof reply.text !== "string" || reply.text.length > MAX_READ_BYTES
      || typeof reply.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(reply.sha256)) throw invalid();
  return { path, text: reply.text, sha256: reply.sha256 };
}
