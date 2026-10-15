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

const REFUSAL = /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/;
const FORBIDDEN = /[\u0000-\u001f\u007f-\u009f\\%:]/;

const NOTES: Readonly<Record<string, string>> = {
  "frontdoor:document-path-refused":
    "A path or a name in this folder is not allowed. Names may not be empty, '.' or '..', or contain a backslash, a percent sign, a colon or a control character.",
  "frontdoor:document-symlink-refused": "A symbolic link was refused. Only real files and folders inside the document root are read.",
  "frontdoor:document-root-refused": "The document root is not available.",
  "frontdoor:document-kind-refused": "That entry is not a regular file.",
  "frontdoor:document-too-large": "That file is larger than 32 KiB, the most this app reads.",
  "frontdoor:document-utf8-refused": "That file is not valid UTF-8 text.",
  "frontdoor:document-read-refused": "That file could not be read.",
  "frontdoor:document-list-refused": "That folder could not be listed.",
  "frontdoor:document-page-refused": "The page size was refused.",
  "frontdoor:document-directory-too-large": "That folder has more entries than can be listed.",
  "frontdoor:document-session-refused": "Reading documents needs a live, signed-in session.",
  "frontdoor:session-required": "Reading documents needs a live, signed-in session.",
  "frontdoor:capability-denied": "This app is not allowed to read documents.",
  "frontdoor:response-too-large": "The reply was larger than the data channel allows.",
  "app:capability-denied": "This app is not allowed to read documents.",
  "app:service-unavailable": "The documents service is not connected.",
  "app:data-limit": "The reply was larger than the app channel carries.",
  "app:deadline": "The documents service did not answer in time.",
  "app:invalid-reply": "The documents service answered in a shape this app cannot read.",
};

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

/** A refusal code and one plain sentence for it. The code is always shown beside the sentence. */
export function failure(error: unknown): { code: string; note: string } {
  const code = error instanceof Error && REFUSAL.test(error.message) ? error.message : "app:service-unavailable";
  return { code, note: NOTES[code] ?? "The documents service refused the request." };
}
