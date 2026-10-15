// SPDX-License-Identifier: AGPL-3.0-or-later
export const REQUEST_SCHEMA = "aukora-go-sovereign-request-v1";
export const HANDOFF_SCHEMA = "aukora-go-sovereign-handoff-v1";
export const ALLOCATE_PATH = "/allocate";
export const BODY_LIMIT = 1024;
export const INVITE_SECONDS = 172800;

export class AllocationRefusal extends Error {
  readonly code: string;
  constructor(code: string) {
    super(code);
    this.code = code;
  }
}

export function refuse(reason: string): never {
  throw new AllocationRefusal(`go-sovereign:${reason}`);
}

export function hex(value: unknown, length: number): value is string {
  return typeof value === "string" && value.length === length && /^[0-9a-f]+$/u.test(value);
}

export function token(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(value);
}

export function tokenBytes(value: string): Uint8Array {
  if (!token(value)) refuse("token-invalid");
  const decoded = atob(value.replace(/-/gu, "+").replace(/_/gu, "/") + "=");
  return Uint8Array.from(decoded, character => character.charCodeAt(0));
}

export async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)));
  return Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
}

export function shellOrigin(value: unknown): string {
  if (typeof value !== "string" || value.length > 300) refuse("shell-invalid");
  let url: URL;
  try { url = new URL(value); } catch { refuse("shell-invalid"); }
  if (url.protocol !== "https:" || url.origin !== value || url.username || url.password ||
      url.port || url.hostname.startsWith("owner.") || !url.hostname.includes(".") ||
      !/^[a-z0-9.-]+$/u.test(url.hostname) || url.hostname.endsWith(".")) refuse("shell-invalid");
  return value;
}

export interface AllocationRequest {
  readonly code: string;
  readonly request_key: string;
  readonly schema: typeof REQUEST_SCHEMA;
}

export function encodeRequest(request: AllocationRequest): string {
  if (!hex(request.code, 32) || !token(request.request_key) || request.schema !== REQUEST_SCHEMA) {
    refuse("request-invalid");
  }
  return JSON.stringify({ code: request.code, request_key: request.request_key, schema: REQUEST_SCHEMA });
}

export function decodeRequest(raw: string): AllocationRequest {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { refuse("request-invalid"); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) refuse("request-invalid");
  const fields = value as Record<string, unknown>;
  if (Object.keys(fields).length !== 3 || !hex(fields.code, 32) || !token(fields.request_key) ||
      fields.schema !== REQUEST_SCHEMA) refuse("request-invalid");
  const request: AllocationRequest = { code: fields.code, request_key: fields.request_key, schema: REQUEST_SCHEMA };
  if (encodeRequest(request) !== raw) refuse("request-invalid");
  return request;
}

export interface Handoff {
  readonly claim_token: string;
  readonly schema: typeof HANDOFF_SCHEMA;
  readonly shell_origin: string;
}

export function encodeHandoff(handoff: Handoff): string {
  if (!token(handoff.claim_token) || handoff.schema !== HANDOFF_SCHEMA) refuse("handoff-invalid");
  return JSON.stringify({ claim_token: handoff.claim_token, schema: HANDOFF_SCHEMA,
    shell_origin: shellOrigin(handoff.shell_origin) });
}

export function decodeHandoff(raw: string): Handoff {
  let value: unknown;
  try { value = JSON.parse(raw); } catch { refuse("handoff-invalid"); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) refuse("handoff-invalid");
  const fields = value as Record<string, unknown>;
  if (Object.keys(fields).length !== 3 || !token(fields.claim_token) || fields.schema !== HANDOFF_SCHEMA) {
    refuse("handoff-invalid");
  }
  const handoff: Handoff = { claim_token: fields.claim_token, schema: HANDOFF_SCHEMA,
    shell_origin: shellOrigin(fields.shell_origin) };
  if (encodeHandoff(handoff) !== raw) refuse("handoff-invalid");
  return handoff;
}

export async function readBody(body: ReadableStream<Uint8Array> | null, signal?: AbortSignal): Promise<string> {
  if (!body) refuse("body-invalid");
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let onAbort: (() => void) | undefined;
  const stopped = new Promise<never>((_resolve, reject) => {
    const stop = (reason: string): void => {
      reject(new AllocationRefusal(`go-sovereign:${reason}`));
      void reader.cancel().catch(() => undefined);
    };
    timer = setTimeout(() => stop("body-timeout"), 10000);
    onAbort = () => stop("cancelled");
    signal?.addEventListener("abort", onAbort, { once: true });
  });
  try {
    for (;;) {
      if (signal?.aborted) refuse("cancelled");
      const chunk = await Promise.race([reader.read(), stopped]);
      if (chunk.done) break;
      size += chunk.value.byteLength;
      if (size > BODY_LIMIT) refuse("body-too-large");
      chunks.push(chunk.value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
    catch { refuse("body-invalid"); }
  } finally {
    clearTimeout(timer);
    if (onAbort) signal?.removeEventListener("abort", onAbort);
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}
