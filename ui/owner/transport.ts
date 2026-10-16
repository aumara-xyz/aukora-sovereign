// SPDX-License-Identifier: AGPL-3.0-or-later
import { credentialBytes } from "./passkey/codec.js";
import type { AssertionOptions, RegistrationOptions } from "./passkey/index.js";

type Route = "/api/enrol/start" | "/api/enrol/finish" | "/api/binding/prepare"
  | "/api/binding/confirm" | "/api/signin/start" | "/api/signin/finish";
export type RecordValue = Record<string, unknown>;

export function record(value: unknown): RecordValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("owner:response-invalid");
  return value as RecordValue;
}

export function exact(value: RecordValue, keys: readonly string[]): void {
  if (Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) throw new Error("owner:response-invalid");
}

export function text(value: unknown, maximum = 256): string {
  if (typeof value !== "string" || !value || value.length > maximum) throw new Error("owner:response-invalid");
  return value;
}

export async function post(route: Route, body: RecordValue, signal: AbortSignal): Promise<RecordValue> {
  const response = await fetch(route, {
    method: "POST", credentials: "same-origin", mode: "same-origin", redirect: "error",
    cache: "no-store", referrerPolicy: "no-referrer", signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
    headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (response.headers.get("Content-Type")?.split(";")[0].trim() !== "application/json" || !response.body) {
    throw new Error("owner:response-invalid");
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      length += part.value.length;
      if (length > 65_536) throw new Error("owner:response-invalid");
      chunks.push(part.value);
    }
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
  signal.throwIfAborted();
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const result = record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
  if (response.status !== 200) {
    exact(result, ["error"]);
    const code = result.error;
    throw new Error(typeof code === "string" && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(code)
      ? code : "owner:request-refused");
  }
  return result;
}

export function handle(value: unknown): string {
  const id = text(value, 32);
  if (!/^[0-9a-f]{32}$/.test(id)) throw new Error("aumlok:ceremony-id");
  return id;
}

export function deadline(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) <= Date.now()) throw new Error("aumlok:ceremony-expired");
  return value as number;
}

export type Options = {
  readonly id: string; readonly expires: number;
  readonly registration?: RegistrationOptions; readonly assertion?: AssertionOptions;
};

export function options(reply: RecordValue, enrolment: boolean, rp: string): Options {
  const key = enrolment ? "enrolment_id" : "ceremony_id";
  exact(reply, [key, "expires_at", "public_key"]);
  const id = handle(reply[key]);
  const expires = deadline(reply.expires_at);
  const source = record(reply.public_key);
  const challenge = credentialBytes(text(source.challenge));
  if (challenge.length !== 32) throw new Error("aumlok:challenge-mismatch");
  if (!Number.isInteger(source.timeout) || (source.timeout as number) < 100
    || (source.timeout as number) > 300_000) throw new Error("aumlok:ceremony-expired");
  const timeoutMs = source.timeout as number;
  if ("rp" in source) {
    exact(source, ["challenge", "rp", "user", "pubKeyCredParams", "timeout", "attestation",
      "authenticatorSelection", "excludeCredentials", "extensions"]);
    if (!enrolment || record(source.rp).id !== rp || source.attestation !== "none") throw new Error("aumlok:origin-mismatch");
    const selection = record(source.authenticatorSelection);
    if (selection.residentKey !== "required" || selection.userVerification !== "required") throw new Error("aumlok:registration-refused");
    const user = record(source.user);
    const algorithms = source.pubKeyCredParams;
    if (!Array.isArray(algorithms) || algorithms.length !== 2
      || algorithms.some((value, index) => {
        const algorithm = record(value);
        exact(algorithm, ["type", "alg"]);
        return algorithm.type !== "public-key" || algorithm.alg !== [-7, -8][index];
      })) throw new Error("aumlok:registration-refused");
    const extensions = record(source.extensions);
    exact(extensions, ["prf"]);
    exact(record(extensions.prf), []);
    if (!Array.isArray(source.excludeCredentials) || source.excludeCredentials.length !== 0) throw new Error("aumlok:credential-id");
    return { id, expires, registration: { challenge, timeoutMs, enablePrf: true, excludeCredentials: [],
      user: { id: credentialBytes(text(user.id)), name: text(user.name), displayName: text(user.displayName) } } };
  }
  exact(source, ["challenge", "rpId", "timeout", "userVerification", "allowCredentials"]);
  if (source.rpId !== rp || source.userVerification !== "required" || !Array.isArray(source.allowCredentials)
    || source.allowCredentials.length !== 1) throw new Error("aumlok:origin-mismatch");
  const descriptor = record(source.allowCredentials[0]);
  exact(descriptor, ["id", "type"]);
  if (descriptor.type !== "public-key") throw new Error("aumlok:credential-type");
  const allowed = text(descriptor.id, 1366);
  credentialBytes(allowed);
  return { id, expires, assertion: { challenge, timeoutMs, allowCredentials: [allowed] } };
}

export function state(reply: RecordValue): "enrolled" | "bound" {
  exact(reply, ["ok", "state", "subject"]);
  if (reply.ok === true && reply.state === "enrolled" && reply.subject === null) return "enrolled";
  if (reply.ok === true && reply.state === "bound" && typeof reply.subject === "string"
    && /^aukora:1:[0-9a-f]{64}$/.test(reply.subject)) return "bound";
  throw new Error("owner:response-invalid");
}
