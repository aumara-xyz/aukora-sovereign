// SPDX-License-Identifier: AGPL-3.0-or-later
export type JsonValue = null | boolean | number | string | readonly JsonValue[] | JsonObject;
export type JsonObject = { readonly [key: string]: JsonValue };

export type ApprovalCard = {
  readonly v: 1;
  readonly risk: "routine" | "critical";
  readonly says: string;
  readonly facts: readonly (readonly [string, JsonValue])[];
  readonly from_to: JsonObject;
  readonly model_note: string;
};

export type Authorization = JsonObject & {
  readonly v: 1;
  readonly node: string;
  readonly subject: string;
  readonly op: "apply" | "retire" | "release" | "grant" | "permission";
  readonly proposal: string;
  readonly target: string;
  readonly base_sha256: string;
  readonly new_sha256: string;
  readonly cell: JsonObject | null;
  readonly display_sha256: string;
  readonly challenge: string;
  readonly expires_at: number;
  readonly epoch: number;
  readonly operation: string;
};

export function refuse(reason: string): never {
  throw new Error(`card:${reason}`);
}

function scalarText(text: string): void {
  for (let index = 0; index < text.length; index += 1) {
    const code = text.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) refuse("unicode");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) refuse("unicode");
  }
}

function checked(value: unknown, depth = 0): asserts value is JsonValue {
  if (value === null || typeof value === "boolean") return;
  if (typeof value === "string") { scalarText(value); return; }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) refuse("integer");
    return;
  }
  if (typeof value !== "object" || depth >= 64) refuse("json");
  if (Array.isArray(value)) {
    for (const child of value) checked(child, depth + 1);
  } else {
    for (const key of Object.keys(value)) {
      scalarText(key);
      checked((value as Record<string, unknown>)[key], depth + 1);
    }
  }
}

export function object(value: JsonValue): value is JsonObject {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function canonical(value: JsonValue): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const record = value as JsonObject;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonical(record[key])}`).join(",")}}`;
}

function checkContainerDepth(text: string): void {
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (const character of text) {
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '\"') quoted = false;
    } else if (character === '\"') quoted = true;
    else if (character === "[" || character === "{") {
      depth += 1;
      if (depth > 64) refuse("depth");
    } else if (character === "]" || character === "}") depth -= 1;
  }
}

export function parseCanonical(bytes: Uint8Array): JsonValue {
  let value: unknown;
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
    checkContainerDepth(text);
    value = JSON.parse(text);
  } catch { return refuse("json"); }
  checked(value);
  // Equality also refuses duplicate keys, alternate escapes and number spellings.
  if (canonical(value) !== text) refuse("noncanonical");
  return value;
}

function exactKeys(value: JsonObject, fields: readonly string[]): boolean {
  return Object.keys(value).length === fields.length
    && fields.every(field => Object.prototype.hasOwnProperty.call(value, field));
}

export function parseCard(bytes: Uint8Array): ApprovalCard {
  const value = parseCanonical(bytes);
  if (!object(value) || !exactKeys(value, ["v", "risk", "says", "facts", "from_to", "model_note"])) refuse("shape");
  if (value.v !== 1 || (value.risk !== "routine" && value.risk !== "critical")) refuse("version-or-risk");
  if (typeof value.says !== "string" || /[\r\n\u2028\u2029]/u.test(value.says)) refuse("says");
  if (!Array.isArray(value.facts) || !value.facts.every(row => Array.isArray(row)
    && row.length === 2 && typeof row[0] === "string")) refuse("facts");
  if (!object(value.from_to) || typeof value.model_note !== "string") refuse("shape");
  return value as unknown as ApprovalCard;
}

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;

export function parseAuthorization(bytes: Uint8Array, proposalId: string): Authorization {
  const value = parseCanonical(bytes);
  if (!object(value) || !exactKeys(value, ["v", "node", "subject", "op", "proposal", "target", "base_sha256",
    "new_sha256", "cell", "display_sha256", "challenge", "expires_at", "epoch", "operation"])) refuse("authorization-shape");
  if (value.v !== 1 || typeof value.node !== "string" || !HEX32.test(value.node)
    || typeof value.subject !== "string" || !/^aukora:1:[0-9a-f]{64}$/.test(value.subject)
    || typeof value.proposal !== "string" || !HEX32.test(value.proposal) || value.proposal !== proposalId
    || typeof value.challenge !== "string" || !HEX32.test(value.challenge)) refuse("authorization-identity");
  if (!["apply", "retire", "release", "grant", "permission"].includes(value.op as string)) refuse("unknown-operation");
  if (typeof value.target !== "string" || !/^[A-Za-z0-9._:-]+(?:\/[A-Za-z0-9._:-]+)*$/.test(value.target)
    || value.target.length > 256 || value.target.split("/").some(part => part === "." || part === "..")) refuse("target");
  for (const key of ["new_sha256", "display_sha256", "operation"]) {
    if (typeof value[key] !== "string" || !HEX64.test(value[key] as string)) refuse("authorization-digest");
  }
  if (value.base_sha256 !== "absent" && (typeof value.base_sha256 !== "string" || !HEX64.test(value.base_sha256))) refuse("authorization-base");
  if (typeof value.epoch !== "number" || value.epoch < 0 || typeof value.expires_at !== "number" || value.expires_at < 0) refuse("authorization-time-or-epoch");
  if (value.cell !== null) {
    if (!object(value.cell) || !exactKeys(value.cell, ["module_sha256", "input_sha256", "effect_sha256"])
      || !Object.values(value.cell).every(digest => typeof digest === "string" && HEX64.test(digest))) refuse("cell");
  }
  return value as Authorization;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(bytes)));
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}

export async function domainDigest(domain: string, bytes: Uint8Array): Promise<Uint8Array> {
  const prefix = new TextEncoder().encode(`${domain}\0`);
  const message = new Uint8Array(prefix.length + bytes.length);
  message.set(prefix);
  message.set(bytes, prefix.length);
  return sha256(message);
}

export async function verifyCommitments(card: Uint8Array, authorization: Authorization): Promise<void> {
  if (hex(await sha256(card)) !== authorization.display_sha256) refuse("display-mismatch");
  const operation: JsonObject = {
    v: 1, node: authorization.node, target: authorization.target,
    base_sha256: authorization.base_sha256, new_sha256: authorization.new_sha256, cell: authorization.cell,
  };
  const digest = await domainDigest("aukora:operation-content:v1", new TextEncoder().encode(canonical(operation)));
  if (hex(digest) !== authorization.operation) refuse("operation-mismatch");
}
