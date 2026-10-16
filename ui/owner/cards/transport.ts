// SPDX-License-Identifier: AGPL-3.0-or-later
import type { ProposalCardBytes, SupervisorCards } from "../contracts.js";
import { credentialBytes } from "../passkey/codec.js";
import { canonical, domainDigest, object, parseAuthorization, parseCanonical, parseCard, refuse,
  verifyCommitments } from "./codec.js";
import type { Authorization, JsonObject, JsonValue } from "./codec.js";
import type { SupervisorApprovalActions } from "./index.js";

export type ApprovalRoute = "/api/v1/approvals/review" | "/api/v1/approvals/assertion";
export type ApprovalResponse = { readonly body: unknown; readonly relativeTimeoutMs?: number };
export type ApprovalRequest = (route: ApprovalRoute, body: JsonObject, signal: AbortSignal) => Promise<ApprovalResponse>;
export type ApprovalServiceOptions = {
  readonly request?: ApprovalRequest;
  readonly action?: "apply" | "retire";
};
const LIMIT = 2 * 1024 * 1024;

function keys(value: JsonObject, expected: readonly string[]): void {
  if (Object.keys(value).length !== expected.length
    || expected.some(key => !Object.prototype.hasOwnProperty.call(value, key))) refuse("response");
}

function responseObject(value: unknown): JsonObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) refuse("response");
  return value as JsonObject;
}

function remaining(value: unknown, started: number): number {
  const elapsed = performance.now() - started;
  if (!Number.isSafeInteger(value) || (value as number) <= 0 || (value as number) > 300_000
    || !Number.isFinite(elapsed) || elapsed < 0) refuse("ceremony-expired");
  const duration = Math.floor((value as number) - elapsed);
  if (duration <= 0) refuse("ceremony-expired");
  return duration;
}

async function request(route: ApprovalRoute, body: JsonObject, signal: AbortSignal): Promise<ApprovalResponse> {
  const started = performance.now();
  const response = await fetch(route, {
    method: "POST", mode: "same-origin", credentials: "same-origin", redirect: "error",
    cache: "no-store", referrerPolicy: "no-referrer",
    headers: { "Content-Type": "application/json" }, body: canonical(body),
    signal: AbortSignal.any([signal, AbortSignal.timeout(30_000)]),
  });
  if (response.headers.get("content-type")?.split(";")[0].trim() !== "application/json" || !response.body) {
    refuse("response");
  }
  const chunks: Uint8Array[] = [];
  const reader = response.body.getReader();
  let length = 0;
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      length += chunk.value.length;
      if (length > LIMIT) refuse("response-too-large");
      chunks.push(chunk.value);
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  signal.throwIfAborted();
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const result = parseCanonical(bytes);
  if (response.status !== 200) {
    if (object(result)) {
      keys(result, ["error"]);
      if (typeof result.error === "string" && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(result.error)) {
        throw new Error(result.error);
      }
    }
    refuse("request-refused");
  }
  if (route === "/api/v1/approvals/review") {
    const header = response.headers.get("x-aukora-ceremony-timeout-ms");
    if (header === null || !/^[1-9][0-9]{0,5}$/.test(header)) refuse("ceremony-expired");
    return { body: result, relativeTimeoutMs: remaining(Number(header), started) };
  }
  return { body: result };
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function proposal(value: string): void {
  if (!/^[0-9a-f]{32}$/.test(value)) refuse("proposal");
}

export function createApprovalTransport(options: ApprovalServiceOptions = {}): SupervisorCards & SupervisorApprovalActions {
  const post = options.request ?? request;
  if (typeof post !== "function") refuse("configuration");
  const action = options.action ?? "apply";
  if (action !== "apply" && action !== "retire") refuse("unknown-operation");
  const reviewed = new Map<string, Authorization["op"]>();
  return {
    async loadByProposalId(id, signal): Promise<ProposalCardBytes> {
      proposal(id);
      signal.throwIfAborted();
      reviewed.delete(id);
      const loaded = await post("/api/v1/approvals/review", { proposal_id: id, op: action }, signal);
      const started = performance.now();
      const timeoutMs = remaining(loaded.relativeTimeoutMs, started);
      const result = responseObject(loaded.body);
      keys(result, ["schema", "proposal_id", "card", "authorization", "challenge"]);
      if (result.schema !== "aukora-owner-review-v1" || result.proposal_id !== id
        || typeof result.card !== "string" || typeof result.authorization !== "string"
        || typeof result.challenge !== "string") refuse("response");
      const card = new TextEncoder().encode(result.card);
      const authorization = new TextEncoder().encode(result.authorization);
      if (card.length > 1024 * 1024 || authorization.length > 16_384) refuse("response-too-large");
      parseCard(card);
      const auth = parseAuthorization(authorization, id);
      // The installed release is reviewed through the apply route; the gate answers it as op "release" (38abcd1).
      if (auth.op !== action && !(action === "apply" && auth.op === "release")) refuse("operation-mismatch");
      await verifyCommitments(card, auth);
      const challenge = await domainDigest("aukora:owner-authorization:v1", authorization);
      if (!equal(challenge, credentialBytes(result.challenge))) refuse("challenge-mismatch");
      signal.throwIfAborted();
      reviewed.set(id, auth.op);
      return { proposalId: id, canonicalCard: card, canonicalAuthorization: authorization,
        relativeTimeoutMs: remaining(timeoutMs, started) };
    },
    async submitAuthorization(id, action, bytes, signal): Promise<void> {
      proposal(id);
      signal.throwIfAborted();
      const op = reviewed.get(id);
      if ((op !== action && !(action === "apply" && op === "release"))
        || (action !== "apply" && action !== "retire" && action !== "release")) {
        refuse("review-required");
      }
      reviewed.delete(id);
      if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > 32_768) refuse("assertion");
      const assertion = parseCanonical(bytes);
      if (!object(assertion)) refuse("assertion");
      keys(assertion, ["kind", "credential_id", "client_data_json", "authenticator_data", "signature", "user_handle"]);
      if (assertion.kind !== "passkey") refuse("assertion");
      const loaded = await post("/api/v1/approvals/assertion", {
        proposal_id: id, op: op as string, assertion: assertion as JsonValue,
      }, signal);
      const result = responseObject(loaded.body);
      keys(result, ["schema", "proposal_id", "state"]);
      if (result.schema !== "aukora-owner-outcome-v1" || result.proposal_id !== id
        || result.state !== (action === "retire" ? "retired" : "applied")) refuse("effect-unconfirmed");
      signal.throwIfAborted();
    },
  };
}
