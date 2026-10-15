// SPDX-License-Identifier: AGPL-3.0-or-later
// What the broker reports about the model route, in the shape the Models contract gives it: the model in the slot, whether
// the node holds a key for it (never the key), the signed spend grant with what has been used, and how the last reply's
// model identity stands. The three identity claims stay three: what was asked for, what the provider said it was, and
// whether anything independent checked. Any other shape refuses, and so does a model name or verifier with text shaped
// like a provider key in it.
import type { JsonValue } from "../../core/index.js";
import { reader } from "../general/data.js";

export type ModelSource =
  | { readonly kind: "provider"; readonly provider: "deepseek" | "openrouter" }
  | { readonly kind: "local"; readonly artifact: string };
export interface ModelSlot {
  readonly name: string;
  readonly source: ModelSource;
}
export interface SpendGrant {
  readonly totalCap: number;
  readonly perRequestCap: number;
  readonly maxRequests: number;
  readonly expiresAt: number;
  readonly promptPrice: number;
  readonly completionPrice: number;
  readonly spent: number;
  readonly reserved: number;
  readonly requests: number;
  readonly frozen: boolean;
}
export type Verification =
  | { readonly verified: false }
  | { readonly verified: true; readonly model: string; readonly verifier: string };
export interface LastReply {
  readonly requested: string;
  readonly reported: string | null;
  readonly verification: Verification;
  readonly outcome: "completed" | "cancelled" | "refused" | "unknown";
  readonly charged: number;
  readonly costUnknown: boolean;
}
export interface ModelsReport {
  readonly model: ModelSlot | null;
  readonly keyPresent: boolean;
  readonly grant: SpendGrant | null;
  readonly last: LastReply | null;
}

const PROVIDERS = ["deepseek", "openrouter"] as const;
const OUTCOMES = ["completed", "cancelled", "refused", "unknown"] as const;
const GRANT_KEYS = [
  "completion_microusd_per_token", "expires_at_ms", "frozen", "max_requests", "per_request_cap_microusd",
  "prompt_microusd_per_token", "requests", "reserved_microusd", "spent_microusd", "total_cap_microusd",
];
const read = reader("models:reply-invalid");

function source(value: JsonValue | undefined): ModelSource {
  if (value !== null && value !== undefined && typeof value === "object" && !Array.isArray(value) && "artifact" in value) {
    return { kind: "local", artifact: read.digest(read.object(value, ["artifact"]).artifact) };
  }
  return { kind: "provider", provider: read.choice(read.object(value, ["provider"]).provider, PROVIDERS) };
}

function grant(value: JsonValue): SpendGrant {
  const row = read.object(value, GRANT_KEYS);
  const total = read.whole(row.total_cap_microusd);
  const perRequest = read.whole(row.per_request_cap_microusd);
  const maxRequests = read.whole(row.max_requests);
  const requests = read.whole(row.requests);
  const spent = read.whole(row.spent_microusd);
  const reserved = read.whole(row.reserved_microusd);
  const expiresAt = read.whole(row.expires_at_ms);
  if (total < 1 || perRequest < 1 || perRequest > total || maxRequests < 1 || requests > maxRequests || expiresAt < 1
    || !Number.isSafeInteger(spent + reserved)) read.fail();
  return {
    totalCap: total, perRequestCap: perRequest, maxRequests, expiresAt, requests, spent, reserved,
    promptPrice: read.whole(row.prompt_microusd_per_token), completionPrice: read.whole(row.completion_microusd_per_token),
    frozen: read.flag(row.frozen),
  };
}

function verification(value: JsonValue | undefined): Verification {
  if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) return read.fail();
  if (value.status === "unverified") {
    read.object(value, ["status"]);
    return { verified: false };
  }
  const row = read.object(value, ["model", "status", "verifier"]);
  if (row.status !== "verified") return read.fail();
  return { verified: true, model: read.model(row.model), verifier: read.keyless(row.verifier, 256) };
}

function lastReply(value: JsonValue): LastReply {
  const row = read.object(value, ["charged_microusd", "cost_unknown", "identity", "outcome"]);
  const identity = read.object(row.identity, ["reported", "requested", "verified"]);
  return {
    requested: read.model(identity.requested), reported: read.nullable(identity.reported, read.model),
    verification: verification(identity.verified), outcome: read.choice(row.outcome, OUTCOMES),
    charged: read.whole(row.charged_microusd), costUnknown: read.flag(row.cost_unknown),
  };
}

export function parseModels(value: JsonValue): ModelsReport {
  const row = read.object(value, ["grant", "key", "last_reply", "model"]);
  const slot = read.nullable(row.model, item => {
    const entry = read.object(item, ["name", "source"]);
    return { name: read.model(entry.name), source: source(entry.source) };
  });
  return {
    model: slot, keyPresent: read.flag(read.object(row.key, ["present"]).present),
    grant: read.nullable(row.grant, grant), last: read.nullable(row.last_reply, lastReply),
  };
}
