// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  JOINING_CONTEXT_SCHEMA, type JoiningConfiguration, type JoiningContext,
  type JoiningParticipant, type JoiningSnapshot, type PreparedJoiningExchange,
} from "./services.js";

export function refuse(reason: string): never { throw new Error(`invites:${reason}`); }

export function live(signal: AbortSignal): void {
  if (signal.aborted) refuse("joining-cancelled");
}

function record(value: unknown, fields: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
    || Object.keys(value).sort().join("\0") !== [...fields].sort().join("\0")) refuse("joining-fields");
  return value as Record<string, unknown>;
}

function text(value: unknown, pattern: RegExp): string {
  if (typeof value !== "string" || !pattern.test(value)) refuse("joining-context");
  return value;
}

export function hex(value: unknown, length: number): string {
  if (typeof value !== "string" || value.length !== length * 2 || !/^[0-9a-f]+$/.test(value)) {
    refuse("joining-context");
  }
  return value;
}

function integer(value: unknown, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || Object.is(value, -0) || value < minimum) {
    refuse("joining-context");
  }
  return value;
}

function participant(value: unknown): JoiningParticipant {
  const item = record(value, ["ownerCredential", "ownerPublicKey", "ownerEpoch", "devicePublicKey", "deviceEpoch", "sessionContribution"]);
  const ownerCredential = text(item.ownerCredential, /^[A-Za-z0-9_-]{1,1366}$/);
  const ownerPublicKey = text(item.ownerPublicKey, /^(?:[0-9a-f]{2}){1,2048}$/);
  const devicePublicKey = text(item.devicePublicKey, /^04[0-9a-f]{128}$/);
  return Object.freeze({ ownerCredential, ownerPublicKey, ownerEpoch: integer(item.ownerEpoch), devicePublicKey,
    deviceEpoch: integer(item.deviceEpoch), sessionContribution: hex(item.sessionContribution, 32) });
}

function joiningContext(value: unknown): JoiningContext {
  const item = record(value, ["schema", "ceremony", "node", "claimDigest", "purpose", "participants", "scopes", "method", "requiredLayers", "issuedAtMs", "expiresAtMs"]);
  if (item.schema !== JOINING_CONTEXT_SCHEMA || item.purpose !== "join-own-devices" || item.method !== "screen-to-screen") {
    refuse("joining-context");
  }
  if (!Array.isArray(item.participants) || item.participants.length !== 2) refuse("joining-participants");
  const a = participant(item.participants[0]), b = participant(item.participants[1]);
  if (a.devicePublicKey === b.devicePublicKey || a.sessionContribution === b.sessionContribution) refuse("joining-participants");
  if (!Array.isArray(item.scopes) || item.scopes.length < 1 || item.scopes.length > 32) refuse("joining-scopes");
  const scopes = item.scopes.map(scope => text(scope, /^[a-z][a-z0-9._:-]{0,127}$/));
  if (scopes.some((scope, index) => index > 0 && scopes[index - 1] >= scope)) refuse("joining-scopes");
  const layers = record(item.requiredLayers, ["sound", "motion", "intentAcknowledgement"]);
  if (typeof layers.sound !== "boolean" || typeof layers.motion !== "boolean"
    || typeof layers.intentAcknowledgement !== "boolean") refuse("joining-layers");
  const requiredLayers = Object.freeze({ sound: layers.sound, motion: layers.motion, intentAcknowledgement: layers.intentAcknowledgement });
  const issuedAtMs = integer(item.issuedAtMs, 1), expiresAtMs = integer(item.expiresAtMs, 1);
  if (expiresAtMs <= issuedAtMs || expiresAtMs - issuedAtMs > 300_000) refuse("joining-expired");
  return Object.freeze({ schema: JOINING_CONTEXT_SCHEMA, ceremony: hex(item.ceremony, 16), node: hex(item.node, 16),
    claimDigest: hex(item.claimDigest, 32), purpose: "join-own-devices", participants: Object.freeze([a, b]) as readonly [JoiningParticipant, JoiningParticipant],
    scopes: Object.freeze(scopes), method: "screen-to-screen", requiredLayers, issuedAtMs, expiresAtMs });
}

export function origin(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch { return refuse("joining-origin"); }
  if (parsed.protocol !== "https:" || parsed.origin !== value || parsed.username || parsed.password) refuse("joining-origin");
  return value;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}

export async function prepared(value: unknown, checkpoint: Pick<JoiningSnapshot, "node" | "ceremony" | "claimDigest">,
  configuration: JoiningConfiguration, signal: AbortSignal, requireFresh: boolean): Promise<PreparedJoiningExchange> {
  live(signal);
  if (!configuration.contextFormatPinned(JOINING_CONTEXT_SCHEMA)) refuse("joining-format-unpinned");
  const item = record(value, ["context", "canonicalContext", "contextDigest"]);
  const context = joiningContext(item.context), contextDigest = hex(item.contextDigest, 32);
  if (context.node !== checkpoint.node || context.ceremony !== checkpoint.ceremony || context.claimDigest !== checkpoint.claimDigest) {
    refuse("joining-context-mismatch");
  }
  if (!(item.canonicalContext instanceof Uint8Array) || item.canonicalContext.length < 1 || item.canonicalContext.length > 16_384) {
    refuse("joining-context-size");
  }
  const canonicalContext = Uint8Array.from(item.canonicalContext);
  const computed = await configuration.codec.encode(context, signal);
  live(signal);
  if (!(computed.canonical instanceof Uint8Array) || !equal(canonicalContext, computed.canonical)
    || hex(computed.digest, 32) !== contextDigest) refuse("joining-context-mismatch");
  if (requireFresh && (context.issuedAtMs > Date.now() || context.expiresAtMs <= Date.now())) refuse("joining-expired");
  return Object.freeze({ context, canonicalContext, contextDigest });
}

export function stageNumber(snapshot: JoiningSnapshot): number {
  switch (snapshot.stage) {
    case "copresence": return 0;
    case "phrase": return 1;
    case "passkey": return 2;
    case "bound": return 3;
    default: return refuse("joining-stage");
  }
}

function snapshotToken(snapshot: JoiningSnapshot): string {
  const base: unknown[] = [snapshot.ceremony, snapshot.node, snapshot.claimDigest, snapshot.revision, snapshot.stage];
  if (snapshot.stage !== "copresence") base.push(snapshot.evidence.receiptDigest, snapshot.evidence.exchange.contextDigest,
    Array.from(snapshot.evidence.exchange.canonicalContext));
  if (snapshot.stage === "passkey" || snapshot.stage === "bound") base.push(snapshot.phrase.subject, snapshot.phrase.envelopeDigest);
  if (snapshot.stage === "bound") base.push(snapshot.binding.subject, snapshot.binding.credential,
    snapshot.binding.ownerPublicKey, snapshot.binding.ownerEpoch, snapshot.binding.receiptSequence);
  return JSON.stringify(base);
}

export async function snapshot(value: unknown, previous: JoiningSnapshot | null, configuration: JoiningConfiguration,
  signal: AbortSignal): Promise<JoiningSnapshot> {
  live(signal);
  if (!value || typeof value !== "object" || !("stage" in value)) refuse("joining-stage");
  const stage = value.stage;
  const extra = stage === "copresence" ? [] : stage === "phrase" ? ["evidence"]
    : stage === "passkey" ? ["evidence", "phrase"] : stage === "bound" ? ["evidence", "phrase", "binding"] : refuse("joining-stage");
  const item = record(value, ["ceremony", "node", "claimDigest", "revision", "stage", ...extra]);
  const base = { ceremony: hex(item.ceremony, 16), node: hex(item.node, 16), claimDigest: hex(item.claimDigest, 32), revision: integer(item.revision) };
  if (base.node !== configuration.node) refuse("joining-context-mismatch");
  let next: JoiningSnapshot;
  if (stage === "copresence") next = Object.freeze({ ...base, stage });
  else {
    const evidence = record(item.evidence, ["exchange", "receiptDigest"]);
    const exchange = await prepared(evidence.exchange, base, configuration, signal, false);
    const recorded = Object.freeze({ exchange, receiptDigest: hex(evidence.receiptDigest, 32) });
    if (stage === "phrase") next = Object.freeze({ ...base, stage, evidence: recorded });
    else {
      const phrase = record(item.phrase, ["subject", "envelopeDigest"]);
      const sealed = Object.freeze({ subject: text(phrase.subject, /^aukora:1:[0-9a-f]{64}$/), envelopeDigest: hex(phrase.envelopeDigest, 32) });
      if (stage === "passkey") next = Object.freeze({ ...base, stage, evidence: recorded, phrase: sealed });
      else {
        const binding = record(item.binding, ["subject", "credential", "ownerPublicKey", "ownerEpoch", "receiptSequence"]);
        const bound = Object.freeze({ subject: text(binding.subject, /^aukora:1:[0-9a-f]{64}$/),
          credential: text(binding.credential, /^[A-Za-z0-9_-]{1,1366}$/),
          ownerPublicKey: text(binding.ownerPublicKey, /^(?:[0-9a-f]{2}){1,2048}$/), ownerEpoch: integer(binding.ownerEpoch),
          receiptSequence: integer(binding.receiptSequence, 1) });
        if (bound.subject !== sealed.subject || !exchange.context.participants.some(part =>
          part.ownerCredential === bound.credential && part.ownerPublicKey === bound.ownerPublicKey
            && part.ownerEpoch === bound.ownerEpoch)) refuse("joining-binding-mismatch");
        next = Object.freeze({ ...base, stage: "bound", evidence: recorded, phrase: sealed, binding: bound });
      }
    }
  }
  if (previous) {
    if (next.ceremony !== previous.ceremony || next.claimDigest !== previous.claimDigest || next.node !== previous.node
      || next.revision < previous.revision || stageNumber(next) < stageNumber(previous)) refuse("joining-checkpoint-mismatch");
    if (next.revision === previous.revision && snapshotToken(next) !== snapshotToken(previous)) refuse("joining-checkpoint-mismatch");
    if (previous.stage !== "copresence" && next.stage !== "copresence"
      && (previous.evidence.receiptDigest !== next.evidence.receiptDigest
        || previous.evidence.exchange.contextDigest !== next.evidence.exchange.contextDigest)) refuse("joining-context-mismatch");
    if ((previous.stage === "passkey" || previous.stage === "bound") && (next.stage === "passkey" || next.stage === "bound")
      && (previous.phrase.subject !== next.phrase.subject || previous.phrase.envelopeDigest !== next.phrase.envelopeDigest)) {
      refuse("joining-binding-mismatch");
    }
  }
  live(signal);
  return next;
}
