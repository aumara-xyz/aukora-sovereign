// SPDX-License-Identifier: AGPL-3.0-or-later
import { be, concat, domain, encode, hex, integer, object, optional, refuse, string, unhex, utf8, verify, type Json } from "./bytes.ts";

export type Participant = { node: string; device_key: string; device_epoch: number; session_id: string; attempt_sequence: number };
export type Layers = { sound: boolean; motion: boolean; intent_ack: boolean };
export type Context = { a: Participant; b: Participant; method: "screen-to-screen" | "remote" | "relayed"; required_layers: Layers; purpose: string; intent: string | null };
export type Channels = { sound: string | null; motion: string | null };
export type Core = { context: Context; nonce_a: string; nonce_b: string; t_a_seconds: number; t_b_seconds: number; transcript: string; channels: Channels };
export type Frame = { type: string; t_seconds: number; frame_index: number; [key: string]: Json };
export type Packet = { schema: "aukora.copresence.frame.v1"; body: { body: Frame; signature: string } };
export const RECEIPT_SCHEMA = "aukora.copresence.hardened.v1";
export const FRAME_SCHEMA = "aukora.copresence.frame.v1";
const PARTICIPANT_KEYS = ["node", "device_key", "device_epoch", "session_id", "attempt_sequence"];

export function participant(value: Json): Participant {
  const data = object(value, PARTICIPANT_KEYS);
  unhex(data.node, 16); unhex(data.session_id, 16);
  const key = unhex(data.device_key, 65);
  if (key[0] !== 4 || integer(data.attempt_sequence) === 0) refuse("participant");
  integer(data.device_epoch);
  return data as Participant;
}
export function layers(value: Json): Layers {
  const data = object(value, ["sound", "motion", "intent_ack"]);
  if (Object.values(data).some(item => typeof item !== "boolean")) refuse("layers");
  return data as Layers;
}
export function context(value: Json): Context {
  const data = object(value, ["a", "b", "method", "required_layers", "purpose", "intent"]);
  participant(data.a); participant(data.b); layers(data.required_layers);
  if (!["screen-to-screen", "remote", "relayed"].includes(string(data.method))) refuse("method");
  if (object(data.a).device_key === object(data.b).device_key || object(data.a).session_id === object(data.b).session_id) refuse("participants");
  string(data.purpose);
  optional(data.intent);
  if (object(data.required_layers).intent_ack && data.intent === null) refuse("intent-required");
  return data as Context;
}
function participantBytes(value: Participant): Uint8Array {
  participant(value);
  return concat(unhex(value.node, 16), unhex(value.device_key, 65), be(value.device_epoch, 8), unhex(value.session_id, 16), be(value.attempt_sequence, 8));
}
export function contextDigest(value: Context): Promise<Uint8Array> {
  context(value);
  const layer = value.required_layers;
  const flags = (layer.sound ? 1 : 0) | (layer.motion ? 2 : 0) | (layer.intent_ack ? 4 : 0);
  const purpose = utf8.encode(value.purpose);
  return domain("copresence.context.v1", participantBytes(value.a), participantBytes(value.b),
    new Uint8Array([["screen-to-screen", "remote", "relayed"].indexOf(value.method), flags]), be(purpose.length, 4), purpose, optional(value.intent));
}
export function nonceCommitment(who: Participant, nonce: string): Promise<Uint8Array> {
  return domain("copresence.nonce-commitment.v1", participantBytes(who), unhex(nonce, 32));
}
export function core(value: Json): Core {
  const data = object(value, ["context", "nonce_a", "nonce_b", "t_a_seconds", "t_b_seconds", "transcript", "channels"]);
  context(data.context); unhex(data.nonce_a, 32); unhex(data.nonce_b, 32); unhex(data.transcript, 32);
  const a = integer(data.t_a_seconds), b = integer(data.t_b_seconds);
  if (b < a || b - a > 10) refuse("window");
  const channels = object(data.channels, ["sound", "motion"]);
  const required = object(object(data.context).required_layers);
  for (const channel of ["sound", "motion"]) {
    optional(channels[channel]);
    if (required[channel] && channels[channel] === null) refuse(`${channel}-required`);
  }
  return data as Core;
}
export async function coreDigest(value: Core): Promise<Uint8Array> {
  core(value);
  return domain("copresence.v1", await contextDigest(value.context), unhex(value.nonce_a, 32), unhex(value.nonce_b, 32),
    be(value.t_a_seconds, 8), be(value.t_b_seconds, 8), unhex(value.transcript, 32), optional(value.channels.sound), optional(value.channels.motion));
}
export function frameDigest(value: Frame): Promise<Uint8Array> {
  const bytes = encode(value);
  return domain("copresence.frame.v1", be(bytes.length, 4), bytes);
}
export function transcript(frames: readonly Uint8Array[]): Promise<Uint8Array> {
  if (frames.length !== 4) refuse("transcript");
  return domain("copresence.transcript.v1", be(frames.length, 4), ...frames.flatMap(bytes => [be(bytes.length, 4), bytes]));
}
export async function validateFrame(value: Json, now: number): Promise<{ packet: Packet; key: string }> {
  const envelope = object(value, ["schema", "body"]);
  if (envelope.schema !== FRAME_SCHEMA) refuse("frame-schema");
  const signed = object(envelope.body, ["body", "signature"]);
  const frame = object(signed.body);
  const type = string(frame.type);
  let key: string;
  if (type === "FACE") {
    object(frame, ["type", "participant", "method", "required_layers", "nonce_commitment", "t_seconds", "frame_index"]);
    const who = participant(frame.participant); layers(frame.required_layers); unhex(frame.nonce_commitment, 32);
    if (!["screen-to-screen", "remote", "relayed"].includes(string(frame.method))) refuse("method");
    key = who.device_key;
  } else if (type === "SEENYOU") {
    object(frame, ["type", "context", "sender", "face_a", "face_b", "nonce", "t_seconds", "frame_index"]);
    const bound = context(frame.context);
    if (frame.sender !== "A" && frame.sender !== "B") refuse("sender");
    unhex(frame.face_a, 32); unhex(frame.face_b, 32); unhex(frame.nonce, 32);
    key = (frame.sender === "A" ? bound.a : bound.b).device_key;
  } else if (type === "HANDSHAKE") {
    object(frame, ["type", "core", "sig_b", "t_seconds", "frame_index"]);
    const input = core(frame.core); unhex(frame.sig_b, 64); key = input.context.b.device_key;
  } else if (type === "BLOOM") {
    object(frame, ["type", "context", "core", "sig_a", "t_seconds", "frame_index"]);
    unhex(frame.context, 32); unhex(frame.core, 32); unhex(frame.sig_a, 64);
    key = "";
  } else refuse("frame-type");
  const time = integer(frame.t_seconds);
  integer(frame.frame_index);
  if (time > now || now - time > 5) refuse("frame-stale");
  if (key) await verify(key, signed.signature, await frameDigest(frame as Frame));
  return { packet: envelope as Packet, key };
}
export function intentAckDigest(coreHash: Uint8Array, contextHash: Uint8Array, intent: string, by: "A" | "B"): Promise<Uint8Array> {
  return domain("copresence.intent-ack.v2", coreHash, contextHash, unhex(intent, 32), new Uint8Array([by === "A" ? 0 : 1]));
}
export function same(a: Json, b: Json): boolean { return hex(encode(a)) === hex(encode(b)); }
