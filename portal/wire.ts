// SPDX-License-Identifier: AGPL-3.0-or-later
import { be, concat, domain, encode, hex, integer, object, optional, refuse, string, unhex, utf8, verify, type Json } from "./bytes.js";
import { COMPACT_MAGIC } from "./frame-text.js";
import { compressKey, decompressKey } from "./p256.js";

export type Participant = { node: string; device_key: string; device_epoch: number; session_id: string; attempt_sequence: number };
export type Layers = { sound: boolean; motion: boolean; intent_ack: boolean };
export type Context = { a: Participant; b: Participant; method: "screen-to-screen" | "remote" | "relayed"; required_layers: Layers; purpose: string; intent: string | null };
export type Channels = { sound: string | null; motion: string | null };
export type Core = { context: Context; nonce_a: string; nonce_b: string; t_a_seconds: number; t_b_seconds: number; transcript: string; channels: Channels };
export type Frame = { type: string; t_seconds: number; frame_index: number; [key: string]: Json };
export type Packet = { schema: string; body: { body: Frame; signature: string } };
export const RECEIPT_SCHEMA = "aukora.copresence.hardened.v1";
export const FRAME_SCHEMA = "aukora.copresence.frame.v1";
// The compact frame wire (see COMPACT FRAMES below). The engine speaks one or the other for a whole exchange.
export const COMPACT_SCHEMA = "aukora.copresence.compact-frame.v1";
export const COMPACT_DOMAIN = "copresence.compact-frame.v1";
export type FrameWire = "json-v1" | "compact-v1";
// How old a compact frame may be when it is read. A screen redraws its first frames (the face, the reveal) all through the exchange, and
// they cannot be re-signed (the transcript hashes their exact bytes), so a peer that reads one late must still accept it. 30 s, within
// the exchange. (json-v1 keeps its original 5 s.)
export const COMPACT_FRESH_SECONDS = 30;
// How old a receipt may be, from its second timestamp (t_b), when it is verified: the node's rule and this engine's, 20 seconds (it was 10:
// a slow reader can need more than ten between B's reveal and the receipt). The two reveals must still be at most 10 s apart.
export const RECEIPT_FRESH_SECONDS = 20;
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

// ---------------------------------------------------------------------------------------------------------------------------------
// COMPACT FRAMES ("compact-v1"): the same four frames, the same fields and the same signatures, in binary, so a frame fits a small
// QR code. Nothing here changes a receipt, the transcript function or what a device signs over the core: the transcript is still
// domain("copresence.transcript.v1", ...) over the four frames' bytes, which are now these bytes, and the node never reads frames.
//
//   frame      = body || signature (64-byte raw r||s over compactDigest(body); WebCrypto ECDSA P-256 / SHA-256)
//   body       = 0xC1 || type || fields...           all integers big-endian, fixed width
//   FACE       01  node[16] key[33, SEC1 compressed] epoch u32  attempt u32  session[16]  method u8  layers u8
//                  nonce_commitment[32]  t u32  index u16
//   SEENYOU    02  sender u8 (0 = A, 1 = B)  context_digest[32]  face_a[32]  face_b[32]  nonce[32]  t u32  index u16
//   HANDSHAKE  03  core_digest[32]  sig_b[64]  t u32  index u16
//   BLOOM      04  flags u8 (bit 0 = has intent signature)  core_digest[32]  sig_a[64]  [intent_sig[64]]  t u32  index u16
//
// Where the JSON frames repeated the whole context (SEENYOU) and the whole core (HANDSHAKE), each device already holds both: the
// compact frames carry their digests and the receiver compares them with the ones it computed itself. A QR code carries the frame
// as base45 text in the alphanumeric mode (portal/frame-text.ts).
// ---------------------------------------------------------------------------------------------------------------------------------
const COMPACT_TYPES = ["", "FACE", "SEENYOU", "HANDSHAKE", "BLOOM"] as const;
const METHODS = ["screen-to-screen", "remote", "relayed"] as const;
const layerBits = (value: Layers): number => (value.sound ? 1 : 0) | (value.motion ? 2 : 0) | (value.intent_ack ? 4 : 0);

function putInt(value: unknown, width: 2 | 4): Uint8Array {
  const n = integer(value, width === 2 ? 0xffff : 0xffffffff);
  const out = new Uint8Array(width);
  for (let i = width - 1, rest = n; i >= 0; --i, rest = Math.floor(rest / 256)) out[i] = rest % 256;
  return out;
}
const getInt = (bytes: Uint8Array, at: number, width: 2 | 4): number => bytes.subarray(at, at + width).reduce((sum, byte) => sum * 256 + byte, 0);

/** The unsigned body of a compact frame. Field names are the JSON frames' (the engine reads either), except the digests that replace
 *  the context and the core: `context_digest`, `core_digest`. */
export function encodeCompact(frame: Frame): Uint8Array {
  const type = COMPACT_TYPES.indexOf(frame.type as typeof COMPACT_TYPES[number]);
  if (type < 1) refuse("frame-type");
  const head = new Uint8Array([COMPACT_MAGIC, type]);
  const tail = concat(putInt(frame.t_seconds, 4), putInt(frame.frame_index, 2));
  if (frame.type === "FACE") {
    const who = participant(frame.participant);
    const method = METHODS.indexOf(string(frame.method) as typeof METHODS[number]);
    if (method < 0) refuse("method");
    return concat(head, unhex(who.node, 16), compressKey(unhex(who.device_key, 65)), putInt(who.device_epoch, 4), putInt(who.attempt_sequence, 4),
      unhex(who.session_id, 16), new Uint8Array([method, layerBits(layers(frame.required_layers))]), unhex(frame.nonce_commitment, 32), tail);
  }
  if (frame.type === "SEENYOU") {
    if (frame.sender !== "A" && frame.sender !== "B") refuse("sender");
    return concat(head, new Uint8Array([frame.sender === "A" ? 0 : 1]), unhex(frame.context_digest, 32), unhex(frame.face_a, 32), unhex(frame.face_b, 32),
      unhex(frame.nonce, 32), tail);
  }
  if (frame.type === "HANDSHAKE") return concat(head, unhex(frame.core_digest, 32), unhex(frame.sig_b, 64), tail);
  const intent = frame.intent_sig === null || frame.intent_sig === undefined ? null : unhex(frame.intent_sig, 64);
  return concat(head, new Uint8Array([intent ? 1 : 0]), unhex(frame.core_digest, 32), unhex(frame.sig_a, 64), intent ?? new Uint8Array(0), tail);
}

export function compactDigest(body: Uint8Array): Promise<Uint8Array> {
  return domain(COMPACT_DOMAIN, be(body.length, 4), body);
}

/** Splits and decodes a whole compact frame; refuses any length, type or reserved value that is not exact. Verifies nothing. */
export function decodeCompact(bytes: Uint8Array): { frame: Frame; body: Uint8Array; signature: string } {
  if (bytes.length < 2 + 6 + 64 || bytes.length > 512 || bytes[0] !== COMPACT_MAGIC) refuse("frame-wire");
  const body = bytes.subarray(0, bytes.length - 64);
  const signature = hex(bytes.subarray(bytes.length - 64));
  const type = COMPACT_TYPES[body[1]!];
  if (!type) refuse("frame-type");
  const tailAt = body.length - 6;
  const times = { t_seconds: getInt(body, tailAt, 4), frame_index: getInt(body, tailAt + 4, 2) };
  const exact = (length: number): void => { if (body.length !== length) refuse("frame-length"); };
  let frame: Frame;
  if (type === "FACE") {
    exact(2 + 16 + 33 + 4 + 4 + 16 + 1 + 1 + 32 + 6);
    const method = METHODS[body[75]!];
    const bits = body[76]!;
    if (!method || bits > 7) refuse("frame-fields");
    frame = { type, participant: { node: hex(body.subarray(2, 18)), device_key: hex(decompressKey(body.subarray(18, 51))), device_epoch: getInt(body, 51, 4),
      session_id: hex(body.subarray(59, 75)), attempt_sequence: getInt(body, 55, 4) }, method,
      required_layers: { sound: (bits & 1) !== 0, motion: (bits & 2) !== 0, intent_ack: (bits & 4) !== 0 }, nonce_commitment: hex(body.subarray(77, 109)), ...times };
    participant(frame.participant);
  } else if (type === "SEENYOU") {
    exact(2 + 1 + 32 * 4 + 6);
    if (body[2]! > 1) refuse("sender");
    frame = { type, sender: body[2] === 0 ? "A" : "B", context_digest: hex(body.subarray(3, 35)), face_a: hex(body.subarray(35, 67)), face_b: hex(body.subarray(67, 99)),
      nonce: hex(body.subarray(99, 131)), ...times };
  } else if (type === "HANDSHAKE") {
    exact(2 + 32 + 64 + 6);
    frame = { type, core_digest: hex(body.subarray(2, 34)), sig_b: hex(body.subarray(34, 98)), ...times };
  } else {
    const flags = body[2]!;
    if (flags > 1) refuse("frame-fields");
    exact(2 + 1 + 32 + 64 + (flags ? 64 : 0) + 6);
    frame = { type, core_digest: hex(body.subarray(3, 35)), sig_a: hex(body.subarray(35, 99)), intent_sig: flags ? hex(body.subarray(99, 163)) : null, ...times };
  }
  return { frame, body: body.slice(), signature };
}

/** Decodes a compact frame and checks what can be checked without the exchange's context: its shape, its age and, for a FACE (which
 *  names its own key), its signature. The other frames are verified against the bound context when the engine has it. */
export async function validateCompact(bytes: Uint8Array, now: number): Promise<{ packet: Packet; key: string }> {
  const { frame, body, signature } = decodeCompact(bytes);
  if (frame.t_seconds > now + 2 || now - frame.t_seconds > COMPACT_FRESH_SECONDS) refuse("frame-stale");
  let key = "";
  if (frame.type === "FACE") {
    key = participant(frame.participant).device_key;
    await verify(key, signature, await compactDigest(body));
  }
  return { packet: { schema: COMPACT_SCHEMA, body: { body: frame, signature } }, key };
}
