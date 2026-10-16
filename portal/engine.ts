// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AttemptStore, ContextExchange, CopresenceEngine, ExchangeMethod, PersonNostrKeys, PersonNostrKeysForReceipt, PortalExchange, PortalObservation, ReceiptVerdict, RelationshipBloomDigest } from "./contracts.js";
import { checkAbort, digest, domain, encode, hex, integer, object, parse, refuse, sign, string, text, unhex, verify, type Json } from "./bytes.js";
import { IndexedAttempts, ticket } from "./attempts.js";
import { copyPersonNostrKey, pairingDigest, type PentoraPairingDigest } from "./bloom/derive.js";
import { context, contextDigest, core, coreDigest, frameDigest, FRAME_SCHEMA, intentAckDigest, nonceCommitment, participant, RECEIPT_SCHEMA, same, transcript, validateFrame, type Channels, type Context, type Core, type Frame, type Layers, type Packet, type Participant } from "./wire.js";

export type ChannelRequest = { readonly context: Context; readonly side: "A" | "B"; readonly nonceA: string; readonly nonceB: string };
export interface ChannelProbe { collect(request: ChannelRequest, signal: AbortSignal): Promise<Channels> }
export type BrowserEngineOptions = {
  readonly node: string;
  readonly deviceEpoch: number;
  readonly attempts: AttemptStore;
  readonly consumeReceipt: (digest: string, signal: AbortSignal) => Promise<void>;
  readonly contextFormatPinned: () => boolean;
  readonly channels?: ChannelProbe;
  readonly personNostrKeys?: PersonNostrKeysForReceipt;
  readonly pentora?: PentoraPairingDigest;
  readonly legacyVerifier: (receipt: Uint8Array, approved: Uint8Array | null, signal: AbortSignal) => Promise<ReceiptVerdict>;
};
const cleanupSignal = (): AbortSignal => new AbortController().signal;
const now = (): number => Math.floor(Date.now() / 1000);
const result: ReceiptVerdict = Object.freeze({ accepted: true, code: null });
function code(error: unknown): `copresence:${string}` {
  return error instanceof Error && /^copresence:[A-Za-z0-9_-]+$/.test(error.message) ? error.message as `copresence:${string}` : "copresence:invalid-input";
}

function receiptVerdict(value: ReceiptVerdict): ReceiptVerdict {
  if (!value || typeof value !== "object") refuse("receipt-verdict");
  if (value.accepted === true && value.code === null) {
    if (value.position === undefined) return result;
    if (!value.position || value.position.verdict !== "CONSISTENT_CLAIMED"
      || value.position.positionSource !== "SELF_REPORTED_UNVERIFIABLE") refuse("receipt-verdict");
    return { accepted: true, code: null, position: { verdict: "CONSISTENT_CLAIMED", positionSource: "SELF_REPORTED_UNVERIFIABLE" } };
  }
  if (value.accepted === false && typeof value.code === "string" && /^copresence:[A-Za-z0-9_-]+$/.test(value.code)
    && (value.verdict === "SUSPICIOUS" || value.verdict === "UNDETERMINED")) {
    return { accepted: false, code: value.code, verdict: value.verdict };
  }
  refuse("receipt-verdict");
}

export class BrowserCopresenceEngine implements CopresenceEngine {
  private expected: Context | null = null;
  private readonly options: BrowserEngineOptions;
  constructor(options: BrowserEngineOptions) {
    this.options = options;
    unhex(options.node, 16); integer(options.deviceEpoch);
  }
  async begin(exchange: ContextExchange, signal: AbortSignal): Promise<PortalExchange> {
    checkAbort(signal);
    if (!this.options.contextFormatPinned()) refuse("format-unpinned");
    if (exchange.domain !== "copresence.v1") refuse("domain");
    const purpose = text.decode(exchange.contextBytes);
    if (exchange.contextBytes.length > 4096 || purpose.length === 0) refuse("context");
    if (!["optical", "optical-audio", "optical-audio-motion"].includes(exchange.method)) refuse("method");
    if (exchange.method !== "optical" && !this.options.channels) refuse("channels-unavailable");
    const reserved = ticket(exchange.attemptId);
    const intent = exchange.approvedText === null ? null : hex(await domain("copresence.intent.v1", exchange.approvedText));
    const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
    checkAbort(signal);
    const who: Participant = { node: this.options.node, device_key: hex(new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey))), device_epoch: this.options.deviceEpoch, session_id: reserved.session, attempt_sequence: reserved.sequence };
    checkAbort(signal);
    const session = new BrowserExchange(exchange, who, keys.privateKey, purpose, intent, this.options, signal, bound => { this.expected = bound; });
    try { await session.start(); } catch (error) { session.stop(); throw error; }
    return session;
  }
  async verifyLegacyReceipt(bytes: Uint8Array, approved: Uint8Array | null, signal: AbortSignal): Promise<ReceiptVerdict> {
    checkAbort(signal);
    const id = await this.options.attempts.reserve("optical", signal);
    try {
      const verdict = receiptVerdict(await this.options.legacyVerifier(bytes.slice(), approved?.slice() ?? null, signal));
      await this.options.attempts.finish(id, verdict.accepted ? "bloom" : "refused", cleanupSignal());
      return verdict;
    } catch (error) {
      await this.options.attempts.finish(id, "refused", cleanupSignal());
      return { accepted: false, verdict: "SUSPICIOUS", code: code(error) };
    }
  }
  async verifyContextReceipt(bytes: Uint8Array, approved: Uint8Array | null, signal: AbortSignal): Promise<ReceiptVerdict> {
    const id = await this.options.attempts.reserve("optical", signal);
    try {
      if (!this.options.contextFormatPinned()) refuse("format-unpinned");
      if (!this.expected) refuse("expected-context-required");
      await verifyReceipt(bytes, this.expected, approved, signal, this.options.consumeReceipt);
      await this.options.attempts.finish(id, "bloom", cleanupSignal());
      return result;
    } catch (error) {
      await this.options.attempts.finish(id, "refused", cleanupSignal());
      return { accepted: false, verdict: "SUSPICIOUS", code: code(error) };
    }
  }
}

async function verifyReceipt(bytes: Uint8Array, expected: Context, approved: Uint8Array | null, signal: AbortSignal, consume: BrowserEngineOptions["consumeReceipt"], expectedCore?: Core): Promise<{ body: { [key: string]: Json }; hash: Uint8Array }> {
  checkAbort(signal);
  const envelope = object(parse(bytes), ["schema", "body"]);
  if (envelope.schema !== RECEIPT_SCHEMA) refuse("receipt-schema");
  const body = object(envelope.body, ["core", "sig_a", "sig_b", "intent_ack"]);
  const input = core(body.core);
  if (expectedCore && !same(input, expectedCore)) refuse("core-mismatch");
  if (!same(input.context, expected)) refuse("context-mismatch");
  if (input.t_b_seconds > now() || now() - input.t_b_seconds > 10) refuse("receipt-stale");
  const hash = await coreDigest(input);
  await verify(input.context.a.device_key, body.sig_a, hash);
  await verify(input.context.b.device_key, body.sig_b, hash);
  const intent = approved === null ? null : hex(await domain("copresence.intent.v1", approved));
  if (intent !== expected.intent) refuse("intent-mismatch");
  if (intent !== null) {
    const ack = object(body.intent_ack, ["by", "intent", "core", "context", "signature"]);
    const contextHash = await contextDigest(expected);
    if ((ack.by !== "A" && ack.by !== "B") || ack.intent !== intent || ack.core !== hex(hash) || ack.context !== hex(contextHash)) refuse("intent-ack");
    await verify(ack.by === "A" ? expected.a.device_key : expected.b.device_key, ack.signature, await intentAckDigest(hash, contextHash, intent, ack.by));
  } else if (body.intent_ack !== null) refuse("unexpected-intent");
  checkAbort(signal);
  await consume(hex(hash), signal);
  return { body, hash };
}

class BrowserExchange implements PortalExchange {
  private readonly listeners = new Set<(observation: PortalObservation) => void>();
  private readonly controller = new AbortController();
  private readonly nonce = hex(crypto.getRandomValues(new Uint8Array(32)));
  private readonly layers: Layers;
  private readonly frames = new Map<string, { bytes: Uint8Array; packet: Packet }>();
  private readonly seen = new Set<string>();
  private readonly pending = new Map<string, Uint8Array>();
  private ownFace: Uint8Array | null = null;
  private ownFaceHash = "";
  private peerFace: Uint8Array | null = null;
  private peer: Participant | null = null;
  private bound: Context | null = null;
  private side: "A" | "B" | null = null;
  private revealA: Uint8Array | null = null;
  private revealB: Uint8Array | null = null;
  private ownReveal: Uint8Array | null = null;
  private input: Core | null = null;
  private receipt: Uint8Array | null = null;
  private bloom: RelationshipBloomDigest | null = null;
  private personKeys: PersonNostrKeys | null = null;
  private phase: PortalObservation["phase"] = "FACE";
  private verdict: ReceiptVerdict | null = null;
  private current: Uint8Array | null = null;
  private primary: Uint8Array | null = null;
  private index = 0;
  private displayIndex = 0;
  private timer: ReturnType<typeof setInterval> | undefined;
  private timeout: ReturnType<typeof setTimeout> | undefined;
  private queue: Promise<void> = Promise.resolve();
  private stopped = false;
  private channelPromise: Promise<Channels> | null = null;
  private emissionBlocked = false;
  private pendingEmission = false;
  private peerProgress: { index: number; time: number } | null = null;
  private outerAbort: () => void;
  private readonly exchange: ContextExchange;
  private readonly who: Participant;
  private readonly key: CryptoKey;
  private readonly purpose: string;
  private readonly intent: string | null;
  private readonly options: BrowserEngineOptions;
  private readonly onContext: (context: Context) => void;

  constructor(exchange: ContextExchange, who: Participant, key: CryptoKey,
    purpose: string, intent: string | null, options: BrowserEngineOptions,
    signal: AbortSignal, onContext: (context: Context) => void) {
    this.exchange = exchange;
    this.who = who;
    this.key = key;
    this.purpose = purpose;
    this.intent = intent;
    this.options = options;
    this.onContext = onContext;
    this.layers = { sound: exchange.method !== "optical", motion: exchange.method === "optical-audio-motion", intent_ack: intent !== null };
    this.outerAbort = () => this.stop();
    signal.addEventListener("abort", this.outerAbort, { once: true });
    this.controller.signal.addEventListener("abort", () => signal.removeEventListener("abort", this.outerAbort), { once: true });
    if (signal.aborted) this.stop();
  }
  async start(): Promise<void> {
    await this.makeFace();
    this.timer = setInterval(() => {
      this.queue = this.queue.then(async () => {
        if (this.stopped) return;
        if (this.phase === "FACE") await this.makeFace();
        else {
          if (this.primary && (!this.receipt || this.side === "A")) {
            const frame = object(object(object(parse(this.primary)).body).body);
            if (frame.type === "HANDSHAKE" || frame.type === "BLOOM") {
              const { t_seconds: _time, frame_index: _index, ...fields } = frame;
              this.primary = await this.packet(fields);
            }
          }
          const sequence = this.receipt ? [this.receipt, this.primary] : [this.primary, this.ownFace, this.ownReveal];
          const frames = sequence.filter((item): item is Uint8Array => item !== null);
          this.current = frames[this.displayIndex++ % frames.length] ?? this.current;
          this.emit();
        }
      }).catch(error => this.fail(error));
    }, 1000);
    this.timeout = setTimeout(() => { if (this.phase !== "BLOOM") this.fail(new Error("copresence:exchange-timeout")); else this.stop(); }, 25000);
  }
  subscribe(listener: (observation: PortalObservation) => void): () => void {
    this.listeners.add(listener);
    if (!this.emissionBlocked || this.phase !== "BLOOM") listener(this.observation());
    return () => { this.listeners.delete(listener); };
  }
  receive(bytes: Uint8Array): Promise<void> {
    const safe = bytes.slice();
    this.queue = this.queue.then(async () => {
      if (this.stopped || this.phase === "REFUSED") return;
      const id = await this.options.attempts.reserve(this.exchange.method, this.controller.signal);
      let failed = false, failure: unknown;
      this.emissionBlocked = true;
      try {
        checkAbort(this.controller.signal);
        if (safe.length > 65536) refuse("size");
        const key = hex(await digest(safe));
        if (!this.seen.has(key)) {
          await this.process(safe);
          this.seen.add(key);
          if (this.seen.size > 256) refuse("frame-budget");
          for (const [hash, waiting] of [...this.pending]) {
            this.pending.delete(hash);
            await this.process(waiting);
          }
        }
      } catch (error) {
        failed = true; failure = error;
      }
      try {
        await this.options.attempts.finish(id, failed ? "refused" : "cancelled", cleanupSignal());
      } catch (error) {
        failed = true; failure = error;
      }
      this.emissionBlocked = false;
      if (failed) {
        this.pendingEmission = false;
        this.fail(failure);
      } else if (this.pendingEmission) {
        this.pendingEmission = false;
        this.emit();
      }
    }).catch(error => this.fail(error));
    return this.queue;
  }
  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.controller.abort();
    if (this.timer) clearInterval(this.timer);
    if (this.timeout) clearTimeout(this.timeout);
    this.listeners.clear();
  }
  private observation(): PortalObservation {
    return { phase: this.phase, attemptId: this.exchange.attemptId, method: this.exchange.method,
      frameBytes: this.current?.slice() ?? null, bloomDigest: this.bloom ? { domain: this.bloom.domain, bytes: this.bloom.bytes.slice() } : null,
      personNostrKeys: this.personKeys ? { local: this.personKeys.local ? copyPersonNostrKey(this.personKeys.local) : null, peer: this.personKeys.peer ? copyPersonNostrKey(this.personKeys.peer) : null } : null,
      verdict: this.verdict, receiptBytes: this.receipt?.slice() ?? null };
  }
  private async resolveBloom(receipt: Uint8Array): Promise<void> {
    this.bloom = null;
    this.personKeys = null;
    try {
      const keys = this.options.personNostrKeys?.(receipt.slice());
      if (!keys || keys.local === null || keys.peer === null) return;
      const local = copyPersonNostrKey(keys.local), peer = copyPersonNostrKey(keys.peer);
      this.personKeys = { local, peer };
      const bloom = await pairingDigest(local, peer, this.options.pentora);
      if (this.stopped) return;
      this.bloom = bloom;
      this.emit();
    } catch {
      // An unavailable person binding or display adapter does not invalidate a receipt.
    }
  }
  private emit(): void {
    if (this.emissionBlocked && this.phase === "BLOOM") { this.pendingEmission = true; return; }
    if (!this.stopped) for (const listener of this.listeners) listener(this.observation());
  }
  private fail(error: unknown): void {
    if (this.stopped) return;
    this.phase = "REFUSED"; this.current = null;
    this.bloom = null; this.personKeys = null;
    this.verdict = { accepted: false, verdict: "SUSPICIOUS", code: code(error) }; this.emit(); this.stop();
  }
  private async packet(fields: { [key: string]: Json }, at = now()): Promise<Uint8Array> {
    checkAbort(this.controller.signal);
    const body = { ...fields, t_seconds: at, frame_index: ++this.index } as Frame;
    const packet: Packet = { schema: FRAME_SCHEMA, body: { body, signature: await sign(this.key, await frameDigest(body)) } };
    const bytes = encode(packet);
    this.frames.set(hex(await digest(bytes)), { bytes, packet });
    return bytes;
  }
  private async makeFace(): Promise<void> {
    this.ownFace = await this.packet({ type: "FACE", participant: this.who, method: "screen-to-screen", required_layers: this.layers, nonce_commitment: hex(await nonceCommitment(this.who, this.nonce)) });
    this.ownFaceHash = hex(await digest(this.ownFace));
    this.primary = this.ownFace; this.current = this.ownFace; this.emit();
  }
  private async process(bytes: Uint8Array): Promise<void> {
    const value = parse(bytes);
    if (object(value).schema === RECEIPT_SCHEMA) {
      if (this.receipt && same(parse(this.receipt), value)) return;
      if (!this.bound || this.side !== "B" || !this.input) refuse("unexpected-receipt");
      await verifyReceipt(bytes, this.bound, this.exchange.approvedText, this.controller.signal, this.options.consumeReceipt, this.input);
      this.receipt = bytes; this.phase = "BLOOM"; this.verdict = result; this.primary = bytes; this.current = bytes;
      void this.resolveBloom(bytes);
      this.emit(); return;
    }
    const { packet, key } = await validateFrame(value, now());
    const frame = packet.body.body;
    const hash = hex(await digest(bytes));
    if (key === this.who.device_key) return;
    this.frames.set(hash, { bytes, packet });
    if (this.frames.size > 128) refuse("frame-budget");
    if (frame.type === "FACE") {
      const peer = participant(frame.participant);
      if (frame.method !== "screen-to-screen" || !same(frame.required_layers, this.layers)) refuse("method-mismatch");
      if (this.peer && !same(peer, this.peer)) refuse("peer-changed");
      if (this.peerFace) {
        const prior = object(object(object(parse(this.peerFace)).body).body);
        if (frame.nonce_commitment !== prior.nonce_commitment) refuse("nonce-commitment-changed");
      }
      this.peer = peer;
      if (!this.bound) {
        this.peerFace = bytes;
        this.side = this.who.device_key < peer.device_key ? "A" : "B";
        this.bound = { a: this.side === "A" ? this.who : peer, b: this.side === "B" ? this.who : peer, method: "screen-to-screen", required_layers: this.layers, purpose: this.purpose, intent: this.intent };
        this.onContext(this.bound);
        if (this.side === "A") await this.makeReveal(this.ownFaceHash, hash);
      }
      return;
    }
    if (frame.type === "SEENYOU") {
      if (!this.bound) {
        const proposed = context(frame.context);
        if ((!same(proposed.a, this.who) && !same(proposed.b, this.who)) || proposed.purpose !== this.purpose || proposed.intent !== this.intent || proposed.method !== "screen-to-screen" || !same(proposed.required_layers, this.layers)) refuse("context-mismatch");
        this.pending.set(hash, bytes); return;
      }
      if (!same(frame.context, this.bound) || frame.sender === this.side) refuse("context-mismatch");
      const faceA = this.frames.get(string(frame.face_a)), faceB = this.frames.get(string(frame.face_b));
      if (!faceA || !faceB) { this.pending.set(hash, bytes); return; }
      for (const [face, who] of [[faceA, this.bound.a], [faceB, this.bound.b]] as const) {
        if (face.packet.body.body.type !== "FACE" || !same(face.packet.body.body.participant, who)) refuse("face-mismatch");
      }
      const sender = frame.sender === "A" ? this.bound.a : this.bound.b;
      const theirFace = frame.sender === "A" ? faceA : faceB;
      if (hex(await nonceCommitment(sender, string(frame.nonce))) !== theirFace.packet.body.body.nonce_commitment) refuse("nonce-mismatch");
      if (integer(frame.frame_index) <= integer(theirFace.packet.body.body.frame_index) || integer(frame.t_seconds) < integer(theirFace.packet.body.body.t_seconds)) refuse("frame-order");
      if (frame.sender === "A") {
        if (this.revealA && !same(parse(this.revealA), value)) refuse("reveal-changed");
        this.revealA = bytes;
        this.progress(frame);
        this.ownFace = faceB.bytes;
        if (!this.ownReveal) await this.makeReveal(string(frame.face_a), string(frame.face_b), Math.max(now(), integer(frame.t_seconds)));
        await this.makeHandshake();
      } else {
        if (this.revealB && !same(parse(this.revealB), value)) refuse("reveal-changed");
        this.revealB = bytes;
        this.progress(frame);
        void this.collect().catch(error => this.fail(error));
      }
      return;
    }
    if (frame.type === "HANDSHAKE") { await this.acceptHandshake(frame); return; }
    if (frame.type === "BLOOM") {
      if (this.side !== "B" || !this.input || !this.bound) refuse("unexpected-bloom");
      const hash = await coreDigest(this.input);
      if (frame.core !== hex(hash) || frame.context !== hex(await contextDigest(this.bound))) refuse("core-mismatch");
      await verify(this.bound.a.device_key, packet.body.signature, await frameDigest(frame));
      await verify(this.bound.a.device_key, frame.sig_a, hash);
      this.progress(frame);
      // The following receipt carries the optional intent acknowledgement.
      return;
    }
  }
  private async makeReveal(faceA: string, faceB: string, at = now()): Promise<void> {
    if (!this.bound || !this.side) refuse("state");
    this.ownReveal = await this.packet({ type: "SEENYOU", context: this.bound, sender: this.side, face_a: faceA, face_b: faceB, nonce: this.nonce }, at);
    if (this.side === "A") this.revealA = this.ownReveal; else this.revealB = this.ownReveal;
    this.phase = "SEENYOU"; this.primary = this.ownReveal; this.current = this.ownReveal; this.emit();
  }
  private progress(frame: Frame): void {
    const index = integer(frame.frame_index), time = integer(frame.t_seconds);
    if (this.peerProgress && (index <= this.peerProgress.index || time < this.peerProgress.time)) refuse("frame-order");
    this.peerProgress = { index, time };
  }
  private async buildCore(channels: Channels): Promise<Core> {
    if (!this.bound || !this.revealA || !this.revealB) refuse("state");
    const a = object(object(object(parse(this.revealA)).body).body), b = object(object(object(parse(this.revealB)).body).body);
    if (a.face_a !== b.face_a || a.face_b !== b.face_b) refuse("face-mismatch");
    const faceA = this.frames.get(string(a.face_a)), faceB = this.frames.get(string(a.face_b));
    if (!faceA || !faceB) refuse("transcript");
    return { context: this.bound, nonce_a: string(a.nonce), nonce_b: string(b.nonce), t_a_seconds: integer(a.t_seconds), t_b_seconds: integer(b.t_seconds),
      transcript: hex(await transcript([faceA.bytes, faceB.bytes, this.revealA, this.revealB])), channels };
  }
  private async collect(): Promise<Channels> {
    if (!this.bound || !this.side || !this.revealA || !this.revealB) refuse("state");
    if (!this.layers.sound && !this.layers.motion) return { sound: null, motion: null };
    const a = object(object(object(parse(this.revealA)).body).body), b = object(object(object(parse(this.revealB)).body).body);
    this.channelPromise ??= this.options.channels!.collect({ context: this.bound, side: this.side, nonceA: string(a.nonce), nonceB: string(b.nonce) }, this.controller.signal);
    return this.channelPromise;
  }
  private async makeHandshake(): Promise<void> {
    if (this.side !== "B") refuse("state");
    this.input = await this.buildCore(await this.collect());
    const hash = await coreDigest(this.input);
    this.current = await this.packet({ type: "HANDSHAKE", core: this.input, sig_b: await sign(this.key, hash) });
    this.primary = this.current;
    this.phase = "HANDSHAKE"; this.emit();
  }
  private async acceptHandshake(frame: Frame): Promise<void> {
    if (this.side !== "A" || !this.bound) refuse("unexpected-handshake");
    if (this.receipt && this.input) {
      if (!same(frame.core, this.input)) refuse("core-mismatch");
      this.progress(frame); return;
    }
    if (!this.revealB) {
      const packet = [...this.frames.values()].find(item => item.packet.body.body === frame);
      if (packet) this.pending.set(hex(await digest(packet.bytes)), packet.bytes);
      return;
    }
    const input = core(frame.core);
    const expected = await this.buildCore(await this.collect());
    if (!same(input, expected)) refuse("core-mismatch");
    const hash = await coreDigest(input);
    await verify(this.bound.b.device_key, frame.sig_b, hash);
    this.progress(frame);
    this.input = input;
    const sigA = await sign(this.key, hash), boundHash = await contextDigest(this.bound);
    const ack: Json = this.intent === null ? null : { by: "A", intent: this.intent, core: hex(hash), context: hex(boundHash),
      signature: await sign(this.key, await intentAckDigest(hash, boundHash, this.intent, "A")) };
    this.receipt = encode({ schema: RECEIPT_SCHEMA, body: { core: input, sig_a: sigA, sig_b: frame.sig_b, intent_ack: ack } });
    await verifyReceipt(this.receipt, this.bound, this.exchange.approvedText, this.controller.signal, this.options.consumeReceipt);
    this.current = await this.packet({ type: "BLOOM", context: hex(boundHash), core: hex(hash), sig_a: sigA });
    this.primary = this.current;
    this.current = this.receipt;
    this.phase = "BLOOM"; this.verdict = result;
    void this.resolveBloom(this.receipt);
    this.emit();
  }
}

export function browserStorage(): { attempts: IndexedAttempts; consumeReceipt: BrowserEngineOptions["consumeReceipt"] } {
  const attempts = new IndexedAttempts();
  return { attempts, consumeReceipt: (hash, signal) => attempts.consumeReceipt(hash, signal) };
}
