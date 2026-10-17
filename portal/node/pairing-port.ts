// SPDX-License-Identifier: AGPL-3.0-or-later
// The node-backed pairing port for the owner's pairing scene (ui/owner/pairing-port.ts). It is structurally the
// scene's PairingPort: `open()` returns the portal's own services, and `phoneLink` draws the one-time address the
// phone opens. What it adds to the portal engine:
//   - the owner device's durable key (node/device-key.ts), registered when the pairing starts;
//   - the node's pinned context: the scene's context text is replaced by the exact bytes the node issued once the
//     phone has joined, so both devices sign the same node-chosen context;
//   - the node's verdict: a local BLOOM is held (shown as HANDSHAKE, frames still rotating for the other screen)
//     until the node has verified and spent the receipt; the node's refusal becomes REFUSED.
// Co-presence is evidence; nothing here grants a permission.
import { BrowserCopresenceEngine } from "../engine.js";
import { IndexedAttempts } from "../attempts.js";
import { cameraSurface, type FrameDecoder } from "../optical.js";
import { drawQrLink } from "../qr.js";
import { checkAbort, refuse, utf8 } from "../bytes.js";
import type { PentoraExpansion } from "../bloom/index.js";
import type { ContextExchange, PersonNostrKeys, PortalExchange, PortalObservation, PortalServices, ReceiptVerdict } from "../contracts.js";
import { awaitContext, contextNode, PairingClient, type PairingStart, type PairingVerdict } from "./client.js";
import { deviceKey, OWNER_DEVICE_STORE, type DeviceKey } from "./device-key.js";
import { frameDecoder, loadJsQr } from "./decoder.js";

export type PairingCanvases = { readonly frame: HTMLCanvasElement; readonly video: HTMLVideoElement; readonly bloom: HTMLCanvasElement };
export type NodePairingPortOptions = {
  readonly client?: PairingClient;
  /** The owner origin the phone opens; this page's origin by default. */
  readonly origin?: string;
  readonly decode?: FrameDecoder;
  readonly pentora?: PentoraExpansion;
  readonly pollMs?: number;
  /** Called when the node has verified and spent a receipt. */
  readonly onVerdict?: (verdict: PairingVerdict) => void;
  /** This device's key; the durable IndexedDB key by default. */
  readonly deviceKey?: () => Promise<DeviceKey>;
};
export type NodePairingPort = {
  open(canvases: PairingCanvases, signal: AbortSignal): Promise<PortalServices>;
  readonly phoneLink: { readonly url: string; readonly caption: string; draw(canvas: HTMLCanvasElement): void };
  /** The current pairing, started on first use and again after it ends. */
  session(signal?: AbortSignal): Promise<PairingStart>;
};

const REFRESH_BEFORE_MS = 20_000;
const unavailablePentora: PentoraExpansion = { pairing_expansion: () => refuse("pairing-expansion-unavailable") };
const refusal = (code: string): ReceiptVerdict => ({ verdict: "SUSPICIOUS", code: /^copresence:[A-Za-z0-9_-]+$/.test(code) ? code as `copresence:${string}` : "copresence:node-refused" });

function personKeys(verdict: PairingVerdict): PersonNostrKeys | null {
  const keys = verdict.personNostrKeys;
  const bytes = (value: string | null): Uint8Array | null => value && /^[0-9a-f]{64}$/.test(value) ? Uint8Array.from(value.match(/../g)!, pair => Number.parseInt(pair, 16)) : null;
  return keys ? { local: bytes(keys.local), peer: bytes(keys.peer) } : null;
}

class NodeExchange implements PortalExchange {
  readonly #inner: PortalExchange;
  readonly #submit: (receipt: Uint8Array) => Promise<PairingVerdict>;
  #final: PortalObservation | null = null;
  #pending: Promise<void> | null = null;
  constructor(inner: PortalExchange, submit: (receipt: Uint8Array) => Promise<PairingVerdict>) {
    this.#inner = inner;
    this.#submit = submit;
  }
  receive(frameBytes: Uint8Array): Promise<void> { return this.#inner.receive(frameBytes); }
  stop(): void { this.#inner.stop(); }
  subscribe(listener: (observation: PortalObservation) => void): () => void {
    return this.#inner.subscribe(observation => {
      if (this.#final) { listener(this.#final.phase === "BLOOM" ? { ...this.#final, frameBytes: observation.frameBytes } : this.#final); return; }
      if (observation.phase !== "BLOOM" || observation.receiptBytes === null) { listener(observation); return; }
      // Keep the frames moving (the other screen may still be reading the receipt) while the node decides.
      listener({ ...observation, phase: "HANDSHAKE", verdict: null, receiptBytes: null, bloomDigest: null, personNostrKeys: null });
      this.#pending ??= this.#submit(observation.receiptBytes).then(verdict => {
        this.#final = { ...observation, verdict: { verdict: "UNDETERMINED", code: null }, personNostrKeys: personKeys(verdict), bloomDigest: null };
      }, error => {
        this.#final = { ...observation, phase: "REFUSED", frameBytes: null, receiptBytes: null, bloomDigest: null, personNostrKeys: null,
          verdict: refusal(error instanceof Error ? error.message : "") };
      }).then(() => { if (this.#final) listener(this.#final); });
    });
  }
}

function drawLink(canvas: HTMLCanvasElement, url: string): void {
  drawQrLink(canvas, utf8.encode(url));   // the smallest code that holds the address, not the frames' version 40
  canvas.dataset.url = url;
}

export function createNodePairingPort(options: NodePairingPortOptions = {}): NodePairingPort {
  const client = options.client ?? new PairingClient();
  const origin = options.origin ?? globalThis.location?.origin ?? "";
  let key: Promise<DeviceKey> | null = null;
  let current: Promise<PairingStart> | null = null;
  let started: PairingStart | null = null;
  let localExpiry = 0;
  // A phone has joined the current pairing (or an exchange runs on it): never replace it early.
  let joined = false;
  let linkCanvas: HTMLCanvasElement | null = null;
  let refresh: ReturnType<typeof setTimeout> | undefined;
  const ownKey = (): Promise<DeviceKey> => (key ??= (options.deviceKey ?? (() => deviceKey(OWNER_DEVICE_STORE)))().catch(error => { key = null; throw error; }));
  const url = (): string => started ? `${origin}${started.joinPath}` : "";
  const remaining = (): number => localExpiry - Date.now();

  // Near expiry, an unjoined pairing's phone link is renewed. A joined one is left alone: starting a new pairing
  // closes the owner's open and joined ones, which would end the phone's exchange. It is checked again at expiry.
  async function renew(pairing: string): Promise<void> {
    if (!started || started.pairing !== pairing) return;
    const status = await client.status(pairing).catch(() => null);
    // A spent pairing is finished; the next session() starts a new one when the scene asks.
    if (status?.state === "spent") return;
    if (status?.state === "joined") joined = true;
    if (joined && remaining() > 0) {
      refresh = setTimeout(() => { void renew(pairing); }, Math.max(1_000, remaining()));
      return;
    }
    if (started.pairing !== pairing) return;
    current = null;
    joined = false;
    if (linkCanvas) void session().catch(() => {});
  }

  async function session(signal?: AbortSignal): Promise<PairingStart> {
    if (current && started && (joined ? remaining() <= 0 : remaining() < REFRESH_BEFORE_MS)) current = null;
    current ??= (async () => {
      const value = await client.start((await ownKey()).publicKey, signal);
      started = value;
      joined = false;
      localExpiry = Date.now() + (value.expiresAtMs - value.nodeTimeMs);
      if (linkCanvas) drawLink(linkCanvas, url());
      clearTimeout(refresh);
      // A pairing lasts five minutes; an unjoined phone link on screen is renewed before it lapses.
      refresh = setTimeout(() => { void renew(value.pairing); }, Math.max(1_000, remaining() - REFRESH_BEFORE_MS));
      return value;
    })().catch(error => { current = null; throw error; });
    return current;
  }

  async function begin(request: ContextExchange, signal: AbortSignal, keys: DeviceKey, attempts: IndexedAttempts): Promise<PortalExchange> {
    const pairing = await session(signal);
    const status = await awaitContext(abort => client.status(pairing.pairing, abort), signal, options.pollMs ?? 1000)
      .catch(error => { if (started?.pairing === pairing.pairing && /pairing-(closed|expired)/.test(String(error))) current = null; throw error; });
    if (started?.pairing === pairing.pairing) joined = true;
    if (status.state === "spent") { current = null; refuse("pairing-spent"); }
    checkAbort(signal);
    let verdictKeys: PersonNostrKeys | null = null;
    const engine = new BrowserCopresenceEngine({
      node: contextNode(status.context!),
      deviceEpoch: 0,
      attempts,
      consumeReceipt: (digest, abort) => attempts.consumeReceipt(digest, abort),
      contextFormatPinned: () => true,
      deviceKey: keys.keys,
      personNostrKeys: () => verdictKeys,
      legacyVerifier: async () => refuse("legacy-unavailable"),
    });
    const inner = await engine.begin({ ...request, contextBytes: utf8.encode(status.context!) }, signal);
    return new NodeExchange(inner, async receipt => {
      const verdict = await client.receipt(pairing.pairing, receipt);
      verdictKeys = personKeys(verdict);
      current = null;
      options.onVerdict?.(verdict);
      return verdict;
    });
  }

  return {
    session,
    phoneLink: {
      get url() { return url(); },
      caption: "Scan with your phone to pair it. The code works once, for five minutes.",
      draw(canvas: HTMLCanvasElement) {
        linkCanvas = canvas;
        if (started) drawLink(canvas, url());
        void session().catch(() => { canvas.dataset.url = ""; });
      },
    },
    async open({ frame, video, bloom }, signal) {
      checkAbort(signal);
      const keys = await ownKey();
      if (!options.decode) await loadJsQr().catch(() => { /* BarcodeDetector may still serve */ });
      const decode = options.decode ?? frameDecoder();
      const attempts = new IndexedAttempts("aukora.copresence.attempts.owner.v1");
      const optical = cameraSurface(frame, video, options.pentora ?? unavailablePentora, decode, bloom);
      const engine = {
        begin: (request: ContextExchange, abort: AbortSignal) => begin(request, abort, keys, attempts),
        verifyLegacyReceipt: async () => refusal("copresence:legacy-unavailable"),
        verifyContextReceipt: async () => refusal("copresence:node-verifies"),
      };
      return { engine, attempts, optical };
    },
  };
}
