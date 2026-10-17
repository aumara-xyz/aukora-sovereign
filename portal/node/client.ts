// SPDX-License-Identifier: AGPL-3.0-or-later
// The node's pairing endpoints on the owner origin (COPRESENCE-NODE.md). Bodies are small JSON objects; a refusal is
// HTTP 400 with {"error":"organ:reason"} and is thrown as an Error with that message.
import { refuse } from "../bytes.js";

export type PairingState = "open" | "joined" | "spent" | "closed" | "expired";
export type PairingVerdict = {
  readonly schema: "aukora.copresence.pairing-verdict.v1";
  readonly pairing: string;
  readonly verdict: "UNDETERMINED";
  readonly code: null;
  readonly receipt: string;
  readonly devices: { readonly initiator: string; readonly joiner: string };
  readonly personNostrKeys: { readonly local: string | null; readonly peer: string | null } | null;
  readonly recorded: { readonly sequence: number; readonly entry: string } | null;
  readonly evidence: string;
};
export type PairingStatus = {
  readonly schema: "aukora.copresence.pairing-status.v1";
  readonly pairing: string;
  readonly state: PairingState;
  readonly expiresAtMs: number;
  readonly nodeTimeMs: number;
  readonly context: string | null;
  readonly verdict: PairingVerdict | null;
};
export type PairingStart = {
  readonly schema: "aukora.copresence.pairing-start.v1";
  readonly pairing: string;
  readonly join: string;
  readonly joinPath: string;
  readonly expiresAtMs: number;
  readonly nodeTimeMs: number;
};
export type PairingJoin = { readonly schema: "aukora.copresence.pairing-join.v1"; readonly phone: string; readonly status: PairingStatus };
export type PairedDevices = {
  readonly schema: "aukora.copresence.paired-devices.v1";
  readonly devices: readonly {
    readonly key: string; readonly publicKey: string; readonly role: "initiator" | "joiner";
    readonly firstPairing: string; readonly lastPairing: string;
    readonly firstPairedAtMs: number; readonly lastPairedAtMs: number; readonly pairings: number;
  }[];
  readonly evidence: string;
};

type Fetch = typeof fetch;
const PATH = /^\/api\/pairing\/(start|status|receipt|devices|join|phone)$/;

export class PairingClient {
  readonly #fetch: Fetch;
  constructor(fetcher: Fetch = globalThis.fetch.bind(globalThis)) { this.#fetch = fetcher; }

  async #call<T>(path: string, body: Record<string, string> | null, signal?: AbortSignal): Promise<T> {
    if (!PATH.test(path)) refuse("pairing-path");
    const response = await this.#fetch(path, body === null
      ? { method: "GET", credentials: "same-origin", cache: "no-store", signal }
      : { method: "POST", credentials: "same-origin", cache: "no-store", signal,
        headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const value = await response.json().catch(() => null) as { error?: unknown } | null;
    if (!response.ok || value === null || typeof value !== "object") {
      const code = typeof value?.error === "string" && /^[a-z]+:[A-Za-z0-9_-]+$/.test(value.error) ? value.error : "copresence:node-unavailable";
      throw new Error(code);
    }
    return value as T;
  }

  start(deviceKey: string, signal?: AbortSignal): Promise<PairingStart> {
    return this.#call("/api/pairing/start", { deviceKey }, signal);
  }
  status(pairing: string, signal?: AbortSignal): Promise<PairingStatus> {
    return this.#call("/api/pairing/status", { pairing }, signal);
  }
  receipt(pairing: string, receipt: Uint8Array, signal?: AbortSignal): Promise<PairingVerdict> {
    return this.#call("/api/pairing/receipt", { pairing, receipt: base64url(receipt) }, signal);
  }
  devices(signal?: AbortSignal): Promise<PairedDevices> {
    return this.#call("/api/pairing/devices", null, signal);
  }
  join(join: string, deviceKey: string, signal?: AbortSignal): Promise<PairingJoin> {
    return this.#call("/api/pairing/join", { join, deviceKey }, signal);
  }
  phone(phone: string, signal?: AbortSignal): Promise<PairingStatus> {
    return this.#call("/api/pairing/phone", { phone }, signal);
  }
}

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** The node id the context names; both devices put it in their exchange participant. */
export function contextNode(context: string): string {
  const parsed = JSON.parse(context) as { schema?: unknown; node?: unknown };
  if (parsed.schema !== "aukora.copresence.pairing-context.v1" || typeof parsed.node !== "string" || !/^[0-9a-f]{32}$/.test(parsed.node)) {
    refuse("context");
  }
  return parsed.node;
}

export function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new Error("copresence:cancelled")); return; }
    const timer = setTimeout(() => { signal.removeEventListener("abort", stop); resolve(); }, ms);
    const stop = (): void => { clearTimeout(timer); reject(new Error("copresence:cancelled")); };
    signal.addEventListener("abort", stop, { once: true });
  });
}

/** Polls until the pairing has a context (both keys known), or refuses when it ends first. */
export async function awaitContext(read: (signal: AbortSignal) => Promise<PairingStatus>, signal: AbortSignal, everyMs = 1000): Promise<PairingStatus> {
  for (;;) {
    const status = await read(signal);
    if (status.context !== null && (status.state === "joined" || status.state === "spent")) return status;
    if (status.state === "closed" || status.state === "expired") refuse(`pairing-${status.state}`);
    await sleep(everyMs, signal);
  }
}
