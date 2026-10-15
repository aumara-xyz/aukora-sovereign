// SPDX-License-Identifier: AGPL-3.0-or-later
import { connectFace } from "../core/index.js";
import type { FaceClient, JsonValue } from "../core/index.js";
import { FACE_CATALOG } from "./catalog.js";
import { createCoherenceViews } from "./coherence/views.js";
import type { HealthDecoder, PentoraExpansion } from "./coherence/views.js";
import { mountThreads } from "./threads/view.js";

export interface FaceAdapters {
  readonly health?: HealthDecoder;
  readonly pentora?: PentoraExpansion;
}

export function refusalText(error: unknown): string {
  if (error instanceof Error && /^[a-z][a-z0-9-]*:[a-z0-9-]+$/.test(error.message)) return error.message;
  return "app:service-unavailable";
}

export function record(value: unknown): Record<string, JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("app:invalid-reply");
  return value as Record<string, JsonValue>;
}

function readout(root: HTMLElement, client: FaceClient, organ: string, method: string, params: JsonValue, signal: AbortSignal) {
  const refresh = document.createElement("button");
  refresh.textContent = "Refresh";
  const output = document.createElement("pre");
  output.setAttribute("aria-live", "polite");
  const load = async () => {
    refresh.disabled = true;
    try {
      const data = await client.call(organ, method, params, { signal });
      if (!signal.aborted) output.textContent = JSON.stringify(data, null, 2);
    } catch (error) {
      if (!signal.aborted) output.textContent = `Unavailable · ${refusalText(error)}`;
    } finally { refresh.disabled = signal.aborted; }
  };
  refresh.addEventListener("click", () => void load(), { signal });
  root.append(refresh, output);
  void load();
}

function opaqueBytes(value: JsonValue): Uint8Array {
  const row = record(value);
  if (typeof row.snapshot_b64 !== "string" || row.snapshot_b64.length > 87_384 ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(row.snapshot_b64)) {
    throw new Error("coherence:snapshot-encoding");
  }
  const decoded = atob(row.snapshot_b64);
  if (!decoded.length || decoded.length > 65_536 || btoa(decoded) !== row.snapshot_b64) {
    throw new Error("coherence:snapshot-bounds");
  }
  return Uint8Array.from(decoded, char => char.charCodeAt(0));
}

async function displayDigest(value: JsonValue): Promise<Uint8Array> {
  const { head } = record(value);
  if (typeof head !== "string" || !/^[0-9a-f]{64}$/.test(head)) throw new Error("coherence:head-invalid");
  const domain = new TextEncoder().encode("pentora.display.v1\0");
  const bytes = new Uint8Array(domain.length + 32);
  bytes.set(domain);
  for (let at = 0; at < 32; at++) bytes[domain.length + at] = parseInt(head.slice(at * 2, at * 2 + 2), 16);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function coherence(root: HTMLElement, client: FaceClient, adapters: FaceAdapters, signal: AbortSignal) {
  const views = createCoherenceViews(root);
  signal.addEventListener("abort", () => views.dispose(), { once: true });
  let headVersion = 0;
  const health = (value: JsonValue) => {
    try {
      if (!adapters.health) throw new Error("coherence:health-decoder-unavailable");
      views.health(opaqueBytes(value), adapters.health);
    } catch (error) { views.clearHealth(`Unavailable · ${refusalText(error)}`); }
  };
  const fingerprint = async (value: JsonValue) => {
    const version = ++headVersion;
    views.clearFingerprint("Loading fingerprint");
    try {
      if (!adapters.pentora) throw new Error("coherence:pentora-unavailable");
      const digest = await displayDigest(value);
      if (!signal.aborted && version === headVersion) views.fingerprint(digest, adapters.pentora);
    } catch (error) {
      if (!signal.aborted && version === headVersion) views.clearFingerprint(`Unavailable · ${refusalText(error)}`);
    }
  };
  await Promise.all([
    client.call("body", "health.snapshot", {}, { signal }).then(health,
      error => views.clearHealth(`Unavailable · ${refusalText(error)}`)),
    client.call("gate-aura", "head", {}, { signal }).then(fingerprint,
      error => views.clearFingerprint(`Unavailable · ${refusalText(error)}`)),
  ]);
  if (signal.aborted) return;
  await Promise.all([
    client.subscribe("body", "health.snapshot", {}, health, {
      signal, onError: code => { if (!signal.aborted) views.clearHealth(`Unavailable · ${code}`); },
    }).catch(error => { if (!signal.aborted) views.clearHealth(`Unavailable · ${refusalText(error)}`); }),
    client.subscribe("gate-aura", "head", {}, value => { void fingerprint(value); }, {
      signal, onError: code => { if (!signal.aborted) { ++headVersion; views.clearFingerprint(`Unavailable · ${code}`); } },
    }).catch(error => {
      if (!signal.aborted) { ++headVersion; views.clearFingerprint(`Unavailable · ${refusalText(error)}`); }
    }),
  ]);
}

export async function mountFace(id: string, adapters: FaceAdapters = {}): Promise<() => void> {
  const manifest = FACE_CATALOG.find(face => face.id === id);
  const root = document.getElementById("face");
  if (!manifest || !root) throw new Error("app:unknown-face");
  const life = new AbortController();
  const heading = document.createElement("h1");
  heading.textContent = manifest.title;
  const status = document.createElement("p");
  status.setAttribute("role", "status");
  status.textContent = "Connecting";
  root.append(heading, status);
  let client: FaceClient | undefined;
  const dispose = () => { life.abort(); client?.dispose(); root.replaceChildren(); };
  window.addEventListener("pagehide", dispose, { once: true, signal: life.signal });
  try {
    if (window.parent === window || !document.referrer) throw new Error("app:shell-required");
    const shellOrigin = new URL(document.referrer).origin;
    if (shellOrigin === "null") throw new Error("app:shell-required");
    client = connectFace({ shellOrigin, pluginId: id, signal: life.signal });
    if (life.signal.aborted) { client.dispose(); return dispose; }
    status.textContent = "";
    if (id === "threads" || id === "sidebar" || id === "archived") {
      mountThreads(root, client, life.signal, id);
    } else if (id === "coherence") {
      await coherence(root, client, adapters, life.signal);
    } else if (id === "memory") {
      readout(root, client, "kira", "memory.list", { tier: "remembered", before: null }, life.signal);
    } else {
      const method = manifest.capabilities[manifest.organ].methods[0];
      if (method) readout(root, client, manifest.organ, method, {}, life.signal);
      else status.textContent = "This face is registered. Its service is not connected.";
    }
  } catch (error) {
    if (!life.signal.aborted) status.textContent = `Unavailable · ${refusalText(error)}`;
  }
  return dispose;
}
