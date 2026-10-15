// SPDX-License-Identifier: AGPL-3.0-or-later
// The Aura Coherence flow. Two independent feeds, each with its own failure text: the body's health snapshot (opaque
// bytes, read for display only) and the gate-aura head (expanded by the WASM export into the fingerprint). A failure in
// one never changes what the other canvas shows, and a canvas that cannot be drawn is cleared with its reason. A map or
// picture that can no longer be kept current is cleared rather than left up as if it were; Refresh starts both feeds over.
import type { JsonValue } from "../../core/index.js";
import { refusalText } from "../aumlok/link.js";
import type { FaceHost } from "../aumlok/link.js";
import { MAX_SNAPSHOT_BYTES } from "./health.js";
import { parseHead } from "./head.js";
import type { PentoraModule } from "./pentora.js";
import { createCoherenceViews } from "./views.js";
import type { HealthDecoder } from "./views.js";

const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const MAX_BASE64 = Math.ceil(MAX_SNAPSHOT_BYTES / 3) * 4;

/** The FD 4 health body is exactly `{snapshot_b64}` in standard padded base64, 1 to 65,536 bytes once decoded. */
export function snapshotBytes(value: JsonValue): Uint8Array {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("coherence:snapshot-encoding");
  const text = value.snapshot_b64;
  if (Object.keys(value).length !== 1 || typeof text !== "string" || !text.length || text.length > MAX_BASE64
    || !BASE64.test(text)) throw new Error("coherence:snapshot-encoding");
  const raw = atob(text);
  if (!raw.length || raw.length > MAX_SNAPSHOT_BYTES || btoa(raw) !== text) throw new Error("coherence:snapshot-bounds");
  return Uint8Array.from(raw, character => character.charCodeAt(0));
}

export async function mountCoherence(
  host: FaceHost,
  loadPentora: (signal: AbortSignal) => Promise<PentoraModule>,
  loadHealthDecoder: (signal: AbortSignal) => Promise<HealthDecoder>,
): Promise<void> {
  const { root, client, signal } = host;
  const lede = document.createElement("p");
  lede.textContent = "Two pictures of one node, kept apart: what its organs report about themselves, and a digest of the Aura head. Neither can approve, open or change anything.";
  const refresh = document.createElement("button");
  refresh.type = "button";
  refresh.textContent = "Refresh";
  const stage = document.createElement("div");
  stage.className = "stage";
  root.append(lede, refresh, stage);
  const views = createCoherenceViews(stage);
  signal.addEventListener("abort", () => views.dispose(), { once: true });

  // Each module loads once; its failure clears only the canvas that depends on it.
  const pentora = loadPentora(signal);
  const health = loadHealthDecoder(signal);
  pentora.catch(() => undefined);
  health.catch(() => undefined);

  let generation = 0;
  let healthGeneration = 0;
  let run: AbortController | undefined;

  const start = async () => {
    run?.abort();
    const mine = new AbortController();
    run = mine;
    const live = AbortSignal.any([signal, mine.signal]);
    refresh.disabled = true;

    // The client reports an aborted subscription to its error handler, so every handler checks that its own run is live.
    const showHealth = async (value: JsonValue) => {
      if (live.aborted) return;
      const current = ++healthGeneration;
      views.clearHealth("Loading health snapshot…");
      try {
        const bytes = snapshotBytes(value);
        const decoder = await health;
        if (!live.aborted && current === healthGeneration) views.health(bytes, decoder);
      } catch (error) {
        if (!live.aborted && current === healthGeneration) views.clearHealth(`Unavailable · ${refusalText(error)}`);
      }
    };
    const healthFailed = (error: unknown) => {
      if (live.aborted) return;
      ++healthGeneration;
      views.clearHealth(`Unavailable · ${refusalText(error)}`);
    };
    const showHead = async (value: JsonValue) => {
      if (live.aborted) return;
      const current = ++generation;
      // Nothing is drawn or named while a head is being read; a failure then forgets the last head.
      views.loadingFingerprint();
      try {
        const head = parseHead(value);
        const module = await pentora;
        if (live.aborted || current !== generation) return;
        const { digest, trits } = module.expand(head.bytes);
        views.showFingerprint(digest, trits, head.hex);
        views.showSources(head.sources);
      } catch (error) {
        if (!live.aborted && current === generation) views.clearFingerprint(`Unavailable · ${refusalText(error)}`);
      }
    };
    const headFailed = (error: unknown) => {
      if (live.aborted) return;
      ++generation;
      views.clearFingerprint(`Unavailable · ${refusalText(error)}`);
    };

    try {
      await Promise.all([
        client.call("body", "health.snapshot", {}, { signal: live }).then(showHealth, healthFailed),
        client.call("gate-aura", "head", {}, { signal: live }).then(value => showHead(value), headFailed),
      ]);
      if (live.aborted) return;
      await Promise.all([
        client.subscribe("body", "health.snapshot", {}, value => { void showHealth(value); }, {
          signal: live, onError: code => healthFailed(new Error(code)),
        }).catch(healthFailed),
        client.subscribe("gate-aura", "head", {}, value => { void showHead(value); }, {
          signal: live, onError: code => headFailed(new Error(code)),
        }).catch(headFailed),
      ]);
    } finally {
      if (run === mine) refresh.disabled = signal.aborted;
    }
  };
  refresh.addEventListener("click", () => void start(), { signal });
  await start();
}
