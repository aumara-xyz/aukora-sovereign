// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OpticalSurface } from "./contracts.js";
import { checkAbort, refuse, utf8 } from "./bytes.js";
import { drawQr } from "./qr.js";
import { drawRelationshipBloom, type PentoraExpansion } from "./bloom/index.js";

export type FrameDecoder = (source: HTMLVideoElement) => Promise<readonly string[]>;
type Detector = { detect(source: HTMLVideoElement): Promise<readonly { rawValue: string }[]> };
type DetectorConstructor = new (options: { formats: string[] }) => Detector;
export function nativeQrDecoder(): FrameDecoder {
  const constructor = (globalThis as typeof globalThis & { BarcodeDetector?: DetectorConstructor }).BarcodeDetector;
  if (!constructor) refuse("camera-decoder-unavailable");
  const detector = new constructor({ formats: ["qr_code"] });
  return async source => (await detector.detect(source)).map(found => found.rawValue);
}
export function cameraSurface(canvas: HTMLCanvasElement, video: HTMLVideoElement, pentora: PentoraExpansion, decode?: FrameDecoder, bloomCanvas?: HTMLCanvasElement): OpticalSurface {
  let release = (): void => {};
  let bloomRequest: AbortController | null = null;
  const relationship = bloomCanvas ?? canvas.ownerDocument.createElement("canvas");
  if (!bloomCanvas) canvas.after(relationship);
  relationship.hidden = true;
  return {
    showFrame(bytes) { drawQr(canvas, bytes); },
    async showBloom(keys, signal) {
      bloomRequest?.abort();
      const request = new AbortController();
      bloomRequest = request;
      const abort = (): void => request.abort();
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) request.abort();
      relationship.hidden = true;
      try {
        const digest = await drawRelationshipBloom(relationship, keys, pentora, request.signal);
        if (request.signal.aborted) return null;
        relationship.hidden = digest === null;
        return digest;
      } finally {
        signal?.removeEventListener("abort", abort);
        if (bloomRequest === request) bloomRequest = null;
      }
    },
    async scan(consume, signal) {
      checkAbort(signal);
      const decoder = decode ?? nativeQrDecoder();
      const stream = await navigator.mediaDevices.getUserMedia({ audio: false, video: { facingMode: "user", width: { ideal: 1280 }, height: { ideal: 720 } } });
      let stopped = false, timer: ReturnType<typeof setTimeout> | undefined;
      const stop = (): void => {
        if (stopped) return;
        stopped = true;
        if (timer) clearTimeout(timer);
        stream.getTracks().forEach(track => track.stop());
        video.pause(); video.srcObject = null;
        signal.removeEventListener("abort", stop);
      };
      release(); release = stop;
      if (signal.aborted) { stop(); checkAbort(signal); }
      signal.addEventListener("abort", stop, { once: true });
      video.muted = true; video.playsInline = true; video.srcObject = stream;
      try { await video.play(); } catch (error) { stop(); throw error; }
      const scan = async (): Promise<void> => {
        if (stopped) return;
        try {
          if (video.readyState >= 2) {
            for (const value of await decoder(video)) {
              if (!stopped && value.length <= 65536) consume(utf8.encode(value));
            }
          }
        } catch { stop(); return; }
        if (!stopped) timer = setTimeout(() => { void scan(); }, 100);
      };
      void scan();
      return stop;
    },
    clear() {
      bloomRequest?.abort(); bloomRequest = null;
      release();
      const context = canvas.getContext("2d");
      context?.clearRect(0, 0, canvas.width, canvas.height);
      relationship.hidden = true;
      relationship.getContext("2d")?.clearRect(0, 0, relationship.width, relationship.height);
      relationship.setAttribute("aria-label", "Relationship bloom. Nothing shown.");
    },
  };
}
