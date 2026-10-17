// SPDX-License-Identifier: AGPL-3.0-or-later
// Reading the other screen's code from the camera. The decoder is jsQR 1.4.0 (portal/vendor/jsQR.min.js, Apache-2.0,
// pinned in checks/pins.json), the one the phone-tested portal-v0 used; iPhone and desktop Safari have no
// BarcodeDetector. It is loaded only by the pairing pages: statically by the phone page, on demand by the owner's
// pairing port. Where jsQR is absent, BarcodeDetector is the fallback; with neither, pairing refuses with
// copresence:camera-decoder-unavailable.
import { nativeQrDecoder, type FrameDecoder } from "../optical.js";
import { refuse } from "../bytes.js";

type JsQr = (data: Uint8ClampedArray, width: number, height: number, options?: { inversionAttempts?: string }) => { data: string } | null;

export function jsQrDecoder(jsQR: JsQr): FrameDecoder {
  const canvas = document.createElement("canvas");
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) refuse("camera-decoder-unavailable");
  return async video => {
    const width = Math.min(video.videoWidth || 0, 1920);
    if (!width) return [];
    canvas.width = width;
    canvas.height = Math.round(width * video.videoHeight / video.videoWidth);
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    const image = context.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(image.data, canvas.width, canvas.height, { inversionAttempts: "attemptBoth" });
    return code ? [code.data] : [];
  };
}

export const JSQR_PATH = "/portal/vendor/jsQR.min.js";

function loadedJsQr(): JsQr | undefined {
  const jsQR = (globalThis as typeof globalThis & { jsQR?: JsQr }).jsQR;
  return typeof jsQR === "function" ? jsQR : undefined;
}

/** Adds the pinned jsQR script once; a page CSP of script-src 'self' admits it. */
export function loadJsQr(): Promise<void> {
  if (loadedJsQr()) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const script = document.createElement("script");
    script.src = JSQR_PATH;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("copresence:camera-decoder-unavailable"));
    document.head.append(script);
  });
}

export function frameDecoder(): FrameDecoder {
  const jsQR = loadedJsQr();
  if (jsQR) return jsQrDecoder(jsQR);
  if ("BarcodeDetector" in globalThis) return nativeQrDecoder();
  refuse("camera-decoder-unavailable");
}
