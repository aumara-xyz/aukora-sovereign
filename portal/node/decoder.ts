// SPDX-License-Identifier: AGPL-3.0-or-later
// Reading the other screen's code from the camera. The decoder is jsQR 1.4.0 (portal/vendor/jsQR.min.js, Apache-2.0,
// pinned in checks/pins.json), the one the phone-tested portal-v0 used; iPhone and desktop Safari have no
// BarcodeDetector. It is loaded only by the pairing pages: statically by the phone page, on demand by the owner's
// pairing port. Where jsQR is absent, BarcodeDetector is the fallback; with neither, pairing refuses with
// copresence:camera-decoder-unavailable.
import { nativeQrDecoder, type FrameDecoder } from "../optical.js";
import { refuse } from "../bytes.js";

type JsQr = (data: Uint8ClampedArray, width: number, height: number, options?: { inversionAttempts?: string }) => { data: string } | null;

/** Each camera frame is tried at half size first (the browser's own averaging: four times less work, and it cancels sensor noise),
 *  then at full size, which also tries the inverted picture. portal-v0 read this way, and a full-size pass alone costs several
 *  hundred milliseconds on a phone, so frames that stay on screen for one second were missed. */
export function jsQrDecoder(jsQR: JsQr): FrameDecoder {
  const full = document.createElement("canvas");
  const half = document.createElement("canvas");
  const fullContext = full.getContext("2d", { willReadFrequently: true });
  const halfContext = half.getContext("2d", { willReadFrequently: true });
  if (!fullContext || !halfContext) refuse("camera-decoder-unavailable");
  return async video => {
    const width = Math.min(video.videoWidth || 0, 1920);
    if (!width) return [];
    const height = Math.round(width * video.videoHeight / video.videoWidth);
    half.width = width >> 1; half.height = height >> 1;
    halfContext.drawImage(video, 0, 0, half.width, half.height);
    const small = halfContext.getImageData(0, 0, half.width, half.height);
    const quick = jsQR(small.data, half.width, half.height, { inversionAttempts: "dontInvert" });
    if (quick) return [quick.data];
    full.width = width; full.height = height;
    fullContext.drawImage(video, 0, 0, width, height);
    const image = fullContext.getImageData(0, 0, width, height);
    const code = jsQR(image.data, width, height, { inversionAttempts: "attemptBoth" });
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
