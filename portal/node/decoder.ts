// SPDX-License-Identifier: AGPL-3.0-or-later
// Reading the other screen's code from the camera. Chrome on Android and macOS has BarcodeDetector; iPhone Safari and
// desktop Safari do not. There, a page that has loaded jsQR (the decoder the phone-tested portal-v0 used) reads the
// frame through a canvas. With neither, pairing refuses with copresence:camera-decoder-unavailable.
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

export function frameDecoder(): FrameDecoder {
  if ("BarcodeDetector" in globalThis) return nativeQrDecoder();
  const jsQR = (globalThis as typeof globalThis & { jsQR?: JsQr }).jsQR;
  if (typeof jsQR === "function") return jsQrDecoder(jsQR);
  refuse("camera-decoder-unavailable");
}
