// SPDX-License-Identifier: AGPL-3.0-or-later
// Reading the other screen's code from the camera. The decoder is jsQR 1.4.0 (portal/vendor/jsQR.min.js, Apache-2.0,
// pinned in checks/pins.json), the one the phone-tested portal-v0 used; iPhone and desktop Safari have no
// BarcodeDetector. It is loaded only by the pairing pages: statically by the phone page, on demand by the owner's
// pairing port. Where jsQR is absent, BarcodeDetector is the fallback; with neither, pairing refuses with
// copresence:camera-decoder-unavailable.
import { nativeQrDecoder, type FrameDecoder } from "../optical.js";
import { refuse } from "../bytes.js";
import { findFinders, Guide } from "../guide.js";

type JsQr = (data: Uint8ClampedArray, width: number, height: number, options?: { inversionAttempts?: string }) => { data: string } | null;

const CROP = 0.62;      // the middle of the picture, where the code should land (the framing guide shows the same square)
const FIRST = 512;      // the crop is read at no more than this many pixels a side (a code half the picture wide is still 7 pixels a module)
const SECOND = 640;     // then, if that missed, the whole picture at no more than this on its longer side
const WIDE = 1280;      // every few misses, the whole picture larger, for a code that is small in view

/** Reads the other screen's code from a camera frame, quickly enough that a phone sees every frame that stays on screen.
 *
 *  A phone's video is large (1080 by 1920 is common) and jsQR's cost grows with the pixels, so decoding the whole picture took 400 to
 *  600 ms on an iPhone and it read one frame in a second or two. Instead: first the centre crop, downscaled to about 512 pixels (a
 *  few tens of milliseconds); only if that misses, the whole picture at 640 on its longer side; and every fifth miss the whole picture
 *  larger. Dark-on-light only (the frames are drawn that way), as portal-v0 read. When nothing reads, the same small picture is
 *  searched for the code's corner squares so the page can tell the person what to do (portal/guide.ts). */
export function jsQrDecoder(jsQR: JsQr): FrameDecoder {
  const crop = document.createElement("canvas");
  const whole = document.createElement("canvas");
  const cropContext = crop.getContext("2d", { willReadFrequently: true });
  const wholeContext = whole.getContext("2d", { willReadFrequently: true });
  if (!cropContext || !wholeContext) refuse("camera-decoder-unavailable");
  const guide = new Guide();
  let misses = 0;
  const read = (context: CanvasRenderingContext2D, canvas: HTMLCanvasElement, video: HTMLVideoElement, width: number, height: number,
    sx: number, sy: number, sw: number, sh: number): { data: string | null; pixels: ImageData } => {
    canvas.width = width; canvas.height = height;
    context.drawImage(video, sx, sy, sw, sh, 0, 0, width, height);
    const pixels = context.getImageData(0, 0, width, height);
    const code = jsQR(pixels.data, width, height, { inversionAttempts: "dontInvert" });
    return { data: code ? code.data : null, pixels };
  };
  const decode: FrameDecoder = async video => {
    const vw = video.videoWidth || 0, vh = video.videoHeight || 0;
    if (!vw || !vh) return [];
    const side = Math.round(Math.min(vw, vh) * CROP);
    const first = Math.min(side, FIRST);
    const a = read(cropContext, crop, video, first, first, Math.round((vw - side) / 2), Math.round((vh - side) / 2), side, side);
    if (a.data !== null) { misses = 0; guide.note({ hit: true, sight: { finders: 0, size: 0, clipped: false } }); return [a.data]; }
    ++misses;
    // The whole picture is tried on every other miss (a code larger than the crop, or off to one side, shows up there); the centre crop
    // that was just read stands in for it in between, so a miss costs one picture, not two.
    let seen = a.pixels, seenWidth = first, seenHeight = first, scale = 1 / CROP;
    if (misses % 2 === 1) {
      const factor = Math.min(1, SECOND / Math.max(vw, vh));
      const b = read(wholeContext, whole, video, Math.round(vw * factor), Math.round(vh * factor), 0, 0, vw, vh);
      if (b.data !== null) { misses = 0; guide.note({ hit: true, sight: { finders: 0, size: 0, clipped: false } }); return [b.data]; }
      seen = b.pixels; seenWidth = b.pixels.width; seenHeight = b.pixels.height; scale = 1;
    }
    if (misses % 6 === 0) {
      const wide = Math.min(1, WIDE / Math.max(vw, vh));
      const c = read(wholeContext, whole, video, Math.round(vw * wide), Math.round(vh * wide), 0, 0, vw, vh);
      if (c.data !== null) { misses = 0; guide.note({ hit: true, sight: { finders: 0, size: 0, clipped: false } }); return [c.data]; }
    }
    // Nothing read: look for the corner squares in the small picture, as greyscale, so the page can say what to do.
    const gray = new Uint8Array(seenWidth * seenHeight);
    for (let i = 0, p = 0; i < gray.length; ++i, p += 4) gray[i] = (seen.data[p]! + 2 * seen.data[p + 1]! + seen.data[p + 2]!) >> 2;
    const sight = findFinders(gray, seenWidth, seenHeight);
    // Sizes are fractions of the picture's shorter side; the crop is CROP of it.
    guide.note({ hit: false, sight: scale === 1 ? sight : { ...sight, size: sight.size / scale, clipped: false } });
    return [];
  };
  return Object.assign(decode, { guide });
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
