// SPDX-License-Identifier: AGPL-3.0-or-later
// How a frame travels in a QR code. Compact frames (portal/wire.ts, "compact-v1") begin with a magic byte and are drawn as base45
// text in the QR alphanumeric mode; the older JSON frames (first byte "{") are drawn as plain bytes. A reader gets text back from
// jsQR and asks here which it was.
import { decode45, encode45 } from "./base45.js";
import { utf8 } from "./bytes.js";

export const COMPACT_MAGIC = 0xc1;
const ALPHANUMERIC = /^[0-9A-Z $%*+\-./:]+$/;

/** The base45 text for a compact frame, or null for anything else (which is drawn as bytes). */
export function frameQrText(bytes: Uint8Array): string | null {
  return bytes.length > 0 && bytes[0] === COMPACT_MAGIC ? encode45(bytes) : null;
}

/** The frame bytes for the text a camera read: base45 that decodes to a compact frame, else the text's own UTF-8 bytes. */
export function frameFromQrText(value: string): Uint8Array {
  if (ALPHANUMERIC.test(value) && value.length % 3 !== 1) {
    try {
      const bytes = decode45(value);
      if (bytes[0] === COMPACT_MAGIC) return bytes;
    } catch { /* not base45: a plain text frame */ }
  }
  return utf8.encode(value);
}
