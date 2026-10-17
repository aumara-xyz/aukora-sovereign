// SPDX-License-Identifier: AGPL-3.0-or-later
// Base45 (RFC 9285): bytes as the 45 characters a QR code's alphanumeric mode carries at 5.5 bits each, instead of 8 bits a byte
// in byte mode. portal-v0 sent its frames this way.
import { refuse } from "./bytes.js";

export const BASE45 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

export function encode45(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 2) {
    if (i + 1 < bytes.length) {
      const n = bytes[i]! * 256 + bytes[i + 1]!;
      out += BASE45[n % 45]! + BASE45[Math.floor(n / 45) % 45]! + BASE45[Math.floor(n / 2025)]!;
    } else {
      out += BASE45[bytes[i]! % 45]! + BASE45[Math.floor(bytes[i]! / 45)]!;
    }
  }
  return out;
}

export function decode45(text: string): Uint8Array {
  if (text.length % 3 === 1) refuse("base45");
  const out: number[] = [];
  for (let i = 0; i < text.length; i += 3) {
    const c = BASE45.indexOf(text[i]!), d = BASE45.indexOf(text[i + 1]!);
    if (c < 0 || d < 0) refuse("base45");
    if (i + 2 < text.length) {
      const e = BASE45.indexOf(text[i + 2]!);
      if (e < 0) refuse("base45");
      const n = c + d * 45 + e * 2025;
      if (n > 0xffff) refuse("base45");
      out.push(n >> 8, n & 255);
    } else {
      const n = c + d * 45;
      if (n > 0xff) refuse("base45");
      out.push(n);
    }
  }
  return Uint8Array.from(out);
}
