// SPDX-License-Identifier: AGPL-3.0-or-later
// Lowercase hexadecimal, the only spelling digests and heads take on the wire.

const HEX64 = /^[0-9a-f]{64}$/;

export function isHex64(value: unknown): value is string {
  return typeof value === "string" && HEX64.test(value);
}

export function toHex(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += byte.toString(16).padStart(2, "0");
  return text;
}

/** Exactly 64 lowercase hex digits become 32 bytes; anything else refuses. */
export function fromHex64(text: string): Uint8Array {
  if (!isHex64(text)) throw new Error("coherence:head-invalid");
  const bytes = new Uint8Array(32);
  for (let at = 0; at < 32; at++) bytes[at] = parseInt(text.slice(at * 2, at * 2 + 2), 16);
  return bytes;
}
