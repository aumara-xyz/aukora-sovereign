// SPDX-License-Identifier: AGPL-3.0-or-later
export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export const utf8 = new TextEncoder();
export const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
export function refuse(reason: string): never { throw new Error(`copresence:${reason}`); }
export function checkAbort(signal: AbortSignal): void { if (signal.aborted) refuse("cancelled"); }
export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, item) => sum + item.length, 0));
  let at = 0;
  for (const item of parts) { out.set(item, at); at += item.length; }
  return out;
}
export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
}
export function unhex(value: unknown, length: number): Uint8Array {
  if (typeof value !== "string" || value.length !== length * 2 || !/^[0-9a-f]+$/.test(value)) refuse("hex");
  return Uint8Array.from(value.match(/../g)!, pair => Number.parseInt(pair, 16));
}
export function integer(value: unknown, maximum = Number.MAX_SAFE_INTEGER): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || Object.is(value, -0) || value > maximum) refuse("integer");
  return value;
}
export function be(value: number, width: 4 | 8): Uint8Array {
  integer(value, width === 4 ? 0xffffffff : Number.MAX_SAFE_INTEGER);
  let n = BigInt(value);
  const out = new Uint8Array(width);
  for (let i = width - 1; i >= 0; --i) { out[i] = Number(n & 255n); n >>= 8n; }
  return out;
}
function validString(value: string): void {
  for (let i = 0; i < value.length; ++i) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) refuse("unicode");
    } else if (code >= 0xdc00 && code <= 0xdfff) refuse("unicode");
  }
}
export function canonical(value: Json, depth = 0): string {
  if (depth > 64) refuse("depth");
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") { integer(Math.abs(value)); return JSON.stringify(value); }
  if (typeof value === "string") { validString(value); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(item => canonical(item, depth + 1)).join(",")}]`;
  return `{${Object.keys(value).sort().map(key => {
    validString(key);
    return `${JSON.stringify(key)}:${canonical(value[key], depth + 1)}`;
  }).join(",")}}`;
}
export function encode(value: Json): Uint8Array { return utf8.encode(canonical(value)); }
export function parse(bytes: Uint8Array): Json {
  if (bytes.length < 1 || bytes.length > 65536) refuse("size");
  const source = text.decode(bytes);
  const value: Json = JSON.parse(source);
  if (canonical(value) !== source) refuse("noncanonical");
  return value;
}
export function object(value: Json, keys?: readonly string[]): { [key: string]: Json } {
  if (value === null || Array.isArray(value) || typeof value !== "object") refuse("object");
  if (keys && Object.keys(value).sort().join("\0") !== [...keys].sort().join("\0")) refuse("fields");
  return value;
}
export function string(value: Json, maximum = 4096): string {
  if (typeof value !== "string" || utf8.encode(value).length > maximum) refuse("text");
  validString(value);
  return value;
}
export function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, index) => byte === b[index]);
}
export async function digest(...parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", concat(...parts)));
}
export function domain(label: string, ...parts: Uint8Array[]): Promise<Uint8Array> {
  return digest(utf8.encode(label), new Uint8Array([0]), ...parts);
}
export function optional(value: Json): Uint8Array {
  return value === null ? new Uint8Array([0]) : concat(new Uint8Array([1]), unhex(value, 32));
}
export async function sign(key: CryptoKey, bytes: Uint8Array): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, bytes)));
}
export async function verify(key: Json, signature: Json, bytes: Uint8Array): Promise<void> {
  const raw = unhex(key, 65);
  if (raw[0] !== 4) refuse("key");
  const imported = await crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, imported, unhex(signature, 64), bytes)) refuse("signature");
}
