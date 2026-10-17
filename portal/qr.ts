// SPDX-License-Identifier: AGPL-3.0-or-later
import { refuse } from "./bytes.js";

// QR Model 2, byte mode, error correction L, mask 0.
//
// qrModules is the fixed version 40 reference. qrModulesFit builds the smallest version (1 to 40) that holds the bytes:
// the same payload in fewer, larger modules, which is what a phone camera can actually resolve at arm's length. The bytes
// are all a reader sees, so the version never reaches the protocol; a reader decodes any version.

// Per version at level L: [error-correction codewords per block, blocks of the short size, short data size, blocks of the long size (one more codeword)].
const BLOCKS: ReadonlyArray<readonly [number, number, number, number]> = [
  [7, 1, 19, 0], [10, 1, 34, 0], [15, 1, 55, 0], [20, 1, 80, 0], [26, 1, 108, 0], [18, 2, 68, 0], [20, 2, 78, 0], [24, 2, 97, 0],
  [30, 2, 116, 0], [18, 2, 68, 2], [20, 4, 81, 0], [24, 2, 92, 2], [26, 4, 107, 0], [30, 3, 115, 1], [22, 5, 87, 1], [24, 5, 98, 1],
  [28, 1, 107, 5], [30, 5, 120, 1], [28, 3, 113, 4], [28, 3, 107, 5], [28, 4, 116, 4], [28, 2, 111, 7], [30, 4, 121, 5], [30, 6, 117, 4],
  [26, 8, 106, 4], [28, 10, 114, 2], [30, 8, 122, 4], [30, 3, 117, 10], [30, 7, 116, 7], [30, 5, 115, 10], [30, 13, 115, 3],
  [30, 17, 115, 0], [30, 17, 115, 1], [30, 13, 115, 6], [30, 12, 121, 7], [30, 6, 121, 14], [30, 17, 122, 4], [30, 4, 122, 18],
  [30, 20, 117, 4], [30, 19, 118, 6],
];

function dataCodewords(version: number): number {
  const [, shortCount, shortSize, longCount] = BLOCKS[version - 1];
  return shortCount * shortSize + longCount * (shortSize + 1);
}

/** The most bytes a version holds (byte mode, level L). */
export function qrCapacity(version: number): number {
  return Math.floor((8 * dataCodewords(version) - 4 - (version < 10 ? 8 : 16)) / 8);
}

/** The smallest version that holds the bytes, or 0 when they do not fit even version 40. Version 23 is never chosen: jsQR 1.4.0,
 *  the pinned decoder the pairing pages use (portal/vendor), cannot read it (it fails on a version 23 code from an independent
 *  encoder too), so a payload that would land there is drawn at version 24 instead. */
export function qrVersionFor(length: number): number {
  for (let version = 1; version <= 40; ++version) {
    if (version === 23) continue;
    if (4 + (version < 10 ? 8 : 16) + 8 * length <= 8 * dataCodewords(version)) return version;
  }
  return 0;
}

function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2, size = 17 + 4 * version;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let position = size - 7; result.length < count; position -= step) result.splice(1, 0, position);
  return result;
}

function build(bytes: Uint8Array, version: number): boolean[][] {
  const size = 17 + 4 * version;
  const [ec, shortCount, shortSize, longCount] = BLOCKS[version - 1];
  const capacity = dataCodewords(version);
  const pixels = Array.from({ length: size }, () => Array<boolean>(size).fill(false));
  const fixed = Array.from({ length: size }, () => Array<boolean>(size).fill(false));
  const put = (x: number, y: number, on: boolean): void => {
    if (x >= 0 && y >= 0 && x < size && y < size) { pixels[y][x] = on; fixed[y][x] = true; }
  };
  for (let i = 0; i < size; ++i) { put(6, i, i % 2 === 0); put(i, 6, i % 2 === 0); }
  for (const [x, y] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; ++dy) for (let dx = -4; dx <= 4; ++dx) {
      const distance = Math.max(Math.abs(dx), Math.abs(dy));
      put(x + dx, y + dy, distance !== 2 && distance !== 4);
    }
  }
  const alignment = alignmentPositions(version), last = alignment.length - 1;
  for (let iy = 0; iy <= last; ++iy) for (let ix = 0; ix <= last; ++ix) {
    if ((ix === 0 && iy === 0) || (ix === last && iy === 0) || (ix === 0 && iy === last)) continue;
    for (let dy = -2; dy <= 2; ++dy) for (let dx = -2; dx <= 2; ++dx) {
      put(alignment[ix] + dx, alignment[iy] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
  const bit = (n: number, at: number): boolean => ((n >>> at) & 1) !== 0;
  let remainder = 8;
  for (let i = 0; i < 10; ++i) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
  const format = ((8 << 10) | remainder) ^ 0x5412;
  for (let i = 0; i <= 5; ++i) put(8, i, bit(format, i));
  put(8, 7, bit(format, 6)); put(8, 8, bit(format, 7)); put(7, 8, bit(format, 8));
  for (let i = 9; i < 15; ++i) put(14 - i, 8, bit(format, i));
  for (let i = 0; i < 8; ++i) put(size - 1 - i, 8, bit(format, i));
  for (let i = 8; i < 15; ++i) put(8, size - 15 + i, bit(format, i));
  put(8, size - 8, true);
  if (version >= 7) {
    remainder = version;
    for (let i = 0; i < 12; ++i) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
    const info = (version << 12) | remainder;
    for (let i = 0; i < 18; ++i) {
      const a = size - 11 + i % 3, b = Math.floor(i / 3);
      put(a, b, bit(info, i)); put(b, a, bit(info, i));
    }
  }
  const bits: number[] = [];
  const append = (value: number, count: number): void => {
    for (let i = count - 1; i >= 0; --i) bits.push((value >>> i) & 1);
  };
  append(4, 4); append(bytes.length, version < 10 ? 8 : 16);
  for (const byte of bytes) append(byte, 8);
  for (let i = 0; i < Math.min(4, capacity * 8 - bits.length); ++i) bits.push(0);
  while (bits.length % 8) bits.push(0);
  const data: number[] = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((n, v) => n * 2 + v, 0));
  for (let pad = 0; data.length < capacity; ++pad) data.push(pad % 2 ? 0x11 : 0xec);
  const multiply = (a: number, b: number): number => {
    let product = 0;
    for (let i = 7; i >= 0; --i) {
      product = (product << 1) ^ ((product >>> 7) * 0x11d);
      product ^= ((b >>> i) & 1) * a;
    }
    return product;
  };
  const divisor = Array<number>(ec).fill(0);
  divisor[ec - 1] = 1;
  for (let root = 1, i = 0; i < ec; ++i, root = multiply(root, 2)) {
    for (let j = 0; j < ec; ++j) {
      divisor[j] = multiply(divisor[j], root);
      if (j < ec - 1) divisor[j] ^= divisor[j + 1];
    }
  }
  const blocks: number[][] = [], checks: number[][] = [];
  let at = 0;
  for (let block = 0; block < shortCount + longCount; ++block) {
    const count = block < shortCount ? shortSize : shortSize + 1;
    const part = data.slice(at, at + count); at += count;
    const parity = Array<number>(ec).fill(0);
    for (const byte of part) {
      const factor = byte ^ parity.shift()!;
      parity.push(0);
      for (let j = 0; j < ec; ++j) parity[j] ^= multiply(divisor[j], factor);
    }
    blocks.push(part); checks.push(parity);
  }
  const codewords: number[] = [];
  for (let i = 0; i <= shortSize; ++i) for (const block of blocks) if (i < block.length) codewords.push(block[i]);
  for (let i = 0; i < ec; ++i) for (const block of checks) codewords.push(block[i]);
  let index = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let vertical = 0; vertical < size; ++vertical) for (let j = 0; j < 2; ++j) {
      const x = right - j, y = ((right + 1) & 2) === 0 ? size - 1 - vertical : vertical;
      if (fixed[y][x]) continue;
      const value = index < codewords.length * 8 && bit(codewords[index >>> 3], 7 - (index & 7));
      pixels[y][x] = value !== ((x + y) % 2 === 0);
      ++index;
    }
  }
  return pixels;
}

/** Version 40, the fixed reference. */
export function qrModules(bytes: Uint8Array): boolean[][] {
  if (bytes.length > 2953) refuse("optical-frame-size");
  return build(bytes, 40);
}

/** The smallest version that holds the bytes. */
export function qrModulesFit(bytes: Uint8Array): boolean[][] {
  const version = qrVersionFor(bytes.length);
  if (version === 0) refuse("optical-frame-size");
  return build(bytes, version);
}

function paintModules(canvas: HTMLCanvasElement, modules: boolean[][], scale: number, paper = "#fff", ink = "#000"): void {
  const border = 4;
  canvas.width = canvas.height = (modules.length + border * 2) * scale;
  const context = canvas.getContext("2d");
  if (!context) refuse("canvas");
  context.fillStyle = paper; context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = ink;
  for (let y = 0; y < modules.length; ++y) for (let x = 0; x < modules.length; ++x) {
    if (modules[y][x]) context.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
  }
}

/** The fixed version 40 reference, black on white, four pixels a module with a four-module quiet zone. */
export function drawQr(canvas: HTMLCanvasElement, bytes: Uint8Array): void {
  paintModules(canvas, qrModules(bytes), 4);
}

/** Dark ink on a soft plate: portal-v0's colours, which read reliably (a bright white plate washes out in the peer's auto-exposure). */
export const FRAME_PLATE = "#d8d4ca";
export const FRAME_INK = "#0b0e18";

/** A signed exchange frame: the smallest version that holds it, dark ink on the soft plate, the four-module quiet zone inside the
 *  plate. Each module is a whole number of CSS pixels (and of device pixels), as large as the canvas's parent allows, so a camera
 *  sees even, sharp modules. A reader decodes any version, so nothing else depends on the size. */
export function drawQrFrame(canvas: HTMLCanvasElement, bytes: Uint8Array): void {
  const modules = qrModulesFit(bytes);
  const total = modules.length + 8;
  const density = Math.max(1, Math.round(globalThis.devicePixelRatio || 1));
  const room = canvas.parentElement?.clientWidth ?? 0;
  const css = room > 0 ? Math.max(2, Math.floor(room / total)) : 4;
  paintModules(canvas, modules, css * density, FRAME_PLATE, FRAME_INK);
  canvas.style.width = canvas.style.height = `${total * css}px`;
}

/** The phone-link code: the smallest version, dark on light, a four-module quiet zone included. Each module is a whole number of
 *  CSS pixels (and of device pixels), so a camera sees even, sharp modules; the canvas is sized to match, about 220 CSS pixels. */
export function drawQrLink(canvas: HTMLCanvasElement, bytes: Uint8Array): void {
  const modules = qrModulesFit(bytes);
  const total = modules.length + 8;
  const density = Math.max(1, Math.round(globalThis.devicePixelRatio || 1));
  const css = Math.max(3, Math.floor(220 / total));
  paintModules(canvas, modules, css * density);
  canvas.style.width = canvas.style.height = `${total * css}px`;
}
