// SPDX-License-Identifier: AGPL-3.0-or-later
import { refuse } from "./bytes.js";

// QR Model 2, version 40, error correction L, byte mode, mask 0.
export function qrModules(bytes: Uint8Array): boolean[][] {
  if (bytes.length > 2953) refuse("optical-frame-size");
  const size = 177;
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
  const alignment = [6, 30, 58, 86, 114, 142, 170];
  for (let iy = 0; iy < 7; ++iy) for (let ix = 0; ix < 7; ++ix) {
    if ((ix === 0 && iy === 0) || (ix === 6 && iy === 0) || (ix === 0 && iy === 6)) continue;
    for (let dy = -2; dy <= 2; ++dy) for (let dx = -2; dx <= 2; ++dx) {
      put(alignment[ix] + dx, alignment[iy] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
  let remainder = 8;
  for (let i = 0; i < 10; ++i) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
  const format = ((8 << 10) | remainder) ^ 0x5412;
  const bit = (n: number, at: number): boolean => ((n >>> at) & 1) !== 0;
  for (let i = 0; i <= 5; ++i) put(8, i, bit(format, i));
  put(8, 7, bit(format, 6)); put(8, 8, bit(format, 7)); put(7, 8, bit(format, 8));
  for (let i = 9; i < 15; ++i) put(14 - i, 8, bit(format, i));
  for (let i = 0; i < 8; ++i) put(size - 1 - i, 8, bit(format, i));
  for (let i = 8; i < 15; ++i) put(8, size - 15 + i, bit(format, i));
  put(8, size - 8, true);
  remainder = 40;
  for (let i = 0; i < 12; ++i) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
  const version = (40 << 12) | remainder;
  for (let i = 0; i < 18; ++i) {
    const a = size - 11 + i % 3, b = Math.floor(i / 3);
    put(a, b, bit(version, i)); put(b, a, bit(version, i));
  }
  const bits: number[] = [];
  const append = (value: number, count: number): void => {
    for (let i = count - 1; i >= 0; --i) bits.push((value >>> i) & 1);
  };
  append(4, 4); append(bytes.length, 16);
  for (const byte of bytes) append(byte, 8);
  for (let i = 0; i < Math.min(4, 2956 * 8 - bits.length); ++i) bits.push(0);
  while (bits.length % 8) bits.push(0);
  const data: number[] = [];
  for (let i = 0; i < bits.length; i += 8) data.push(bits.slice(i, i + 8).reduce((n, v) => n * 2 + v, 0));
  for (let pad = 0; data.length < 2956; ++pad) data.push(pad % 2 ? 0x11 : 0xec);
  const multiply = (a: number, b: number): number => {
    let product = 0;
    for (let i = 7; i >= 0; --i) {
      product = (product << 1) ^ ((product >>> 7) * 0x11d);
      product ^= ((b >>> i) & 1) * a;
    }
    return product;
  };
  const divisor = Array<number>(30).fill(0);
  divisor[29] = 1;
  for (let root = 1, i = 0; i < 30; ++i, root = multiply(root, 2)) {
    for (let j = 0; j < 30; ++j) {
      divisor[j] = multiply(divisor[j], root);
      if (j < 29) divisor[j] ^= divisor[j + 1];
    }
  }
  const blocks: number[][] = [], checks: number[][] = [];
  let at = 0;
  for (let block = 0; block < 25; ++block) {
    const count = block < 19 ? 118 : 119;
    const part = data.slice(at, at + count); at += count;
    const parity = Array<number>(30).fill(0);
    for (const byte of part) {
      const factor = byte ^ parity.shift()!;
      parity.push(0);
      for (let j = 0; j < 30; ++j) parity[j] ^= multiply(divisor[j], factor);
    }
    blocks.push(part); checks.push(parity);
  }
  const codewords: number[] = [];
  for (let i = 0; i < 119; ++i) for (const block of blocks) if (i < block.length) codewords.push(block[i]);
  for (let i = 0; i < 30; ++i) for (const block of checks) codewords.push(block[i]);
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

export function drawQr(canvas: HTMLCanvasElement, bytes: Uint8Array): void {
  const modules = qrModules(bytes);
  const scale = 4, border = 4;
  canvas.width = canvas.height = (modules.length + border * 2) * scale;
  const context = canvas.getContext("2d");
  if (!context) refuse("canvas");
  context.fillStyle = "#fff"; context.fillRect(0, 0, canvas.width, canvas.height);
  context.fillStyle = "#000";
  for (let y = 0; y < modules.length; ++y) for (let x = 0; x < modules.length; ++x) {
    if (modules[y][x]) context.fillRect((x + border) * scale, (y + border) * scale, scale, scale);
  }
}
