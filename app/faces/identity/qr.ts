// SPDX-License-Identifier: AGPL-3.0-or-later
// QR Model 2 encoder for short contact codes: UTF-8 byte mode, error correction level M, versions 1 to 40, the mask chosen
// by the standard four-rule penalty. It returns modules only; drawing is the caller's. A code is a picture of text the
// node already issued: encoding it signs nothing and grants nothing.

export interface QrSymbol {
  readonly version: number;
  readonly size: number;
  dark(x: number, y: number): boolean;
}

// Level M, indexed by version - 1: error-correction codewords per block, and the number of blocks.
const EC_PER_BLOCK = [
  10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
  26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];
const BLOCKS = [
  1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
  17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
];
const BYTE_MODE = 0b0100;
const LEVEL_M = 0;
const MASKS = 8;
const PADDING = [0xec, 0x11];

// GF(256) with the QR polynomial 0x11d.
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
for (let power = 0, value = 1; power < 255; power++) {
  EXP[power] = value;
  LOG[value] = power;
  value <<= 1;
  if (value & 0x100) value ^= 0x11d;
}
for (let power = 255; power < 512; power++) EXP[power] = EXP[power - 255];
const multiply = (a: number, b: number) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);

const generators = new Map<number, number[]>();
function generator(degree: number): number[] {
  let found = generators.get(degree);
  if (found) return found;
  found = [1];
  for (let root = 0; root < degree; root++) {
    const next = new Array<number>(found.length + 1).fill(0);
    found.forEach((coefficient, at) => {
      next[at] ^= coefficient;
      next[at + 1] ^= multiply(coefficient, EXP[root]);
    });
    found = next;
  }
  generators.set(degree, found);
  return found;
}

function errorCodewords(data: readonly number[], degree: number): number[] {
  const divisor = generator(degree);
  const rest = new Array<number>(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ rest[0];
    rest.shift();
    rest.push(0);
    for (let at = 0; at < degree; at++) rest[at] ^= multiply(divisor[at + 1], factor);
  }
  return rest;
}

const sizeOf = (version: number) => version * 4 + 17;

function alignmentCentres(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const centres = [6];
  for (let at = sizeOf(version) - 7; centres.length < count; at -= step) centres.splice(1, 0, at);
  return centres;
}

function rawCodewords(version: number): number {
  let modules = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const count = Math.floor(version / 7) + 2;
    modules -= (25 * count - 10) * count - 55;
    if (version >= 7) modules -= 36;
  }
  return Math.floor(modules / 8);
}

const dataCodewords = (version: number) => rawCodewords(version) - EC_PER_BLOCK[version - 1] * BLOCKS[version - 1];

/** Data codewords in, data and error-correction codewords out, interleaved across blocks as the standard orders them. */
function interleave(data: readonly number[], version: number): number[] {
  const blocks = BLOCKS[version - 1];
  const ec = EC_PER_BLOCK[version - 1];
  const raw = rawCodewords(version);
  const shortBlocks = blocks - (raw % blocks);
  const shortLength = Math.floor(raw / blocks);
  const dataBlocks: number[][] = [];
  const ecBlocks: number[][] = [];
  let at = 0;
  for (let block = 0; block < blocks; block++) {
    const length = shortLength - ec + (block < shortBlocks ? 0 : 1);
    const chunk = data.slice(at, at + length);
    at += length;
    dataBlocks.push(chunk);
    ecBlocks.push(errorCodewords(chunk, ec));
  }
  const out: number[] = [];
  for (let position = 0; position <= shortLength - ec; position++) {
    for (const chunk of dataBlocks) if (position < chunk.length) out.push(chunk[position]);
  }
  for (let position = 0; position < ec; position++) for (const chunk of ecBlocks) out.push(chunk[position]);
  return out;
}

class Matrix {
  readonly size: number;
  readonly cells: Uint8Array;
  readonly fixed: Uint8Array;
  constructor(size: number) {
    this.size = size;
    this.cells = new Uint8Array(size * size);
    this.fixed = new Uint8Array(size * size);
  }
  bit(x: number, y: number): number { return this.cells[y * this.size + x]; }
  /** Writes a function module; positions outside the symbol are ignored. */
  put(x: number, y: number, dark: boolean) {
    if (x < 0 || y < 0 || x >= this.size || y >= this.size) return;
    this.cells[y * this.size + x] = dark ? 1 : 0;
    this.fixed[y * this.size + x] = 1;
  }
}

function formatBits(mask: number): number {
  const data = (LEVEL_M << 3) | mask;
  let rest = data;
  for (let step = 0; step < 10; step++) rest = (rest << 1) ^ ((rest >>> 9) * 0x537);
  return ((data << 10) | rest) ^ 0x5412;
}

function drawFormat(matrix: Matrix, mask: number) {
  const bits = formatBits(mask);
  const on = (at: number) => ((bits >>> at) & 1) !== 0;
  const size = matrix.size;
  for (let at = 0; at <= 5; at++) matrix.put(8, at, on(at));
  matrix.put(8, 7, on(6));
  matrix.put(8, 8, on(7));
  matrix.put(7, 8, on(8));
  for (let at = 9; at < 15; at++) matrix.put(14 - at, 8, on(at));
  for (let at = 0; at < 8; at++) matrix.put(size - 1 - at, 8, on(at));
  for (let at = 8; at < 15; at++) matrix.put(8, size - 15 + at, on(at));
  matrix.put(8, size - 8, true);
}

function drawVersion(matrix: Matrix, version: number) {
  let rest = version;
  for (let step = 0; step < 12; step++) rest = (rest << 1) ^ ((rest >>> 11) * 0x1f25);
  const bits = (version << 12) | rest;
  for (let at = 0; at < 18; at++) {
    const dark = ((bits >>> at) & 1) !== 0;
    const a = matrix.size - 11 + (at % 3);
    const b = Math.floor(at / 3);
    matrix.put(a, b, dark);
    matrix.put(b, a, dark);
  }
}

function drawFunctions(matrix: Matrix, version: number) {
  const size = matrix.size;
  for (let at = 0; at < size; at++) {
    matrix.put(6, at, at % 2 === 0);
    matrix.put(at, 6, at % 2 === 0);
  }
  for (const [cx, cy] of [[3, 3], [size - 4, 3], [3, size - 4]]) {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const ring = Math.max(Math.abs(dx), Math.abs(dy));
        matrix.put(cx + dx, cy + dy, ring !== 2 && ring !== 4);
      }
    }
  }
  const centres = alignmentCentres(version);
  const last = centres.length - 1;
  centres.forEach((cy, row) => centres.forEach((cx, column) => {
    if ((row === 0 && column === 0) || (row === 0 && column === last) || (row === last && column === 0)) return;
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) matrix.put(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }));
  drawFormat(matrix, 0);
  if (version >= 7) drawVersion(matrix, version);
}

/** Data modules run in two-column strips from the lower right, upward then downward, skipping the timing column. */
function place(matrix: Matrix, codewords: readonly number[]) {
  const size = matrix.size;
  let bit = 0;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      for (let column = 0; column < 2; column++) {
        const x = right - column;
        const y = ((right + 1) & 2) === 0 ? size - 1 - step : step;
        if (matrix.fixed[y * size + x] || bit >= codewords.length * 8) continue;
        matrix.cells[y * size + x] = (codewords[bit >>> 3] >>> (7 - (bit & 7))) & 1;
        bit++;
      }
    }
  }
}

const MASK_RULES: readonly ((x: number, y: number) => boolean)[] = [
  (x, y) => (x + y) % 2 === 0,
  (_x, y) => y % 2 === 0,
  (x) => x % 3 === 0,
  (x, y) => (x + y) % 3 === 0,
  (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0,
  (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0,
  (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0,
  (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0,
];

function applyMask(matrix: Matrix, mask: number) {
  const size = matrix.size;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      if (!matrix.fixed[y * size + x] && MASK_RULES[mask](x, y)) matrix.cells[y * size + x] ^= 1;
    }
  }
}

/** The four standard penalty rules: runs, 2 x 2 blocks, finder-like lines, and dark/light balance. */
function penalty(matrix: Matrix): number {
  const size = matrix.size;
  let score = 0;
  const line = (module: (at: number) => number) => {
    let run = 1;
    let recent = module(0);
    for (let at = 1; at < size; at++) {
      const value = module(at);
      if (value === module(at - 1)) run++;
      else {
        if (run >= 5) score += run - 2;
        run = 1;
      }
      recent = ((recent << 1) | value) & 0x7ff;
      if (at >= 10 && (recent === 0x5d0 || recent === 0x05d)) score += 40;
    }
    if (run >= 5) score += run - 2;
  };
  let dark = 0;
  for (let a = 0; a < size; a++) {
    line(at => matrix.bit(at, a));
    line(at => matrix.bit(a, at));
    for (let b = 0; b < size; b++) {
      dark += matrix.bit(b, a);
      if (a + 1 < size && b + 1 < size) {
        const value = matrix.bit(b, a);
        if (value === matrix.bit(b + 1, a) && value === matrix.bit(b, a + 1) && value === matrix.bit(b + 1, a + 1)) score += 3;
      }
    }
  }
  return score + Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
}

function dataFor(payload: Uint8Array, version: number): number[] {
  const bits: number[] = [];
  const push = (value: number, count: number) => {
    for (let at = count - 1; at >= 0; at--) bits.push((value >>> at) & 1);
  };
  push(BYTE_MODE, 4);
  push(payload.length, version < 10 ? 8 : 16);
  for (const byte of payload) push(byte, 8);
  const capacity = dataCodewords(version) * 8;
  push(0, Math.min(4, capacity - bits.length));
  while (bits.length % 8) bits.push(0);
  const words: number[] = [];
  for (let at = 0; at < bits.length; at += 8) {
    words.push(bits.slice(at, at + 8).reduce((word, bit) => (word << 1) | bit, 0));
  }
  for (let pad = 0; words.length < dataCodewords(version); pad++) words.push(PADDING[pad % 2]);
  return words;
}

/** Text of 1 byte or more that fits version 40 at level M (2,331 bytes); anything else refuses. */
export function encodeQr(text: string): QrSymbol {
  const payload = new TextEncoder().encode(text);
  if (payload.length === 0) throw new Error("identity:contact-empty");
  let version = 1;
  while (version <= 40 && 4 + (version < 10 ? 8 : 16) + payload.length * 8 > dataCodewords(version) * 8) version++;
  if (version > 40) throw new Error("identity:contact-too-long");
  const matrix = new Matrix(sizeOf(version));
  drawFunctions(matrix, version);
  place(matrix, interleave(dataFor(payload, version), version));
  let best = 0;
  let lowest = Infinity;
  for (let mask = 0; mask < MASKS; mask++) {
    applyMask(matrix, mask);
    drawFormat(matrix, mask);
    const score = penalty(matrix);
    if (score < lowest) {
      lowest = score;
      best = mask;
    }
    applyMask(matrix, mask);
  }
  applyMask(matrix, best);
  drawFormat(matrix, best);
  return { version, size: matrix.size, dark: (x, y) => x >= 0 && y >= 0 && x < matrix.size && y < matrix.size && matrix.bit(x, y) === 1 };
}
