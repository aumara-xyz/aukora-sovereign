// SPDX-License-Identifier: AGPL-3.0-or-later
// What the camera can tell the person while the decoder is failing: is a code in view, how large, is it cut off, and are the corner
// squares visible even though the code will not read (the sign of glare or a tilt)? Pure image arithmetic on a small greyscale picture;
// nothing here reads a code or touches the protocol. The decoder (portal/node/decoder.ts) feeds it, the pairing pages show the hint.
export type Sight = {
  /** How many corner squares (the 1:1:3:1:1 finder patterns) were found, 0 to 3. */
  readonly finders: number;
  /** The code's width as a fraction of the picture's shorter side (estimated when fewer than three squares are visible). */
  readonly size: number;
  /** A corner square touches the edge of the picture, so the code is probably cut off. */
  readonly clipped: boolean;
};
export type Hint = "aim" | "hold" | "back" | "closer" | "tilt";
export const HINT_TEXT: Record<Hint, string> = {
  aim: "Bring the other screen into view",
  hold: "Hold steady",
  back: "Move back a little",
  closer: "Move closer",
  tilt: "Tilt slightly to avoid glare",
};
const NONE: Sight = { finders: 0, size: 0, clipped: false };
const TYPICAL_MODULES = 55;       // compact frames are QR versions 8 to 10: 49 to 57 modules a side

type Candidate = { x: number; y: number; module: number; votes: number };

function near(a: number, b: number, tolerance: number): boolean { return Math.abs(a - b) <= tolerance; }

/** Do five run lengths (dark, light, dark, light, dark) have the 1:1:3:1:1 proportion of a finder square? Returns the module size or 0. */
function finderRuns(runs: readonly number[]): number {
  const total = runs[0]! + runs[1]! + runs[2]! + runs[3]! + runs[4]!;
  if (total < 14) return 0;           // modules under two pixels cannot be read anyway, and sensor speckle looks like that
  const module = total / 7, slack = module * 0.7;
  return near(runs[0]!, module, slack) && near(runs[1]!, module, slack) && near(runs[2]!, 3 * module, 3 * slack)
    && near(runs[3]!, module, slack) && near(runs[4]!, module, slack) ? module : 0;
}

/** Looks for the code's corner squares in a greyscale picture (one byte a pixel) and says how the code sits in view. */
export function findFinders(gray: Uint8Array, width: number, height: number): Sight {
  // A global threshold halfway between the dark and light ends of the picture; a code on a plate has plenty of both.
  let low = 255, high = 0, sum = 0, count = 0;
  for (let i = 0; i < gray.length; i += 7) { const v = gray[i]!; if (v < low) low = v; if (v > high) high = v; sum += v; ++count; }
  if (high - low < 40) return NONE;
  const threshold = (low + high) / 2 * 0.6 + (sum / count) * 0.4;
  const candidates: Candidate[] = [];
  const LIMIT = 400;                  // a picture that offers more than this is noise, not a code
  const step = Math.max(2, Math.floor(height / 160));
  for (let y = 0; y < height && candidates.length < LIMIT; y += step) {
    const row = y * width;
    const runs = [0, 0, 0, 0, 0];
    let kind = gray[row]! < threshold, length = 0, filled = 0;
    const push = (x: number, dark: boolean): void => {
      // runs[0..4] hold the last five runs; a candidate needs the newest to be dark and the five to alternate dark-light-dark-light-dark.
      runs.shift(); runs.push(length); ++filled;
      if (filled >= 5 && dark) {
        const module = finderRuns(runs);
        if (module > 0) {
          const centre = x - runs[4]! - runs[3]! - runs[2]! / 2;
          const verified = verticalCheck(Math.round(centre), y, module);
          if (verified) candidates.push({ x: centre, y: verified, module, votes: 1 });
        }
      }
    };
    for (let x = 0; x < width; ++x) {
      const dark = gray[row + x]! < threshold;
      if (dark === kind) { ++length; continue; }
      push(x, kind);
      kind = dark; length = 1;
    }
  }
  function verticalCheck(x: number, y: number, module: number): number {
    if (x < 0 || x >= width) return 0;
    // From the candidate's centre go up and down: the middle square is about three modules of dark, then light, then dark on each side.
    const dark = (yy: number): boolean => gray[yy * width + x]! < threshold;
    if (!dark(y)) return 0;
    let up = y, down = y;
    while (up > 0 && dark(up - 1)) --up;
    while (down < height - 1 && dark(down + 1)) ++down;
    const middle = down - up + 1;
    if (!near(middle, 3 * module, 2.2 * module)) return 0;
    let top = up - 1, ringTop = 0;
    while (top >= 0 && !dark(top)) { --top; ++ringTop; }
    let ringTopDark = 0;
    while (top >= 0 && dark(top)) { --top; ++ringTopDark; }
    let bottom = down + 1, ringBottom = 0;
    while (bottom < height && !dark(bottom)) { ++bottom; ++ringBottom; }
    let ringBottomDark = 0;
    while (bottom < height && dark(bottom)) { ++bottom; ++ringBottomDark; }
    const ok = (n: number): boolean => near(n, module, 0.9 * module);
    // Near an edge the outer dark run can be cut; the light ring on both sides must be there.
    if (!ok(ringTop) || !ok(ringBottom)) return 0;
    if (!(ok(ringTopDark) || top < 0) || !(ok(ringBottomDark) || bottom >= height)) return 0;
    return (up + down) / 2;
  }
  // Merge the rows that saw the same square.
  const clusters: Candidate[] = [];
  for (const c of candidates) {
    if (clusters.length > 200) break;
    const same = clusters.find(k => Math.hypot(k.x - c.x, k.y - c.y) < 2.5 * Math.max(k.module, c.module));
    if (same) { same.x = (same.x * same.votes + c.x) / (same.votes + 1); same.y = (same.y * same.votes + c.y) / (same.votes + 1);
      same.module = (same.module * same.votes + c.module) / (same.votes + 1); ++same.votes; }
    else clusters.push({ ...c });
  }
  if (candidates.length >= LIMIT) return NONE;
  const found = clusters.filter(k => k.votes >= 2).sort((a, b) => b.votes - a.votes).slice(0, 24);
  if (found.length === 0) return NONE;
  const shorter = Math.min(width, height);
  // Three squares of one module size at the corners of a right-angled triangle with two equal sides are a QR code's finder patterns.
  let best: { corner: Candidate; a: Candidate; b: Candidate; score: number } | null = null;
  for (const corner of found) for (const a of found) for (const b of found) {
    if (a === corner || b === corner || a === b || a.x + a.y > b.x + b.y) continue;
    const module = (corner.module + a.module + b.module) / 3;
    if ([corner, a, b].some(k => Math.abs(k.module - module) > 0.25 * module)) continue;
    const ab = Math.hypot(a.x - corner.x, a.y - corner.y), ac = Math.hypot(b.x - corner.x, b.y - corner.y);
    if (ab / module < 14 || ab / module > 180 || Math.abs(ab - ac) > 0.2 * Math.max(ab, ac)) continue;
    const cos = ((a.x - corner.x) * (b.x - corner.x) + (a.y - corner.y) * (b.y - corner.y)) / (ab * ac);
    if (Math.abs(cos) > 0.3) continue;
    const score = corner.votes + a.votes + b.votes;
    if (!best || score > best.score) best = { corner, a, b, score };
  }
  if (best) {
    const squares = [best.corner, best.a, best.b];
    const module = squares.reduce((sum, k) => sum + k.module, 0) / 3;
    const side = (Math.hypot(best.a.x - best.corner.x, best.a.y - best.corner.y) + Math.hypot(best.b.x - best.corner.x, best.b.y - best.corner.y)) / 2;
    const clipped = squares.some(k => k.x < 4 * module || k.y < 4 * module || k.x > width - 4 * module || k.y > height - 4 * module);
    return { finders: 3, size: (side + 7 * module) / shorter, clipped };
  }
  // No full set: report the largest group of squares of one size, with the size a typical code of that module size would have.
  let group: Candidate[] = [];
  for (const seed of found) {
    const same = found.filter(k => Math.abs(k.module - seed.module) <= 0.2 * seed.module);
    if (same.length > group.length) group = same;
  }
  const module = group.reduce((sum, k) => sum + k.module, 0) / group.length;
  const clipped = group.some(k => k.x < 4 * module || k.y < 4 * module || k.x > width - 4 * module || k.y > height - 4 * module);
  return { finders: Math.min(2, group.length), size: (module * TYPICAL_MODULES) / shorter, clipped };
}

export type Attempt = { readonly hit: boolean; readonly sight: Sight };

/** The hint for the last few decode attempts: nothing is said while the camera is reading, and one thing at a time when it is not. */
export function hintFor(recent: readonly Attempt[]): Hint {
  const last = recent.slice(-8);
  if (last.slice(-6).some(a => a.hit)) return "hold";
  const misses = last.filter(a => !a.hit);
  if (misses.length < 5) return "hold";
  const full = misses.filter(a => a.sight.finders >= 3);
  const partial = misses.filter(a => a.sight.finders >= 1 && a.sight.finders < 3);
  const seen = full.length + partial.length;
  if (seen < 4) return "aim";
  const typical = (items: readonly Attempt[]): number => items.map(a => a.sight.size).sort((a, b) => a - b)[Math.floor(items.length / 2)]!;
  if (full.length >= Math.max(3, partial.length)) {
    if (full.filter(a => a.sight.clipped).length >= full.length / 2 || typical(full) > 0.8) return "back";
    if (typical(full) < 0.18) return "closer";
    return "tilt";            // the corner squares are there and the code will not read: glare or a tilt
  }
  return typical(partial) > 0.6 ? "back" : "closer";
}

/** Tells the pages the hint, changing it only when a new one has held for a few attempts so the words do not flicker. */
export class Guide {
  readonly #listeners = new Set<(hint: Hint) => void>();
  #recent: Attempt[] = [];
  #current: Hint = "aim";
  #candidate: Hint = "aim";
  #held = 0;
  get hint(): Hint { return this.#current; }
  subscribe(listener: (hint: Hint) => void): () => void { this.#listeners.add(listener); listener(this.#current); return () => { this.#listeners.delete(listener); }; }
  reset(): void { this.#recent = []; this.#candidate = "aim"; this.#held = 0; this.#set("aim"); }
  note(attempt: Attempt): void {
    this.#recent.push(attempt);
    if (this.#recent.length > 12) this.#recent.shift();
    const next = hintFor(this.#recent);
    if (next === this.#current) { this.#held = 0; return; }
    if (next === this.#candidate) ++this.#held; else { this.#candidate = next; this.#held = 1; }
    if (this.#held >= (next === "hold" ? 1 : 3)) this.#set(next);
  }
  #set(hint: Hint): void {
    this.#held = 0;
    if (hint === this.#current) return;
    this.#current = hint;
    for (const listener of this.#listeners) listener(hint);
  }
}
