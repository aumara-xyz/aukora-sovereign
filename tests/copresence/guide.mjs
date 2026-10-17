#!/usr/bin/env node
// SPDX-License-Identifier: AGPL-3.0-or-later
// The camera guidance (portal/guide.ts): find a code's corner squares in a small greyscale picture, say how large it is and whether it is
// cut off, and turn what the last few decode attempts saw into one calm hint (move back, move closer, tilt, hold steady). Pure arithmetic
// on rendered QR codes; no camera. Also the speed claim: finding the squares in an 800-pixel picture costs a few milliseconds.
//
//   node tests/copresence/guide.mjs
import { compilePortal } from './portal-compile.mjs';

let failed = 0;
const check = (ok, label, detail = '') => { if (!ok || process.env.VERBOSE) console.log(`${ok ? 'ok  ' : 'FAIL'} ${label}${detail ? `  ${detail}` : ''}`); if (!ok) failed++; };
const portal = compilePortal();
const qr = await portal.load('qr.js'), guide = await portal.load('guide.js');
const modules = qr.qrModulesOf({ kind: 'alnum', text: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'.repeat(8).slice(0, 270) });   // a version 8 code, as a compact frame is
const N = modules.length;

// The code drawn dark on a light plate (and a dark surround) into a W by H greyscale picture, `fraction` of the shorter side across.
function render(W, H, fraction, cx = 0.5, cy = 0.5, glare = false) {
  const g = new Uint8Array(W * H).fill(60);
  const side = Math.min(W, H) * fraction, m = side / (N + 8), x0 = cx * W - side / 2, y0 = cy * H - side / 2;
  for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {
    const u = (x - x0) / m - 4, v = (y - y0) / m - 4;
    if (u >= -4 && v >= -4 && u < N + 4 && v < N + 4) g[y * W + x] = (u >= 0 && v >= 0 && u < N && v < N && modules[Math.floor(v)][Math.floor(u)]) ? 20 : 215;
  }
  if (glare) for (let y = 0; y < H; y++) for (let x = 0; x < W; x++) {   // a bright band washing out the middle of the code
    if (x > W * cx - 5 && x < W * cx + 5 && y > H * cy - side / 2 && y < H * cy + side / 4) g[y * W + x] = 250;
  }
  return g;
}
const sight = (fraction, cx, cy, glare) => guide.findFinders(render(450, 800, fraction, cx, cy, glare), 450, 800);

for (const fraction of [0.35, 0.5, 0.7, 0.9]) {
  const s = sight(fraction);
  const expected = fraction * N / (N + 8);
  check(s.finders === 3 && Math.abs(s.size - expected) < 0.06 && !s.clipped, `a code ${Math.round(fraction * 100)}% of the picture: three squares, size ${s.size.toFixed(2)} (about ${expected.toFixed(2)})`);
}
check(sight(0.5, 0.3, 0.7, false).finders === 3, 'the squares are found off-centre too');
check(sight(1.3).finders < 3 && sight(1.3).size > 0.9, 'a code larger than the picture: fewer than three squares and a large estimate', JSON.stringify(sight(1.3)));
check(sight(0.12).finders === 0, 'a tiny code is not mistaken for a code in range', JSON.stringify(sight(0.12)));
check(guide.findFinders(new Uint8Array(450 * 800).fill(120), 450, 800).finders === 0, 'a plain picture has no squares');
const noise = new Uint8Array(450 * 800).map((_, i) => (Math.imul(i + 1, 2654435761) >>> 24) & 255);
check(guide.findFinders(noise, 450, 800).finders < 3, 'noise has no code');
const picture = render(450, 800, 0.5);
const started = performance.now();
for (let i = 0; i < 50; ++i) guide.findFinders(picture, 450, 800);
const per = (performance.now() - started) / 50;
check(per < 8, 'the search for the squares takes a few milliseconds', `${per.toFixed(1)} ms`);

// Hints, from the last attempts.
const miss = s => ({ hit: false, sight: s });
const run = (attempt, count = 8) => guide.hintFor(Array.from({ length: count }, (_, i) => attempt(i)));
check(run(() => ({ hit: true, sight: sight(0.5) })) === 'hold', 'reading: hold steady');
check(run(i => i === 3 ? { hit: true, sight: sight(0.5) } : miss(sight(0.5))) === 'hold', 'a hit within the last few attempts keeps "hold steady"');
check(run(() => miss(sight(0.5))) === 'tilt', 'squares found but nothing reads: tilt to avoid glare');
check(run(() => miss(sight(1.0))) === 'back', 'a code filling the picture: move back a little', JSON.stringify(sight(1.0)));
check(run(() => miss(sight(1.3))) === 'back', 'a code bigger than the picture: move back a little');
check(['closer', 'aim'].includes(run(() => miss(sight(0.2)))), 'a small code: move closer, or at least bring the screen into view', JSON.stringify(sight(0.2)) + ' ' + run(() => miss(sight(0.2))));
check(run(() => miss({ finders: 2, size: 0.3, clipped: false })) === 'closer', 'two squares of a small code: move closer');
check(run(() => miss(sight(0.12))) === 'aim', 'nothing in view: bring the other screen into view');
check(run(() => miss(sight(0.5)), 3) === 'hold', 'three attempts say nothing yet');

// The Guide changes its words only when a new hint has held, and says "hold steady" at once.
const g = new guide.Guide();
const seen = [];
g.subscribe(h => seen.push(h));
for (let i = 0; i < 8; ++i) g.note(miss(sight(0.5)));
check(seen[seen.length - 1] === 'tilt' && seen.filter(h => h === 'tilt').length === 1, 'a steady failure settles on one hint, without flicker', seen.join('>'));
g.note({ hit: true, sight: sight(0.5) });
check(g.hint === 'hold', 'a hit turns the hint to hold steady at once');
g.reset();
check(g.hint === 'aim', 'reset goes back to bringing the screen into view');
portal.cleanup();
console.log(failed ? `${failed} FAILED` : 'ALL OK');
process.exit(failed ? 1 : 0);
