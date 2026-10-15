/* Pentora v1 display expansion + geometry, ported verbatim from aukora-prime @de410bb
   apps/aukora-desktop/pentora.mjs (byte-identical to plugins/aukora-face/settings/src/aura/pentora.mjs).
   Display only: it never authenticates or authorises. */
export const PENTORA = {
  centre: 55,
  mutable: [
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,
    37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,
    75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100,101,102,103,104,105,106,107,108,109,110],
  points: [
    [-0.934172,0,-0.356822],[-0.934172,0,0.356822],[-0.755761,-0.288675,-0.110264],[-0.755761,-0.288675,0.110264],[-0.755761,0.288675,-0.110264],
    [-0.755761,0.288675,0.110264],[-0.645497,-0.467086,-0.178411],[-0.645497,-0.467086,0.178411],[-0.645497,0.467086,-0.178411],[-0.645497,0.467086,0.178411],
    [-0.57735,-0.57735,-0.57735],[-0.57735,-0.57735,0],[-0.57735,-0.57735,0.57735],[-0.57735,0,-0.57735],[-0.57735,0,0],
    [-0.57735,0,0.57735],[-0.57735,0.57735,-0.57735],[-0.57735,0.57735,0],[-0.57735,0.57735,0.57735],[-0.467086,-0.178411,-0.645497],
    [-0.467086,-0.178411,-0.288675],[-0.467086,-0.178411,0.288675],[-0.467086,-0.178411,0.645497],[-0.467086,0.178411,-0.645497],[-0.467086,0.178411,-0.288675],
    [-0.467086,0.178411,0.288675],[-0.467086,0.178411,0.645497],[-0.356822,-0.934172,0],[-0.356822,0.934172,0],[-0.288675,-0.467086,-0.178411],
    [-0.288675,-0.467086,0.178411],[-0.288675,-0.110264,-0.755761],[-0.288675,-0.110264,0.755761],[-0.288675,0.110264,-0.755761],[-0.288675,0.110264,0.755761],
    [-0.288675,0.467086,-0.178411],[-0.288675,0.467086,0.178411],[-0.178411,-0.645497,-0.467086],[-0.178411,-0.645497,0.467086],[-0.178411,-0.288675,-0.467086],
    [-0.178411,-0.288675,0.467086],[-0.178411,0.288675,-0.467086],[-0.178411,0.288675,0.467086],[-0.178411,0.645497,-0.467086],[-0.178411,0.645497,0.467086],
    [-0.110264,-0.755761,-0.288675],[-0.110264,-0.755761,0.288675],[-0.110264,0.755761,-0.288675],[-0.110264,0.755761,0.288675],[0,-0.57735,-0.57735],
    [0,-0.57735,0],[0,-0.57735,0.57735],[0,-0.356822,-0.934172],[0,-0.356822,0.934172],[0,0,-0.57735],
    [0,0,0],[0,0,0.57735],[0,0.356822,-0.934172],[0,0.356822,0.934172],[0,0.57735,-0.57735],
    [0,0.57735,0],[0,0.57735,0.57735],[0.110264,-0.755761,-0.288675],[0.110264,-0.755761,0.288675],[0.110264,0.755761,-0.288675],
    [0.110264,0.755761,0.288675],[0.178411,-0.645497,-0.467086],[0.178411,-0.645497,0.467086],[0.178411,-0.288675,-0.467086],[0.178411,-0.288675,0.467086],
    [0.178411,0.288675,-0.467086],[0.178411,0.288675,0.467086],[0.178411,0.645497,-0.467086],[0.178411,0.645497,0.467086],[0.288675,-0.467086,-0.178411],
    [0.288675,-0.467086,0.178411],[0.288675,-0.110264,-0.755761],[0.288675,-0.110264,0.755761],[0.288675,0.110264,-0.755761],[0.288675,0.110264,0.755761],
    [0.288675,0.467086,-0.178411],[0.288675,0.467086,0.178411],[0.356822,-0.934172,0],[0.356822,0.934172,0],[0.467086,-0.178411,-0.645497],
    [0.467086,-0.178411,-0.288675],[0.467086,-0.178411,0.288675],[0.467086,-0.178411,0.645497],[0.467086,0.178411,-0.645497],[0.467086,0.178411,-0.288675],
    [0.467086,0.178411,0.288675],[0.467086,0.178411,0.645497],[0.57735,-0.57735,-0.57735],[0.57735,-0.57735,0],[0.57735,-0.57735,0.57735],
    [0.57735,0,-0.57735],[0.57735,0,0],[0.57735,0,0.57735],[0.57735,0.57735,-0.57735],[0.57735,0.57735,0],
    [0.57735,0.57735,0.57735],[0.645497,-0.467086,-0.178411],[0.645497,-0.467086,0.178411],[0.645497,0.467086,-0.178411],[0.645497,0.467086,0.178411],
    [0.755761,-0.288675,-0.110264],[0.755761,-0.288675,0.110264],[0.755761,0.288675,-0.110264],[0.755761,0.288675,0.110264],[0.934172,0,-0.356822],
    [0.934172,0,0.356822]],
  edges: [
    [10,12],[10,16],[10,92],[12,18],[12,94],[16,18],[16,98],[18,100],[92,94],[92,98],[94,100],[98,100],[10,57],[1,10],[10,82],
    [53,100],[100,109],[28,100],[1,53],[53,82],[57,109],[28,57],[82,109],[1,28],[12,58],[0,12],[12,82],[52,98],[98,110],[28,98],
    [0,52],[52,82],[58,110],[28,58],[0,28],[82,110],[16,52],[1,16],[16,83],[58,94],[94,109],[27,94],[52,109],[27,52],[1,58],
    [58,83],[83,109],[1,27],[18,53],[0,18],[18,83],[57,92],[92,110],[27,92],[53,110],[27,53],[0,57],[57,83],[0,27],[83,110]],
  cubes: [
    [10,49,92,13,54,95,16,59,98,11,50,93,14,55,96,17,60,99,12,51,94,15,56,97,18,61,100],
    [10,45,82,2,30,67,1,22,53,31,68,101,24,55,86,9,42,79,57,88,109,43,80,108,28,65,100],
    [12,46,82,3,29,66,0,19,52,32,69,102,25,55,85,8,41,78,58,91,110,44,81,107,28,64,98],
    [16,47,83,4,36,73,1,26,58,33,70,103,20,55,90,7,40,77,52,84,109,37,74,106,27,63,94],
    [18,48,83,5,35,72,0,23,57,34,71,104,21,55,89,6,39,76,53,87,110,38,75,105,27,62,92]]
};
export async function pentoraDigest(head32, sha256) {
  if (!(head32 instanceof Uint8Array) || head32.length !== 32) throw new RangeError('pentora:head-invalid');
  const msg = new Uint8Array(51); // "pentora.display.v1" (18) || 0x00 || head (32)
  for (let i = 0; i < 18; i++) msg[i] = 'pentora.display.v1'.charCodeAt(i);
  msg.set(head32, 19);
  const out = await sha256(msg), digest = out instanceof ArrayBuffer ? new Uint8Array(out) : out;
  if (!(digest instanceof Uint8Array) || digest.length !== 32) throw new TypeError('pentora:hash-invalid');
  return digest;
}
export async function pentoraDigits(head32, sha256) {
  const n = Array.from(await pentoraDigest(head32, sha256)), digits = new Uint8Array(110);
  for (let i = 0; i < 110; i++) { // digit[i] = floor(N / 3^i) mod 3: divide the big-endian N by 3, keep the remainder
    let r = 0;
    for (let k = 0; k < 32; k++) { const v = r * 256 + n[k]; n[k] = (v - v % 3) / 3; r = v % 3; }
    digits[i] = r;
  }
  return digits;
}

/* Browser hash wrapper (aukora-prime apps/aukora-desktop/pentora-cells.mjs). */
export async function browserSha256(bytes) {
  if (!globalThis.crypto?.subtle) throw Object.assign(new TypeError('pentora:hash-unavailable'), { code: 'pentora:hash-unavailable' });
  return globalThis.crypto.subtle.digest('SHA-256', bytes);
}

/* Static SVG renderer, from aukora-prime apps/aukora-desktop/pentora-view.mjs.
   Draws into `target` (an element); head is 64 lowercase hex of the Aura root. */
const TRIT_COLORS = ['rgb(86,190,255)', 'rgb(236,232,245)', 'rgb(255,184,92)'];

export async function drawPentora(target, headHex, hash = browserSha256) {
  target.replaceChildren();
  if (!/^[0-9a-fA-F]{64}$/.test(headHex)) return 'pentora:head-invalid';
  let digits;
  try {
    digits = await pentoraDigits(Uint8Array.from(headHex.match(/../g), b => parseInt(b, 16)), hash);
  } catch {
    return 'pentora:hash-unavailable';
  }
  const el = (name, attrs) => {
    const node = target.ownerDocument.createElementNS('http://www.w3.org/2000/svg', name);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    return node;
  };
  const svg = el('svg', { viewBox: '-1.2 -1.2 2.4 2.4', role: 'img', 'aria-label': 'Pentora of the Aura root', width: '100%', height: '100%' });
  const project = ([x, y, z]) => [0.86 * x + 0.5 * z, 0.25 * x - 0.86 * y - 0.43 * z];
  const points = PENTORA.points.map(project);
  for (const [a, b] of PENTORA.edges) {
    svg.appendChild(el('line', { x1: points[a][0], y1: points[a][1], x2: points[b][0], y2: points[b][1],
      stroke: 'currentColor', 'stroke-width': 0.008, opacity: 0.25 }));
  }
  for (const [i, index] of PENTORA.mutable.entries()) {
    const [cx, cy] = points[index], digit = digits[i];
    svg.appendChild(el('circle', { cx, cy, r: 0.024, 'data-cell': index, 'data-digit': digit,
      fill: TRIT_COLORS[digit], stroke: 'currentColor', 'stroke-width': 0.008 }));
  }
  svg.appendChild(el('circle', { cx: 0, cy: 0, r: 0.03, fill: TRIT_COLORS[1] }));
  target.replaceChildren(svg);
  return 'pentora:displayed';
}


export function compareTrits(ours, text) {
  if (!Array.isArray(ours) || ours.length !== 110 || !ours.every(value => Number.isInteger(value) && value >= 0 && value <= 2)) {
    return { state: 'invalid', reason: 'pentora:trits-invalid' };
  }
  const compact = String(text).replace(/\s/g, '');
  if (!/^[012]{110}$/.test(compact)) return { state: 'invalid', reason: 'pentora:comparison-invalid' };
  const differences = [];
  for (let index = 0; index < 110; index++) if (ours[index] !== Number(compact[index])) differences.push(index + 1);
  return { state: differences.length ? 'different' : 'same', differences };
}

export function mountTritComparison(target, trits) {
  const doc = target.ownerDocument;
  const label = doc.createElement('label');
  label.textContent = 'Pentora: 110 trits, in index order (0, 1, 2)';
  const own = doc.createElement('textarea');
  own.className = 'pentora-trits';
  own.readOnly = true;
  own.value = trits.join('');
  own.setAttribute('aria-label', 'this device Pentora trits');
  label.appendChild(own);
  const otherLabel = doc.createElement('label');
  otherLabel.textContent = 'Paste the 110 trits shown on another device';
  const other = doc.createElement('textarea');
  other.className = 'pentora-trits';
  other.setAttribute('aria-label', 'other device Pentora trits');
  otherLabel.appendChild(other);
  const compare = doc.createElement('button');
  compare.textContent = 'Compare trits';
  const result = doc.createElement('p');
  result.className = 'instruct';
  result.setAttribute('role', 'status');
  compare.onclick = () => {
    const comparison = compareTrits(trits, other.value);
    result.textContent = comparison.state === 'same'
      ? 'All 110 trits match. Compare the same tree size on both devices.'
      : comparison.state === 'different'
        ? `Pentora differs at trit positions ${comparison.differences.join(', ')}. Compare the tree sizes and retained heads.`
        : 'Enter exactly 110 trits using only 0, 1 and 2; spaces and line breaks are allowed.';
    result.dataset.comparison = comparison.state;
  };
  target.append(label, otherLabel, compare, result);
}
