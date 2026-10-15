/* C6 approval card renderer — injective: two different cards never look the same.
   Every character of every field is escaped and rendered visible (containers use
   white-space: pre-wrap, so whitespace and newlines are shown, not collapsed).
   The escape round-trip is proven in ui/owner/test/card.test.mjs.
   Card shape (CONTRACTS.md C6):
   {"v":1,"risk":"routine"|"critical","says":<one line>,"facts":[[label,value],...],
    "from_to":{<path>:{"from","to"}|...},"model_note":<string, fenced last>} */

import { canonicalJSON } from './canon.js';

const ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const UNESCAPES = { amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'" };

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, ch => ESCAPES[ch]);
}

export function unescapeHtml(escaped) {
  return String(escaped).replace(/&(amp|lt|gt|quot|#39);/g, (_, name) => UNESCAPES[name]);
}

export function validateCard(card) {
  const fail = code => { throw Object.assign(new Error(code), { code }); };
  if (card === null || typeof card !== 'object' || Array.isArray(card)) fail('card:not-object');
  if (card.v !== 1) fail('card:version');
  if (card.risk !== 'routine' && card.risk !== 'critical') fail('card:risk');
  if (typeof card.says !== 'string') fail('card:says');
  if (!Array.isArray(card.facts) || !card.facts.every(
    f => Array.isArray(f) && f.length === 2 && typeof f[0] === 'string')) fail('card:facts');
  if (card.from_to === null || typeof card.from_to !== 'object' || Array.isArray(card.from_to)) fail('card:from_to');
  if (typeof card.model_note !== 'string') fail('card:model_note');
  if ('model_note_label' in card && typeof card.model_note_label !== 'string') fail('card:model_note_label');
  return true;
}

// A string renders as itself; any other JSON value renders as its canonical JSON in a
// distinct element, so a string can never look like a structured value.
function valueHtml(v) {
  if (typeof v === 'string') return `<span class="text">${escapeHtml(v)}</span>`;
  return `<code class="json">${escapeHtml(canonicalJSON(v))}</code>`;
}

const isPair = v => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.values(v).every(x => typeof x === 'string');

const CORE = new Set(['v', 'risk', 'says', 'facts', 'from_to', 'model_note', 'model_note_label']);

function decodedFactHtml(label, value) {
  const limit = new Map([['Contact label (base64 UTF-8)', 128]]).get(label);
  if (!limit || typeof value !== 'string' || value.length > Math.ceil(limit / 3) * 4 ||
      value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) return '';
  try {
    const binary = atob(value);
    if (binary.length > limit || btoa(binary) !== value) return '';
    const decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Uint8Array.from(binary, character => character.charCodeAt(0)));
    return `<div class="decoded-fact"><span>Decoded UTF-8</span><pre>${escapeHtml(decoded)}</pre></div>`;
  } catch { return ''; }
}


/* Renders the card to an HTML string, every field visible: says, then gate facts and
   from->to on top, then any further gate fields (the gate's review, warnings), and the
   model note fenced LAST. Accepts C6 cards and the gate's richer Prime-parity card. */
export function renderCardHtml(card) {
  validateCard(card);
  const parts = [];
  parts.push(`<article class="approval-card" data-risk="${card.risk}" data-v="1">`);
  parts.push(`<p class="says">${escapeHtml(card.says)}</p>`);
  parts.push('<dl class="facts">');
  for (const [label, value] of card.facts) {
    parts.push(`<dt>${escapeHtml(label)}</dt><dd>${valueHtml(value)}${decodedFactHtml(label, value)}</dd>`);
  }
  parts.push('</dl>');
  const entries = Object.entries(card.from_to);
  if (entries.length > 0) {
    parts.push('<div class="fromto">');
    for (const [path, pair] of entries) {
      parts.push(`<div class="path">${escapeHtml(path)}</div>`);
      if (!isPair(pair)) {
        parts.push(`<div class="value">${valueHtml(pair)}</div>`);
        continue;
      }
      for (const [key, v] of Object.entries(pair)) {
        // {"from": "...", "to": "..."} renders as from → to; any other key as a labelled value.
        if (key === 'from' && typeof pair.to === 'string') continue; // handled with "to"
        if (key === 'to' && typeof pair.from === 'string') {
          parts.push(`<div class="pair"><span class="from">${escapeHtml(pair.from)}</span><span class="arrow">→</span><span class="to">${escapeHtml(v)}</span></div>`);
        } else {
          parts.push(`<div class="pair"><span class="from">${escapeHtml(key)}</span><span class="arrow">·</span><span class="to">${escapeHtml(v)}</span></div>`);
        }
      }
    }
    parts.push('</div>');
  }
  const extra = Object.keys(card).filter(key => !CORE.has(key)).sort();
  if (extra.length > 0) {
    parts.push('<dl class="facts gate-extra">');
    for (const key of extra) parts.push(`<dt>${escapeHtml(key)}</dt><dd>${valueHtml(card[key])}</dd>`);
    parts.push('</dl>');
  }
  const label = typeof card.model_note_label === 'string' ? card.model_note_label : 'model note — not verified by the gate';
  parts.push(`<div class="model-fence"><div class="fence-label">${escapeHtml(label)}</div>` +
    `<pre>${escapeHtml(card.model_note)}</pre></div>`);
  parts.push('</article>');
  return parts.join('');
}

/* Browser mount. The Approve button is wired by the approvals screen, not here. */
export function mountCard(target, card) {
  target.innerHTML = renderCardHtml(card);
  return target.firstElementChild;
}
