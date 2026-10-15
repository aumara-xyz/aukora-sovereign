/* Injective card renderer: the escape must round-trip, and two different cards
   must never render to the same HTML. Run: node --test ui/owner/test/ */

import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, unescapeHtml, renderCardHtml, validateCard } from '../card.js';

const NASTY = [
  'plain text',
  '&lt;already escaped&gt;',
  '</pre><script>alert(1)</script>',
  '"quotes" and \'apostrophes\'',
  'ampersand &amp; & &lt; &#39;',
  'new\nlines\r\nand\ttabs',
  'unicode: héllo — “em” \u2028line-separator\u2029 \u007f',
  'emoji 🔐 and combining e\u0301',
  '<img src=x onerror=alert(2)>',
  '   leading and trailing   ',
  'a'.repeat(500),
  '',
];

test('escape round-trips: unescape(escape(s)) === s for every character', () => {
  for (const s of NASTY) assert.equal(unescapeHtml(escapeHtml(s)), s);
});

test('escape is injective over the corpus', () => {
  const seen = new Map();
  for (const s of NASTY) {
    const e = escapeHtml(s);
    assert.ok(!seen.has(e), `collision: ${JSON.stringify(s)} vs ${JSON.stringify(seen.get(e))}`);
    seen.set(e, s);
  }
});

test('no raw markup survives: rendered HTML never contains an unescaped field', () => {
  for (const s of NASTY) {
    if (!/[<>&"']/.test(s)) continue;
    const html = renderCardHtml(card({ says: s }));
    assert.ok(!html.includes(s), `raw field leaked into HTML: ${JSON.stringify(s)}`);
    assert.ok(html.includes(escapeHtml(s)));
  }
});

function card(overrides = {}) {
  return {
    v: 1,
    risk: 'routine',
    says: 'one line',
    facts: [['target', 'workspace/a.txt'], ['base', 'present']],
    from_to: { 'workspace/a.txt': { from: 'old', to: 'new' } },
    model_note: 'model words',
    ...overrides,
  };
}

test('two cards differing by one character never look the same', () => {
  const base = card();
  const variants = [
    card({ says: 'one linf' }),
    card({ says: 'one line ' }),
    card({ facts: [['target', 'workspace/a.txt'], ['base', 'absent']] }),
    card({ facts: [['target', 'workspace/a.txt '], ['base', 'present']] }),
    card({ from_to: { 'workspace/a.txt': { from: 'old', to: 'new ' } } }),
    card({ from_to: { 'workspace/b.txt': { from: 'old', to: 'new' } } }),
    card({ model_note: 'model words.' }),
    card({ model_note: 'model words\n' }),
    card({ risk: 'critical' }),
  ];
  const rendered = new Set([renderCardHtml(base)]);
  for (const v of variants) {
    const html = renderCardHtml(v);
    assert.ok(!rendered.has(html), 'different cards rendered identically');
    rendered.add(html);
  }
});

test('rendered fields round-trip out of the HTML', () => {
  const c = card({
    says: NASTY[2],
    facts: [[NASTY[3], NASTY[5]]],
    from_to: { 'weird<&>path': { from: NASTY[8], to: NASTY[6] } },
    model_note: NASTY[7],
  });
  const html = renderCardHtml(c);
  const text = unescapeHtml(html.replace(/<[^>]+>/g, '')); // strip tags, unescape
  for (const s of [c.says, ...c.facts.flat(), 'weird<&>path', NASTY[8], NASTY[6], c.model_note]) {
    assert.ok(text.includes(s), `field not visible verbatim: ${JSON.stringify(s)}`);
  }
});

test('model note is fenced and rendered last', () => {
  const c = card();
  const html = renderCardHtml(c);
  const fence = html.indexOf('model-fence');
  assert.ok(fence > html.indexOf('facts'), 'fence must come after facts');
  assert.ok(fence > html.indexOf('fromto'), 'fence must come after from_to');
  assert.ok(html.indexOf('</article>') > fence, 'fence must be the last block');
});

test('risk maps to the outline class', () => {
  assert.match(renderCardHtml(card({ risk: 'routine' })), /data-risk="routine"/);
  assert.match(renderCardHtml(card({ risk: 'critical' })), /data-risk="critical"/);
});

test('validateCard refuses malformed cards', () => {
  assert.throws(() => validateCard(null), /card:not-object/);
  assert.throws(() => validateCard(card({ v: 2 })), /card:version/);
  assert.throws(() => validateCard(card({ risk: 'high' })), /card:risk/);
  assert.throws(() => validateCard(card({ facts: [['only-label']] })), /card:facts/);
  assert.throws(() => validateCard(card({ model_note: 42 })), /card:model_note/);
});

test('the gate card (Prime parity shape) renders every field, and a string never looks like JSON', () => {
  const gateCard = {
    v: 1, risk: 'critical', says: 'Start the agent runtime',
    facts: [['target', 'release'], ['base_sha256', 'absent'], ['count', 3]],
    from_to: { encoding: 'utf-8', base: null, new: '{"v":1}', diff: [{ op: 'add', line: '{"v":1}' }], summary: null },
    target_review: { pinned: { prices: {} } }, warnings: [],
    model_note_label: 'UNVERIFIED MODEL NOTE; DATA ONLY', model_note: '', model_note_meta: {},
  };
  const html = renderCardHtml(gateCard);
  for (const fragment of ['Start the agent runtime', 'target_review', 'warnings', 'UNVERIFIED MODEL NOTE; DATA ONLY', 'utf-8', 'model_note_meta']) {
    assert.ok(html.includes(fragment), fragment);
  }
  const asString = renderCardHtml({ ...gateCard, facts: [['x', 'null']] });
  const asJson = renderCardHtml({ ...gateCard, facts: [['x', null]] });
  assert.notEqual(asString, asJson);
});

// Antibody, review issue 1.2: the gate's real cards (fixtures written by the gate test
// antibody_owner_card_fixtures_are_the_gates_real_cards) are one character apart. Every
// from_to field must reach the owner, and the two cards must never render alike.
test('antibody: real gate cards show base, new, diff and summary, and differ when the change differs', async () => {
  const { readFileSync } = await import('node:fs');
  const load = name => JSON.parse(readFileSync(new URL(`./fixtures/gate-card-${name}.json`, import.meta.url), 'utf8'));
  const [a, b] = [load('a'), load('b')];
  const [htmlA, htmlB] = [renderCardHtml(a), renderCardHtml(b)];
  assert.notEqual(htmlA, htmlB);
  for (const [card, html] of [[a, htmlA], [b, htmlB]]) {
    for (const key of Object.keys(card.from_to)) assert.ok(html.includes(`<div class="path">${escapeHtml(key)}</div>`), key);
    for (const key of ['base', 'new', 'diff']) assert.ok(html.includes(escapeHtml(card.from_to[key])), key);
  }
  assert.ok(htmlB.includes(escapeHtml('+Pick the mint!')));
});
