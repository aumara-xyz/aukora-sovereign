/* Acrostic phrase layout (the new construction, SPEC §5 / CARRY-LIST Aumlok).
   Word 1 is a six-letter anchor, laid ACROSS in gold boxes. Words 2–7 are laid
   DOWN from each anchor letter, grouped ROOT (green, nature) / UNITE (blue,
   people and connection) / RISE (violet, spirit, space, technology). */

export const BANDS = [
  { id: 'root', tone: 'green', positions: [2, 3] },
  { id: 'unite', tone: 'blue', positions: [4, 5] },
  { id: 'rise', tone: 'violet', positions: [6, 7] },
];

export const ANCHOR_LETTERS = 6;
export const PHRASE_WORDS = 7;

export function bandOf(position) {
  for (const band of BANDS) if (band.positions.includes(position)) return band;
  return null;
}

const fail = code => { throw Object.assign(new Error(code), { code }); };

/* words: array of exactly 7 strings (positions 1..7).
   Returns {
     anchor: { word, letters: [6 upper-case letters] },
     columns: [{ letter, position (2..7), word, band: 'root'|'unite'|'rise' } × 6]
   } — column i sits under anchor letter i and holds word i+2. */
export function layoutPhrase(words) {
  if (!Array.isArray(words) || words.length !== PHRASE_WORDS) fail('phrase:word-count');
  if (!words.every(w => typeof w === 'string' && w.length > 0)) fail('phrase:empty-word');
  const anchor = words[0];
  const letters = [...anchor];
  if (letters.length !== ANCHOR_LETTERS) fail('phrase:anchor-length');
  const columns = letters.map((letter, i) => {
    const position = i + 2; // words 2..7
    const word = words[i + 1];
    if (word[0].toLowerCase() !== letter.toLowerCase()) {
      throw Object.assign(new Error('phrase:acrostic-broken'), { code: 'phrase:acrostic-broken', position });
    }
    return { letter: letter.toUpperCase(), position, word, band: bandOf(position).id };
  });
  return { anchor: { word: anchor, letters: letters.map(l => l.toUpperCase()) }, columns };
}

/* Type-back check: exact match, case-insensitive, trimmed. Returns the first
   mismatching position (1..7) or 0 when all match. */
export function firstMismatch(expected, typed) {
  if (!Array.isArray(typed) || typed.length !== PHRASE_WORDS) return -1;
  for (let i = 0; i < PHRASE_WORDS; i++) {
    if ((typed[i] ?? '').trim().toLowerCase() !== expected[i].toLowerCase()) return i + 1;
  }
  return 0;
}
