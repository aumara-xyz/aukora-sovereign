// SPDX-License-Identifier: AGPL-3.0-or-later
// Acceptance input parsing; this is not a product wire codec.
export function strictJSON(bytes) {
  const invalid = () => { throw new Error('acceptance:json-invalid'); };
  let source;
  try { source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { invalid(); }
  if (source.charCodeAt(0) === 0xfeff) invalid();
  let at = 0;
  const space = () => { while (/[\t\r\n ]/.test(source[at] ?? '\0')) at++; };
  function string() {
    const start = at++;
    if (source[start] !== '"') invalid();
    let escaped = false;
    while (at < source.length) {
      const ch = source[at++];
      if (!escaped && ch === '"') {
        let value;
        try { value = JSON.parse(source.slice(start, at)); } catch { invalid(); }
        if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) invalid();
        return value;
      }
      if (!escaped && ch === '\\') escaped = true;
      else escaped = false;
    }
    invalid();
  }
  function value(depth) {
    if (depth > 64) invalid();
    space();
    if (source[at] === '"') return string();
    if (source[at] === '{') {
      at++; space();
      const object = Object.create(null), seen = new Set();
      if (source[at] === '}') { at++; return object; }
      while (at < source.length) {
        space();
        const key = string();
        if (seen.has(key)) invalid();
        seen.add(key); space();
        if (source[at++] !== ':') invalid();
        object[key] = value(depth + 1); space();
        const delimiter = source[at++];
        if (delimiter === '}') return object;
        if (delimiter !== ',') invalid();
      }
      invalid();
    }
    if (source[at] === '[') {
      at++; space();
      const array = [];
      if (source[at] === ']') { at++; return array; }
      while (at < source.length) {
        array.push(value(depth + 1)); space();
        const delimiter = source[at++];
        if (delimiter === ']') return array;
        if (delimiter !== ',') invalid();
      }
      invalid();
    }
    for (const [literal, parsed] of [['true', true], ['false', false], ['null', null]]) {
      if (source.startsWith(literal, at)) { at += literal.length; return parsed; }
    }
    const token = source.slice(at).match(/^-?(?:0|[1-9][0-9]*)/)?.[0];
    if (!token || token === '-0' || !Number.isSafeInteger(Number(token))) invalid();
    at += token.length;
    return Number(token);
  }
  const parsed = value(0);
  space();
  if (at !== source.length) invalid();
  return parsed;
}
