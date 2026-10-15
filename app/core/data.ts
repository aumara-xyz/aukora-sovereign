// SPDX-License-Identifier: AGPL-3.0-or-later

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export const MAX_RPC_BYTES = 65_536;
const encoder = new TextEncoder();

function string(value: string): string {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) throw new Error('app:invalid-data');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('app:invalid-data');
  }
  return JSON.stringify(value);
}

export function encodeData(value: unknown): string {
  const seen = new Set<object>();
  let budget = MAX_RPC_BYTES;
  const visit = (item: unknown, depth: number): string => {
    if (depth > 64 || --budget < 0) throw new Error('app:data-limit');
    if (item === null) return 'null';
    if (typeof item === 'boolean') return String(item);
    if (typeof item === 'number') {
      if (!Number.isSafeInteger(item) || Object.is(item, -0)) throw new Error('app:invalid-data');
      return String(item);
    }
    if (typeof item === 'string') {
      budget -= item.length;
      if (budget < 0) throw new Error('app:data-limit');
      return string(item);
    }
    if (typeof item !== 'object' || !item || seen.has(item)) throw new Error('app:invalid-data');
    seen.add(item);
    let output: string;
    if (Array.isArray(item)) {
      if (item.length > MAX_RPC_BYTES) throw new Error('app:data-limit');
      output = '[' + Array.from(item, entry => visit(entry, depth + 1)).join(',') + ']';
    } else {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) throw new Error('app:invalid-data');
      const descriptors = Object.getOwnPropertyDescriptors(item);
      output = '{' + Object.keys(descriptors).sort().map(key => {
        const property = descriptors[key];
        if (!property.enumerable || !('value' in property)) throw new Error('app:invalid-data');
        budget -= key.length;
        return string(key) + ':' + visit(property.value, depth + 1);
      }).join(',') + '}';
    }
    seen.delete(item);
    return output;
  };
  const output = visit(value, 0);
  if (encoder.encode(output).byteLength > MAX_RPC_BYTES) throw new Error('app:data-limit');
  return output;
}

export function decodeData(value: unknown): JsonValue {
  if (typeof value !== 'string' || value.length > MAX_RPC_BYTES) throw new Error('app:data-limit');
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error('app:invalid-data'); }
  if (encodeData(parsed) !== value) throw new Error('app:invalid-data');
  return parsed as JsonValue;
}

export function objectData(value: JsonValue): { [key: string]: JsonValue } {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('app:invalid-message');
  return value;
}

export function exactKeys(value: { [key: string]: JsonValue }, keys: readonly string[]): void {
  if (Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) throw new Error('app:invalid-message');
}
