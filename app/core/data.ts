// SPDX-License-Identifier: AGPL-3.0-or-later

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };
export const MAX_RPC_BYTES = 65_536;
const encoder = new TextEncoder();
const MAX_DEPTH = 64;

function quote(text: string): string {
  for (let index = 0; index < text.length; index++) {
    const unit = text.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const low = text.charCodeAt(++index);
      if (!(low >= 0xdc00 && low <= 0xdfff)) throw new Error('app:invalid-data');
    } else if (unit >= 0xdc00 && unit <= 0xdfff) throw new Error('app:invalid-data');
  }
  return JSON.stringify(text);
}

export function encodeData(value: unknown): string {
  const parts: string[] = [];
  const ancestors = new Set<object>();
  let remaining = MAX_RPC_BYTES;
  const append = (token: string) => {
    remaining -= encoder.encode(token).byteLength;
    if (remaining < 0) throw new Error('app:data-limit');
    parts.push(token);
  };
  const appendString = (text: string) => {
    if (text.length > remaining) throw new Error('app:data-limit');
    append(quote(text));
  };
  const visit = (item: unknown, depth: number): void => {
    if (remaining === 0) throw new Error('app:data-limit');
    if (item === null) { append('null'); return; }
    switch (typeof item) {
      case 'boolean': append(item ? 'true' : 'false'); return;
      case 'number':
        if (!Number.isSafeInteger(item) || Object.is(item, -0)) throw new Error('app:invalid-data');
        append(String(item));
        return;
      case 'string': appendString(item); return;
      case 'object': break;
      default: throw new Error('app:invalid-data');
    }
    if (depth >= MAX_DEPTH) throw new Error('app:data-limit');
    if (ancestors.has(item)) throw new Error('app:invalid-data');
    ancestors.add(item);
    const keys = Reflect.ownKeys(item);
    if (keys.length > MAX_RPC_BYTES || keys.some(key => typeof key !== 'string')) throw new Error('app:invalid-data');
    const properties = Object.getOwnPropertyDescriptors(item);
    if (Array.isArray(item)) {
      const length = properties.length?.value;
      if (!Number.isSafeInteger(length) || length < 0 || length > MAX_RPC_BYTES || keys.length !== length + 1) {
        throw new Error('app:invalid-data');
      }
      append('[');
      for (let index = 0; index < length; index++) {
        const property = properties[String(index)];
        if (!property || !property.enumerable || !('value' in property)) throw new Error('app:invalid-data');
        if (index) append(',');
        visit(property.value, depth + 1);
      }
      append(']');
    } else {
      const prototype = Object.getPrototypeOf(item);
      if (prototype !== Object.prototype && prototype !== null) throw new Error('app:invalid-data');
      append('{');
      let first = true;
      for (const key of (keys as string[]).sort()) {
        const property = properties[key];
        if (!property.enumerable || !('value' in property)) throw new Error('app:invalid-data');
        if (!first) append(',');
        first = false;
        appendString(key);
        append(':');
        visit(property.value, depth + 1);
      }
      append('}');
    }
    ancestors.delete(item);
  };
  visit(value, 0);
  return parts.join('');
}

export function decodeData(value: unknown): JsonValue {
  if (typeof value !== 'string') throw new Error('app:invalid-data');
  if (!value.length || value.length > MAX_RPC_BYTES || encoder.encode(value).byteLength > MAX_RPC_BYTES) {
    throw new Error('app:data-limit');
  }
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error('app:invalid-data'); }
  if (encodeData(parsed) !== value) throw new Error('app:invalid-data');
  return parsed as JsonValue;
}

export function objectData(value: JsonValue): { [key: string]: JsonValue } {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('app:invalid-message');
  return value;
}

export function exactKeys(value: { [key: string]: JsonValue }, keys: readonly string[]): void {
  const actual = Object.keys(value);
  if (actual.length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) throw new Error('app:invalid-message');
}
