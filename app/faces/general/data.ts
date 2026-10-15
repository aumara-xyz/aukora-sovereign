// SPDX-License-Identifier: AGPL-3.0-or-later
// Strict readers for the replies the System settings faces print. A reply is accepted only in exactly the shape its
// contract.json states: every key present and none extra, each value of the stated type and inside its bounds. Anything
// else throws the face's own refusal code, and the face then prints nothing from that reply. Numbers are whole numbers
// the page can hold exactly, text is kept as text, and nothing read here is ever treated as markup or as an instruction.
import type { JsonValue } from "../../core/index.js";

export type Row = { readonly [key: string]: JsonValue };

// Control characters, line and paragraph separators, and the characters that reorder or hide text.
const UNREADABLE = /[\u{0}-\u{1f}\u{7f}-\u{9f}\u{61c}\u{200b}-\u{200f}\u{2028}-\u{202e}\u{2060}-\u{2069}\u{feff}]/u;
const ENCODER = new TextEncoder();

export interface Reader {
  /** Throws this reader's refusal code. */
  fail(): never;
  /** A plain object with exactly these keys. */
  object(value: JsonValue | undefined, keys: readonly string[]): Row;
  /** An array of at most `max` items. */
  list(value: JsonValue | undefined, max: number): readonly JsonValue[];
  /** Readable text of 1 to `max` characters with no leading or trailing space, optionally matching `pattern`. */
  text(value: JsonValue | undefined, max: number, pattern?: RegExp): string;
  /** Text of at most `maxBytes` UTF-8 bytes, empty allowed, line breaks allowed; meant to be printed as text only. */
  literal(value: JsonValue | undefined, maxBytes: number): string;
  /** A model name as the broker accepts one: printable ASCII with no space, 1 to 256 characters, nothing key-shaped. */
  model(value: JsonValue | undefined): string;
  /** Readable text, as `text`, that has nothing in it shaped like a provider key. */
  keyless(value: JsonValue | undefined, max: number): string;
  /** A whole number from 0 to `max`, which cannot exceed the largest number the page holds exactly. */
  whole(value: JsonValue | undefined, max?: number): number;
  flag(value: JsonValue | undefined): boolean;
  /** Sixty-four lowercase hexadecimal digits. */
  digest(value: JsonValue | undefined): string;
  choice<T extends string>(value: JsonValue | undefined, allowed: readonly T[]): T;
  /** Null, or whatever `read` accepts. */
  nullable<T>(value: JsonValue | undefined, read: (item: JsonValue) => T): T | null;
}

/** Readers that all throw `code`, which has the shape `<face>:<reason>` so the face can print it. */
export function reader(code: string): Reader {
  const fail = (): never => { throw new Error(code); };
  const text = (value: JsonValue | undefined, max: number, pattern?: RegExp): string => {
    if (typeof value !== "string" || value.length === 0 || [...value].length > max) return fail();
    if (UNREADABLE.test(value) || value.trim() !== value || (pattern !== undefined && !pattern.test(value))) return fail();
    return value;
  };
  // The provider key has no place in any reply; text shaped like one is refused rather than shown.
  const keyless = (value: JsonValue | undefined, max: number, pattern?: RegExp): string => {
    const checked = text(value, max, pattern);
    return checked.includes("sk-") ? fail() : checked;
  };
  return {
    fail,
    text,
    keyless: (value, max) => keyless(value, max),
    model: value => keyless(value, 256, /^[\x21-\x7e]+$/),
    object(value, keys) {
      if (value === null || value === undefined || typeof value !== "object" || Array.isArray(value)) return fail();
      const present = Object.keys(value).sort();
      const wanted = [...keys].sort();
      if (present.length !== wanted.length || present.some((key, at) => key !== wanted[at])) return fail();
      return value;
    },
    list(value, max) {
      if (!Array.isArray(value) || value.length > max) return fail();
      return value;
    },
    literal(value, maxBytes) {
      if (typeof value !== "string" || ENCODER.encode(value).length > maxBytes) return fail();
      return value;
    },
    whole(value, max = Number.MAX_SAFE_INTEGER) {
      if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > max) return fail();
      return value;
    },
    flag(value) {
      if (typeof value !== "boolean") return fail();
      return value;
    },
    digest(value) {
      if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) return fail();
      return value;
    },
    choice<T extends string>(value: JsonValue | undefined, allowed: readonly T[]): T {
      if (typeof value !== "string" || !allowed.includes(value as T)) return fail();
      return value as T;
    },
    nullable<T>(value: JsonValue | undefined, read: (item: JsonValue) => T): T | null {
      if (value === undefined) return fail();
      return value === null ? null : read(value);
    },
  };
}

/** True for text with a control, reordering or hidden character in it. */
export function unreadable(text: string): boolean {
  return UNREADABLE.test(text);
}
