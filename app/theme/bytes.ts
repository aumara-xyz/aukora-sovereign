// SPDX-License-Identifier: AGPL-3.0-or-later
import { exactKeys, objectData } from '../core/data.js';
import type { JsonValue } from '../core/data.js';
import { decodeThemeEffect, MAX_EFFECT_BYTES, THEME_TARGET } from './protocol.js';
import type { Theme } from './protocol.js';

export interface ThemeRead {
  readonly theme: Readonly<Theme>;
  readonly bytes: Uint8Array;
  readonly sha256: string;
}

export function digest(value: unknown): string {
  if (typeof value !== 'string' || value.length !== 64 || !/^[0-9a-f]{64}$/.test(value)) throw new Error('theme:digest-invalid');
  return value;
}

export async function sha256(bytes: Uint8Array): Promise<string> {
  try {
    const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes.slice()));
    return Array.from(hash, byte => byte.toString(16).padStart(2, '0')).join('');
  } catch { throw new Error('theme:digest-unavailable'); }
}

export function base64(bytes: Uint8Array): string {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_EFFECT_BYTES) throw new Error('theme:effect-invalid');
  return btoa(String.fromCharCode(...bytes));
}

function unbase64(value: JsonValue): Uint8Array {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(MAX_EFFECT_BYTES / 3)
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('theme:read-invalid');
  }
  let binary: string;
  try { binary = atob(value); } catch { throw new Error('theme:read-invalid'); }
  const bytes = Uint8Array.from(binary, char => char.charCodeAt(0));
  if (base64(bytes) !== value) throw new Error('theme:read-invalid');
  return bytes;
}

/** Checks the fixed target, complete bytes and digest of a C4 read.reply body. */
export async function decodeThemeRead(reply: JsonValue): Promise<Readonly<ThemeRead>> {
  let fields: { [key: string]: JsonValue };
  try {
    fields = objectData(reply);
    exactKeys(fields, ['target', 'sha256', 'bytes_b64']);
  } catch { throw new Error('theme:read-invalid'); }
  if (fields.target !== THEME_TARGET) throw new Error('theme:target-mismatch');
  const claimed = digest(fields.sha256);
  const bytes = unbase64(fields.bytes_b64);
  const theme = decodeThemeEffect(bytes);
  if (await sha256(bytes) !== claimed) throw new Error('theme:read-digest-mismatch');
  return Object.freeze({ theme, bytes, sha256: claimed });
}
