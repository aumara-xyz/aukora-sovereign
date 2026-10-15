// SPDX-License-Identifier: AGPL-3.0-or-later

export const THEME_TARGET = 'theme';
export const THEME_ADAPTER_VERSION = 1;
export const THEME_KEY = 'theme:v1';
export const CELL_MODULE_SHA256 = '34ce6cab618b626243e876befb49ccf8a6780dc836e757484886b34ae977a438';
export const CELL_INPUT_BUDGET = 65_536;
export const MAX_EFFECT_BYTES = 48;
export interface Theme { readonly accent: string }

/** The accepted value grammar admits no CSS syntax beyond a single colour. */
export function themeValue(accent: unknown): Readonly<Theme> {
  if (typeof accent !== 'string' || accent.length !== 7 || !/^(?:default|#[0-9A-Fa-f]{6})$/.test(accent)) {
    throw new Error('theme:accent-invalid');
  }
  return Object.freeze({ accent: accent === 'default' ? accent : accent.toUpperCase() });
}

export function canonicalTheme(accent: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(themeValue(accent)));
}

export function cellInput(accent: unknown): Uint8Array {
  const value = canonicalTheme(accent);
  if (new TextEncoder().encode(THEME_KEY).length + value.length > CELL_INPUT_BUDGET) {
    throw new Error('theme:budget-exceeded');
  }
  return new TextEncoder().encode(`{"key":"${THEME_KEY}","value":${new TextDecoder().decode(value)}}`);
}

export function decodeThemeEffect(bytes: Uint8Array): Readonly<Theme> {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_EFFECT_BYTES) throw new Error('theme:effect-invalid');
  let text: string;
  try { text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch { throw new Error('theme:effect-invalid'); }
  const match = /^\{"key":"theme:v1","value":\{"accent":"(default|#[0-9A-F]{6})"\}\}\n$/.exec(text);
  if (!match || match[0] !== text) throw new Error('theme:effect-invalid');
  return themeValue(match[1]);
}
