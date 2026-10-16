// SPDX-License-Identifier: AGPL-3.0-or-later
export const THREAD_NAVIGATION = 'aukora:spatial-navigation:v1';
export type ThreadNavigation =
  | { type: typeof THREAD_NAVIGATION; action: 'ready' | 'new-thread' }
  | { type: typeof THREAD_NAVIGATION; action: 'open-thread'; sessionId: string };

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

export function threadNavigation(value: unknown): ThreadNavigation | null {
  if (!record(value) || value.type !== THREAD_NAVIGATION) return null;
  if ((value.action === 'ready' || value.action === 'new-thread') && exact(value, ['type', 'action'])) {
    return { type: THREAD_NAVIGATION, action: value.action };
  }
  if (value.action === 'open-thread' && exact(value, ['type', 'action', 'sessionId'])
    && typeof value.sessionId === 'string' && /^[0-9a-f]{32}$/.test(value.sessionId)) {
    return { type: THREAD_NAVIGATION, action: value.action, sessionId: value.sessionId };
  }
  throw new Error('app:invalid-message');
}

export function ownerNavigation(value: unknown): '/passkey' | '/phrase' | '/phrase/refresh' | null {
  if (!record(value) || value.protocol !== 'aukora.aumlok-navigation.v1') return null;
  if (!exact(value, ['protocol', 'route'])) throw new Error('app:invalid-message');
  if (value.route === '/passkey' || value.route === '/phrase' || value.route === '/phrase/refresh') return value.route;
  throw new Error('app:invalid-message');
}
