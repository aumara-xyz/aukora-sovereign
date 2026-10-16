// SPDX-License-Identifier: AGPL-3.0-or-later

export interface ServiceState {
  readonly kind: 'unavailable' | 'session-ended' | 'failure';
  readonly icon: string;
  readonly label: string;
  readonly retryable?: boolean;
}

const CODE = /^[a-z][a-z0-9_-]{0,31}:[a-z0-9-]{1,64}$/;
const ENDED = new Set([
  'frontdoor:session-required',
]);
const NO_MODEL = new Set([
  'broker:model-unavailable', 'broker:model-not-configured', 'broker:streaming-unavailable',
  'supervisor:model-unavailable',
]);
const NOT_YET = new Set([
  'supervisor:not-ready', 'supervisor:sessions-missing',
  'broker:not-configured', 'app:disconnected', 'app:reconnected',
  'app:transport-failed', 'app:service-failed', 'app:deadline',
]);
const RETRYABLE: ReadonlyMap<string, string> = new Map([
  ['frontdoor:overloaded', 'Busy. Try again shortly.'],
  ['supervisor:read-rate-limited', 'Busy. Try again shortly.'],
  ['broker:busy', 'Busy. Try again shortly.'],
  ['broker:provider-no-credit', 'Add credit with your model provider, then try again.'],
  ['broker:grant-expired', 'A new spend grant needs your passkey approval. Try again after it is approved.'],
]);

/** Read subscriptions send a sole code field when their service read refuses. */
export function throwServiceRefusal(value: unknown): void {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return;
  const row = value as Record<string, unknown>;
  if (Object.keys(row).length === 1 && typeof row.code === 'string' && CODE.test(row.code)) {
    throw new Error(row.code);
  }
}

/** Display only: a refusal is never converted to a successful service reply. */
export function serviceState(error: unknown): ServiceState {
  const code = error instanceof Error ? error.message : typeof error === 'string' ? error : '';
  if (ENDED.has(code)) return { kind: 'session-ended', icon: '↪', label: 'Sign in again' };
  if (NO_MODEL.has(code)) return { kind: 'unavailable', icon: '◌', label: 'No model yet' };
  const retry = RETRYABLE.get(code);
  if (retry !== undefined) return { kind: 'unavailable', icon: '◌', label: retry, retryable: true };
  if (CODE.test(code) && (NOT_YET.has(code) || code.endsWith('-unavailable') || code.endsWith(':unavailable'))) {
    return { kind: 'unavailable', icon: '◌', label: 'Not yet' };
  }
  return { kind: 'failure', icon: '◇', label: 'Request refused' };
}

export function serviceMessage(error: unknown): string {
  const state = serviceState(error);
  return `${state.icon} ${state.label}`;
}

export function showServiceState(target: HTMLElement, error: unknown): void {
  const state = serviceState(error);
  target.dataset.serviceState = state.kind;
  target.setAttribute('role', state.kind === 'failure' ? 'alert' : 'status');
  target.textContent = `${state.icon} ${state.label}`;
}

export function clearServiceState(target: HTMLElement): void {
  delete target.dataset.serviceState;
  target.setAttribute('role', 'status');
}
