// SPDX-License-Identifier: AGPL-3.0-or-later

/** The node has no bound shell session for this browser: the owner signs in. */
export const SESSION_REFUSALS: ReadonlySet<string> = new Set([
  'frontdoor:session-required', 'frontdoor:session-expired', 'frontdoor:session-revoked',
  'frontdoor:cookie-host-refused', 'aumlok:binding-required',
]);

/** Shared by the approval response validator and the shell's connection notice. */
export function isEngineRefusal(code: unknown): code is string {
  return typeof code === 'string' && /^supervisor:(?:authority-[a-z0-9-]+|profile-plugin-disabled)$/.test(code);
}

export function signoutFailure(signedIn: boolean | null): string {
  return signedIn === false
    ? 'Signed out. Owner cookie cleanup did not finish. Sign in to continue.'
    : 'Sign out did not finish. Try again.';
}
