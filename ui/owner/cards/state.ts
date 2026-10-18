// SPDX-License-Identifier: AGPL-3.0-or-later

/** Only supervisor-owned engine and release requests can be raised again through this pane. */
export function retryTarget(target: string): boolean {
  return target === "release" || target.startsWith("engine/");
}

/** A generic not-pending response also covers an approval completed in another tab. */
export function closedState(error: unknown): { message: string; again: boolean } | null {
  const code = error instanceof Error ? error.message : "";
  if (code === "gate:declined-retryable") return { message: "You declined this request.", again: true };
  if (code === "gate:expired-retryable") return { message: "This request ran out of time.", again: true };
  if (/:(?:not-pending|expired|declined-unchanged)$/.test(code)) {
    return { message: "This request is no longer available. Its state may have changed elsewhere.", again: false };
  }
  return null;
}
