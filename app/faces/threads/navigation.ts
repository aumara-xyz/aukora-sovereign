// SPDX-License-Identifier: AGPL-3.0-or-later
const TYPE = "aukora:spatial-navigation:v1";
export type Navigation = { type: typeof TYPE; action: "new-thread" } | { type: typeof TYPE; action: "open-thread"; sessionId: string };

function origin(): string {
  if (window.parent === window || !document.referrer) throw new Error("app:shell-required");
  const value = new URL(document.referrer).origin;
  if (value === "null") throw new Error("app:shell-required");
  return value;
}

export function navigateThread(sessionId?: string): void {
  if (sessionId !== undefined && !/^[0-9a-f]{32}$/.test(sessionId)) throw new Error("app:invalid-message");
  const message: Navigation = sessionId === undefined ? { type: TYPE, action: "new-thread" } : { type: TYPE, action: "open-thread", sessionId };
  window.parent.postMessage(message, origin());
}

export function receiveNavigation(signal: AbortSignal, receive: (message: Navigation) => void, refuse: (code: string) => void): void {
  const shell = origin();
  window.addEventListener("message", event => {
    if (event.source !== window.parent || event.origin !== shell) return;
    const data: unknown = event.data;
    if (typeof data !== "object" || data === null || !("type" in data) || data.type !== TYPE) return;
    for (const port of event.ports) port.close();
    if (event.ports.length || Array.isArray(data) || !("action" in data)) { refuse("app:invalid-message"); return; }
    const keys = Object.keys(data).sort().join(",");
    if (data.action === "new-thread" && keys === "action,type") receive({ type: TYPE, action: "new-thread" });
    else if (data.action === "open-thread" && keys === "action,sessionId,type" && "sessionId" in data && typeof data.sessionId === "string" && /^[0-9a-f]{32}$/.test(data.sessionId)) receive({ type: TYPE, action: "open-thread", sessionId: data.sessionId });
    else refuse("app:invalid-message");
  }, { signal });
  window.parent.postMessage({ type: TYPE, action: "ready" }, shell);
}
