// SPDX-License-Identifier: AGPL-3.0-or-later
export function checkAbort(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  if (typeof signal.throwIfAborted === "function") signal.throwIfAborted();
  throw signal.reason ?? new DOMException("Pane closed", "AbortError");
}

export function abortScope(parent: AbortSignal | undefined, timeoutMs: number): {
  readonly signal: AbortSignal; dispose(): void;
} {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const dispose = (): void => {
    clearTimeout(timer);
    parent?.removeEventListener("abort", abort);
    controller.abort();
  };
  const abort = (): void => {
    controller.abort(parent?.reason);
    dispose();
  };
  if (parent?.aborted) abort();
  else {
    parent?.addEventListener("abort", abort, { once: true });
    timer = setTimeout(() => {
      controller.abort(new DOMException("Request timed out", "TimeoutError"));
      dispose();
    }, timeoutMs);
  }
  return { signal: controller.signal, dispose };
}
