// SPDX-License-Identifier: AGPL-3.0-or-later
export {};
const CLAIM_OPEN = '{"ok":true,"state":"claim-open"}';
const MAX_REPLY_BYTES = 4096;

async function reply(response: Response, signal: AbortSignal): Promise<string> {
  if (!response.body) throw new Error("frontdoor:body-invalid");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let ended = false;
  try {
    for (;;) {
      if (signal.aborted) throw new DOMException("Claim closed", "AbortError");
      const next = await reader.read();
      if (next.done) { ended = true; break; }
      size += next.value.byteLength;
      if (size > MAX_REPLY_BYTES) throw new Error("frontdoor:body-invalid");
      chunks.push(next.value);
    }
  } finally {
    if (!ended) await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new Error("frontdoor:body-invalid"); }
}

export async function consumeClaim(body: string, signal: AbortSignal): Promise<void> {
  const lifetime = new AbortController();
  const abort = () => lifetime.abort();
  if (signal.aborted) abort();
  signal.addEventListener("abort", abort, { once: true });
  const deadline = setTimeout(abort, 15_000);
  try {
    const response = await fetch("/api/claim", {
      method: "POST", credentials: "same-origin", mode: "same-origin", redirect: "error",
      cache: "no-store", referrerPolicy: "no-referrer", headers: { "Content-Type": "application/json" },
      body, signal: lifetime.signal,
    });
    const media = response.headers.get("Content-Type")?.split(";")[0].trim().toLowerCase();
    if (response.status !== 200 || media !== "application/json") throw new Error("invites:claim-refused");
    if (await reply(response, lifetime.signal) !== CLAIM_OPEN) throw new Error("invites:claim-response");
    if (lifetime.signal.aborted) throw new DOMException("Claim closed", "AbortError");
  } finally {
    clearTimeout(deadline);
    signal.removeEventListener("abort", abort);
  }
}
