// SPDX-License-Identifier: AGPL-3.0-or-later
import { ALLOCATE_PATH, AllocationRefusal, HANDOFF_SCHEMA, INVITE_SECONDS, decodeRequest,
  encodeHandoff, hex, readBody, refuse, sha256, shellOrigin, token, tokenBytes } from "./contracts.js";

export interface InviteAdmission {
  readonly allocationId: string;
  readonly inviteId: string;
  readonly codeId: string;
  readonly inviteFormat: "legacy-v1" | "conserved-v1";
  readonly signedInvite: Uint8Array;
  readonly signedBinding: Uint8Array | null;
  readonly claimBindingId: string | null;
  readonly handoverCommitment: string;
  readonly issuedAtSeconds: number;
  readonly expiresAtSeconds: number;
}

export interface NodeReadback {
  readonly allocationId: string;
  readonly inviteId: string;
  readonly claimBindingId: string | null;
  readonly handoverCommitment: string;
  readonly claimCommitment: string;
  readonly shellOrigin: string;
  readonly claimConsumed: boolean;
  readonly releasePointerVerified: boolean;
}

export interface Allocator {
  reserveVerifiedInvite(candidate: {
    readonly codeId: string;
    readonly requestKeyDigest: string;
    readonly nowSeconds: number;
  }, signal: AbortSignal): Promise<InviteAdmission>;
  provisionReserved(admission: InviteAdmission, signal: AbortSignal): Promise<void>;
  readback(admission: InviteAdmission, signal: AbortSignal): Promise<NodeReadback>;
  handoffForRequest(admission: InviteAdmission, requestKeyDigest: string, signal: AbortSignal): Promise<string>;
}

export interface ServiceOptions {
  readonly origin: string;
  readonly allowedShellOrigins: readonly string[];
  readonly allocator: Allocator;
  readonly nowSeconds: () => number;
}

const RESPONSE_HEADERS = {
  "cache-control": "no-store",
  "content-type": "application/json",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
};

function validTime(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0;
}

function checkAdmission(admission: InviteAdmission, code: string, now: number): void {
  if (!hex(admission.allocationId, 32) || !hex(admission.inviteId, 64) || admission.codeId !== code ||
      !hex(admission.handoverCommitment, 64) || !(admission.signedInvite instanceof Uint8Array) ||
      admission.signedInvite.length < 1 || admission.signedInvite.length > 16384 ||
      !validTime(admission.issuedAtSeconds) ||
      !validTime(admission.expiresAtSeconds) ||
      admission.expiresAtSeconds - admission.issuedAtSeconds !== INVITE_SECONDS ||
      now < admission.issuedAtSeconds || now >= admission.expiresAtSeconds) refuse("invite-invalid");
  if (admission.inviteFormat === "legacy-v1") {
    if (admission.signedBinding !== null || admission.claimBindingId !== null) refuse("invite-invalid");
  } else if (admission.inviteFormat === "conserved-v1") {
    if (!(admission.signedBinding instanceof Uint8Array) || admission.signedBinding.length < 1 ||
        admission.signedBinding.length > 16384 || !hex(admission.claimBindingId, 64)) refuse("invite-invalid");
  } else refuse("invite-invalid");
}

async function active<T>(signal: AbortSignal, operation: () => Promise<T>): Promise<T> {
  if (signal.aborted) refuse("cancelled");
  let onAbort: (() => void) | undefined;
  const cancelled = new Promise<never>((_resolve, reject) => {
    onAbort = () => reject(new AllocationRefusal("go-sovereign:cancelled"));
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try { return await Promise.race([operation(), cancelled]); }
  finally { if (onAbort) signal.removeEventListener("abort", onAbort); }
}

export function createAllocationHandler(options: ServiceOptions): (request: Request) => Promise<Response> {
  const origin = shellOrigin(options.origin);
  const shells = new Set(options.allowedShellOrigins.map(shellOrigin));
  if (shells.size === 0 || shells.has(origin)) refuse("configuration-invalid");
  return async request => {
    const controller = new AbortController();
    const cancel = (): void => controller.abort();
    request.signal.addEventListener("abort", cancel, { once: true });
    if (request.signal.aborted) controller.abort();
    const timer = setTimeout(cancel, 180000);
    const signal = controller.signal;
    try {
      const url = new URL(request.url);
      if (url.origin !== origin || url.pathname !== ALLOCATE_PATH || url.search || url.hash ||
          request.method !== "POST") refuse("unknown-route");
      if (request.headers.get("origin") !== origin || request.headers.get("sec-fetch-site") !== "same-origin" ||
          request.headers.get("sec-fetch-mode") !== "same-origin" ||
          request.headers.get("sec-fetch-dest") !== "empty") refuse("origin-refused");
      if (request.headers.get("content-type") !== "application/json" ||
          request.headers.has("content-encoding") || request.headers.has("authorization")) refuse("body-invalid");
      const candidate = decodeRequest(await readBody(request.body, signal));
      const requestKeyDigest = await sha256(tokenBytes(candidate.request_key));
      const now = options.nowSeconds();
      if (!validTime(now)) refuse("clock-invalid");
      const admission = await active(signal, () => options.allocator.reserveVerifiedInvite({ codeId: candidate.code,
        requestKeyDigest, nowSeconds: now }, signal));
      const reservedAt = options.nowSeconds();
      if (!validTime(reservedAt) || reservedAt < now) refuse("clock-invalid");
      checkAdmission(admission, candidate.code, reservedAt);
      await active(signal, () => options.allocator.provisionReserved(admission, signal));
      const observed = await active(signal, () => options.allocator.readback(admission, signal));
      if (observed.allocationId !== admission.allocationId || observed.inviteId !== admission.inviteId ||
          observed.claimBindingId !== admission.claimBindingId ||
          observed.handoverCommitment !== admission.handoverCommitment || !hex(observed.claimCommitment, 64) ||
          observed.claimConsumed !== false || observed.releasePointerVerified !== true ||
          !shells.has(shellOrigin(observed.shellOrigin))) refuse("readback-mismatch");
      const freshNow = options.nowSeconds();
      if (!validTime(freshNow) || freshNow < reservedAt) refuse("clock-invalid");
      checkAdmission(admission, candidate.code, freshNow);
      const claim = await active(signal, () => options.allocator.handoffForRequest(admission, requestKeyDigest, signal));
      if (!token(claim) || await sha256(tokenBytes(claim)) !== observed.claimCommitment) refuse("claim-mismatch");
      if (signal.aborted) refuse("cancelled");
      const finalNow = options.nowSeconds();
      if (!validTime(finalNow) || finalNow < freshNow) refuse("clock-invalid");
      checkAdmission(admission, candidate.code, finalNow);
      return new Response(encodeHandoff({ claim_token: claim, schema: HANDOFF_SCHEMA,
        shell_origin: observed.shellOrigin }), { status: 200, headers: RESPONSE_HEADERS });
    } catch (error) {
      const code = error instanceof AllocationRefusal ? error.code : "go-sovereign:allocation-unavailable";
      return new Response(JSON.stringify({ code }), { status: 409, headers: RESPONSE_HEADERS });
    } finally {
      clearTimeout(timer);
      request.signal.removeEventListener("abort", cancel);
    }
  };
}
