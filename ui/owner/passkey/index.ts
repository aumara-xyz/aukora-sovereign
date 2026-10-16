// SPDX-License-Identifier: AGPL-3.0-or-later
import type { OwnerDisposer, OwnerPaneContext, PasskeyPaneService } from "../contracts.js";
import {
  assertionBytes, assertionMaterial, checkClientData, credentialBytes, registrationMaterial,
} from "./codec.js";
import type { AssertionMaterial, RegistrationMaterial } from "./codec.js";

export type { AssertionMaterial, RegistrationMaterial } from "./codec.js";

export interface AssertionOptions {
  readonly challenge: Uint8Array;
  readonly allowCredentials?: readonly string[];
  readonly timeoutMs?: number;
}

export interface RegistrationOptions {
  readonly challenge: Uint8Array;
  readonly user: { readonly id: Uint8Array; readonly name: string; readonly displayName: string };
  readonly excludeCredentials?: readonly string[];
  readonly timeoutMs?: number;
  readonly enablePrf?: boolean;
}

export type PasskeyStep =
  | { readonly kind: "register"; readonly ceremonyId: string; readonly publicKey: RegistrationOptions }
  | { readonly kind: "assert"; readonly ceremonyId: string; readonly purpose: "enrol" | "signin"; readonly publicKey: AssertionOptions }
  | { readonly kind: "complete" };

// This adapter is composed by the trusted owner release, never by a frame message.
export interface OwnerPasskeyCeremonies {
  current(signal: AbortSignal): Promise<PasskeyStep>;
  advance(
    ceremonyId: string, material: AssertionMaterial | RegistrationMaterial, signal: AbortSignal,
  ): Promise<PasskeyStep>;
}

export interface PasskeyConfiguration {
  readonly ownerOrigin: string;
  readonly shellOrigin: string;
  readonly relyingParty: string;
  readonly credentialIds?: readonly string[];
  readonly ceremonies: OwnerPasskeyCeremonies;
}

export interface OwnerPasskeyService extends PasskeyPaneService {
  register(options: RegistrationOptions, signal: AbortSignal): Promise<RegistrationMaterial>;
  assert(options: AssertionOptions, signal: AbortSignal): Promise<AssertionMaterial>;
  backupPrf(
    challenge: Uint8Array, credentialId: string, signal: AbortSignal,
  ): Promise<{ readonly assertion: AssertionMaterial; readonly key: Uint8Array }>;
}

function origin(value: string): string {
  let parsed: URL;
  try { parsed = new URL(value); } catch { throw new Error("owner:invalid-origin"); }
  if (parsed.origin !== value || parsed.protocol !== "https:") throw new Error("owner:invalid-origin");
  return value;
}

function challengeBytes(value: Uint8Array): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) throw new Error("aumlok:challenge-mismatch");
  return Uint8Array.from(value);
}

function timeout(value?: number): number {
  if (value === undefined) return 60_000;
  if (!Number.isInteger(value) || value < 1 || value > 300_000) throw new Error("aumlok:ceremony-expired");
  return value;
}

function descriptors(ids?: readonly string[]): PublicKeyCredentialDescriptor[] | undefined {
  if (ids === undefined) return undefined;
  if (!Array.isArray(ids) || ids.length > 64) throw new Error("aumlok:credential-id");
  return ids.map(id => ({ type: "public-key", id: Uint8Array.from(credentialBytes(id)) }));
}

function live(signal: AbortSignal): void {
  if (signal.aborted) throw new DOMException("Ceremony closed", "AbortError");
}

function credential(value: Credential | null): PublicKeyCredential {
  if (!(value instanceof PublicKeyCredential)) throw new Error("aumlok:assertion-refused");
  return value;
}

function ceremonyId(value: string): void {
  if (typeof value !== "string" || !/^[0-9a-f]{32}$/.test(value)) throw new Error("aumlok:ceremony-id");
}

function refusal(error: unknown): string {
  if (error instanceof DOMException && (error.name === "NotAllowedError" || error.name === "AbortError")) {
    return "Passkey cancelled or expired. Try again.";
  }
  if (error instanceof Error && error.message === "aumlok:webauthn-unavailable") {
    return "Passkeys are unavailable in this browser.";
  }
  return "Passkey not confirmed. Try again.";
}

export function createPasskeyService(configuration: PasskeyConfiguration): OwnerPasskeyService {
  const ownerOrigin = origin(configuration.ownerOrigin);
  const shellOrigin = origin(configuration.shellOrigin);
  const relyingParty = configuration.relyingParty;
  const hostname = new URL(ownerOrigin).hostname;
  if (!relyingParty || relyingParty.toLowerCase() !== relyingParty
    || !/^[a-z0-9.-]+$/.test(relyingParty)
    || (hostname !== relyingParty && !hostname.endsWith(`.${relyingParty}`))
    || ownerOrigin === shellOrigin) throw new Error("aumlok:origin-mismatch");
  const credentialIds = configuration.credentialIds === undefined ? undefined : [...configuration.credentialIds];
  descriptors(credentialIds);
  const ceremonies = configuration.ceremonies;
  let pending = false;

  function environment(expectedTopOrigin: string, signal: AbortSignal): void {
    live(signal);
    if (location.origin !== ownerOrigin || expectedTopOrigin !== shellOrigin
      || window.parent === window || window.top !== window.parent) throw new Error("owner:frame-required");
    if (!window.isSecureContext || !navigator.credentials || typeof PublicKeyCredential === "undefined") {
      throw new Error("aumlok:webauthn-unavailable");
    }
  }

  async function browserRequest<T>(signal: AbortSignal, action: () => Promise<T>): Promise<T> {
    environment(shellOrigin, signal);
    if (pending) throw new Error("aumlok:ceremony-busy");
    pending = true;
    try {
      const result = await action();
      live(signal);
      return result;
    } finally { pending = false; }
  }

  async function assert(options: AssertionOptions, signal: AbortSignal): Promise<AssertionMaterial> {
    const challenge = challengeBytes(options.challenge);
    const allowed = options.allowCredentials === undefined ? credentialIds : [...options.allowCredentials];
    return browserRequest(signal, async () => {
      const result = credential(await navigator.credentials.get({
        publicKey: {
          challenge, rpId: relyingParty, userVerification: "required",
          allowCredentials: descriptors(allowed), timeout: timeout(options.timeoutMs),
        }, signal,
      }));
      checkClientData(result.response.clientDataJSON, "webauthn.get", challenge, ownerOrigin, shellOrigin);
      const material = assertionMaterial(result);
      if (allowed?.length && !allowed.includes(material.credential_id)) throw new Error("aumlok:credential-id");
      return material;
    });
  }

  async function register(options: RegistrationOptions, signal: AbortSignal): Promise<RegistrationMaterial> {
    const challenge = challengeBytes(options.challenge);
    const user = options.user;
    if (!(user.id instanceof Uint8Array) || user.id.byteLength < 1 || user.id.byteLength > 64
      || typeof user.name !== "string" || !user.name || user.name.length > 256
      || typeof user.displayName !== "string" || !user.displayName || user.displayName.length > 256) {
      throw new Error("aumlok:user-handle");
    }
    return browserRequest(signal, async () => {
      const extensions = options.enablePrf ? { prf: {} } as AuthenticationExtensionsClientInputs : undefined;
      const result = credential(await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { id: relyingParty, name: "AUKORA" },
          user: { id: Uint8Array.from(user.id), name: user.name, displayName: user.displayName },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          attestation: "none", excludeCredentials: descriptors(options.excludeCredentials),
          timeout: timeout(options.timeoutMs), extensions,
        }, signal,
      }));
      checkClientData(result.response.clientDataJSON, "webauthn.create", challenge, ownerOrigin, shellOrigin);
      return registrationMaterial(result);
    });
  }

  async function backupPrf(challengeInput: Uint8Array, id: string, signal: AbortSignal) {
    const challenge = challengeBytes(challengeInput);
    if (credentialIds?.length && !credentialIds.includes(id)) throw new Error("aumlok:credential-id");
    const allowed = descriptors([id]);
    let secret: Uint8Array | undefined;
    try { return await browserRequest(signal, async () => {
      const domain = new TextEncoder().encode("aukora:aumlok-backup-prf:v2");
      const input = await crypto.subtle.digest("SHA-256", domain);
      live(signal);
      const result = credential(await navigator.credentials.get({
        publicKey: {
          challenge, rpId: relyingParty, allowCredentials: allowed,
          userVerification: "required", timeout: 60_000,
          extensions: { prf: { eval: { first: input } } } as AuthenticationExtensionsClientInputs,
        }, signal,
      }));
      checkClientData(result.response.clientDataJSON, "webauthn.get", challenge, ownerOrigin, shellOrigin);
      const material = assertionMaterial(result);
      if (material.credential_id !== id) throw new Error("aumlok:credential-id");
      const extensions = result.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
        prf?: { results?: { first?: ArrayBuffer } };
      };
      const first = extensions.prf?.results?.first;
      if (!(first instanceof ArrayBuffer) || first.byteLength !== 32) throw new Error("aumlok:prf-unavailable");
      const key = new Uint8Array(first.slice(0));
      secret = key;
      new Uint8Array(first).fill(0);
      return { assertion: material, key };
    }); } catch (error) {
      secret?.fill(0);
      throw error;
    }
  }

  function mount(context: OwnerPaneContext): OwnerDisposer {
    environment(context.shellOrigin, context.signal);
    if (context.route.pane !== "passkey") throw new Error("owner:unknown-route");
    const lifetime = new AbortController();
    const stop = () => lifetime.abort();
    context.signal.addEventListener("abort", stop, { once: true });
    const title = document.createElement("h2");
    title.tabIndex = -1;
    const detail = document.createElement("p");
    const status = document.createElement("p");
    status.setAttribute("role", "status");
    const action = document.createElement("button");
    action.type = "button";
    action.disabled = true;
    context.host.replaceChildren(title, detail, status, action);
    let step: PasskeyStep | undefined;
    let busy = false;

    function show(next: PasskeyStep): void {
      live(lifetime.signal);
      if (next.kind !== "complete" && next.kind !== "register" && next.kind !== "assert") {
        throw new Error("aumlok:ceremony-kind");
      }
      if (next.kind !== "complete") ceremonyId(next.ceremonyId);
      step = next;
      if (next.kind === "complete") {
        title.textContent = "Passkey confirmed";
        detail.textContent = "The owner service confirmed this ceremony.";
        action.hidden = true;
        status.textContent = "Complete.";
        title.focus();
        context.complete();
      } else if (next.kind === "register") {
        title.textContent = "Create your owner passkey";
        detail.textContent = "Your passkey authorizes owner actions after your device verifies you.";
        action.textContent = "Create passkey";
        action.disabled = false;
        status.textContent = "Ready to create a passkey.";
      } else if (next.kind === "assert" && (next.purpose === "enrol" || next.purpose === "signin")) {
        title.textContent = next.purpose === "enrol" ? "Confirm your new passkey" : "Sign in with your passkey";
        detail.textContent = next.purpose === "enrol"
          ? "Verify your new passkey to finish enrolment." : "Your device will ask you to verify your passkey.";
        action.textContent = "Verify passkey";
        action.disabled = false;
        status.textContent = "Ready for your passkey.";
      } else throw new Error("aumlok:ceremony-kind");
      if (next.kind !== "complete") title.focus();
    }

    const invoke = async (): Promise<void> => {
      if (step?.kind === "complete" || busy || lifetime.signal.aborted) return;
      const current = step;
      let submitted = false;
      busy = true;
      action.disabled = true;
      status.textContent = "Waiting for your passkey.";
      try {
        if (!current) {
          status.textContent = "Resuming the owner ceremony.";
          show(await ceremonies.current(lifetime.signal));
          return;
        }
        const material = current.kind === "register"
          ? await register(current.publicKey, lifetime.signal) : await assert(current.publicKey, lifetime.signal);
        live(lifetime.signal);
        status.textContent = "Waiting for the owner service to confirm.";
        submitted = true;
        const next = await ceremonies.advance(current.ceremonyId, material, lifetime.signal);
        show(next);
      } catch (error) {
        if (!lifetime.signal.aborted) {
          if (submitted || !current) {
            step = undefined;
            action.textContent = "Resume ceremony";
          }
          status.textContent = refusal(error);
          action.disabled = false;
          action.focus();
        }
      } finally { busy = false; }
    };
    action.addEventListener("click", invoke);
    title.textContent = "Owner passkey";
    status.textContent = "Resuming the owner ceremony.";
    title.focus();
    void ceremonies.current(lifetime.signal).then(show).catch(error => {
      if (!lifetime.signal.aborted) {
        step = undefined;
        action.textContent = "Resume ceremony";
        action.disabled = false;
        status.textContent = refusal(error);
        action.focus();
      }
    });
    return () => {
      lifetime.abort();
      context.signal.removeEventListener("abort", stop);
      action.removeEventListener("click", invoke);
      context.host.replaceChildren();
    };
  }

  return {
    mount,
    register,
    assert,
    async assertExact(challenge, expectedTopOrigin, signal, timeoutMs) {
      environment(expectedTopOrigin, signal);
      return assertionBytes(await assert({ challenge, timeoutMs }, signal));
    },
    backupPrf,
  };
}
