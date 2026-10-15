// SPDX-License-Identifier: AGPL-3.0-or-later
export interface AssertionMaterial {
  readonly kind: "passkey";
  readonly credential_id: string;
  readonly client_data_json: string;
  readonly authenticator_data: string;
  readonly signature: string;
  readonly user_handle: string | null;
}

export interface RegistrationMaterial {
  readonly kind: "passkey-registration";
  readonly type: "public-key";
  readonly id: string;
  readonly raw_id: string;
  readonly client_data_json: string;
  readonly attestation_object: string;
  readonly client_extension_results: {} | { readonly prf: { readonly enabled: boolean } };
}

export function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function credentialBytes(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]{2,1366}$/.test(value)) throw new Error("aumlok:credential-id");
  let binary: string;
  try { binary = atob(value.replace(/-/g, "+").replace(/_/g, "/")); }
  catch { throw new Error("aumlok:credential-id"); }
  const bytes = Uint8Array.from(binary, character => character.charCodeAt(0));
  if (bytes.byteLength < 1 || bytes.byteLength > 1024 || base64url(bytes) !== value) {
    throw new Error("aumlok:credential-id");
  }
  return bytes;
}

function boundedBuffer(value: unknown, minimum: number, maximum: number, reason: string): Uint8Array {
  if (!(value instanceof ArrayBuffer) || value.byteLength < minimum || value.byteLength > maximum) {
    throw new Error(`aumlok:${reason}`);
  }
  return new Uint8Array(value);
}

export function checkClientData(
  raw: ArrayBuffer, type: "webauthn.create" | "webauthn.get", challenge: Uint8Array,
  ownerOrigin: string, topOrigin: string,
): void {
  const bytes = boundedBuffer(raw, 1, 16_384, "client-data-json");
  let data: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error();
    data = parsed as Record<string, unknown>;
  } catch { throw new Error("aumlok:client-data-json"); }
  if (data.type !== type || data.challenge !== base64url(challenge)) {
    throw new Error("aumlok:challenge-mismatch");
  }
  if (data.origin !== ownerOrigin || data.crossOrigin !== true || data.topOrigin !== topOrigin) {
    throw new Error("aumlok:origin-mismatch");
  }
}

function identifier(credential: PublicKeyCredential): string {
  if (credential.type !== "public-key") throw new Error("aumlok:credential-type");
  const id = base64url(boundedBuffer(credential.rawId, 1, 1024, "credential-id"));
  if (credential.id !== id) throw new Error("aumlok:credential-id");
  return id;
}

export function assertionMaterial(credential: PublicKeyCredential): AssertionMaterial {
  const id = identifier(credential);
  const response = credential.response;
  if (!(response instanceof AuthenticatorAssertionResponse)) throw new Error("aumlok:assertion-refused");
  return {
    kind: "passkey",
    credential_id: id,
    client_data_json: base64url(boundedBuffer(response.clientDataJSON, 1, 16_384, "client-data-json")),
    authenticator_data: base64url(boundedBuffer(response.authenticatorData, 37, 4096, "authenticator-data")),
    signature: base64url(boundedBuffer(response.signature, 1, 128, "signature-invalid")),
    user_handle: response.userHandle === null ? null
      : base64url(boundedBuffer(response.userHandle, 1, 64, "user-handle")),
  };
}

export function registrationMaterial(credential: PublicKeyCredential): RegistrationMaterial {
  const id = identifier(credential);
  const response = credential.response;
  if (!(response instanceof AuthenticatorAttestationResponse)) throw new Error("aumlok:registration-refused");
  const results = credential.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: { enabled?: boolean };
  };
  const keys = Object.keys(results);
  if (keys.length !== 0 && (keys.length !== 1 || keys[0] !== "prf"
    || !results.prf || Object.keys(results.prf).join(",") !== "enabled"
    || typeof results.prf.enabled !== "boolean")) throw new Error("aumlok:registration-extension");
  return {
    kind: "passkey-registration",
    type: "public-key",
    id,
    raw_id: id,
    client_data_json: base64url(boundedBuffer(response.clientDataJSON, 1, 16_384, "client-data-json")),
    attestation_object: base64url(boundedBuffer(response.attestationObject, 1, 16_384, "attestation-object")),
    client_extension_results: typeof results.prf?.enabled === "boolean"
      ? { prf: { enabled: results.prf.enabled } } : {},
  };
}

export function assertionBytes(assertion: AssertionMaterial): Uint8Array {
  const canonical = {
    authenticator_data: assertion.authenticator_data,
    client_data_json: assertion.client_data_json,
    credential_id: assertion.credential_id,
    kind: assertion.kind,
    signature: assertion.signature,
    user_handle: assertion.user_handle,
  };
  return new TextEncoder().encode(JSON.stringify(canonical));
}
