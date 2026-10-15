/* Canonical JSON (CONTRACTS.md C1): sorted keys (JavaScript default sort),
   no whitespace, JSON.stringify string rules, canonical safe integers only.
   The owner authorization challenge (C5) is
   sha256("aukora:owner-authorization:v1" || 0x00 || canonicalJSON(auth)). */

export function canonicalJSON(value) {
  if (value === null) return 'null';
  if (value === true) return 'true';
  if (value === false) return 'false';
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || Math.abs(value) > 9007199254740991) {
      throw Object.assign(new Error('canon:non-canonical-number'), { code: 'canon:non-canonical-number' });
    }
    return String(value); // integers only; no -0 (String(-0) === "0" is impossible here: -0 fails isInteger? no — guard below)
  }
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  if (typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
  }
  throw Object.assign(new Error('canon:unsupported-type'), { code: 'canon:unsupported-type' });
}

export const OWNER_AUTH_DOMAIN = 'aukora:owner-authorization:v1';

/* The exact WebAuthn challenge bytes for a C5 authorization. */
export async function ownerAuthChallenge(auth, sha256) {
  const canon = canonicalJSON(auth);
  const head = new TextEncoder().encode(OWNER_AUTH_DOMAIN + '\0' + canon);
  const out = await sha256(head);
  return out instanceof ArrayBuffer ? new Uint8Array(out) : out;
}
