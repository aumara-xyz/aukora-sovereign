/* Same-origin JSON calls against plan/OWNER-API.md. Errors carry the
   "<organ>:<reason>" code from the response envelope. */

async function call(method, path, body) {
  const init = {
    method,
    credentials: 'same-origin',
    cache: 'no-store',
    headers: {},
    redirect: 'error',
  };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const response = await fetch(path, init);
  let data = null;
  try { data = await response.json(); } catch { /* non-JSON error page */ }
  if (!response.ok) {
    const code = data && typeof data.error === 'string' ? data.error : `frontdoor:http-${response.status}`;
    throw Object.assign(new Error(code), { code, status: response.status, detail: data });
  }
  return data;
}

export const api = {
  state: () => call('GET', '/api/state'),
  claim: token => call('POST', '/api/claim', { token }),
  logout: () => call('POST', '/api/logout', {}),
  logoutEverywhere: () => call('POST', '/api/logout/everywhere', {}),
  logoutEverywhereConfirm: (ceremony_id, assertion) => call('POST', '/api/logout/everywhere/confirm', { ceremony_id, assertion }),

  enrolStart: () => call('POST', '/api/enrol/start', {}),
  enrolFinish: (enrolment_id, attestation) => call('POST', '/api/enrol/finish', { enrolment_id, attestation }),
  // The server asks the new passkey to sign once before enrolment closes (possession proof).
  enrolProve: (enrolment_id, assertion) => call('POST', '/api/enrol/finish', { enrolment_id, assertion }),

  signinStart: () => call('POST', '/api/signin/start', {}),
  signinFinish: (ceremony_id, assertion) => call('POST', '/api/signin/finish', { ceremony_id, assertion }),

  bindingPrepare: () => call('POST', '/api/binding/prepare', {}),
  bindingConfirm: (ceremony_id, words) => call('POST', '/api/binding/confirm', { ceremony_id, words }),
  bindingCancel: ceremony_id => call('POST', '/api/binding/cancel', { ceremony_id }),
  bindingBackupStart: () => call('POST', '/api/binding/backup/start', {}),
  bindingBackupFinish: (backup_id, current_phrase, assertion, prf_output) => call('POST', '/api/binding/backup/finish', { backup_id, current_phrase, assertion, prf_output }),
  bindingRefresh: () => call('POST', '/api/binding/refresh', {}),
  bindingRefreshPrepare: (ceremony_id, current_phrase, assertion) => call('POST', '/api/binding/refresh/prepare', { ceremony_id, current_phrase, assertion }),
  bindingRefreshResume: (ceremony_id, current_phrase) => call('POST', '/api/binding/refresh/resume', { ceremony_id, current_phrase }),
  bindingRefreshConfirm: (ceremony_id, current_phrase, words) => call('POST', '/api/binding/refresh/confirm', { ceremony_id, current_phrase, words }),
  bindingRefreshCancel: ceremony_id => call('POST', '/api/binding/refresh/cancel', { ceremony_id }),

  approvals: () => call('GET', '/api/approvals'),
  approvalChallenge: id => call('POST', '/api/approvals/challenge', { id }),
  approvalDecide: (id, approve, assertion) => call('POST', '/api/approvals/decide', { id, approve, assertion }),
  approvalDespiteChallenge: id => call('POST', '/api/approvals/despite/challenge', { id }),
  approvalDespiteDecide: (id, assertion) => call('POST', '/api/approvals/despite/decide', { id, assertion }),
  approvalRetireChallenge: id => call('POST', '/api/approvals/retire/challenge', { id }),
  approvalRetire: (id, assertion) => call('POST', '/api/approvals/retire', { id, assertion }),
  approvalReconcileChallenge: id => call('POST', '/api/approvals/reconcile/challenge', { id }),
  approvalReconcile: (id, assertion) => call('POST', '/api/approvals/reconcile', { id, assertion }),

  auraHead: since => call('GET', `/api/aura/head${since !== undefined ? `?since=${since}` : ''}`),
  auraRecent: (limit = 20) => call('GET', `/api/aura/recent?limit=${limit}`),
  nostr: () => call('GET', '/api/nostr'),
  nostrContacts: () => call('GET', '/api/nostr/contacts'),
  nostrContactPropose: (npub, label, action) => call('POST', '/api/nostr/contacts/propose', { npub, label, action }),
  nostrSendPropose: (npub, content) => call('POST', '/api/nostr/send/propose', { npub, content }),
  nostrInbox: () => call('GET', '/api/nostr/inbox'),
  nostrSendPreview: id => call('GET', `/api/nostr/send/preview?id=${encodeURIComponent(id)}`),

  memoryRecall: (query, limit = 20) => call('POST', '/api/memory/recall', { query, limit }),
  memoryDemote: (note_id, reason) => call('POST', '/api/memory/demote', { note_id, reason }),
  memoryPermissionPropose: () => call('POST', '/api/memory/permission/propose', {}),

  broker: () => call('GET', '/api/broker'),
  brokerKeyPropose: key_sha256 => call('POST', '/api/broker/key/propose', { key_sha256 }),
  brokerKeyDeliver: (id, key) => call('POST', '/api/broker/key', { id, key }),
  // Delivers to an already approved record for this key's fingerprint, if there is one.
  brokerKeyDeliverApproved: key => call('POST', '/api/broker/key', { key }),
  brokerGrantPropose: grant => call('POST', '/api/broker/grant/propose', grant),

  release: () => call('GET', '/api/release'),
  releaseRetry: () => call('POST', '/api/release/retry', {}),
};

/* base64url <-> bytes for WebAuthn JSON fields */
export function b64urlToBytes(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export function bytesToB64url(bytes) {
  let bin = '';
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/* WebAuthn option JSON (base64url fields) -> PublicKeyCredential options */
export function decodeCreationOptions(pk) {
  return {
    ...pk,
    challenge: b64urlToBytes(pk.challenge),
    user: { ...pk.user, id: b64urlToBytes(pk.user.id) },
    excludeCredentials: (pk.excludeCredentials ?? []).map(c => ({ ...c, id: b64urlToBytes(c.id) })),
  };
}
export function decodeRequestOptions(pk) {
  return {
    ...pk,
    challenge: b64urlToBytes(pk.challenge),
    allowCredentials: (pk.allowCredentials ?? []).map(c => ({ ...c, id: b64urlToBytes(c.id) })),
  };
}

export function encodeAttestation(credential) {
  return {
    kind: 'passkey-registration',
    id: credential.id,
    raw_id: bytesToB64url(credential.rawId),
    client_data_json: bytesToB64url(credential.response.clientDataJSON),
    attestation_object: bytesToB64url(credential.response.attestationObject),
    client_extension_results: credential.getClientExtensionResults(),
  };
}
export function encodeAssertion(credential) {
  return {
    kind: 'passkey',
    credential_id: bytesToB64url(credential.rawId),
    client_data_json: bytesToB64url(credential.response.clientDataJSON),
    authenticator_data: bytesToB64url(credential.response.authenticatorData),
    signature: bytesToB64url(credential.response.signature),
    user_handle: credential.response.userHandle == null ? null : bytesToB64url(credential.response.userHandle),
  };
}
