// SPDX-License-Identifier: AGPL-3.0-or-later
import { b64urlToBytes, decodeRequestOptions, encodeAssertion } from './api.js';
import { canonicalJSON, ownerAuthChallenge } from './canon.js';
import { browserSha256 } from './pentora.js';

const fail = code => { throw Object.assign(new Error(code), { code }); };
const digest = async value => [...new Uint8Array(await browserSha256(new TextEncoder().encode(value)))].map(b => b.toString(16).padStart(2, '0')).join('');
export async function checkPermissionChallenge(ch, state, target, refusal) {
  const auth = ch.auth;
  if (auth?.v !== 1 || auth.op !== 'permission' || auth.target !== target
    || auth.proposal !== ch.ceremony_id || auth.node !== state.node || auth.subject !== state.subject
    || !Number.isSafeInteger(auth.epoch) || auth.epoch < 1
    || !Number.isSafeInteger(auth.expires_at) || auth.expires_at <= Date.now()) {
    fail(refusal);
  }
  const display = await digest(canonicalJSON(ch.card));
  if (display !== ch.display_sha256 || auth.display_sha256 !== display) fail('gate:card-changed');
  const operation = { v: 1, node: auth.node, target: auth.target,
    base_sha256: auth.base_sha256, new_sha256: auth.new_sha256, cell: auth.cell };
  if (await digest('aukora:operation-content:v1\0' + canonicalJSON(operation)) !== auth.operation) {
    fail(refusal);
  }
  const expected = await ownerAuthChallenge(auth, browserSha256);
  const sent = b64urlToBytes(ch.public_key.challenge);
  if (expected.length !== sent.length || !expected.every((b, i) => b === sent[i])) {
    fail(refusal);
  }
}

export async function permissionAssertion(ch) {
  if (ch.dev_bypass === true && ['localhost', '127.0.0.1'].includes(location.hostname)) {
    return { kind: 'dev-bypass', challenge: ch.public_key.challenge };
  }
  if (!window.PublicKeyCredential) fail('aumlok:webauthn-unavailable');
  const credential = await navigator.credentials.get({ publicKey: {
    ...decodeRequestOptions(ch.public_key), userVerification: 'required',
  } });
  if (!credential) fail('aumlok:approval-cancelled');
  return encodeAssertion(credential);
}

