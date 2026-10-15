// SPDX-License-Identifier: AGPL-3.0-or-later
import { api, b64urlToBytes, bytesToB64url, decodeRequestOptions, encodeAssertion } from './api.js';

const PRF_SALT = 'naArOArmoSIkFCLAd7veGR3-DDWUPnpgE6K5qlMF3Ws';
const fail = code => { throw Object.assign(new Error(code), { code }); };

export async function passkeyBackup(currentPhrase) {
  let output;
  try {
    if (!globalThis.PublicKeyCredential && !globalThis.window?.PublicKeyCredential) fail('aumlok:webauthn-unavailable');
    if (!navigator.credentials?.get) fail('aumlok:webauthn-unavailable');
    const ch = await api.bindingBackupStart();
    const pk = ch.public_key;
    if (typeof ch.backup_id !== 'string' || pk?.extensions?.prf?.eval?.first !== PRF_SALT
      || pk.allowCredentials?.length !== 1 || pk.allowCredentials[0].type !== 'public-key') {
      fail('aumlok:backup-challenge-mismatch');
    }
    const credential = await navigator.credentials.get({ publicKey: {
      ...decodeRequestOptions(pk), userVerification: 'required',
      extensions: { prf: { eval: { first: b64urlToBytes(PRF_SALT) } } },
    } });
    if (!credential) fail('aumlok:approval-cancelled');
    if (bytesToB64url(credential.rawId) !== pk.allowCredentials[0].id) fail('aumlok:backup-credential-mismatch');
    const first = credential.getClientExtensionResults?.()?.prf?.results?.first;
    if (!(first instanceof ArrayBuffer) && !ArrayBuffer.isView(first)) fail('aumlok:backup-prf-unavailable');
    output = first instanceof ArrayBuffer ? new Uint8Array(first) : new Uint8Array(first.buffer, first.byteOffset, first.byteLength);
    if (output.byteLength !== 32) fail('aumlok:backup-prf-unavailable');
    const backup = await api.bindingBackupFinish(ch.backup_id, currentPhrase, encodeAssertion(credential), bytesToB64url(output));
    if (backup?.version !== 2) fail('aumlok:backup-version');
    return backup;
  } finally {
    currentPhrase = '';
    output?.fill(0);
  }
}

export function backupError(ex) {
  if (ex.name === 'NotSupportedError' || ['aumlok:backup-prf-unavailable', 'aumlok:webauthn-unavailable'].includes(ex.code)) {
    return 'This passkey or browser does not support WebAuthn PRF. A passkey-bound backup was not created. You can explicitly download the phrase-only recovery copy below; it is guessable offline. Store it like cash.';
  }
  return ex.code ?? String(ex);
}

export function addBackupControls(panel) {
  const section = document.createElement('section');
  const heading = document.createElement('h2');
  heading.textContent = 'Identity backups';
  const note = document.createElement('p');
  note.className = 'instruct';
  note.textContent = 'A passkey-bound backup needs your current phrase and this same passkey to restore. Losing access to the passkey makes this backup unusable. Download a new backup after replacing your phrase.';
  const download = document.createElement('button');
  download.className = 'primary';
  download.textContent = 'Download passkey-bound backup';
  const form = document.createElement('div');
  form.hidden = true;
  const prompt = document.createElement('p');
  prompt.className = 'instruct';
  prompt.textContent = 'Type your current seven words, then use your passkey to seal the backup.';
  const phrase = document.createElement('input');
  phrase.type = 'text';
  phrase.setAttribute('aria-label', 'backup current phrase');
  for (const name of ['autocomplete', 'autocorrect', 'autocapitalize']) phrase.setAttribute(name, 'off');
  phrase.setAttribute('spellcheck', 'false');
  const seal = document.createElement('button');
  seal.className = 'primary';
  seal.textContent = 'Use passkey and download';
  const cancel = document.createElement('button');
  cancel.textContent = 'Cancel backup';
  const result = document.createElement('p');
  result.className = 'instruct warn';
  result.hidden = true;
  const warning = document.createElement('p');
  warning.className = 'instruct warn';
  warning.textContent = 'Optional phrase-only recovery copy: anyone with this file can guess your phrase offline, without the passkey or node guess limits. Store it like cash.';
  const recovery = document.createElement('a');
  recovery.href = '/api/binding/envelope';
  recovery.download = 'aukora-envelope.json';
  recovery.textContent = 'Download phrase-only recovery copy';
  section.append(heading, note, download, form, result, warning, recovery);
  panel.appendChild(section);
  download.onclick = () => { form.append(prompt, phrase, seal, cancel); form.hidden = false; phrase.focus(); };
  cancel.onclick = () => { phrase.value = ''; phrase.remove(); form.hidden = true; };
  seal.onclick = async () => {
    let current = phrase.value.trim().toLowerCase().split(/\s+/).join(' ');
    phrase.value = '';
    seal.disabled = true;
    cancel.disabled = true;
    result.hidden = true;
    try {
      const backup = await passkeyBackup(current);
      const url = URL.createObjectURL(new Blob([JSON.stringify(backup)], { type: 'application/json' }));
      const link = document.createElement('a');
      link.href = url;
      link.download = 'aukora-envelope-passkey-v2.json';
      link.textContent = 'Save passkey-bound backup';
      section.appendChild(link);
      link.click();
      setTimeout(() => { URL.revokeObjectURL(url); link.remove(); }, 60000);
      phrase.remove();
      form.hidden = true;
      result.textContent = 'Passkey-bound backup created. Restore requires this passkey and the phrase you just used.';
    } catch (ex) {
      result.textContent = backupError(ex);
    } finally {
      current = '';
      seal.disabled = false;
      cancel.disabled = false;
      result.hidden = false;
    }
  };
}
