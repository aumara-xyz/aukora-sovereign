// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { passkeyBackup, addBackupControls } from '../backup.js';
import { addOwnerLinks } from '../owner-links.js';

const SALT = 'naArOArmoSIkFCLAd7veGR3-DDWUPnpgE6K5qlMF3Ws';
const PHRASE = 'planet pine linden accord neighbor eclipse terraform';
const ID = 'ab'.repeat(16);
const b64 = bytes => Buffer.from(bytes).toString('base64url');
const json = body => new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });

class Element {
  constructor(tag) { this.tagName = tag; this.children = []; this.value = ''; this.events = {}; }
  appendChild(child) { child.remove(); this.children.push(child); child.parent = this; return child; }
  append(...children) { children.forEach(child => this.appendChild(child)); }
  setAttribute(name, value) { this[name] = value; }
  focus() { this.focused = true; }
  click() { this.clicked = true; }
  remove() { if (this.parent) this.parent.children = this.parent.children.filter(child => child !== this); this.parent = null; }
}
const all = element => [element, ...element.children.flatMap(all)];
const find = (panel, text) => all(panel).find(element => element.textContent === text);

function setup(t, { prf = new Uint8Array(32).fill(7), credentialId = [1], cancelled = false, webauthn = true, missingGet = false, getError, patch, response = { version: 2, sealed_root: 'encrypted' }, finishFailure = false } = {}) {
  const requests = [], options = [], blobs = [], timers = [];
  const names = ['document', 'window', 'navigator', 'fetch', 'localStorage', 'setTimeout'];
  const previous = names.map(name => Object.getOwnPropertyDescriptor(globalThis, name));
  const globalValues = {
    document: { createElement: tag => new Element(tag) }, window: webauthn ? { PublicKeyCredential: {} } : {},
    navigator: { credentials: { get: async option => {
      options.push(option);
      if (getError) throw getError;
      return cancelled ? null : { rawId: new Uint8Array(credentialId), response: {
        clientDataJSON: new Uint8Array([2]), authenticatorData: new Uint8Array([3]), signature: new Uint8Array([4]), userHandle: null,
      }, getClientExtensionResults: () => prf === undefined ? {} : { prf: { results: { first: prf } } } };
    } } },
    fetch: async (url, init) => {
      requests.push({ url, init, body: init.body && JSON.parse(init.body) });
      if (url.endsWith('/start')) {
        const ch = { backup_id: ID, public_key: { challenge: 'Ag', rpId: 'owner.example',
          allowCredentials: [{ type: 'public-key', id: 'AQ' }], userVerification: 'preferred',
          extensions: { prf: { eval: { first: SALT } } } } };
        if (patch) patch(ch);
        return json(ch);
      }
      if (url.endsWith('/finish')) { if (finishFailure) throw new Error('lost finish response'); return json(response); }
      assert.fail(`unexpected backup request ${url}`);
    },
    localStorage: { setItem: () => assert.fail('backup secrets must not be stored') },
    setTimeout: callback => { timers.push(callback); return 1; },
  };
  if (missingGet) globalValues.navigator.credentials = {};
  names.forEach(name => Object.defineProperty(globalThis, name, { configurable: true, value: globalValues[name] }));
  const createURL = URL.createObjectURL, revokeURL = URL.revokeObjectURL;
  URL.createObjectURL = blob => { blobs.push(blob); return 'blob:backup'; };
  URL.revokeObjectURL = () => {};
  t.after(() => {
    names.forEach((name, i) => {
      if (previous[i]) Object.defineProperty(globalThis, name, previous[i]); else delete globalThis[name];
    });
    URL.createObjectURL = createURL; URL.revokeObjectURL = revokeURL;
  });
  return { panel: new Element('main'), requests, options, blobs, timers, prf };
}

test('antibody_ui_backup_uses_fixed_prf_salt_and_required_owner_verification', async t => {
  const fixture = setup(t);
  await passkeyBackup(PHRASE);
  const pk = fixture.options[0].publicKey;
  assert.equal(pk.userVerification, 'required');
  assert.ok(pk.extensions.prf.eval.first instanceof Uint8Array);
  assert.equal(b64(pk.extensions.prf.eval.first), SALT);
  assert.deepEqual([...pk.allowCredentials[0].id], [1]);
  assert.deepEqual(fixture.requests.map(request => request.url), ['/api/binding/backup/start', '/api/binding/backup/finish']);
  assert.deepEqual(fixture.requests[0].body, {});
  assert.deepEqual(fixture.requests[1].body, { backup_id: ID, current_phrase: PHRASE,
    assertion: { kind: 'passkey', credential_id: 'AQ', client_data_json: 'Ag', authenticator_data: 'Aw', signature: 'BA', user_handle: null },
    prf_output: b64(new Uint8Array(32).fill(7)) });
  for (const request of fixture.requests) {
    assert.equal(request.init.credentials, 'same-origin');
    assert.equal(request.init.redirect, 'error');
    assert.equal(request.init.cache, 'no-store');
    assert.equal(request.url.includes(PHRASE), false);
  }
});

test('antibody_ui_backup_refuses_changed_salt_or_credential_options_before_passkey', async t => {
  const changes = [
    ch => { ch.public_key.extensions.prf.eval.first = 'AA'; },
    ch => { delete ch.public_key.extensions; },
    ch => { ch.public_key.allowCredentials.push({ type: 'public-key', id: 'Ag' }); },
    ch => { ch.public_key.allowCredentials[0].type = 'other'; },
    ch => { delete ch.backup_id; },
  ];
  for (const [i, patch] of changes.entries()) await t.test(String(i), async t => {
    const fixture = setup(t, { patch });
    await assert.rejects(passkeyBackup(PHRASE), { code: 'aumlok:backup-challenge-mismatch' });
    assert.equal(fixture.options.length, 0);
    assert.equal(fixture.requests.length, 1);
  });
});

test('antibody_ui_backup_requires_prf_output_and_never_falls_back_to_phrase_only', async t => {
  for (const prf of [null, {}, new Uint8Array(0), new Uint8Array(31), new Uint8Array(33)]) await t.test(String(prf?.byteLength), async t => {
    const fixture = setup(t, { prf });
    addBackupControls(fixture.panel);
    await find(fixture.panel, 'Download passkey-bound backup').onclick();
    const input = all(fixture.panel).find(element => element['aria-label'] === 'backup current phrase');
    input.value = PHRASE;
    await find(fixture.panel, 'Use passkey and download').onclick();
    assert.equal(fixture.requests.length, 1);
    assert.equal(fixture.blobs.length, 0);
    const message = all(fixture.panel).find(element => element.textContent?.startsWith('This passkey or browser'))?.textContent;
    assert.ok(message?.includes('does not support WebAuthn PRF'));
    assert.ok(message?.includes('guessable offline'));
    assert.ok(message?.includes('Store it like cash'));
    assert.equal(input.value, '');
  });
});

test('antibody_ui_backup_refuses_a_different_credential_prf_before_finish', async t => {
  const fixture = setup(t, { credentialId: [9] });
  await assert.rejects(passkeyBackup(PHRASE), { code: 'aumlok:backup-credential-mismatch' });
  assert.equal(fixture.requests.length, 1);
});

test('antibody_ui_backup_requires_real_passkey_even_with_local_dev_bypass', async t => {
  for (const cancelled of [false, true]) await t.test(String(cancelled), async t => {
    const fixture = setup(t, { cancelled, webauthn: cancelled, patch: ch => { ch.dev_bypass = true; } });
    await assert.rejects(passkeyBackup(PHRASE), { code: cancelled ? 'aumlok:approval-cancelled' : 'aumlok:webauthn-unavailable' });
    assert.equal(fixture.requests.some(request => request.url.endsWith('/finish')), false);
  });
  await t.test('missing credentials get', async t => {
    const fixture = setup(t, { missingGet: true });
    await assert.rejects(passkeyBackup(PHRASE), { code: 'aumlok:webauthn-unavailable' });
    assert.equal(fixture.requests.length, 0);
  });
});

test('antibody_ui_backup_unsupported_authenticator_explains_recovery_copy', async t => {
  const fixture = setup(t, { getError: Object.assign(new Error('PRF unavailable'), { name: 'NotSupportedError' }) });
  addBackupControls(fixture.panel);
  find(fixture.panel, 'Download passkey-bound backup').onclick();
  all(fixture.panel).find(element => element['aria-label'] === 'backup current phrase').value = PHRASE;
  await find(fixture.panel, 'Use passkey and download').onclick();
  assert.equal(fixture.requests.length, 1);
  assert.equal(fixture.blobs.length, 0);
  assert.ok(all(fixture.panel).some(element => element.textContent?.includes('does not support WebAuthn PRF')));
});

test('antibody_ui_backup_refuses_a_v1_response_for_passkey_bound_download', async t => {
  const fixture = setup(t, { response: { version: 1, sealed_root: 'phrase-only' } });
  await assert.rejects(passkeyBackup(PHRASE), { code: 'aumlok:backup-version' });
  assert.equal(fixture.blobs.length, 0);
});

test('antibody_ui_backup_clears_prf_output_on_success_and_failure', async t => {
  for (const finishFailure of [false, true]) await t.test(String(finishFailure), async t => {
    const fixture = setup(t, { finishFailure });
    if (finishFailure) await assert.rejects(passkeyBackup(PHRASE), /lost finish response/);
    else await passkeyBackup(PHRASE);
    assert.deepEqual([...fixture.prf], new Array(32).fill(0));
  });
});

test('antibody_ui_backup_download_contains_only_v2_and_clears_phrase_input', async t => {
  const fixture = setup(t);
  addBackupControls(fixture.panel);
  await find(fixture.panel, 'Download passkey-bound backup').onclick();
  const input = all(fixture.panel).find(element => element['aria-label'] === 'backup current phrase');
  for (const name of ['autocomplete', 'autocorrect', 'autocapitalize']) assert.equal(input[name], 'off');
  assert.equal(input.spellcheck, 'false');
  input.value = PHRASE;
  await find(fixture.panel, 'Use passkey and download').onclick();
  assert.equal(input.value, '');
  assert.equal(fixture.blobs.length, 1);
  assert.deepEqual(JSON.parse(await fixture.blobs[0].text()), { version: 2, sealed_root: 'encrypted' });
  const link = find(fixture.panel, 'Save passkey-bound backup');
  assert.equal(link.download, 'aukora-envelope-passkey-v2.json');
  assert.equal(link.clicked, true);
  fixture.timers.forEach(callback => callback());
});

test('antibody_ui_backup_keeps_phrase_only_copy_explicitly_warned_and_available', t => {
  const fixture = setup(t);
  addBackupControls(fixture.panel);
  const recovery = find(fixture.panel, 'Download phrase-only recovery copy');
  assert.equal(recovery.href, '/api/binding/envelope');
  assert.equal(recovery.download, 'aukora-envelope.json');
  const warning = all(fixture.panel).find(element => element.textContent?.startsWith('Optional phrase-only'))?.textContent;
  assert.ok(warning?.includes('guess your phrase offline'));
  assert.ok(warning?.includes('without the passkey or node guess limits'));
  assert.ok(warning?.includes('Store it like cash'));
  const note = all(fixture.panel).find(element => element.textContent?.startsWith('A passkey-bound backup'))?.textContent;
  assert.ok(note?.includes('Losing access to the passkey makes this backup unusable'));
  const nav = new Element('nav');
  addOwnerLinks(nav);
  assert.equal(nav.children.find(element => element['aria-label'] === 'identity backup').href, '#/identity');
  assert.equal(fixture.requests.length, 0);
});
