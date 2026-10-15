// SPDX-License-Identifier: AGPL-3.0-or-later
import { readFile, lstat } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { strictJSON } from './codec.mjs';

const findings = [
  ['ingress-surface', 'Exercise every frozen shell face/data endpoint through its bound session and every owner ceremony endpoint on the owner origin. Owner ceremony routes on the shell and unknown operations must refuse; a face must not become a ceremony parent.'],
  ['proxy-forwarded', 'Inspect the running proxy configuration: it strips client Forwarded and forwarded host/proto claims, sets its own HTTPS proto, and backend admission uses the actual configured proxy peer. Probe spoofed client headers through the public proxy.'],
  ['ingress-overload', 'Exhaust the disposable node ingress admission limit and deadline independently. Observe frontdoor:overloaded and frontdoor:request-timeout rather than reporting malformed JSON. Restore availability and prove a legitimate request succeeds.'],
  ['success-schema', 'Compare claim success, sign-in finish and durable session schema with the conductor-pinned success vectors. Duplicate/unknown fields refuse where the schema requires; stop if any required vector is absent.'],
  ['signin-subject', 'Attempt sign-in with BindingOnly scope or no passkey subject. Neither attempt may create an owner cookie. Complete a real owner-frame sign-in as the positive control.'],
  ['frame-parent', 'Open the owner ceremony as a top-level page, a face child, and a sibling path/query on the shell host. All refuse. Only the shell root creates the frame, with its exact HTTPS root Referer and expected top origin.'],
  ['portal-isolation', 'Attempt portal and joining content through the node link, including manifest paths and direct aliases. They refuse. The separate co-presence origin remains separate; it is never a second page on the node link.'],
  ['manifest-strict', 'Present disposable approved-manifest candidates with duplicate decoded path/sha256 keys, an escaped duplicate key, an unknown outer key, and an unknown entry key. Each refuses before any candidate asset is trusted. The normal approved manifest serves as control.'],
  ['action-count', 'Reject a phi_guard preset/mode check and inspect the resulting guard evidence: it stays Failed and does not increment checks_passed. A permitted request increments only after passing.'],
  ['model-tools', 'In a chat session declare build-only propose/read/memory.put tools; the model tool declaration filter and dispatch both refuse the disallowed capabilities. Use the permitted preset/mode as control.'],
  ['request-bytes', 'Compare the action guard request digest with the exact outgoing frame bytes if that digest is displayed as the request commitment. An invented guard id or re-encoded substitute must not be presented as owner authorization.'],
  ['model-refusal', 'Receive a pre-start broker refusal in a real turn; the active slot clears, no fabricated stream starts, and a subsequent separately granted turn can start. Confirm the installed loop was compiled and is the one serving this turn.'],
  ['early-cancel', 'Cancel model startup before model.start. Observe the matching cancelled receipt at next index zero and both correlations closed; retrying/cancelling an unknown id refuses.'],
  ['delta-window', 'Withhold delta acknowledgement on a disposable stream: the window does not advance. Only acknowledging the correlated delta advances it; a default-success link must not bypass accounting.'],
  ['aura-head', 'Supply gap, broken previous-link, wrong head hash and mismatched context commitment proofs. Chain-head, consumption and terminal health checks must not become Verified. A complete gap-free signed chain is the positive control. Health evidence grants no authority.'],
  ['declined-evidence', 'Repropose a declined target with a body evidence_sha256 string but no later matching evidence row: it refuses. A later real evidence row whose row hash matches change.current is the control.'],
];

export async function boundary(c) {
  const json = { 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' };
  c.refusal('owner-route-on-shell', await c.http(c.shell, '/api/claim', {
    method: 'POST', headers: { ...json, origin: c.shell.origin }, body: '{"token":"disposable"}',
  }), 'frontdoor:unknown-route');
  c.refusal('wrong-owner-origin', await c.http(c.owner, '/api/claim', {
    method: 'POST', headers: { ...json, origin: c.shell.origin }, body: '{"token":"disposable"}',
  }), 'frontdoor:origin-refused');
  c.refusal('cross-site-owner', await c.http(c.owner, '/api/claim', {
    method: 'POST', headers: { ...json, origin: c.owner.origin, 'sec-fetch-site': 'cross-site' }, body: '{"token":"disposable"}',
  }), 'frontdoor:fetch-site-refused');
  c.refusal('duplicate-json', await c.http(c.owner, '/api/claim', {
    method: 'POST', headers: { ...json, origin: c.owner.origin }, body: '{"token":"disposable","token":"other"}',
  }), 'frontdoor:body-invalid');
  c.refusal('owner-top-page', await c.http(c.owner, '/', {
    headers: { 'sec-fetch-dest': 'document', referer: `${c.shell.origin}/` },
  }), 'frontdoor:origin-refused');
  for (const [id, suffix] of [['face', '/app/lingwa'], ['query', '/?face=lingwa']]) {
    c.refusal(`owner-parent-${id}`, await c.http(c.owner, '/', {
      headers: { 'sec-fetch-dest': 'iframe', referer: `${c.shell.origin}${suffix}` },
    }), 'frontdoor:origin-refused');
  }
  c.refusal('unknown-owner-operation', await c.http(c.owner, '/api/acceptance-unknown', {
    method: 'POST', headers: { ...json, origin: c.owner.origin }, body: '{}',
  }), 'frontdoor:unknown-route');
  for (const path of ['/portal/', '/portal/index.html']) {
    const response = await c.http(c.shell, path);
    c.require('portal-not-served', response.status >= 400 && response.status < 600);
  }
}

export async function reviewFindings(c) {
  await boundary(c);
  for (const [id, instruction] of findings) {
    await c.witness(`review-${id}`, `Recheck the supplied post-merge finding on the installed new code. ${instruction} A source review alone does not satisfy this observation.`);
  }
  const name = c.flags.findings;
  c.require('archive-46-index-required', typeof name === 'string' && name.length > 0
    && !isAbsolute(name) && !name.split(/[\\/]/).includes('..'));
  const path = resolve(name);
  c.require('archive-46-index-regular', (await lstat(path)).isFile());
  const bytes = await readFile(path);
  c.require('archive-46-index-bounded', bytes.length <= 65_536);
  let index;
  try { index = strictJSON(bytes); } catch { c.require('archive-46-index-json', false); }
  c.require('archive-46-index-object', index !== null && typeof index === 'object' && !Array.isArray(index));
  c.same('archive-46-index-keys', Object.keys(index).sort().join(','), 'ids,schema,source');
  c.same('archive-46-index-version', index.schema, 'aukora-review-46-index-v1');
  c.same('archive-46-index-source', index.source, 'archive-issue-46');
  c.require('archive-46-index-ids', Array.isArray(index.ids) && index.ids.length > 0 && index.ids.length <= 256
    && index.ids.every(id => typeof id === 'string' && /^[A-Za-z0-9._:-]{1,80}$/.test(id))
    && new Set(index.ids).size === index.ids.length);
  await c.witness('archive-46-complete', 'Independently open the complete original archive issue 46 and compare every open finding with the supplied index. Confirm no open finding is missing. Stop if that original issue or its complete inventory cannot be obtained. This is a human completeness attestation, not machine-verified archival coverage.');
  for (const [position, id] of index.ids.entries()) {
    await c.witness(`archive-46-${position}`, `Reproduce archive issue 46 finding ${id} against this installed release using its original trigger. Observe that the unsafe behavior is refused and its legitimate control still works. Preserve the exact refusal and uncertainty on the issue; do not declare an unmeasured case fixed.`);
  }
}
