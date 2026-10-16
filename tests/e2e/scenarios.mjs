// SPDX-License-Identifier: AGPL-3.0-or-later
import { createHash } from 'node:crypto';

const APPS = ['Auma Lingwa', 'Auma Live', 'Zeta Harp', 'Human Graph', 'Media', 'Memory', 'Messages', 'Documents'];
const SYSTEM = ['AUMLOK', 'Identity', 'Aura Coherence', 'General', 'Models', 'Plugins', 'Agent presets', 'Archived sessions'];

function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }
function sameList(c, id, actual, expected) {
  c.require(id, Array.isArray(actual) && actual.length === expected.length);
  expected.forEach((value, index) => c.same(`${id}-${index}`, actual[index], value));
}
async function unchanged(c, id, prompt) {
  const before = await c.digest(`${id}-before`, `${prompt} Enter the independently measured target digest before the attempt.`);
  await c.witness(`${id}-attempt`, 'Perform the named hostile attempt on this disposable acceptance node. Observe the refusal and inspect the actual target afterward; a queued proposal is not an effect.');
  const after = await c.digest(`${id}-after`, 'Enter the independently measured target digest after the refused attempt.');
  c.same(`${id}-unchanged`, before, after);
  c.same(`${id}-effects`, await c.integer(`${id}-writes`, 'Enter the observed effect count caused by this attempt.'), 0);
}
async function relativeFile(c, id, prompt) {
  const value = await c.text(id, prompt);
  c.require(`${id}-relative`, !value.startsWith('/') && !value.startsWith('~') && !value.includes('\\')
    && !value.split('/').includes('..') && !value.includes('\0'));
  return value;
}
async function nodeIdentity(c, prefix) {
  const node = await c.text(`${prefix}-node`, 'Enter this running node public id: 32 lowercase hexadecimal characters.');
  c.require(`${prefix}-node-format`, /^[0-9a-f]{32}$/.test(node));
  const key = await c.digest(`${prefix}-aura-key`, 'Enter its independently retained public Aura signing key, not a key read only from its export.');
  const subject = await c.text(`${prefix}-subject`, 'Enter its public bound owner subject (aukora:1: followed by 64 lowercase hexadecimal characters).');
  c.require(`${prefix}-subject-format`, /^aukora:1:[0-9a-f]{64}$/.test(subject));
  const vm = await c.text(`${prefix}-vm`, 'Enter the independently inspected VM instance id of this node. A different process or browser profile in the same VM is insufficient.');
  return { node, key, subject, vm };
}

export async function m1(c) {
  c.step('m1-one-link');
  const response = await c.http(c.shell, '/');
  c.same('m1-shell-status', response.status, 200);
  c.require('m1-shell-html', (response.headers.get('content-type') ?? '').includes('text/html'));
  c.require('m1-shell-root', response.body.toString('utf8').includes('id="aukora-shell"'));
  sameList(c, 'm1-app-lock-keys', Object.keys(c.appLock ?? {}).sort(), ['aukora_apps', 'schema', 'system']);
  c.same('m1-app-lock-schema', c.appLock?.schema, 'aukora-app-lock-v1');
  sameList(c, 'm1-app-lock-apps', c.appLock.aukora_apps, APPS);
  sameList(c, 'm1-app-lock-system', c.appLock.system, SYSTEM);
  await c.witness('m1-fresh-bootstrap', `Open ${c.shell.href} in Peter's actual browser on this fresh unclaimed acceptance node. Independently confirm no previous owner binding or claim, and that the agent has not started. Existing sign-in or a prior ceremony does not satisfy a fresh-node claim.`);
  await c.witness('m1-claim-passkey-phrase', 'Use this fresh node issued one-time claim fragment, then perform real passkey enrolment and the seven-word binding ceremony inside the shell-created owner frame. Observe the bound state. Never enter the phrase, claim secret or credential private material into this runner.');
  await c.witness('m1-release-popup', 'Observe the release approval opening automatically inside the app. The owner approves its exact displayed release bytes with the real passkey; observe the running release admission afterward.');
  const approved = await c.digest('m1-approved-release', 'Enter the release digest the owner actually approved.');
  const running = await c.digest('m1-running-release', 'Independently inspect the loaded installed release and enter its digest. A checkout revision or installation record alone is insufficient.');
  c.same('m1-release-matches', approved, running);
  await c.witness('m1-spatial-browser', `After binding and release admission, observe the signed-in Spatial app on ${c.shell.href} with Threads, App, and Apps and System lanes. HTTP 200 alone is insufficient.`);
  for (const [section, titles] of [['AUKORA APPS', APPS], ['SYSTEM', SYSTEM]]) {
    for (const [index, title] of titles.entries()) {
      const id = `m1-${section === 'SYSTEM' ? 'system' : 'app'}-${index}`;
      await c.witness(id, `Find ${title} visibly registered under ${section}. Open it from that menu and inspect the actual rendered face and its purpose. A hidden entry, blank frame, waiting plugin, generic placeholder, or failed startup does not satisfy this observation. A documented unavailable backend may be labelled plainly inside a functioning face.`);
      await c.text(`${id}-heading`, `Enter the actual visible heading in the opened ${title} face. The menu title and internal heading may differ.`);
    }
  }
  await c.witness('m1-frame-boundary', 'Observe that the passkey and phrase panes are framed by the root shell, not opened by a face or redirected to a second page. No phrase or credential material appears in the shell or Auma conversation.');
  await c.witness('m1-unbound-cage', 'On a separate fresh unbound acceptance node, observe that only binding screens are admitted and no agent process starts. Do not clear or unbind the owner node to create this control.');
  await c.reviewFindings();
}

export async function m4(c) {
  c.step('m4-reboot');
  const bootBefore = await c.text('m4-boot-before', 'Enter the actual host kernel boot id before the reboot. A process start time is insufficient.');
  c.require('m4-boot-before-format', /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(bootBefore));
  const note = await c.text('m4-note-id', 'Enter the id of a saved acceptance note whose semantic recall was observed before reboot. Do not enter private note text.');
  const cite = await c.integer('m4-citation-before', 'Enter its original durable Aura citation sequence.', 1);
  const demoted = await c.text('m4-demoted-id', 'Enter a separate note id visibly demoted before reboot.');
  c.different('m4-distinct-notes', note, demoted);
  const floor = await c.digest('m4-floor-before', 'Enter the exact durable release-floor object digest before reboot.');
  const target = await c.digest('m4-target-before', 'Enter the measured target digest of an already applied, spent approval.');
  await c.witness('m4-actual-reboot', 'The operator now performs a real reboot of the same node disk through the normal operating route. Reconnect to its installed app; a supervisor restart, upgrade, restored snapshot or cloned disk does not satisfy this step.');
  const bootAfter = await c.text('m4-boot-after', 'Enter the host kernel boot id observed after reconnecting.');
  c.require('m4-boot-after-format', /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(bootAfter));
  c.different('m4-new-kernel-boot', bootBefore, bootAfter);
  const response = await c.http(c.shell, '/');
  c.same('m4-shell-returned', response.status, 200);
  await c.witness('m4-persistent-signin', 'Observe that the same browser remains signed in and the same binding is present after the reboot.');
  await c.witness('m4-semantic-recall', 'Ask Auma for the saved note by meaning, using different words from its saved text. Inspect the returned note and original citation; a transcript echo is insufficient.');
  c.same('m4-note-preserved', await c.text('m4-recalled-note', 'Enter the recalled note id.'), note);
  c.same('m4-citation-preserved', await c.integer('m4-citation-after', 'Enter the recalled Aura citation sequence.', 1), cite);
  await c.witness('m4-demotion-preserved', 'Inspect Forgotten and recall behavior. The demoted note remains demoted; its private text is absent from Forgotten and active semantic recall.');
  c.same('m4-demoted-id-preserved', await c.text('m4-demoted-after', 'Enter the retained demoted note id.'), demoted);
  c.same('m4-floor-preserved', await c.digest('m4-floor-after', 'Enter the independently measured durable release-floor object digest after reboot.'), floor);
  await c.witness('m4-spent-replay', 'Replay the exact already consumed approval through the installed normal apply route. Observe its refusal; do not generate a fresh approval.');
  c.same('m4-replay-effects', await c.integer('m4-replay-writes', 'Enter the observed additional write count for that operation.'), 0);
  c.same('m4-target-preserved', await c.digest('m4-target-after', 'Enter the actual target digest after the spent replay.'), target);
  await c.witness('m4-approval-terminal', 'Inspect the durable operation record after reboot and replay: its consumed state remains spent and exactly one terminal row exists.');
  c.same('m4-terminal-once', await c.integer('m4-terminal-count', 'Enter that operation terminal row count.'), 1);
}

export async function m5(c) {
  c.step('m5-stranger');
  await c.witness('m5-empty-folder', 'Prepare an empty stranger workspace containing only the installed release verifier and the exported cold bundle plus independently retained public key and covering checkpoint. The stranger has no node credentials and makes no node or relay connection during verification.');
  const bundle = await relativeFile(c, 'm5-bundle', 'Enter the existing cold bundle path relative to this runner working directory.');
  const key = await relativeFile(c, 'm5-key', 'Enter the existing independently retained public signing-key file path, relative to this runner.');
  const checkpoint = await relativeFile(c, 'm5-checkpoint', 'Enter the existing independently retained covering checkpoint file path, relative to this runner.');
  await c.verifier(bundle, key, checkpoint);
  for (const [id, description, verdict] of [
    ['forged-key', 'an independently prepared wrong public signing-key file', 'KEY_MISMATCH'],
    ['edited-history', 'an independently prepared canonical export with one signed row body changed and its original hash and signature retained', 'REWRITTEN'],
    ['truncated-export', 'an independently prepared valid-prefix export omitting a signed tail covered by the retained checkpoint', 'REWRITTEN'],
  ]) {
    const twin = await relativeFile(c, `m5-${id}-file`, `Enter the existing relative path for ${description}. The runner does not create mutation artifacts.`);
    if (id === 'forged-key') await c.verifierRefuses(bundle, twin, checkpoint, verdict);
    else await c.verifierRefuses(twin, key, checkpoint, verdict);
  }
  await c.witness('m5-two-canvases', 'Open Aura Coherence. Observe separate canvases labelled Organ health and Aura fingerprint. The fingerprint derives from the Aura root, never from a health cell or health snapshot.');
  c.same('m5-health-title', await c.text('m5-health-label', 'Enter the first canvas visible label.'), 'Organ health');
  c.same('m5-fingerprint-title', await c.text('m5-fingerprint-label', 'Enter the other canvas visible label.'), 'Aura fingerprint');
  c.same('m5-private-count', await c.integer('m5-private-cells', 'Enter the displayed private check count; inspect all five organs.'), 90);
  c.same('m5-corner-count', await c.integer('m5-corner-cells', 'Enter the displayed shared-corner check count.'), 20);
  const verified = await c.integer('m5-verified', 'Enter the displayed verified cell total.');
  const undetermined = await c.integer('m5-undetermined', 'Enter the displayed undetermined cell total.');
  const failed = await c.integer('m5-failed', 'Enter the displayed failed cell total.');
  c.same('m5-all-cells-counted', verified + undetermined + failed, 110);
  c.same('m5-no-unwritten-checks', await c.integer('m5-unwritten', 'Inspect the installed check implementations and live snapshot reasons. Enter the number of unwritten check implementations; a missing optional source must be labelled separately from an unwritten check.'), 0);
  await c.witness('m5-independent-sources', 'Inspect the live snapshot and source details: each organ has 18 implemented checks and each pair has two registered corners with two independent observer sources. Only a matching pair of fresh successful reports becomes verified; absence, unavailable optional sources, stale reports and invariant failures remain explicitly undetermined or failed with reasons. No unwritten implementation counts as a real check. The centre cell has no group.');
  await c.witness('m5-health-failure-twin', 'On a disposable acceptance node, stop one observer or present stale evidence through the host driver. Observe a dim undetermined or red failed cell, a named reason, and no healthy substitute. Restore that observer afterward.');
  await c.witness('m5-health-not-authority', 'With that failed health observation, attempt the same unapproved change through the normal gate. Observe zero effects; changing health or its picture never authorizes an effect.');
  c.same('m5-health-zero-effects', await c.integer('m5-unapproved-effects', 'Enter the observed effect count of that unapproved request.'), 0);
}

function publicRelay(c, id, value) {
  let url;
  try { url = new URL(value); } catch { c.require(id, false); return; }
  const host = url.hostname.toLowerCase();
  c.require(id, url.protocol === 'wss:' && !url.username && !url.password && !url.hash
    && host.includes('.') && !host.endsWith('.local') && !host.endsWith('.localhost')
    && host !== 'localhost' && !/^\d+(?:\.\d+){3}$/.test(host) && !host.includes(':'));
}

export async function m6(c) {
  c.step('m6-public-relays');
  c.require('m6-peer-configured', c.peerShell instanceof URL && c.peerOwner instanceof URL);
  c.different('m6-independent-shells', c.shell.origin, c.peerShell.origin);
  c.same('m6-peer-reachable', (await c.http(c.peerShell, '/')).status, 200);
  const relay = await c.text('m6-relay-url', 'Enter the public wss relay URL actually used by both installed nodes.');
  publicRelay(c, 'm6-public-relay-url', relay);
  await c.witness('m6-no-node-relay', 'Inspect both actual nodes and their configured transport: neither runs a relay, both connect through the allowlisted public relay, and neither Auma guest opens a socket. A local broker masquerading as a public relay does not qualify.');
  const a = await c.digest('m6-person-a', 'Enter node A owner person-Nostr x-only public key.');
  const b = await c.digest('m6-person-b', 'Enter node B owner person-Nostr x-only public key.');
  c.different('m6-distinct-people', a, b);
  await c.witness('m6-contact-cards', 'On both nodes approve the exact reciprocal contact cards with the respective owners passkeys. The pending cards alone must not create approved contacts.');
  for (const [id, from, to] of [['a-to-b', 'A', 'B'], ['b-to-a', 'B', 'A']]) {
    await c.witness(`m6-${id}-send`, `From node ${from} Messages send a fresh non-secret acceptance message to ${to} through the exact passkey-approved send card. Inspect its approved message digest and real relay publication receipt.`);
    const sent = await c.digest(`m6-${id}-sent`, 'Enter the approved plaintext message digest. Do not enter message plaintext.');
    const event = await c.digest(`m6-${id}-event`, 'Enter the actual gift-wrap event id acknowledged by the public relay.');
    await c.witness(`m6-${id}-receive`, `On node ${to}, observe the same fresh message in Messages, with sender ${from}, its citation and the input label that it is data from a contact, not the owner.`);
    c.same(`m6-${id}-content-matches`, await c.digest(`m6-${id}-received`, 'Enter the received plaintext message digest.'), sent);
    c.same(`m6-${id}-event-matches`, await c.digest(`m6-${id}-received-event`, 'Enter the received gift-wrap event id.'), event);
    await c.integer(`m6-${id}-citation`, 'Enter its durable inbound receipt sequence.', 1);
  }
  await c.witness('m6-stranger-twin', 'A separate unapproved identity sends a fresh message to the node. Observe refusal before Auma sees it, an incremented durable refusal count, and its health-map evidence.');
  c.same('m6-stranger-deliveries', await c.integer('m6-stranger-seen', 'Enter the number of stranger messages delivered to Auma.'), 0);
  await unchanged(c, 'm6-inbound-instruction', 'Send an approved-contact message that asks Auma to perform an unapproved target change; it remains data rather than owner authority.');
}

async function coreLines(c, prefix, label) {
  await c.witness(`${prefix}-a1`, `On independent node ${label}, observe a fresh real provider answer with a broker receipt matching that answer and the requested/reported/verified model identity. Its owner has approved the exact spend grant with a real passkey.`);
  const grant = await c.integer(`${prefix}-grant`, `Enter node ${label} grant budget in integer microusd.`, 1);
  const before = await c.integer(`${prefix}-spent-before`, 'Enter cumulative settled cost before the call.');
  const after = await c.integer(`${prefix}-spent-after`, 'Enter cumulative settled cost after the call.');
  const cost = await c.integer(`${prefix}-cost`, 'Enter the fresh call actual charged receipt cost.');
  c.same(`${prefix}-charge-matches`, after - before, cost);
  c.require(`${prefix}-inside-grant`, before <= after && after <= grant);
  await c.integer(`${prefix}-receipt`, 'Enter the durable broker settlement receipt sequence.', 1);
  await unchanged(c, `${prefix}-unapproved`, `On node ${label}, submit a harmless theme change without approval.`);
  await c.witness(`${prefix}-a2`, `On node ${label}, propose a fresh harmless theme change through its confined agent and pinned cell. Inspect the canonical card and approve its exact bytes with that node owner's real passkey; observe the one live effect and retain the receipt and covering head.`);
  const displayed = await c.digest(`${prefix}-displayed`, 'Enter the card canonical display_sha256 actually shown.');
  c.same(`${prefix}-display-bound`, await c.digest(`${prefix}-approved-display`, 'Enter display_sha256 bound in the verified owner authorization.'), displayed);
  const approved = await c.digest(`${prefix}-approved-target`, 'Enter the exact new target bytes digest bound in that authorization.');
  c.same(`${prefix}-target-exact`, await c.digest(`${prefix}-actual-target`, 'Enter the independently measured live target bytes digest.'), approved);
  c.same(`${prefix}-applied-once`, await c.integer(`${prefix}-effect-count`, 'Enter this operation observed effect count.'), 1);
  c.same(`${prefix}-terminal-once`, await c.integer(`${prefix}-terminal-count`, 'Enter this operation durable terminal row count.'), 1);
  return await c.digest(`${prefix}-retained-head`, 'Enter the independently retained covering Aura head hash.');
}

export async function m7(c) {
  c.step('m7-independent-node');
  c.require('m7-peer-configured', c.peerShell instanceof URL && c.peerOwner instanceof URL);
  c.different('m7-independent-origins', c.shell.origin, c.peerShell.origin);
  await c.witness('m7-invite-provision', `Issue a valid 48-hour invite through the owner-approved path. On the deployment page consume it to allocate one fresh independent VM through the guarded provisioner at ${c.peerShell.origin}. Observe the allocation, provenance and conserved allowance; a pre-existing copied node does not qualify.`);
  c.same('m7-peer-shell', (await c.http(c.peerShell, '/')).status, 200);
  await c.witness('m7-copresence-joining', `The new owner completes the joining co-presence ceremony with their own two devices, then phrase and real passkey at ${c.peerShell.origin}. Inspect the signed receipt, fixed method, intent acknowledgement, nonce and both timestamps; a remote pairing is never labelled met in person.`);
  await c.witness('m7-peer-installed-release', 'Inspect node B actual serving process, loaded executable and served asset manifest. Independently measure their installed commit and confirm owner approval; its checkout or installation record alone is insufficient.');
  c.same('m7-peer-release-matches', await c.text('m7-peer-running-release', 'Enter the full commit observed in node B loaded executable and served assets.'), c.flags.release);
  const first = await nodeIdentity(c, 'm7-a');
  const second = await nodeIdentity(c, 'm7-b');
  for (const field of ['node', 'key', 'subject', 'vm']) c.different(`m7-independent-${field}`, first[field], second[field]);
  await c.witness('m7-no-copied-state', 'Independently inspect provisioning: no disk, browser session, key file, binding, grant, proposal, floor or Aura state was copied between these nodes. Each has its own instance and identity.');
  const coveringHeads = new Map();
  coveringHeads.set('a', await coreLines(c, 'm7-a', 'A'));
  coveringHeads.set('b', await coreLines(c, 'm7-b', 'B'));
  const exports = [];
  for (const label of ['a', 'b']) {
    const bundle = await relativeFile(c, `m7-${label}-bundle`, `Enter node ${label.toUpperCase()} existing cold bundle relative path.`);
    const key = await relativeFile(c, `m7-${label}-key-file`, `Enter node ${label.toUpperCase()} independently retained public signing-key file relative path.`);
    const checkpoint = await relativeFile(c, `m7-${label}-checkpoint`, `Enter node ${label.toUpperCase()} independently retained covering checkpoint relative path.`);
    await c.verifier(bundle, key, checkpoint, 'VERIFIED', coveringHeads.get(label));
    exports.push({ bundle, key, checkpoint });
  }
  for (const [own, other] of [[0, 1], [1, 0]]) {
    await c.verifierRefuses(exports[own].bundle, exports[other].key, exports[own].checkpoint, 'KEY_MISMATCH');
  }
  await c.crossNode();
  await c.witness('m7-other-proof-refused', 'Submit node A exact owner authorization and assertion bytes to node B through its installed apply route, then repeat B to A. Observe both refusals against the actual node binding and inspect both targets. A cold verifier key mismatch alone is insufficient.');
  c.same('m7-a-foreign-proof-effects', await c.integer('m7-a-foreign-writes', 'Enter actual effects on A from B foreign proof.'), 0);
  c.same('m7-b-foreign-proof-effects', await c.integer('m7-b-foreign-writes', 'Enter actual effects on B from A foreign proof.'), 0);
  await c.witness('m7-invite-reuse-refused', 'Retry the consumed invite with a different allocation request and the already used claim on the other node. Observe refusal with no additional allocation and no binding.');
  c.same('m7-extra-allocations', await c.integer('m7-allocation-increase', 'Enter additional allocations caused by the replay.'), 0);
  await c.witness('m7-bloom-person-keys', 'Observe the relationship bloom derives from the two sorted person-Nostr keys and matches on both screens. With either person key unavailable it displays nothing; node ids, device keys and receipt hashes do not stand in.');
}

export async function m8(c) {
  c.step('m8-home-base');
  await c.witness('m8-site-proposal', 'Ask confined Auma for a fresh acceptance website. Inspect the gate proposal with its exact bundle digest and separate address. Before approval, request that address and observe no proposed content served.');
  c.same('m8-unapproved-publications', await c.integer('m8-preapproval-publishes', 'Enter the number of proposed-site publications before owner approval.'), 0);
  const siteText = await c.text('m8-site-origin', 'Enter the approved site HTTPS origin, without a path or query.');
  let site;
  try { site = new URL(siteText); } catch { c.require('m8-site-url', false); return; }
  c.require('m8-site-origin-shape', site.protocol === 'https:' && site.pathname === '/' && !site.search && !site.hash && !site.username && !site.password);
  c.different('m8-third-origin-shell', site.origin, c.shell.origin);
  c.different('m8-third-origin-owner', site.origin, c.owner.origin);
  const approvedBundle = await c.digest('m8-approved-bundle', 'Enter the exact website bundle digest on its owner-approved passkey card.');
  await c.witness('m8-site-approved', 'The owner approves that exact bundle and address with a real passkey. Observe the website live on its own host and inspect the publication receipt.');
  c.same('m8-published-bundle', await c.digest('m8-live-bundle', 'Enter the immutable published bundle digest from the actual serving installation.'), approvedBundle);
  const approvedIndex = await c.digest('m8-approved-index', 'Enter the exact approved index document byte digest from that bundle.');
  const response = await c.siteHttp(site, '/');
  c.same('m8-live-site-status', response.status, 200);
  c.same('m8-exact-served-bytes', sha256(response.body), approvedIndex);
  c.require('m8-no-site-cookie', response.headers.get('set-cookie') === null);
  c.require('m8-no-site-framing', /(?:^|;)\s*frame-ancestors\s+'none'\s*(?:;|$)/.test(response.headers.get('content-security-policy') ?? ''));
  await c.witness('m8-site-boundary', 'In the browser inspect the third host: no owner cookies, WebAuthn, ceremony frame or Auma network grant; its content never replaces or executes inside the one-link shell.');
  await unchanged(c, 'm8-altered-site', 'Attempt to publish altered website bytes using the original approval.');
  await c.witness('m8-catalog-discovery', 'Find a newly published third-party app through the public Nostr catalog, verify its author signature and exact package digest, and independently confirm that package is absent from this installed release. A shipped stock face or rating is insufficient.');
  const publication = await c.digest('m8-publication', 'Enter the actual catalog publication event id.');
  const packageDigest = await c.digest('m8-catalog-package', 'Enter its signed package digest.');
  await c.witness('m8-app-pending', 'Request installation from that catalog entry. Observe the exact bytes and grants card, still pending with no app cage or mounted app before approval. Manifest grants are only app.storage.read, app.storage.write, app.clock and app.random; they map to storage.read, storage.write, clock.now and random.bytes. No passkey, gate, broker, Aura append or network grant is permitted.');
  c.same('m8-preapproval-app-effects', await c.integer('m8-pending-effects', 'Enter app installation effects before approval.'), 0);
  await c.witness('m8-one-app-approval', 'The owner approves the exact catalog package and grants once with a real passkey. Open it from the store in the tri-pane and inspect its isolated face and dedicated app cage, separate from Auma and wasmcell, with no network, exec or WASI.');
  c.same('m8-exact-install-package', await c.digest('m8-installed-package', 'Enter the installed receipt package digest.'), packageDigest);
  c.same('m8-origin-publication', await c.digest('m8-installed-publication', 'Enter the installed receipt catalog publication event id.'), publication);
  c.same('m8-install-approval-once', await c.integer('m8-install-approvals', 'Enter the number of owner approvals used for this installation.'), 1);
  c.same('m8-install-effect-once', await c.integer('m8-install-effects', 'Enter the actual completed installation effect count.'), 1);
  await c.witness('m8-app-hostile-twins', 'With the host driver, attempt a modified package under the original signature, replay the consumed installation approval, request a forbidden grant and have the app attempt network and exec. Observe refusal in every case and no second install or escape.');
  c.same('m8-hostile-effects', await c.integer('m8-hostile-additional-effects', 'Enter additional installs or escaped effects caused by these attacks.'), 0);
}
