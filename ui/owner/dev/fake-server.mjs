/* Dev fake server for ui/owner — node built-ins only, no framework.
   Implements plan/OWNER-API.md with fixtures so every screen can be clicked
   through locally. WebAuthn cannot run without a real authenticator, so every
   passkey point answers with "dev_bypass": true (honoured on localhost only).
   Run:  node ui/owner/dev/fake-server.mjs [port]     then open http://localhost:8787
   Fork demo: FORK=1 node ui/owner/dev/fake-server.mjs  (serves a conflicting log) */

import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { createHash, randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { canonicalJSON } from '../canon.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = process.argv[2] === undefined ? 8787 : Number(process.argv[2]);
const FORK = process.env.FORK === '1';
const CONFLICT = process.env.CONFLICT === '1';

const sha256 = bytes => createHash('sha256').update(bytes).digest();
const hex = b => Buffer.from(b).toString('hex');
const b64url = b => Buffer.from(b).toString('base64url');

// ---------------------------------------------------------------- fixtures
const NODE_ID = 'a1b2c3d4e5f60708';
const SUBJECT = 'aukora:1:' + '0f'.repeat(32);

const PHRASE = ['planet', 'pine', 'linden', 'accord', 'neighbor', 'eclipse', 'terraform'];
const REPLACEMENT = ['silver', 'spruce', 'iris', 'laughter', 'village', 'enlighten', 'rocket'];
let currentPhrase = PHRASE.join(' ');
const ENTROPY_BITS = 68; // fixture; the real server computes this over the composed lists

const CARDS = [
  {
    id: randomBytes(16).toString('hex'),
    card: {
      v: 1,
      risk: 'routine',
      says: 'Write a new note in the workspace readme',
      facts: [['target', 'workspace/README.md'], ['base', 'present'], ['cell', 'none']],
      from_to: { 'workspace/README.md': { from: '# notes\n', to: '# notes\n\n- the harbour at dawn\n' } },
      model_note: 'I think this makes the readme <b>warmer</b> & more welcoming — "trust me".',
    },
  },
  {
    id: randomBytes(16).toString('hex'),
    card: {
      v: 1,
      risk: 'critical',
      says: 'Replace the gate policy file',
      facts: [['target', 'config/gate.policy'], ['base', 'present'], ['irreversible', 'no']],
      from_to: {
        'config/gate.policy': {
          from: 'deny  --all\nallow owner\n',
          to: 'allow --all\n</pre><script>alert(1)</script>\nline 3\u2028with separators',
        },
      },
      model_note: 'Routine tidy-up.\n\nNothing to see here &amp; certainly no injection: </pre><img src=x onerror=alert(2)>',
    },
  },
];

const NOTES = [
  { note_id: '01'.repeat(16), text: 'Peter prefers the harbour side desk in winter.', cite_seq: 41, tier: 'owner' },
  { note_id: '02'.repeat(16), text: 'The neighbour’s boat is called Vagabond.', cite_seq: 55, tier: 'owner' },
  { note_id: '03'.repeat(16), text: 'Draft summary of the week, written by the model.', cite_seq: 62, tier: 'model' },
  { note_id: '04'.repeat(16), text: 'Old imported note from the previous machine.', cite_seq: 12, tier: 'imported' },
];

// ------------------------------------------------------------- fixture log
const ENTRY_KINDS = ['boot.facts', 'aumlok.enrol', 'aumlok.bind', 'gate.propose', 'gate.review',
  'gate.consume', 'gate.apply', 'kira.save', 'kira.demote', 'broker.grant', 'sandbox.start'];
const LEAVES = [];
for (let i = 1; i <= 32; i++) {
  const entryHash = sha256(`dev-entry-${FORK && i > 8 ? 'fork' : 'main'}-${i}`);
  LEAVES.push(sha256(Buffer.concat([Buffer.from([0x00]), entryHash]))); // rfc6962 leaf
  LEAVES[LEAVES.length - 1].entryHash = entryHash;
}

const node = (l, r) => sha256(Buffer.concat([Buffer.from([0x01]), l, r]));
const split = size => { let k = 1; while (k * 2 < size) k *= 2; return k; };
function treeHead(leaves) {
  if (leaves.length === 1) return leaves[0];
  const k = split(leaves.length);
  return node(treeHead(leaves.slice(0, k)), treeHead(leaves.slice(k)));
}
// RFC 6962 §2.1.2 SUBPROOF (aukora-prime scripts/aura/verify-append-only.mjs)
function subproof(m, leaves, complete) {
  if (m === leaves.length) return complete ? [] : [treeHead(leaves)];
  const k = split(leaves.length);
  if (m <= k) return [...subproof(m, leaves.slice(0, k), complete), treeHead(leaves.slice(k))];
  return [...subproof(m - k, leaves.slice(k), false), treeHead(leaves.slice(0, k))];
}

const STARTED = Date.now();
const treeSize = () => Math.min(32, 8 + Math.floor((Date.now() - STARTED) / 15000));

function presentedHead(since) {
  const n = treeSize();
  const m = Number.isInteger(since) && since > 0 && since <= n ? since : Math.max(1, n - 3);
  const leaves = LEAVES.slice(0, n);
  const entryHash = LEAVES[n - 1].entryHash;
  return {
    schema: 'aukora-aura-presented-head-v1',
    leafConvention: 'rfc6962-leaf-sha256-0x00-prefixed-v1',
    treeSize: n,
    root: hex(treeHead(leaves)),
    sequence: n,
    hash: hex(entryHash),
    sig: b64url(sha256(`dev-sig-${hex(entryHash)}`)), // fixture, not a real signature
    retainedTreeSize: m,
    proofFromPrevious: m === n ? [] : subproof(m, leaves, true).map(hex),
  };
}

// --------------------------------------------------------------- sessions
let state = 'unclaimed'; // unclaimed -> claim-open -> enrolled -> bound
const sessions = new Set();
const newSession = () => { const s = randomBytes(16).toString('hex'); sessions.add(s); return s; };
// Dev cookie: plain http://localhost cannot set a __Host- cookie (Secure is
// required), so the dev server uses a different name. The production contract
// in plan/OWNER-API.md keeps __Host- over HTTPS.
const COOKIE = 'dev-session';
const principal = req => {
  const cookie = req.headers.cookie ?? '';
  const m = /(?:^|;\s*)dev-session=([0-9a-f]{32})/.exec(cookie);
  return m && sessions.has(m[1]) ? m[1] : null;
};
const authed = req => Boolean(principal(req));

const pending = new Map(CARDS.map(c => [c.id, {
  ...c, target: Object.keys(c.card.from_to)[0], state: 'pending', reviewed: false, operator_only: false,
}]));
const challenges = new Map();
const actionChallenges = new Map();
const retiredProposals = new Map();
const reconciledProposals = new Map();
const appliedProposals = new Map(); // id -> item (with target and approved record)
const redeemedKeys = new Set();
let ceremony = null;
let signinCeremony = null;
const refreshChallenges = new Map();
const logoutChallenges = new Map();
const refreshGuesses = new Map();
let refreshCeremony = null;
let ledgerSeq = 100;

// ------------------------------------------------------------ v1.1 fixtures
const MODELS = ['openai/gpt-5', 'anthropic/claude-sonnet-4.5', 'google/gemini-2.5-pro'];
let currentDigest = 'aa'.repeat(32);
const COMPONENTS = { node: 'bb'.repeat(32), harness: 'cc'.repeat(32), guest: 'dd'.repeat(32) };
let approvedDigest = null;
let agent = 'stopped'; // stopped | starting | running | exited
let agentSince = STARTED;
let brokerKey = null; // { sha256_prefix } — the fake keeps only the fingerprint too
let grant = null;
let memoryPermission = false;

const usd = micro => `$${(micro / 1e6).toFixed(2)}`;

function addProposal(target, record, card) {
  if ([...pending.values()].some(item => item.target === target
    && (['incomplete', 'conflict'].includes(item.state) || item.reviewed))) {
    throw Object.assign(new Error('gate:target-fenced'), { refusal: 'gate:target-fenced' });
  }
  const id = randomBytes(16).toString('hex');
  pending.set(id, { id, target, record, card, state: 'pending', reviewed: false, operator_only: true });
  return id;
}

if (CONFLICT) {
  for (const [id, target, outcome] of [
    ['cf'.repeat(16), 'broker/key', 'conflict'],
    ['ce'.repeat(16), 'kira/permission', 'incomplete'],
  ]) {
    pending.set(id, { id, target, state: outcome, reviewed: true, operator_only: true,
      card: { v: 1, risk: 'critical', says: `Observed ${target} ${outcome}`,
        facts: [['target', target], ['state', outcome]], from_to: {}, model_note: '' } });
  }
}

function authorization(item, operation, card) {
  const display = hex(sha256(canonicalJSON(card)));
  const auth = {
    v: 1, node: NODE_ID, subject: SUBJECT, epoch: 1, op: operation, proposal: item.id,
    operation: '33'.repeat(32), target: item.target,
    base_sha256: '11'.repeat(32), new_sha256: '22'.repeat(32), cell: null,
    display_sha256: display, challenge: hex(randomBytes(32)), expires_at: Date.now() + 120000,
  };
  auth.operation = hex(sha256('aukora:operation-content:v1\0' + canonicalJSON({
    v: 1, node: auth.node, target: auth.target, base_sha256: auth.base_sha256,
    new_sha256: auth.new_sha256, cell: auth.cell,
  })));
  const digest = sha256('aukora:owner-authorization:v1\0' + canonicalJSON(auth));
  return { id: item.id, display_sha256: display, card, auth, dev_bypass: true,
    public_key: { challenge: b64url(digest), rpId: 'localhost',
      allowCredentials: [{ type: 'public-key', id: b64url(randomBytes(32)) }],
      userVerification: 'required', timeout: 60000 } };
}

// §9: the supervisor proposes the release at boot when bound and the runtime
// digest has no approved release. The owner can never propose it here.
function maybeProposeRelease() {
  if (state !== 'bound' && state !== 'released') return;
  if (approvedDigest === currentDigest) return;
  for (const item of pending.values()) {
    if (item.target === 'release' && item.state === 'pending'
      && !item.reviewed && item.operator_only && item.record.digest !== currentDigest) {
      item.state = 'expired';
      pending.delete(item.id);
      ledgerSeq++;
    }
  }
  if ([...pending.values()].some(i => i.target === 'release')) return;
  addProposal('release', { v: 1, digest: currentDigest, components: COMPONENTS }, {
    v: 1, risk: 'critical', says: 'Start the agent runtime',
    facts: [['runtime digest', currentDigest], ['node', COMPONENTS.node],
      ['harness', COMPONENTS.harness], ['guest', COMPONENTS.guest]],
    from_to: {}, model_note: '',
  });
}

export function fakeMeasureRuntime(digest) {
  currentDigest = digest;
  if (approvedDigest !== currentDigest) {
    agent = 'stopped';
    agentSince = Date.now();
  }
  maybeProposeRelease();
}

// Effects of an applied proposal: the supervisor acts on the approved record.
function applyEffect(item) {
  if (item.target === 'release') {
    approvedDigest = item.record.digest;
    if (approvedDigest !== currentDigest) return;
    agent = 'starting';
    agentSince = Date.now();
    setTimeout(() => { if (agent === 'starting') { agent = 'running'; agentSince = Date.now(); } }, 2500).unref();
  } else if (item.target === 'broker/grant') {
    const r = item.record;
    grant = { id: item.id, model: r.model, cap_microusd: r.cap_microusd, spent_microusd: 0,
      remaining_microusd: r.cap_microusd, expires_at: r.expires_at, frozen: false };
  } else if (item.target === 'kira/permission') {
    memoryPermission = true;
  }
  // broker/key: nothing — the page delivers the key once via /api/broker/key
}

// ------------------------------------------------------------------ http
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
  res.end(data);
}
const fail = (res, status, code, extra = {}) => send(res, status, { error: code, ...extra });

function checkCurrentPhrase(res, owner, phrase) {
  let guesses = refreshGuesses.get(owner);
  if (!guesses || Date.now() - guesses.start >= 60000) guesses = { count: 0, start: Date.now() };
  if (guesses.count >= 5) { fail(res, 429, 'aumlok:phrase-rate-limited'); return false; }
  if (phrase !== currentPhrase) {
    guesses.count++;
    refreshGuesses.set(owner, guesses);
    fail(res, 422, 'aumlok:current-phrase');
    return false;
  }
  return true;
}

function refreshDraw() {
  return { ceremony_id: refreshCeremony.id, words: refreshCeremony.words,
    entropy_bits: ENTROPY_BITS, expires_at: refreshCeremony.expires };
}

function ownLiveRefresh(req) {
  return refreshCeremony && refreshCeremony.principal === principal(req)
    && !refreshCeremony.spent && Date.now() < refreshCeremony.expires;
}

function refreshLive() {
  return { ceremony_id: refreshCeremony.id, state: 'live', expires_at: refreshCeremony.expires };
}

async function route(req, res, url, body) {
  const p = url.pathname;

  if (p === '/api/state' && req.method === 'GET') {
    // v1.1: the node state is visible without a session so the page can offer
    // sign-in (§7); `session` says whether this browser is signed in.
    const signed = authed(req);
    return send(res, 200, {
      node: NODE_ID, state, session: signed,
      subject: signed && (state === 'bound' || state === 'released') ? SUBJECT : null,
    });
  }
  if (p === '/api/claim' && req.method === 'POST') {
    if (body?.token !== 'dev-claim-token') return fail(res, 403, 'aumlok:claim-unknown');
    if (state !== 'unclaimed') return fail(res, 403, 'aumlok:claim-spent');
    state = 'claim-open';
    return send(res, 200, { ok: true, state }, { 'Set-Cookie': `${COOKIE}=${newSession()}; Path=/; HttpOnly; SameSite=Strict` });
  }

  // §7 sign-in: reachable without a session — that is the point.
  if (p === '/api/signin/start' && req.method === 'POST') {
    if (state === 'unclaimed' || state === 'claim-open') return fail(res, 409, 'aumlok:not-enrolled');
    signinCeremony = { id: randomBytes(16).toString('hex'), expires: Date.now() + 120000 };
    return send(res, 200, {
      ceremony_id: signinCeremony.id,
      dev_bypass: true,
      public_key: {
        challenge: b64url(randomBytes(32)), rpId: 'localhost',
        allowCredentials: [{ type: 'public-key', id: b64url(randomBytes(32)) }],
        userVerification: 'required', timeout: 60000,
      },
    });
  }
  if (p === '/api/signin/finish' && req.method === 'POST') {
    if (!signinCeremony || body?.ceremony_id !== signinCeremony.id) return fail(res, 403, 'aumlok:ceremony-unknown');
    if (Date.now() > signinCeremony.expires) return fail(res, 410, 'aumlok:ceremony-expired');
    signinCeremony = null; // dev server accepts the bypass assertion; a real one verifies it
    maybeProposeRelease();
    return send(res, 200, { ok: true, state }, { 'Set-Cookie': `${COOKIE}=${newSession()}; Path=/; HttpOnly; SameSite=Strict` });
  }

  if (!authed(req)) return fail(res, 401, 'frontdoor:session-required');

  if (p === '/api/logout' && req.method === 'POST') {
    if (Object.keys(body ?? {}).length) return fail(res, 400, 'frontdoor:body-invalid');
    const owner = principal(req);
    if (ownLiveRefresh(req)) refreshCeremony.spent = true;
    sessions.delete(owner);
    return send(res, 200, { ok: true }, { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` });
  }
  if (p === '/api/logout/everywhere' && req.method === 'POST') {
    if (!['bound', 'released'].includes(state)) return fail(res, 403, 'aumlok:binding-required');
    if (Object.keys(body ?? {}).length) return fail(res, 400, 'frontdoor:body-invalid');
    const owner = principal(req);
    for (const [id, pending] of logoutChallenges) {
      if (pending.principal !== owner) continue;
      if (!pending.spent && pending.challenge.auth.expires_at - Date.now() >= 60000) {
        const { id: _, ...response } = pending.challenge;
        return send(res, 200, { ceremony_id: id, ...response });
      }
      logoutChallenges.delete(id);
    }
    const id = randomBytes(16).toString('hex');
    const card = { v: 1, risk: 'critical', says: 'Sign out every owner session',
      facts: [['identity', SUBJECT], ['effect', 'All owner sessions end and live phrase replacements are cancelled']],
      from_to: {}, model_note: '' };
    const challenge = authorization({ id, target: 'aumlok/session/revoke-all' }, 'permission', card);
    logoutChallenges.set(id, { challenge, principal: principal(req), spent: false });
    const { id: _, ...response } = challenge;
    return send(res, 200, { ceremony_id: id, ...response });
  }
  if (p === '/api/logout/everywhere/confirm' && req.method === 'POST') {
    if (!['bound', 'released'].includes(state)) return fail(res, 403, 'aumlok:binding-required');
    if (Object.keys(body ?? {}).some(key => !['ceremony_id', 'assertion'].includes(key))) return fail(res, 400, 'frontdoor:body-invalid');
    const pending = logoutChallenges.get(body?.ceremony_id);
    if (!pending || pending.principal !== principal(req)) return fail(res, 403, 'aumlok:ceremony-principal');
    if (pending.spent) return fail(res, 403, 'aumlok:ceremony-spent');
    if (Date.now() >= pending.challenge.auth.expires_at) return fail(res, 410, 'aumlok:ceremony-expired');
    pending.spent = true;
    if (body?.assertion?.kind !== 'dev-bypass' || body.assertion.challenge !== pending.challenge.public_key.challenge) return fail(res, 422, 'aumlok:assertion-refused');
    if (refreshCeremony && !refreshCeremony.spent) refreshCeremony.spent = true;
    sessions.clear();
    refreshChallenges.clear();
    logoutChallenges.clear();
    return send(res, 200, { ok: true }, { 'Set-Cookie': `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0` });
  }

  if (p === '/api/enrol/start' && req.method === 'POST') {
    if (state !== 'claim-open') return fail(res, 409, 'aumlok:enrolment-closed');
    return send(res, 200, {
      enrolment_id: randomBytes(16).toString('hex'),
      dev_bypass: true,
      public_key: {
        challenge: b64url(randomBytes(32)),
        rp: { name: 'aukora dev node', id: 'localhost' },
        user: { id: b64url(randomBytes(16)), name: 'owner', displayName: 'Owner' },
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none', timeout: 60000,
      },
    });
  }
  if (p === '/api/enrol/finish' && req.method === 'POST') {
    if (state !== 'claim-open') return fail(res, 409, 'aumlok:enrolment-closed');
    state = 'enrolled';
    return send(res, 200, { ok: true, state });
  }
  if (p === '/api/binding/prepare' && req.method === 'POST') {
    if (state === 'bound') return fail(res, 409, 'aumlok:already-bound');
    if (state !== 'enrolled') return fail(res, 403, 'aumlok:enrolment-required');
    ceremony = { id: randomBytes(16).toString('hex'), expires: Date.now() + 10 * 60 * 1000 };
    return send(res, 200, { ceremony_id: ceremony.id, words: PHRASE, entropy_bits: ENTROPY_BITS, expires_at: ceremony.expires });
  }
  if (p === '/api/binding/confirm' && req.method === 'POST') {
    if (!ceremony || body?.ceremony_id !== ceremony.id) return fail(res, 403, 'aumlok:ceremony-unknown');
    if (Date.now() > ceremony.expires) return fail(res, 410, 'aumlok:ceremony-expired');
    const typed = Array.isArray(body?.words) ? body.words : [];
    for (let i = 0; i < 7; i++) {
      if ((typed[i] ?? '').toLowerCase() !== PHRASE[i]) return fail(res, 422, 'aumlok:word-mismatch', { position: i + 1 });
    }
    ceremony = null;
    state = 'bound';
    maybeProposeRelease();
    return send(res, 200, { ok: true, state, subject: SUBJECT });
  }
  if (p === '/api/binding/cancel' && req.method === 'POST') {
    ceremony = null;
    return send(res, 200, { ok: true });
  }
  if (p === '/api/binding/refresh' && req.method === 'POST') {
    if (!['bound', 'released'].includes(state)) return fail(res, 403, 'aumlok:binding-required');
    if (Object.keys(body ?? {}).length) return fail(res, 400, 'frontdoor:body-invalid');
    if (ownLiveRefresh(req)) return send(res, 200, refreshLive());
    if (refreshCeremony && !refreshCeremony.spent && Date.now() < refreshCeremony.expires) return fail(res, 409, 'aumlok:refresh-live', { expires_at: refreshCeremony.expires });
    const owner = principal(req);
    for (const [id, pending] of refreshChallenges) {
      if (pending.principal !== owner) continue;
      if (!pending.spent && pending.challenge.auth.expires_at - Date.now() >= 60000) {
        const { id: _, ...response } = pending.challenge;
        return send(res, 200, { ceremony_id: id, ...response });
      }
      refreshChallenges.delete(id);
    }
    const id = randomBytes(16).toString('hex');
    const card = { v: 1, risk: 'critical', says: 'Replace your binding phrase',
      facts: [['identity', SUBJECT], ['effect', 'The current phrase stops unlocking this node']],
      from_to: {}, model_note: '' };
    const challenge = authorization({ id, target: 'aumlok/binding/refresh' }, 'permission', card);
    refreshChallenges.set(id, { challenge, principal: principal(req), spent: false });
    const { id: _, ...response } = challenge;
    return send(res, 200, { ceremony_id: id, ...response });
  }
  if (p === '/api/binding/refresh/prepare' && req.method === 'POST') {
    if (!['bound', 'released'].includes(state)) return fail(res, 403, 'aumlok:binding-required');
    if (Object.keys(body ?? {}).some(key => !['ceremony_id', 'current_phrase', 'assertion'].includes(key))) return fail(res, 400, 'frontdoor:body-invalid');
    if (ownLiveRefresh(req)) return send(res, 200, refreshLive());
    if (refreshCeremony && !refreshCeremony.spent && Date.now() < refreshCeremony.expires) return fail(res, 409, 'aumlok:refresh-live', { expires_at: refreshCeremony.expires });
    const challenge = refreshChallenges.get(body?.ceremony_id);
    if (!challenge || challenge.principal !== principal(req)) return fail(res, 403, 'aumlok:ceremony-unknown');
    if (challenge.spent) return fail(res, 403, 'aumlok:ceremony-spent');
    if (Date.now() >= challenge.challenge.auth.expires_at) return fail(res, 410, 'aumlok:ceremony-expired');
    challenge.spent = true;
    if (body?.assertion?.kind !== 'dev-bypass' || body.assertion.challenge !== challenge.challenge.public_key.challenge) return fail(res, 422, 'aumlok:assertion-refused');
    if (!checkCurrentPhrase(res, principal(req), body.current_phrase)) return;
    refreshCeremony = { id: randomBytes(16).toString('hex'), principal: principal(req),
      words: currentPhrase === PHRASE.join(' ') ? [...REPLACEMENT] : [...PHRASE],
      expires: Date.now() + 300000, spent: false };
    return send(res, 200, refreshDraw());
  }
  if (['/api/binding/refresh/resume', '/api/binding/refresh/confirm'].includes(p) && req.method === 'POST') {
    if (!['bound', 'released'].includes(state)) return fail(res, 403, 'aumlok:binding-required');
    const fields = p.endsWith('/resume') ? ['ceremony_id', 'current_phrase'] : ['ceremony_id', 'current_phrase', 'words'];
    if (Object.keys(body ?? {}).some(key => !fields.includes(key))) return fail(res, 400, 'frontdoor:body-invalid');
    if (!refreshCeremony || body?.ceremony_id !== refreshCeremony.id) return fail(res, 403, 'aumlok:ceremony-unknown');
    if (refreshCeremony.principal !== principal(req)) return fail(res, 403, 'aumlok:ceremony-principal');
    if (refreshCeremony.committed) return send(res, 200, { ok: true, state: 'committed', subject: SUBJECT });
    if (refreshCeremony.spent) return fail(res, 403, 'aumlok:ceremony-spent');
    if (Date.now() >= refreshCeremony.expires) return fail(res, 410, 'aumlok:ceremony-expired');
    if (!checkCurrentPhrase(res, principal(req), body.current_phrase)) return;
    if (p.endsWith('/resume')) return send(res, 200, refreshDraw());
    for (let i = 0; i < 7; i++) {
      if (body.words?.[i] !== refreshCeremony.words[i]) return fail(res, 422, 'aumlok:word-mismatch', { position: i + 1 });
    }
    if (body.words.length !== 7) return fail(res, 422, 'aumlok:phrase-word-count');
    currentPhrase = refreshCeremony.words.join(' ');
    refreshCeremony.spent = true;
    refreshCeremony.committed = true;
    return send(res, 200, { ok: true, state: 'committed', subject: SUBJECT });
  }
  if (p === '/api/binding/refresh/cancel' && req.method === 'POST') {
    if (!['bound', 'released'].includes(state)) return fail(res, 403, 'aumlok:binding-required');
    if (Object.keys(body ?? {}).some(key => key !== 'ceremony_id')) return fail(res, 400, 'frontdoor:body-invalid');
    if (!refreshCeremony || body?.ceremony_id !== refreshCeremony.id) return fail(res, 403, 'aumlok:ceremony-unknown');
    if (refreshCeremony.principal !== principal(req)) return fail(res, 403, 'aumlok:ceremony-principal');
    if (refreshCeremony.committed) return send(res, 200, { ok: true, state: 'committed', subject: SUBJECT });
    if (refreshCeremony.spent) return fail(res, 403, 'aumlok:ceremony-spent');
    if (Date.now() >= refreshCeremony.expires) return fail(res, 410, 'aumlok:ceremony-expired');
    refreshCeremony.spent = true;
    return send(res, 200, { ok: true });
  }

  if (state !== 'bound') return fail(res, 403, 'aumlok:binding-required');

  if (p === '/api/approvals' && req.method === 'GET') {
    return send(res, 200, {
      pending: [...pending.values()].map(({ id, card, state, reviewed, operator_only, target, record }) => ({
        id, state, reviewed, operator_only,
        superseded: target === 'release' && record.digest !== currentDigest,
        display_sha256: hex(sha256(canonicalJSON(card))), card,
      })),
    });
  }
  if (p === '/api/approvals/challenge' && req.method === 'POST') {
    const item = pending.get(body?.id);
    if (!item) return fail(res, 404, 'gate:unknown-proposal');
    if (item.state !== 'pending') return fail(res, 409, 'gate:not-pending');
    item.reviewed = true;
    const challenge = authorization(item, 'apply', item.card);
    challenges.set(item.id, challenge);
    return send(res, 200, challenge);
  }
  if (p === '/api/approvals/decide' && req.method === 'POST') {
    const item = pending.get(body?.id);
    if (!item) return fail(res, 404, 'gate:unknown-proposal');
    if (item.state !== 'pending') return fail(res, 409, 'gate:not-pending');
    if (body.approve === false) {
      if (item.operator_only || item.reviewed) return fail(res, 409, 'gate:owner-retirement-required');
      pending.delete(item.id);
      return send(res, 200, { ok: true, state: 'refused', seq: ++ledgerSeq });
    }
    if (!challenges.has(item.id)) return fail(res, 410, 'gate:challenge-expired');
    challenges.delete(item.id);
    pending.delete(item.id);
    appliedProposals.set(item.id, item);
    applyEffect(item);
    return send(res, 200, { ok: true, state: 'applied', seq: ++ledgerSeq });
  }

  const ownerAction = /^\/api\/approvals\/(retire|reconcile)(\/challenge)?$/.exec(p);
  if (ownerAction && req.method === 'POST') {
    const operation = ownerAction[1];
    if (!ownerAction[2] && body?.assertion?.kind !== 'dev-bypass') return fail(res, 403, 'gate:proof-invalid');
    const prior = (operation === 'retire' ? retiredProposals : reconciledProposals).get(body?.id);
    const item = pending.get(body?.id);
    if (prior && !ownerAction[2]) {
      return send(res, 200, prior);
    }
    if (!item) return fail(res, 404, 'gate:unknown-proposal');
    if (operation === 'retire' && item.state !== 'pending') return fail(res, 409, 'gate:not-retirable');
    if (operation === 'reconcile' && !['incomplete', 'conflict'].includes(item.state)) {
      return fail(res, 409, 'gate:not-reconcilable');
    }
    const actionKey = `${operation}:${item.id}`;
    if (ownerAction[2]) {
      item.reviewed = true;
      const card = { v: 1, risk: 'critical',
        says: operation === 'retire' ? 'Retire this pending proposal without applying it.'
          : 'Close this observed outcome without retrying it; adopt the current target hash as the new base.',
        facts: [['operation', operation], ['proposal', item.id], ['target', item.target]],
        from_to: { state: item.state, operation }, model_note: '' };
      const challenge = authorization(item, operation, card);
      actionChallenges.set(actionKey, challenge);
      return send(res, 200, challenge);
    }
    const challenge = actionChallenges.get(actionKey);
    if (!challenge) return fail(res, 410, 'gate:challenge-expired');
    actionChallenges.delete(actionKey);
    challenges.delete(item.id);
    pending.delete(item.id);
    const result = { ok: true, state: operation === 'retire' ? 'retired' : 'reconciled', seq: ++ledgerSeq };
    (operation === 'retire' ? retiredProposals : reconciledProposals).set(item.id, result);
    return send(res, 200, result);
  }

  if (p === '/api/aura/head' && req.method === 'GET') {
    const since = Number(url.searchParams.get('since'));
    return send(res, 200, presentedHead(Number.isInteger(since) && since > 0 ? since : undefined));
  }
  if (p === '/api/aura/retained' && req.method === 'GET') {
    const h = presentedHead(treeSize());
    const retained = {
      schema: 'aukora-aura-retained-head-v1', leafConvention: h.leafConvention,
      sequence: h.sequence, hash: h.hash, treeSize: h.treeSize, root: h.root, sig: h.sig,
    };
    return send(res, 200, retained, { 'Content-Disposition': 'attachment; filename="retained-head.json"' });
  }
  if (p === '/api/aura/recent' && req.method === 'GET') {
    const limit = Math.min(100, Number(url.searchParams.get('limit')) || 20);
    const n = treeSize();
    const rows = [];
    for (let seq = n; seq >= Math.max(1, n - limit + 1); seq--) {
      rows.push({
        seq, at: STARTED + seq * 1000, kind: ENTRY_KINDS[seq % ENTRY_KINDS.length],
        actor: 'dev', phase: seq % 3 === 0 ? 'terminal' : 'intent', hash: hex(LEAVES[seq - 1].entryHash),
      });
    }
    return send(res, 200, { rows, head_seq: n });
  }

  // ---- v1.1: model key and spend grant (§8) ----
  if (p === '/api/broker' && req.method === 'GET') {
    return send(res, 200, {
      key: { present: brokerKey !== null, sha256_prefix: brokerKey?.sha256_prefix ?? null },
      grant, models: MODELS,
    });
  }
  if (p === '/api/broker/key/propose' && req.method === 'POST') {
    if (typeof body?.key_sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(body.key_sha256)) {
      return fail(res, 422, 'broker:invalid-key');
    }
    const id = addProposal('broker/key', { v: 1, key_sha256: body.key_sha256 }, {
      v: 1, risk: 'routine', says: 'Use this model provider key',
      facts: [['Key fingerprint', body.key_sha256.slice(0, 8)]], from_to: {}, model_note: '',
    });
    return send(res, 200, { id });
  }
  if (p === '/api/broker/key' && req.method === 'POST') {
    // Without an id: the applied, unredeemed key record whose fingerprint matches (as the real node).
    const digest = typeof body?.key === 'string' ? hex(sha256(Buffer.from(body.key, 'utf8'))) : null;
    const item = body?.id !== undefined ? appliedProposals.get(body.id)
      : [...appliedProposals.values()].reverse().find(entry => entry.target === 'broker/key'
        && entry.record.key_sha256 === digest && !redeemedKeys.has(entry.id));
    if (!item || item.target !== 'broker/key') return fail(res, 409, 'broker:key-not-approved');
    if (typeof body?.key !== 'string' || hex(sha256(Buffer.from(body.key, 'utf8'))) !== item.record.key_sha256) {
      return fail(res, 422, 'broker:key-mismatch');
    }
    if (redeemedKeys.has(item.id)) return fail(res, 409, 'broker:key-redeemed');
    redeemedKeys.add(item.id);
    brokerKey = { sha256_prefix: item.record.key_sha256.slice(0, 8) }; // the key goes to the broker; the fake keeps the fingerprint
    return send(res, 200, { ok: true, sha256_prefix: brokerKey.sha256_prefix });
  }
  if (p === '/api/broker/grant/propose' && req.method === 'POST') {
    const { model, cap_microusd, per_request_cap_microusd, max_requests, hours } = body ?? {};
    const posInt = v => Number.isInteger(v) && v > 0;
    if (!MODELS.includes(model) || !posInt(cap_microusd) || !posInt(per_request_cap_microusd)
      || !posInt(max_requests) || !Number.isInteger(hours) || hours < 1 || hours > 24) {
      return fail(res, 422, 'broker:invalid-grant');
    }
    const expires_at = Date.now() + hours * 3600_000;
    const record = { v: 1, provider: 'openrouter', model, cap_microusd, per_request_cap_microusd,
      max_requests, expires_at, nonce: hex(randomBytes(16)) };
    const id = addProposal('broker/grant', record, {
      v: 1, risk: 'routine', says: 'Allow model spend',
      facts: [['model', model], ['cap', usd(cap_microusd)], ['per request', usd(per_request_cap_microusd)],
        ['max requests', String(max_requests)], ['expires', new Date(expires_at).toISOString()]],
      from_to: {}, model_note: '',
    });
    return send(res, 200, { id });
  }

  // ---- v1.1: release and agent status (§9) ----
  if (p === '/api/release' && req.method === 'GET') {
    return send(res, 200, {
      current_digest: currentDigest, approved_digest: approvedDigest, agent, since: agentSince,
    });
  }

  // ---- v1.1: memory permission (§10) ----
  if (p === '/api/memory/permission/propose' && req.method === 'POST') {
    const id = addProposal('kira/permission', { v: 1, purpose: 'hosted-context', model_provider: 'openrouter' }, {
      v: 1, risk: 'routine', says: 'Let memory recall enter the hosted model’s context',
      facts: [['purpose', 'hosted-context'], ['model provider', 'openrouter']], from_to: {}, model_note: '',
    });
    return send(res, 200, { id });
  }

  if (p === '/api/memory/recall' && req.method === 'POST') {
    const q = (body?.query ?? '').toLowerCase();
    const items = NOTES.filter(n => !n.demoted && (q === '' || n.text.toLowerCase().includes(q)))
      .map(({ note_id, text, cite_seq, tier }) => ({ note_id, text, cite_seq, tier }));
    return send(res, 200, { result: items.length ? 'found' : 'empty', items });
  }
  if (p === '/api/memory/demote' && req.method === 'POST') {
    const note = NOTES.find(n => n.note_id === body?.note_id);
    if (!note) return fail(res, 404, 'kira:unknown-note');
    if (note.demoted) return fail(res, 409, 'kira:already-demoted');
    note.demoted = true;
    return send(res, 200, { ok: true, seq: ++ledgerSeq });
  }

  return fail(res, 404, 'frontdoor:unknown-route');
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host ?? 'localhost'}`);
  try {
    if (url.pathname.startsWith('/api/')) {
      let raw = '';
      for await (const chunk of req) raw += chunk;
      const body = raw ? JSON.parse(raw) : undefined;
      return await route(req, res, url, body);
    }
    // static
    let rel = decodeURIComponent(url.pathname);
    if (rel === '/') rel = '/index.html';
    const file = path.join(ROOT, rel);
    if (!file.startsWith(ROOT) || file.includes(`${path.sep}dev${path.sep}`)) return fail(res, 404, 'frontdoor:unknown-route');
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] ?? 'application/octet-stream', 'Cache-Control': 'no-store' });
    res.end(data);
  } catch (ex) {
    if (ex?.refusal) return fail(res, 409, ex.refusal);
    fail(res, ex?.code === 'ENOENT' ? 404 : 400, ex?.code === 'ENOENT' ? 'frontdoor:unknown-route' : 'frame:not-canonical');
  }
});

export async function fakeRequest(url, init = {}) {
  let response;
  let status;
  let headers;
  const res = {
    writeHead(code, values) { status = code; headers = values; },
    end(data) { response = new Response(data, { status, headers }); },
  };
  try {
    await route({ method: init.method ?? 'GET', headers: init.headers ?? {} }, res,
      new URL(url, 'http://localhost'), init.body ? JSON.parse(init.body) : undefined);
  } catch (ex) {
    fail(res, ex?.refusal ? 409 : 400, ex?.refusal ?? 'frame:not-canonical');
  }
  return response;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  server.listen(PORT, () => {
    console.log(`fake owner server on http://localhost:${server.address().port}  (claim token: dev-claim-token${FORK ? ', FORK MODE' : ''})`);
  });
}
