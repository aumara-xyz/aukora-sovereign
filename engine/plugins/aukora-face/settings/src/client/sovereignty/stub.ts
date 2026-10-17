// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * ************************************************************************************************************
 * STUB DATA. NOTHING IN THIS FILE IS READ FROM A NODE.
 * ************************************************************************************************************
 *
 * Every value below is made up for the Sovereignty preview. The SHAPES and NAMES are the real ones (see
 * `model.ts`, which says which crate owns each); the digests are sha256 of throwaway strings, the times are
 * relative to one fixed `NOW_MS`, and the owner origin is a `.invalid` name that never resolves.
 *
 * PREVIEW ONLY: the surface reads this only when the page carries `SOVEREIGNTY_PREVIEW_GLOBAL`, which only
 * preview-face.py composes; a node shows honest empty portals instead. WIRING IS A SWAP: replace `readSovereigntyStub` with a reader that returns the same `SovereigntySnapshot` from
 * the node (read-only routes only) and set `source: 'node'`. Nothing in the components changes. The spec
 * (`SOVEREIGNTY-APP-SPEC.md`) lists the real source of every field.
 */
import type {
  ApprovalItem, CrossingClass, DoorAction, DoorGrant, KiraNote, OwnerCard, SovereigntySnapshot,
} from './model.ts'

const MIN = 60_000
const HOUR = 60 * MIN
const DAY = 24 * HOUR
/** 2026-10-17 14:00 UTC: the moment the stub describes. */
const NOW_MS = 1_792_245_600_000
const NOW_S = NOW_MS / 1000
const NODE = 'aukora:node:886b8bc487249d73'

const G_DOCS = '6ac89137832650c0bb56fcc89eec8ee469cd8398f9cf87497cf001511876d356'
const G_KIRA = 'a2573814323a8ab63c2581cb12db32751f7aac8f5d69c95253ab32eee4c12fc0'
const G_GITHUB = 'eee21c1985ef6e35aedfbe8418b7cb479a734fdb0cbbebe691ff04b2e0398ede'
const G_SHARED = '42697a66e21c1ba0b29a0a2ea5d55b60fdbfe8ada987e6b8c5191f8f9ee5a320'
const CREDENTIAL = 'VdkaNWFoSzLfXlig2RlouTeYr08'

function contentCard(target: string, base: string, next: string, risk: 'routine' | 'critical', note: string, extra: readonly (readonly [string, string])[] = []): OwnerCard {
  return {
    v: 1,
    says: 'Replace the target with the displayed bytes.',
    risk,
    facts: [['target', target], ['base_sha256', base], ['new_sha256', next], ...extra],
    model_note: note,
  }
}

function askCard(target: string, tool: string, cls: CrossingClass, call: string, next: string, note: string): OwnerCard {
  return {
    v: 1,
    says: 'Let the engine run this one call, exactly as displayed.',
    risk: 'critical',
    facts: [['target', target], ['tool', tool], ['class', cls], ['call_sha256', call], ['new_sha256', next]],
    model_note: note,
  }
}

const APPROVALS: readonly ApprovalItem[] = [
  {
    proposal: '1566b49718c3acb02ac1788c4fbabdc8',
    target: 'door/ask-03.json',
    state: 'pending',
    created_at_ms: NOW_MS - 4 * MIN,
    settled_at_ms: null,
    expires_at_ms: NOW_MS + 1 * MIN,
    card: askCard('door/ask-03.json', 'read_file', 'fs-outside', '886b8bc487249d73508327231cc35c6c9a5efec22566632a423b329b931213ab',
      'a5e87fe721f18135120cdd3f6ea2a33e9c5570584c98e429dd874c41f1952db4',
      'The engine asks to run read_file (fs-outside). Digest 886b8bc487249d73.'),
    display_sha256: 'ccc486d5e51acb39f2f74a34ff867cd5058248219a09c09052d240089af2a6f5',
    authorization: null,
    credential_id: null,
    receipt_hash: null,
  },
  {
    proposal: 'aaae3f69ed589805ed190a3095ac53fe',
    target: 'engine/plugin-set.json',
    state: 'pending',
    created_at_ms: NOW_MS - 2 * MIN,
    settled_at_ms: null,
    expires_at_ms: NOW_MS + 3 * MIN,
    card: contentCard('engine/plugin-set.json', 'c674616a35dbfd5f097488d0d760a3f5eb0149ea1819195880e0ced5161f61ee',
      'a6fb3f9a00ee04dc5a7acb83ede24a266b34bb11bf2a6365eea14a1856ebe205', 'critical',
      'One plugin changes: @aukora/face-settings (adds the Sovereignty view). Eleven are unchanged.'),
    display_sha256: '05eb27ff91ef13e98ba61e2408b9f69892bfc9e7770380b022ccd7405f56d1a3',
    authorization: null,
    credential_id: null,
    receipt_hash: null,
  },
  {
    proposal: '6acf6294f91642fc0487a414d3596df2',
    target: 'door/standing-grants.json',
    state: 'applied',
    created_at_ms: NOW_MS - 20 * HOUR - 6 * MIN,
    settled_at_ms: NOW_MS - 20 * HOUR - 5 * MIN,
    expires_at_ms: NOW_MS - 20 * HOUR - MIN,
    card: contentCard('door/standing-grants.json', '08fd2fea72b8f7378a6d3ba00a598db3a3f8d0d817a53f1f5fa153a2ad8c1bda',
      'c1cce440570c6f598dfbaa8fbdd61b6b798e67be9f6ee178903bd1ffe6e4b862', 'critical',
      'Adds one grant: net to api.github.com, 20 a day, for one day.'),
    display_sha256: '289bae962e2baad5586e97ebde64b5966bf33ede5f5ef84d26d160f361924ba2',
    authorization: {
      node: NODE, op: 'apply', proposal: '6acf6294f91642fc0487a414d3596df2', target: 'door/standing-grants.json',
      base_sha256: '08fd2fea72b8f7378a6d3ba00a598db3a3f8d0d817a53f1f5fa153a2ad8c1bda',
      new_sha256: 'c1cce440570c6f598dfbaa8fbdd61b6b798e67be9f6ee178903bd1ffe6e4b862',
      display_sha256: '289bae962e2baad5586e97ebde64b5966bf33ede5f5ef84d26d160f361924ba2',
      challenge: '54054588f2ef4ed6954fbd62d59fcb05', expires_at: NOW_MS - 20 * HOUR - MIN, epoch: 3,
      operation: '1aff1f96c198d86a464f49b115fa7c1b13e2e18d92f0a811fef404524269b1f3',
    },
    credential_id: CREDENTIAL,
    receipt_hash: 'aebe8cd51c4dd277e7cad09518750c1dbc5dfde8b170f4dc849ae6c167d94f2c',
  },
  {
    proposal: '427983f3f321daa1f3653de2ccfc11e9',
    target: 'door/ask-01.json',
    state: 'retired',
    created_at_ms: NOW_MS - 26 * HOUR,
    settled_at_ms: NOW_MS - 26 * HOUR + 2 * MIN,
    expires_at_ms: NOW_MS - 26 * HOUR + 5 * MIN,
    card: askCard('door/ask-01.json', 'mcp__github__create_issue', 'mcp', '3f4f9d5b71940847a4aa443293adbf872b1441237927e2c143cf4452cfff927f',
      '47295bc70bccf19db89339850bd3bbf16fd8247831e931acbda94b9f6c5379e4',
      'The engine asks to run mcp__github__create_issue (mcp). Digest 3f4f9d5b71940847.'),
    display_sha256: '692297a8276c4983491e7f389b4b7b91ecad193c6d6d2b08f6a4753824a98101',
    authorization: {
      node: NODE, op: 'retire', proposal: '427983f3f321daa1f3653de2ccfc11e9', target: 'door/ask-01.json',
      base_sha256: 'absent', new_sha256: '47295bc70bccf19db89339850bd3bbf16fd8247831e931acbda94b9f6c5379e4',
      display_sha256: '692297a8276c4983491e7f389b4b7b91ecad193c6d6d2b08f6a4753824a98101',
      challenge: 'aad79020f30adad952dc857dc92a7833', expires_at: NOW_MS - 26 * HOUR + 5 * MIN, epoch: 3,
      operation: '5e8e669d08ad51dce2baa0f6e9bd821c5e9dbe8e9afa225a7abd88538e75a803',
    },
    credential_id: CREDENTIAL,
    receipt_hash: 'a484e56baae538b7b313c07f22804eab4280799b0198892d9f64be9c73cb1ce3',
  },
  {
    proposal: '04f086b122648108cd440d445af24493',
    target: 'engine/model-budget.json',
    state: 'applied',
    created_at_ms: NOW_MS - 7 * DAY,
    settled_at_ms: NOW_MS - 7 * DAY + 3 * MIN,
    expires_at_ms: NOW_MS - 7 * DAY + 5 * MIN,
    card: contentCard('engine/model-budget.json', 'absent', 'b167d34766ea0e496c2e09aa34ff5ffb04089feeb8c8a8bcb152563178f1640f', 'critical',
      'DeepSeek, two models, $20.00 in all, at most $1.00 a call, 5,000 calls, for 30 days.'),
    display_sha256: '38d74ef1781ecc310fdbdce33cd5981a7b33158e725084cb0b106d6f56b9ecda',
    authorization: {
      node: NODE, op: 'apply', proposal: '04f086b122648108cd440d445af24493', target: 'engine/model-budget.json',
      base_sha256: 'absent', new_sha256: 'b167d34766ea0e496c2e09aa34ff5ffb04089feeb8c8a8bcb152563178f1640f',
      display_sha256: '38d74ef1781ecc310fdbdce33cd5981a7b33158e725084cb0b106d6f56b9ecda',
      challenge: 'c1775cdba8d109b8b856af522a5783ef', expires_at: NOW_MS - 7 * DAY + 5 * MIN, epoch: 3,
      operation: '06f819f85943c33582a138fefbd089ca6eefa5630c3c46c875348b6b02106a1a',
    },
    credential_id: CREDENTIAL,
    receipt_hash: '95c2bd43a8ea1477552f089e18e9433105209bfff12d3dac036421a3b0dba3ed',
  },
  {
    proposal: 'ea9e5070b77fb1d72e76ce999c6bee5a',
    target: 'door/slider-policy.json',
    state: 'expired',
    created_at_ms: NOW_MS - 8 * DAY,
    settled_at_ms: NOW_MS - 8 * DAY + 5 * MIN,
    expires_at_ms: NOW_MS - 8 * DAY + 5 * MIN,
    card: contentCard('door/slider-policy.json', 'd6ddf3e54dd57d43850f7568c310fe035a48afac8f1661ec2c4dfcd5846a5369',
      '526fccb08196e6bb1d2eb7db3cc073bf524ffcf4d1df48be12759c0d1bc55cac', 'critical',
      'Loosens the slider from 2 (only risky things) to 4 (trusted). Nobody answered within five minutes.'),
    display_sha256: '7f8f6d9c887f52a0e96e79fc0183c0f940de67730dc70e1677de7758a87f2871',
    authorization: null,
    credential_id: null,
    receipt_hash: 'e3ee5590442abb10ea3dae88b270287d1a64ceafd94c4aa216efea819fbdc20b',
  },
  {
    proposal: '3205bdc46d41ee679dca0b463d4a2cdb',
    target: 'release',
    state: 'applied',
    created_at_ms: NOW_MS - 9 * DAY,
    settled_at_ms: NOW_MS - 9 * DAY + 1 * MIN,
    expires_at_ms: NOW_MS - 9 * DAY + 5 * MIN,
    card: {
      v: 1,
      says: 'Approve the installed release as the owner\'s release floor.',
      risk: 'critical',
      facts: [['target', 'release'], ['base_sha256', 'absent'],
        ['release_sha256', 'ccc656161c832ac9d44a16e195c21b3d0bae5662dae3d871d1a5aa4aa1c23342'],
        ['new_sha256', 'cff0d07312d1d793be66758edb089be32b4dd4d36481d1cc20e0b8c06464f711']],
      model_note: '',
    },
    display_sha256: '559c0f02c8974e500a372361a11e5cc377090fd82c0b5bd8a1df28b2364784d9',
    authorization: {
      node: NODE, op: 'release', proposal: '3205bdc46d41ee679dca0b463d4a2cdb', target: 'release',
      base_sha256: 'absent', new_sha256: 'cff0d07312d1d793be66758edb089be32b4dd4d36481d1cc20e0b8c06464f711',
      display_sha256: '559c0f02c8974e500a372361a11e5cc377090fd82c0b5bd8a1df28b2364784d9',
      challenge: '2abdb03b33beb30ca61368913f73e3e5', expires_at: NOW_MS - 9 * DAY + 5 * MIN, epoch: 3,
      operation: 'c8e9a519dacbcc12076244d42c5560260ca2cee3338877c397c40007da55385f',
    },
    credential_id: CREDENTIAL,
    receipt_hash: '61833ddf9236fa83c61ddddaf6c43a2c0ef6383b91e2faac26181d9a0752b88b',
  },
]

const DOOR_ACTIONS: Readonly<Record<CrossingClass, DoorAction>> = {
  'net': 'allow', 'memory': 'allow', 'mcp': 'ask', 'fs-outside': 'ask', 'delegate': 'deny',
  'plugin': 'deny', 'persist': 'deny', 'shell-interactive': 'deny', 'unknown': 'deny',
}

const GRANTS: readonly DoorGrant[] = [
  { id: G_GITHUB, class: 'net', scope: ['api.github.com'], per_day: 20, not_before: NOW_MS - 20 * HOUR, expires_at: NOW_MS + 4 * HOUR, nonce: '999a2323a99f5af6d308114f11676b89', revoked: false },
  { id: G_DOCS, class: 'net', scope: ['docs.rs', 'crates.io', 'static.crates.io'], per_day: 50, not_before: NOW_MS - 2 * DAY, expires_at: NOW_MS + 5 * DAY, nonce: 'e563b41381d22a54a7c5ca5672275606', revoked: false },
  { id: G_KIRA, class: 'memory', scope: ['read', 'write:experience', 'write:finding'], per_day: 200, not_before: NOW_MS - 3 * DAY, expires_at: NOW_MS + 4 * DAY, nonce: 'a523d5e1d0218dd45a747160724debe5', revoked: false },
  { id: G_SHARED, class: 'fs-outside', scope: ['/srv/shared'], per_day: 10, not_before: NOW_MS - 4 * DAY, expires_at: NOW_MS + 3 * DAY, nonce: 'a92d94f71dbdbc9288f3a5f67be172f5', revoked: true },
]

function note(seq: number, id: string, author: string, ago: number, lane: KiraNote['lane'], subject: string, text: string, capture: KiraNote['capture']): KiraNote {
  return { id, seq, author_name: author, created_at: Math.round(NOW_S - ago / 1000), lane, subject, text, capture, privacy: 'local', review: 'remembered' }
}

const PLUGIN_NAMES = [
  '@aukora/door', '@aukora/kira', '@aukora/dsh-plugin-foundation', '@aukora/face-apps', '@aukora/face-aumlok',
  '@aukora/face-documents', '@aukora/face-layout', '@aukora/face-memory', '@aukora/face-messages',
  '@aukora/face-settings', '@aukora/face-sidebar', '@aukora/face-threads',
]
const PLUGIN_DIGESTS = [
  '72c57c32ca81ca34d83294b0ca9019fba8d7acd2aa1be3eb2e6dd5f852580f38', '64978988ac30d3ce570631f7563ea96212625e870924178e6907c69cfa0389bf',
  '531541b0c38b083fecb995ed6efcc7755aefbd50f5f877c3df368e60d5f8c7b1', 'a18fc82e217d9908ede2ca930b54b2e63206adb9fc3e6bce3083d346f6f1dd2d',
  'd4166a9e6c12e3c1912ef6bb18878d66e2d80190f809e5c88999103b11696d75', 'f1efe2aaa82bbc66842f9b0185b3b4b663ba71a791a77a6c5f04f783037c0566',
  '12c600878d477e5ab52d82098d102a0f3be171356a0574e4f1607234b7796c3d', 'b8ff54b83bc2ffcdc6b48ce81d06081f5ab856fbe1cf7b7faf92b78d122bd27e',
  '886b8bc487249d73508327231cc35c6c9a5efec22566632a423b329b931213ab', '9c1f0e5b7a3d2e4f6a8b0c2d4e6f8a0b1c3d5e7f9a1b3c5d7e9f0a2b4c6d8e0f',
  '1aff1f96c198d86a464f49b115fa7c1b13e2e18d92f0a811fef404524269b1f3', 'aebe8cd51c4dd277e7cad09518750c1dbc5dfde8b170f4dc849ae6c167d94f2c',
]

/** The stub snapshot. A node-backed reader returns the same shape with `source: 'node'`. */
export function readSovereigntyStub(): SovereigntySnapshot {
  return {
    source: 'stub',
    now_ms: NOW_MS,
    owner_origin: 'https://owner.node.invalid',
    approvals: APPROVALS,
    risk: {
      policy: {
        setting: 'risky',
        classes: [
          { class: 'delegate', per_day: 0, risk: 'risky' }, { class: 'fs-outside', per_day: 0, risk: 'risky' },
          { class: 'mcp', per_day: 0, risk: 'risky' }, { class: 'memory', per_day: 500, risk: 'routine' },
          { class: 'net', per_day: 200, risk: 'routine' }, { class: 'persist', per_day: 0, risk: 'risky' },
          { class: 'plugin', per_day: 0, risk: 'risky' }, { class: 'shell-interactive', per_day: 0, risk: 'risky' },
          { class: 'unknown', per_day: 0, risk: 'risky' },
        ],
        // The real pinned starter's hash (laya `STARTER_SHA256`): this stub's policy is the starter.
        policy_sha256: 'd6ddf3e54dd57d43850f7568c310fe035a48afac8f1661ec2c4dfcd5846a5369',
        is_starter: true,
      },
      door: DOOR_ACTIONS,
      grants: GRANTS,
      usage: {
        day: Math.floor(NOW_MS / DAY),
        per_class: { 'net': 43, 'memory': 118 },
        per_grant: { [G_GITHUB]: 7, [G_DOCS]: 36, [G_KIRA]: 118 },
      },
    },
    door: {
      net: { hosts: ['docs.rs', 'crates.io', 'static.crates.io', 'api.github.com', 'en.wikipedia.org'], ports: [443], max_bytes: 1_048_576, timeout_ms: 15_000, allow_http: false },
      crossings: [
        { at_ms: NOW_MS - 4 * MIN, call_id: 'call-2291', tool: 'read_file', class: 'fs-outside', decision: 'ask', reason: 'risky-class', subject: '/srv/shared/invoices/2026-09.pdf', digest_sha256: '886b8bc487249d73508327231cc35c6c9a5efec22566632a423b329b931213ab', grant: null },
        { at_ms: NOW_MS - 9 * MIN, call_id: 'call-2290', tool: 'web_fetch', class: 'net', decision: 'allow', reason: 'clear', subject: 'docs.rs/tokio/latest', digest_sha256: '8a1c5f3e2b7d9046e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8', grant: G_DOCS },
        { at_ms: NOW_MS - 11 * MIN, call_id: 'call-2289', tool: 'kira_remember', class: 'memory', decision: 'allow', reason: 'clear', subject: 'write:experience', digest_sha256: '2f0e1d2c3b4a59687766554433221100ffeeddccbbaa99887766554433221100', grant: G_KIRA },
        { at_ms: NOW_MS - 26 * MIN, call_id: 'call-2287', tool: 'web_fetch', class: 'net', decision: 'deny', reason: 'host-not-allowed', subject: 'pastebin.com', digest_sha256: '0b1c2d3e4f5061728394a5b6c7d8e9f00112233445566778899aabbccddeeff0', grant: null },
        { at_ms: NOW_MS - 41 * MIN, call_id: 'call-2284', tool: 'web_fetch', class: 'net', decision: 'allow', reason: 'clear', subject: 'api.github.com/repos', digest_sha256: '5d4c3b2a1908f7e6d5c4b3a291807f6e5d4c3b2a1908f7e6d5c4b3a291807f6e', grant: G_GITHUB },
        { at_ms: NOW_MS - 1 * HOUR, call_id: 'call-2280', tool: 'kira_remember', class: 'memory', decision: 'deny', reason: 'lane-closed', subject: 'write:charter', digest_sha256: 'c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00', grant: null },
        { at_ms: NOW_MS - 3 * HOUR, call_id: 'call-2266', tool: 'install_plugin', class: 'plugin', decision: 'deny', reason: 'plugin-denied', subject: 'dsh-plugin-browser', digest_sha256: 'feedface0123456789abcdef0123456789abcdef0123456789abcdef01234567', grant: null },
        { at_ms: NOW_MS - 26 * HOUR, call_id: 'call-2201', tool: 'mcp__github__create_issue', class: 'mcp', decision: 'ask', reason: 'risky-class', subject: 'github', digest_sha256: '3f4f9d5b71940847a4aa443293adbf872b1441237927e2c143cf4452cfff927f', grant: null },
        { at_ms: NOW_MS - 27 * HOUR, call_id: 'call-2197', tool: 'terminal', class: 'shell-interactive', decision: 'deny', reason: 'shell-interactive-denied', subject: 'bash -i', digest_sha256: 'ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12', grant: null },
      ],
    },
    plugins: {
      set_sha256: 'c674616a35dbfd5f097488d0d760a3f5eb0149ea1819195880e0ced5161f61ee',
      plugins: PLUGIN_NAMES.map((name, index) => ({
        name, digest: PLUGIN_DIGESTS[index] ?? '', authority: name === '@aukora/door', state: 'active' as const,
      })),
      waiting: [{
        name: '@aukora/face-settings',
        approved_digest: PLUGIN_DIGESTS[9] ?? null,
        offered_digest: '0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e',
        proposal: 'aaae3f69ed589805ed190a3095ac53fe',
      }],
    },
    model: {
      key_fingerprint: 'a6fb3f9a00ee',
      key_stage: 'active',
      budget: {
        budget_sha256: 'b167d34766ea0e496c2e09aa34ff5ffb04089feeb8c8a8bcb152563178f1640f',
        provider: 'deepseek',
        models: ['deepseek-flash', 'deepseek-v4-pro'],
        total_cap_microusd: 20_000_000,
        per_request_cap_microusd: 1_000_000,
        max_requests: 5000,
        expires_at_ms: NOW_MS + 23 * DAY,
        prices: { input_microusd_per_mtok: 1_000_000, output_microusd_per_mtok: 4_000_000, cache_read_microusd_per_mtok: 100_000 },
      },
      used_microusd: 7_412_380,
      used_requests: 1288,
      receipts: [
        { request_id: '015ed11e333a2c3d7a9f43053c85a2ad', model: 'deepseek-flash', reported_model: 'deepseek-flash', outcome: 'completed', detail: '', started_at_ms: NOW_MS - 3 * MIN, ended_at_ms: NOW_MS - 3 * MIN + 4200, charged_microusd: 3_812, reserved_microusd: 40_000, cost_unknown: false, usage: { input_tokens: 2_914, output_tokens: 221, cache_read_input_tokens: 5_120 }, request_sha256: '8f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0' },
        { request_id: 'aaae3f69ed589805ed190a3095ac53fe', model: 'deepseek-v4-pro', reported_model: 'deepseek-v4-pro', outcome: 'completed', detail: '', started_at_ms: NOW_MS - 12 * MIN, ended_at_ms: NOW_MS - 12 * MIN + 18_400, charged_microusd: 41_960, reserved_microusd: 120_000, cost_unknown: false, usage: { input_tokens: 18_204, output_tokens: 5_940, cache_read_input_tokens: 12_288 }, request_sha256: '1f2e3d4c5b6a79880a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6071' },
        { request_id: '6acf6294f91642fc0487a414d3596df2', model: 'deepseek-flash', reported_model: '', outcome: 'interrupted', detail: 'provider-timeout', started_at_ms: NOW_MS - 37 * MIN, ended_at_ms: NOW_MS - 37 * MIN + 60_000, charged_microusd: 0, reserved_microusd: 40_000, cost_unknown: true, usage: { input_tokens: 0, output_tokens: 0, cache_read_input_tokens: 0 }, request_sha256: '2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f70819' },
        { request_id: '54054588f2ef4ed6954fbd62d59fcb05', model: 'deepseek-flash', reported_model: 'deepseek-flash', outcome: 'completed', detail: '', started_at_ms: NOW_MS - 52 * MIN, ended_at_ms: NOW_MS - 52 * MIN + 2900, charged_microusd: 380, reserved_microusd: 40_000, cost_unknown: false, usage: { input_tokens: 212, output_tokens: 48, cache_read_input_tokens: 1_024 }, request_sha256: '3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a' },
        { request_id: '427983f3f321daa1f3653de2ccfc11e9', model: 'deepseek-flash', reported_model: 'deepseek-flash', outcome: 'cancelled', detail: '', started_at_ms: NOW_MS - 2 * HOUR, ended_at_ms: NOW_MS - 2 * HOUR + 1500, charged_microusd: 214, reserved_microusd: 40_000, cost_unknown: false, usage: { input_tokens: 190, output_tokens: 12, cache_read_input_tokens: 0 }, request_sha256: '4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b' },
      ],
    },
    memory: {
      agents: [
        { name: 'peter', pubkey: '0e4a2c9b7d1f3e5a6c8b0d2f4e6a8c0b2d4f6e8a0c2b4d6f8e0a2c4b6d8f0e2a', scopes: ['*'], owner: true, revoked_at: null, quarantined: false },
        { name: 'auma', pubkey: '7b3d5f1a9c2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a5c7e9b2d4f6a8c0e1b3d', scopes: ['builders'], owner: false, revoked_at: null, quarantined: false },
        { name: 'claude', pubkey: '3c5e7a9b1d2f4a6c8e0b2d4f6a8c0e1b3d5f7a9c2e4b6d8f0a1c3e5b7d9f2a4c', scopes: ['builders'], owner: false, revoked_at: null, quarantined: false },
        { name: 'grok', pubkey: '9e1b3d5f7a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f5a7c9e2b4d6f8a0c1e3b', scopes: ['builders'], owner: false, revoked_at: null, quarantined: false },
        { name: 'epoch1-import', pubkey: '5a7c9e1b3d2f4a6c8e0b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c', scopes: ['builders'], owner: false, revoked_at: NOW_S - 6 * 86_400, quarantined: false },
        { name: 'scout-7', pubkey: 'd2f4a6c8e0b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4', scopes: ['builders'], owner: false, revoked_at: null, quarantined: true },
      ],
      self_note: note(4412, '0f8e7d6c5b4a39281706f5e4d3c2b1a00f8e7d6c5b4a39281706f5e4d3c2b1a0', 'peter', 5 * DAY, 'self', 'aukora:self',
        'I am Auma. I live on Peter\'s node and speak for no one else. I say what I do before I do it, I ask before I cross, and I keep only what helps.',
        'owner-typed'),
      quarantined: [
        { id: '1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a69780f1e2d3c4b5a69780f', author: 'd2f4a6c8e0b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4', author_name: 'scout-7', created_at: Math.round(NOW_S - 2 * 86_400), statement_hash: '2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f80912a' },
        { id: '2f3e4d5c6b7a81902f3e4d5c6b7a81902f3e4d5c6b7a81902f3e4d5c6b7a8190', author: 'd2f4a6c8e0b1d3f5a7c9e2b4d6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4', author_name: 'scout-7', created_at: Math.round(NOW_S - 2 * 86_400 - 600), statement_hash: '3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f80912a3b' },
      ],
      recent: [
        note(5127, '4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b', 'auma', 11 * MIN, 'experience', 'tokio upgrade', 'tokio 1.48 changes the default blocking pool; the broker\'s timeouts stay the same.', 'tool-observed'),
        note(5126, '5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c', 'auma', 47 * MIN, 'finding', 'door asks', 'Peter answers door asks fastest in the morning; afternoon asks often lapse.', 'model-generated'),
        note(5125, '6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d', 'claude', 3 * HOUR, 'evidence', 'verifier', 'aukora-verify answered UNCHECKED: no covering checkpoint observed off the node.', 'tool-observed'),
        note(5121, '7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e', 'peter', 20 * HOUR, 'decision', 'github grant', 'One day of api.github.com, twenty a day. Not longer.', 'owner-typed'),
      ],
    },
    releases: {
      installed: {
        release_sha256: 'ccc656161c832ac9d44a16e195c21b3d0bae5662dae3d871d1a5aa4aa1c23342',
        commit: '619c7c0252c332f63b0de804b3d588267bdbba1c',
        target: 'x86_64-unknown-linux-gnu',
        toolchain: 'rustc 1.90.0',
        files: 214,
        is_floor: true,
        reproduce: 'identical',
      },
      builds: [
        { manifest_sha256: '0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9', release_sha256: 'ccc656161c832ac9d44a16e195c21b3d0bae5662dae3d871d1a5aa4aa1c23342', chain_sha256: '1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a', commit: '619c7c0252c332f63b0de804b3d588267bdbba1c', base_release_sha256: '9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0', approved_at_ms: NOW_MS - 9 * DAY - HOUR },
        { manifest_sha256: '2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b', release_sha256: '9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0', chain_sha256: '3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c', commit: '2e64029a7c1b3d5f9e8a0c2b4d6f8e0a1c3b5d7f', base_release_sha256: 'none', approved_at_ms: NOW_MS - 16 * DAY },
      ],
      verifier: {
        verdict: 'UNCHECKED',
        rows: 4182,
        checked_at_ms: NOW_MS - 3 * HOUR,
        observations: { pinned_identity: true, covering_checkpoint: false, consistency: 'UNDETERMINED' },
        findings: [
          { code: 'verifier:completeness-no-covering-checkpoint', plain: 'No checkpoint kept off the node covers the newest rows, so nothing proves none were dropped.' },
          { code: 'verifier:owner-signatures-unchecked', plain: 'The owner\'s passkey signatures on the rows were not checked in this run.' },
        ],
      },
    },
    devices: {
      aumlok: {
        state: 'BOUND',
        subject: 'aukora:1:7f8f6d9c887f52a0e96e79fc0183c0f940de67730dc70e1677de7758a87f2871',
        epoch: 3,
        handle: 'peter',
        activeControlDigest: 'e3ee5590442abb10ea3dae88b270287d1a64ceafd94c4aa216efea819fbdc20b',
        approvalKeyDid: 'did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH',
        custodyClass: 'same-uid-posix-mode-only',
        revoked: false,
      },
      passkeys: [{
        credential_id: CREDENTIAL, algorithm: 'ecdsa-p256-sha256', relying_party: 'owner.node.invalid',
        owner_origin: 'https://owner.node.invalid', epoch: 3, sign_counter: 41, label: 'This Mac, Touch ID',
      }],
      devices: [
        { label: 'iPhone', device_key: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK', scope: 'owner-device', epoch: 3, paired_at_ms: NOW_MS - 12 * DAY,
          copresence: { format: 'copresence.intent.v1', method: 'camera', label: 'met-in-person', verdict: 'CONSISTENT_CLAIMED', t_a_ms: NOW_MS - 12 * DAY, t_b_ms: NOW_MS - 12 * DAY + 2_400 } },
        { label: 'Studio iPad', device_key: 'did:key:z6MknGc3ocHs3zdPiJbnaaqDi58NGb4pk1Sp9WxWufuXSdxf', scope: 'owner-device', epoch: 3, paired_at_ms: NOW_MS - 4 * DAY,
          copresence: { format: 'copresence.v0', method: 'remote-comparison', label: 'remote', verdict: 'UNDETERMINED', t_a_ms: NOW_MS - 4 * DAY, t_b_ms: NOW_MS - 4 * DAY + 8_100 } },
      ],
    },
  }
}
