// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * SOVEREIGNTY: the shapes the view renders, named after the Rust that owns each fact.
 *
 * Every type here mirrors a wire shape in the crates (the comment on each says where), so wiring the view to the
 * node is a swap of `stub.ts` for a reader that returns the same `SovereigntySnapshot`, and nothing in the
 * components changes. Field names keep the Rust/JSON spelling (`expires_at`, `per_day`, `display_sha256`) on
 * purpose: the screen can then be checked against the record by eye.
 *
 * THE READ-ONLY RULE. This view runs inside the engine's origin. It holds no verb: there is no function in this
 * folder that approves, revokes, moves the slider or writes anything. Every change is an `OwnerLink`: a plain link
 * to the owner origin, where the owner's passkey decides (frontdoor `owner_origin.rs`, app/shell `owner-frame.ts`).
 */

import type { Tone } from '@aukora/face-layout/client'

/** The centre-lane surface id and the System-menu row id. */
export const SOVEREIGNTY_SURFACE = 'sovereignty'

/** The eight portals, in the order they appear on the home grid. */
export const CATEGORY_IDS = ['approvals', 'risk', 'door', 'plugins', 'model', 'memory', 'releases', 'devices'] as const
export type CategoryId = typeof CATEGORY_IDS[number]

/** The primitives' palette: the four spatial colours, red for quarantine and failure only, muted for nothing-to-say. */
export type { Tone } from '@aukora/face-layout/client'

/** 64 lowercase hex, no prefix (`canon::digest::Digest32`). */
export type Hex64 = string
/** 32 lowercase hex: a `ProposalId`, nonce or challenge (`canon::ids`). */
export type Hex32 = string

// ── Owner links: the only way out of this view ─────────────────────────────────────────────────────────────────

/** The owner-origin routes the shell can open (app/shell/owner-frame.ts `OwnerRoute`). */
export type OwnerRoute = '/passkey' | '/phrase' | '/phrase/refresh' | '/claim' | '/witness' | `/approval/${Hex32}`

/** A change the owner can make, which this view can only point at. */
export interface OwnerLink {
  /** Short verb for the pill button ("Approve", "Revoke", "Change"). */
  readonly verb: string
  /** The owner-origin route that holds the ceremony; null when no route exists for it yet (an open question). */
  readonly route: OwnerRoute | null
}

// ── 1. Approvals (gate proposals, C6 cards, C5 authorizations, outcomes) ───────────────────────────────────────

/** `gate::service` `ProposalState` wire names. Only `pending` and `consumed` are not terminal. */
export type ProposalState =
  | 'pending' | 'consumed' | 'applied' | 'refused' | 'expired' | 'retired' | 'incomplete' | 'failed' | 'conflict' | 'unknown'

/** C5 `op` (canon `authority.rs`). */
export type OwnerOp = 'apply' | 'retire' | 'release' | 'grant' | 'permission'

/** The C6 card the owner is shown, exactly (canon `authority.rs`): `display_sha256` is the sha256 of these bytes. */
export interface OwnerCard {
  readonly v: 1
  readonly says: string
  readonly risk: 'routine' | 'critical'
  readonly facts: readonly (readonly [string, string])[]
  readonly model_note: string
}

/** The C5 authorization the passkey signed (canon `authority.rs` `OwnerAuthorization`), the fields worth showing. */
export interface OwnerAuthorization {
  readonly node: string
  readonly op: OwnerOp
  readonly proposal: Hex32
  readonly target: string
  readonly base_sha256: Hex64 | 'absent'
  readonly new_sha256: Hex64
  readonly display_sha256: Hex64
  readonly challenge: Hex32
  readonly expires_at: number
  readonly epoch: number
  readonly operation: Hex64
}

/** One proposal, as the owner sees it. */
export interface ApprovalItem {
  readonly proposal: Hex32
  readonly target: string
  readonly state: ProposalState
  /** When the proposal was raised, ms. */
  readonly created_at_ms: number
  /** When it settled (applied, refused, retired, expired), ms; null while pending. */
  readonly settled_at_ms: number | null
  /** `GET /api/approvals` `expires_at_ms`. */
  readonly expires_at_ms: number
  readonly card: OwnerCard
  readonly display_sha256: Hex64
  /** What the passkey signed; null for a proposal nobody signed (pending, expired). */
  readonly authorization: OwnerAuthorization | null
  /** The passkey that signed it (base64url credential id), null when unsigned. */
  readonly credential_id: string | null
  /** `gate::Outcome` `{proposal, state, receipt_hash}`; null while pending. */
  readonly receipt_hash: Hex64 | null
}

// ── 2. Risk (laya: slider policy, standing grants, usage) ──────────────────────────────────────────────────────

/** `laya::SliderSetting` policy wire names, tightest first (`trusted` is policy-only: `from_policy_wire`). */
export const SLIDER_SETTINGS = ['ask', 'risky', 'limits', 'trusted'] as const
export type SliderSetting = typeof SLIDER_SETTINGS[number]

/** `laya::CrossingClass` wire names. */
export type CrossingClass =
  | 'net' | 'memory' | 'mcp' | 'delegate' | 'fs-outside' | 'plugin' | 'persist' | 'shell-interactive' | 'unknown'

/** `laya::GrantShape`: what a grant's scope holds; `never` means no standing grant can cover the class. */
export type GrantShape = 'hosts' | 'memory' | 'servers' | 'providers' | 'prefixes' | 'never'

/** `laya::ClassRule` (policy wire `{"class","per_day","risk"}`). */
export interface ClassRule {
  readonly class: CrossingClass
  readonly risk: 'routine' | 'risky'
  readonly per_day: number
}

/** The door policy's per-class action (`supervisor/door/policy.rs`). Only `net` and `memory` may be `allow`. */
export type DoorAction = 'allow' | 'ask' | 'deny'

/** `laya::SliderPolicy` plus the facts around it the owner needs. */
export interface SliderPolicyView {
  readonly setting: SliderSetting
  readonly classes: readonly ClassRule[]
  /** sha256 of the policy's canonical bytes (`door/slider-policy.json`). */
  readonly policy_sha256: Hex64
  /** True while the policy is still the pinned starter (`STARTER_SHA256`). */
  readonly is_starter: boolean
}

/** `laya::DoorGrant` (wire: class, expires_at, nonce, not_before, per_day, scope, v) plus its derived `id()`. */
export interface DoorGrant {
  readonly id: Hex64
  readonly class: CrossingClass
  readonly scope: readonly string[]
  readonly per_day: number
  readonly not_before: number
  readonly expires_at: number
  readonly nonce: Hex32
  /** True when the id is in the GrantSet's `revoked` list. */
  readonly revoked: boolean
}

/** `laya::Usage`: today's counts (`day = now_ms div 86_400_000`). */
export interface UsageView {
  readonly day: number
  readonly per_class: Readonly<Partial<Record<CrossingClass, number>>>
  readonly per_grant: Readonly<Record<Hex64, number>>
}

// ── 3. Door (supervisor/door: replies, asks.jsonl, autoclear.jsonl, net policy) ────────────────────────────────

/** One crossing Auma asked the door for. There is no single record of this in Rust yet; see the spec. */
export interface Crossing {
  readonly at_ms: number
  readonly call_id: string
  readonly tool: string
  readonly class: CrossingClass
  /** The door reply's `decision`. */
  readonly decision: 'allow' | 'ask' | 'deny'
  /** The reason token: a laya `Decision` reason for allow/ask, the reply's `refusal` token for deny. */
  readonly reason: string
  /** What it was about, in a few words (host, path, lane). */
  readonly subject: string
  readonly digest_sha256: Hex64
  /** The grant id an auto-clear spent, from `autoclear.jsonl`. */
  readonly grant: Hex64 | null
}

/** `door-policy-v1.json` `net`. */
export interface NetPolicy {
  readonly hosts: readonly string[]
  readonly ports: readonly number[]
  readonly max_bytes: number
  readonly timeout_ms: number
  readonly allow_http: boolean
}

// ── 4. Plugins (supervisor `engine_plugins.rs`, floor `plugins.rs`: target `engine/plugin-set.json`) ──────────────

/** One entry of the approved plugin set: `{"authority","digest","name"}`. */
export interface PluginEntry {
  readonly name: string
  /** `sha256("aukora:plugin-package:v1\0" + files)`, full 64 hex (no short form exists for plugins). */
  readonly digest: Hex64
  /** True only for `@aukora/door`, which is mandatory. */
  readonly authority: boolean
  /** `settings.plugins` runtime state (`faces/settings.rs`), when the engine reports it. */
  readonly state: 'waiting' | 'starting' | 'active' | 'stopping' | 'failed' | 'disposed'
}

/** A plugin whose bytes differ from the approved set and that waits for the owner (a new set proposal). */
export interface PluginChange {
  readonly name: string
  readonly approved_digest: Hex64 | null
  readonly offered_digest: Hex64
  readonly proposal: Hex32
}

export interface PluginsView {
  readonly set_sha256: Hex64
  readonly plugins: readonly PluginEntry[]
  readonly waiting: readonly PluginChange[]
}

// ── 5. Model & spending (broker `engine_link`: model-key.json, model-budget.json, spend-v1.jsonl, receipts) ─────

/** `engine/model-budget.json` (`aukora-engine-model-budget-v1`); money is micro-dollars. */
export interface ModelBudget {
  readonly budget_sha256: Hex64
  readonly provider: 'deepseek'
  readonly models: readonly string[]
  readonly total_cap_microusd: number
  readonly per_request_cap_microusd: number
  readonly max_requests: number
  readonly expires_at_ms: number
  readonly prices: {
    readonly input_microusd_per_mtok: number
    readonly output_microusd_per_mtok: number
    readonly cache_read_microusd_per_mtok: number
  }
}

/** `aukora-engine-model-receipt-v1` body (broker `server.rs`), the fields worth a row. */
export interface ModelReceipt {
  readonly request_id: Hex32
  readonly model: string
  readonly reported_model: string
  readonly outcome: 'completed' | 'cancelled' | 'key-echo' | 'unreachable' | 'provider-refused' | 'interrupted'
  readonly detail: string
  readonly started_at_ms: number
  readonly ended_at_ms: number
  readonly charged_microusd: number
  readonly reserved_microusd: number
  readonly cost_unknown: boolean
  readonly usage: {
    readonly input_tokens: number
    readonly output_tokens: number
    readonly cache_read_input_tokens: number
  }
  readonly request_sha256: Hex64
}

export interface ModelView {
  /** First 12 hex of `key_sha256` (`budget.rs` `fingerprint()`). */
  readonly key_fingerprint: string
  /** `KeyStage::Active` or `KeyStage::AwaitingApproval`. */
  readonly key_stage: 'active' | 'awaiting-approval'
  readonly budget: ModelBudget
  /** `Used{microusd, requests}` from `spend-v1.jsonl`: settled charges plus open reservations. */
  readonly used_microusd: number
  readonly used_requests: number
  readonly receipts: readonly ModelReceipt[]
}

// ── 6. Memory (Kira 2: `store.rs` agents, `note.rs` slots and kinds, `service/mod.rs` wire note) ──────────────────

/** `AgentRecord{pubkey, name, scopes, owner, revoked_at}`. One scope list governs reading and writing. */
export interface KiraAgent {
  readonly name: string
  readonly pubkey: Hex64
  readonly scopes: readonly string[]
  readonly owner: boolean
  readonly revoked_at: number | null
  /** Quarantine is per source (author key), owner-only. */
  readonly quarantined: boolean
}

/** Kira lanes; charter, ruling, decision, self and resume are owner-only. */
export type KiraLane = 'evidence' | 'experience' | 'charter' | 'ruling' | 'decision' | 'finding' | 'self' | 'resume'

/** A note on the wire, the fields a row shows (`created_at` is unix SECONDS). */
export interface KiraNote {
  readonly id: Hex64
  readonly seq: number
  readonly author_name: string
  readonly created_at: number
  readonly lane: KiraLane
  readonly subject: string
  readonly text: string
  readonly capture: 'owner-typed' | 'owner-signed' | 'tool-observed' | 'web-derived' | 'model-generated' | 'import'
  readonly privacy: 'local' | 'builders' | 'public'
  readonly review: 'remembered' | 'owner_signed'
}

/** A quarantined note as Kira shows it: a stub, never the text (`"correction":"quarantined"`). */
export interface QuarantinedNote {
  readonly id: Hex64
  readonly author: Hex64
  readonly author_name: string
  readonly created_at: number
  readonly statement_hash: Hex64
}

export interface MemoryView {
  readonly agents: readonly KiraAgent[]
  /** The newest live note in slot `aukora:self` (lane `self`, owner-typed or owner-signed, at most 4,096 bytes). */
  readonly self_note: KiraNote | null
  readonly quarantined: readonly QuarantinedNote[]
  /** `list_recent` (newest first). */
  readonly recent: readonly KiraNote[]
}

// ── 7. Releases (supervisor `release.rs`, gate `build.rs`, `builds.jsonl`, verifier verdicts) ─────────────────────

/** `aukora-verify` verdicts (verifier `report.rs`). */
export type VerifierVerdict = 'VERIFIED' | 'UNCHECKED' | 'REWRITTEN' | 'FORGED' | 'KEY_MISMATCH' | 'INVALID_INPUT'

export interface InstalledRelease {
  /** sha256 of `release.json` (`aukora-release-v1`). */
  readonly release_sha256: Hex64
  readonly commit: string
  readonly target: string
  readonly toolchain: string
  readonly files: number
  /** True when the owner approved it as the release floor (target `release`). */
  readonly is_floor: boolean
  /** `scripts/reproduce.sh` answer for this commit: `identical` or the `reproduce:<code>`. */
  readonly reproduce: string
}

/** One line of `builds.jsonl` plus the manifest facts the card showed. */
export interface ApprovedBuild {
  readonly manifest_sha256: Hex64
  readonly release_sha256: Hex64
  readonly chain_sha256: Hex64
  readonly commit: string
  readonly base_release_sha256: Hex64 | 'none'
  readonly approved_at_ms: number
}

export interface VerifierView {
  readonly verdict: VerifierVerdict
  readonly rows: number
  /** `findings[].code` (`verifier:<reason>`), with what each means in plain words. */
  readonly findings: readonly { readonly code: string; readonly plain: string }[]
  readonly checked_at_ms: number
  readonly observations: {
    readonly pinned_identity: boolean
    readonly covering_checkpoint: boolean
    readonly consistency: 'APPEND_ONLY' | 'OBSERVATION_CONFLICT' | 'UNDETERMINED'
  }
}

export interface ReleasesView {
  readonly installed: InstalledRelease
  readonly builds: readonly ApprovedBuild[]
  readonly verifier: VerifierView
}

// ── 8. Devices & identity (canon `OwnerBinding`, aumlok `devices.rs`, copresence receipts, aumlok-control) ────────

export interface Passkey {
  /** base64url credential id. */
  readonly credential_id: string
  readonly algorithm: string
  readonly relying_party: string
  readonly owner_origin: string
  readonly epoch: number
  readonly sign_counter: number
  readonly label: string
}

/** A paired device (`DevicePairingBody`) with the co-presence evidence it was paired by. */
export interface PairedDevice {
  readonly label: string
  readonly device_key: string
  readonly scope: string
  readonly epoch: number
  readonly paired_at_ms: number
  readonly copresence: {
    readonly format: 'copresence.v0' | 'copresence.intent.v1'
    readonly method: 'camera' | 'relayed-camera' | 'remote-comparison'
    readonly label: 'met-in-person' | 'remote' | 'relayed' | 'unverified-method'
    readonly verdict: 'CONSISTENT_CLAIMED' | 'SUSPICIOUS' | 'UNDETERMINED'
    readonly t_a_ms: number
    readonly t_b_ms: number
  }
}

/** `/api/aukora/aumlok-control` public control, or its not-connected answer. */
export interface AumlokStatus {
  readonly state: 'BOUND' | 'UNBOUND'
  readonly subject: string
  readonly epoch: number
  readonly handle: string | null
  readonly activeControlDigest: Hex64
  readonly approvalKeyDid: string
  readonly custodyClass: string
  readonly revoked: boolean
}

export interface DevicesView {
  readonly aumlok: AumlokStatus
  readonly passkeys: readonly Passkey[]
  readonly devices: readonly PairedDevice[]
}

// ── The whole snapshot ─────────────────────────────────────────────────────────────────────────────────────────

/** Everything the view renders, from one read. A node-backed reader returns exactly this. */
export interface SovereigntySnapshot {
  /** Where the facts came from: `stub` until the node is wired; the view says so. */
  readonly source: 'stub' | 'node'
  /** The time the snapshot describes, ms (relative times are computed from it, never from the clock). */
  readonly now_ms: number
  /** The node the owner origin belongs to (the stub's is a `.invalid` name and never resolves). */
  readonly owner_origin: string
  readonly approvals: readonly ApprovalItem[]
  readonly risk: {
    readonly policy: SliderPolicyView
    readonly door: Readonly<Record<CrossingClass, DoorAction>>
    readonly grants: readonly DoorGrant[]
    readonly usage: UsageView
  }
  readonly door: { readonly crossings: readonly Crossing[]; readonly net: NetPolicy }
  readonly plugins: PluginsView
  readonly model: ModelView
  readonly memory: MemoryView
  readonly releases: ReleasesView
  readonly devices: DevicesView
}

// ── Fixed facts from the crates, and the view's copy ───────────────────────────────────────────────────────────

/** `laya::CrossingClass::grant_shape` and built-in risk, in the order the Risk portal lists them. */
export const CLASS_FACTS: readonly { readonly class: CrossingClass; readonly shape: GrantShape; readonly builtin: 'routine' | 'risky'; readonly plain: string }[] = [
  { class: 'net', shape: 'hosts', builtin: 'routine', plain: 'Reach a website' },
  { class: 'memory', shape: 'memory', builtin: 'routine', plain: 'Read or write Kira' },
  { class: 'mcp', shape: 'servers', builtin: 'risky', plain: 'Call a tool server' },
  { class: 'delegate', shape: 'providers', builtin: 'risky', plain: 'Hand work to another model' },
  { class: 'fs-outside', shape: 'prefixes', builtin: 'risky', plain: 'Files outside the workspace' },
  { class: 'plugin', shape: 'never', builtin: 'risky', plain: 'Change a plugin' },
  { class: 'persist', shape: 'never', builtin: 'risky', plain: 'Keep something running' },
  { class: 'shell-interactive', shape: 'never', builtin: 'risky', plain: 'An interactive terminal' },
  { class: 'unknown', shape: 'never', builtin: 'risky', plain: 'Anything unrecognised' },
]

/** The four notches: Peter's colours (1 mint, 2 blue, 3 violet, 4 gold) and the composer's words. */
export const SETTING_FACTS: Readonly<Record<SliderSetting, { readonly level: number; readonly tone: Tone; readonly label: string }>> = {
  ask: { level: 1, tone: 'mint', label: 'Ask me everything' },
  risky: { level: 2, tone: 'blue', label: 'Only risky things' },
  limits: { level: 3, tone: 'violet', label: 'Within today\'s limits' },
  trusted: { level: 4, tone: 'gold', label: 'Trusted: inside live grants' },
}

/** The view's words. English only in this preview; the locale namespace comes with the wiring. */
export const SOVEREIGNTY_COPY = {
  menuTitle: 'Sovereignty',
  menuDescription: 'everything the system governs',
  eyebrow: 'What your node governs',
  title: 'Sovereignty',
  readOnly: 'Read-only',
  stub: 'Preview data',
  notConnected: 'Not connected yet',
  emptyLead: 'Not connected yet. This node does not serve these facts to the view yet; nothing here is made up. Once its read-only route exists, this shows:',
  footnote: 'This view only reads. Every change opens your passkey on the owner origin, which shows its own card.',
  ownerNote: 'opens the owner origin',
  noRoute: 'The owner origin has no screen for this yet.',
} as const

// ── On a node, until the read-only routes exist: an honest empty state per portal ────────────────────────────────

/** Each portal's name, colour, and what it will show once the node answers. */
export const CATEGORY_FACTS: Readonly<Record<CategoryId, { readonly title: string; readonly tone: Tone; readonly willShow: readonly string[] }>> = {
  approvals: { title: 'Approvals', tone: 'gold', willShow: ['What waits for your passkey, newest first', 'The exact card you signed: target, digests, time', 'What the passkey signed, and the receipt'] },
  risk: { title: 'Risk', tone: 'blue', willShow: ['The Laya slider level, 1 to 4', 'What clears per kind of crossing, and today\'s count', 'Standing grants and when they end'] },
  door: { title: 'Door', tone: 'mint', willShow: ['Auma\'s recent crossings: allowed, asked, refused', 'The reason for each, and the grant it used', 'The hosts the door allows'] },
  plugins: { title: 'Plugins', tone: 'violet', willShow: ['The approved plugin set and each fingerprint', 'Anything changed and waiting for you'] },
  model: { title: 'Model & spending', tone: 'gold', willShow: ['The model key fingerprint', 'Budget terms, spent and left', 'A receipt for every call'] },
  memory: { title: 'Memory', tone: 'mint', willShow: ['Agents and what they may read and write', 'Auma\'s self note', 'Quarantined sources and recent writes'] },
  releases: { title: 'Releases', tone: 'violet', willShow: ['The installed release and whether it rebuilds identically', 'Approved builds', 'The verifier\'s verdict on the node\'s record, and why'] },
  devices: { title: 'Devices & identity', tone: 'blue', willShow: ['AUMLOK binding and epoch', 'Your passkeys', 'Paired devices and their co-presence receipts'] },
}

/**
 * THE PREVIEW GATE is the layout's one preview switch (`isPreviewComposition`, page global `__AUKORA_PREVIEW__`): the
 * stub snapshot is read only in the preview; on a node every portal is empty and says so.
 */
