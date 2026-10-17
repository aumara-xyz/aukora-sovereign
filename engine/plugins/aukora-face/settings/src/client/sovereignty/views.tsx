// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * What opens under each Sovereignty portal. Every view reads the snapshot and nothing else; every change is an
 * `OwnerAction` (a link to the owner origin). Rows that hold a record are nested portals; rows that do not are plain.
 */
import type { ReactNode } from 'react'
import type {
  ApprovalItem, CategoryId, Crossing, CrossingClass, DoorGrant, SovereigntySnapshot, Tone, VerifierVerdict,
} from './model.ts'
import { CLASS_FACTS, SETTING_FACTS, SLIDER_SETTINGS } from './model.ts'
import { approvalGroup, count, relative, short, stateTone, usd, when } from './format.ts'
import {
  FieldTable, Lead, LevelScale, LockedAction, Meter, Mono, Quote, RecordList, RecordRow, SectionLabel, StatTiles, StatusPill,
} from '@aukora/face-layout/client'
import type { OwnerLink } from './model.ts'
import { SOVEREIGNTY_COPY } from './model.ts'
import { ownerHref } from './format.ts'

type ViewProps = { readonly s: SovereigntySnapshot }

/** The locked action for one owner link: a link to the owner origin, never a change in place. */
function Owner({ link, origin, tone }: { readonly link: OwnerLink; readonly origin: string; readonly tone: Tone }) {
  return (
    <LockedAction
      verb={link.verb}
      tone={tone}
      href={ownerHref(origin, link.route)}
      note={link.route === null ? SOVEREIGNTY_COPY.noRoute : SOVEREIGNTY_COPY.ownerNote}
      title={link.route === null ? SOVEREIGNTY_COPY.noRoute : `${origin}${link.route}`}
    />
  )
}

// ── 1. Approvals ───────────────────────────────────────────────────────────────────────────────────────────────

/** A target in a few plain words. */
export function targetWords(item: ApprovalItem): string {
  const fact = (name: string) => item.card.facts.find(([key]) => key === name)?.[1] ?? ''
  if (item.target.startsWith('door/ask-')) return `Door ask · ${fact('tool')}`
  switch (item.target) {
    case 'engine/plugin-set.json': return 'Plugin set'
    case 'door/standing-grants.json': return 'Standing grants'
    case 'door/slider-policy.json': return 'Risk slider'
    case 'engine/model-budget.json': return 'Model budget'
    case 'release': return 'Release floor'
    case 'build/manifest.json': return 'Build'
    default: return item.target.startsWith('apps/') ? 'App install' : item.target
  }
}

function ApprovalRow({ item, s }: { readonly item: ApprovalItem; readonly s: SovereigntySnapshot }) {
  const group = approvalGroup(item.state)
  const at = item.settled_at_ms ?? item.created_at_ms
  const auth = item.authorization
  return (
    <RecordRow
      tone={stateTone(item.state)}
      title={targetWords(item)}
      summary={`${item.target} · ${relative(at, s.now_ms)}`}
      end={<StatusPill tone={stateTone(item.state)}>{item.state}</StatusPill>}
    >
      <Quote>{item.card.says}</Quote>
      {item.card.model_note === '' ? null : <Lead>{item.card.model_note}</Lead>}
      <FieldTable title="The card" rows={[
        ['risk', item.card.risk],
        ...item.card.facts.map(([k, v]) => [k, v] as const),
        ['display_sha256', item.display_sha256],
        ['proposal', item.proposal],
        ['raised', when(item.created_at_ms)],
      ]} />
      {auth === null ? null : (
        <FieldTable title="What the passkey signed" rows={[
          ['op', auth.op],
          ['node', auth.node],
          ['epoch', String(auth.epoch)],
          ['challenge', auth.challenge],
          ['operation', auth.operation],
          ['credential_id', item.credential_id ?? ''],
          ['signed before', when(auth.expires_at)],
        ]} />
      )}
      {item.receipt_hash === null ? null : (
        <FieldTable title="Receipt" rows={[
          ['state', item.state],
          ['receipt_hash', item.receipt_hash],
          ['settled', item.settled_at_ms === null ? '' : when(item.settled_at_ms)],
        ]} />
      )}
      {group === 'waiting' ? (
        <>
          <Lead>Expires {relative(item.expires_at_ms, s.now_ms)}.</Lead>
          <Owner origin={s.owner_origin} tone="gold" link={{ verb: 'Review with passkey', route: `/approval/${item.proposal}` }} />
        </>
      ) : null}
    </RecordRow>
  )
}

export function ApprovalsView({ s }: ViewProps) {
  const groups = ['waiting', 'approved', 'declined'] as const
  const words = { waiting: 'Waiting for you', approved: 'Approved', declined: 'Declined or lapsed' }
  const sorted = [...s.approvals].sort((a, b) => (b.settled_at_ms ?? b.created_at_ms) - (a.settled_at_ms ?? a.created_at_ms))
  return (
    <>
      {groups.map((group) => {
        const items = sorted.filter(item => approvalGroup(item.state) === group)
        return (
          <section key={group}>
            <SectionLabel>{`${words[group]} · ${String(items.length)}`}</SectionLabel>
            {items.length === 0
              ? <Lead>Nothing here.</Lead>
              : <RecordList>{items.map(item => <ApprovalRow key={item.proposal} item={item} s={s} />)}</RecordList>}
          </section>
        )
      })}
    </>
  )
}

// ── 2. Risk ────────────────────────────────────────────────────────────────────────────────────────────────────

function liveGrants(s: SovereigntySnapshot, cls: CrossingClass): DoorGrant[] {
  return s.risk.grants.filter(g => g.class === cls && !g.revoked && g.not_before <= s.now_ms && s.now_ms < g.expires_at)
}

/** What the door and Laya do today with a crossing of this class, in one word and one line. */
export function classStatus(s: SovereigntySnapshot, cls: CrossingClass): { word: string; tone: Tone; why: string } {
  const facts = CLASS_FACTS.find(f => f.class === cls)
  const rule = s.risk.policy.classes.find(c => c.class === cls)
  const risk = rule?.risk ?? facts?.builtin ?? 'risky'
  const setting = s.risk.policy.setting
  if (s.risk.door[cls] === 'deny') return { word: 'refused', tone: 'muted', why: `the door refuses it (${cls}-denied)` }
  if (facts?.shape === 'never') return { word: 'always asks', tone: 'gold', why: 'no grant can cover it (never-standing)' }
  const clears = setting === 'ask' ? false : setting === 'risky' ? risk === 'routine' : true
  if (!clears) return { word: 'asks', tone: 'gold', why: setting === 'ask' ? 'the slider asks everything (ask-everything)' : 'a risky class at this level (risky-class)' }
  if (liveGrants(s, cls).length === 0) return { word: 'asks', tone: 'gold', why: 'no live grant covers it (no-grant)' }
  return { word: 'clears', tone: 'mint', why: setting === 'trusted' ? 'inside a live grant, no daily count (clear-trusted)' : 'inside a live grant, within today\'s count (clear)' }
}

function GrantRow({ g, s }: { readonly g: DoorGrant; readonly s: SovereigntySnapshot }) {
  const used = s.risk.usage.per_grant[g.id] ?? 0
  const live = !g.revoked && g.not_before <= s.now_ms && s.now_ms < g.expires_at
  const state = g.revoked ? 'revoked' : live ? 'live' : 'expired'
  const tone: Tone = live ? 'mint' : 'muted'
  return (
    <RecordRow
      tone={tone}
      title={<><Mono>{g.class}</Mono> · {g.scope.join(', ')}</>}
      summary={g.revoked ? 'revoked' : `${String(used)} of ${String(g.per_day)} today · ends ${relative(g.expires_at, s.now_ms)}`}
      end={<>{live ? <Meter used={used} cap={g.per_day} tone="mint" /> : null}<StatusPill tone={tone}>{state}</StatusPill></>}
    >
      <FieldTable title="The grant" rows={[
        ['id', g.id],
        ['class', g.class],
        ['scope', g.scope.join(' · ')],
        ['per_day', String(g.per_day)],
        ['not_before', when(g.not_before)],
        ['expires_at', when(g.expires_at)],
        ['nonce', g.nonce],
      ]} />
      {live ? <Owner origin={s.owner_origin} tone="mint" link={{ verb: 'Revoke', route: null }} /> : null}
    </RecordRow>
  )
}

export function RiskView({ s }: ViewProps) {
  const setting = s.risk.policy.setting
  return (
    <>
      <SectionLabel>Laya slider</SectionLabel>
      <LevelScale
        label={`Level ${String(SETTING_FACTS[setting].level)}: ${SETTING_FACTS[setting].label}`}
        current={setting}
        levels={SLIDER_SETTINGS.map(name => ({ key: name, name: `${String(SETTING_FACTS[name].level)} · ${name}`, label: SETTING_FACTS[name].label, tone: SETTING_FACTS[name].tone }))}
      />
      <Lead>
        {`Policy ${short(s.risk.policy.policy_sha256)}${s.risk.policy.is_starter ? ' (the pinned starter)' : ''}. Moving right needs your passkey; moving left applies at once.`}
      </Lead>
      <Owner origin={s.owner_origin} tone={SETTING_FACTS[setting].tone} link={{ verb: 'Move the slider', route: null }} />

      <SectionLabel>Each kind of crossing, today</SectionLabel>
      <RecordList>
        {CLASS_FACTS.map(({ class: cls, plain }) => {
          const status = classStatus(s, cls)
          const cap = s.risk.policy.classes.find(c => c.class === cls)?.per_day ?? 0
          const used = s.risk.usage.per_class[cls] ?? 0
          return (
            <RecordRow tone="muted"
              key={cls}
              title={<><Mono>{cls}</Mono> · {plain}</>}
              summary={cap > 0 ? `${status.why} · ${String(used)} of ${String(cap)} today` : status.why}
              end={<>{cap > 0 ? <Meter used={used} cap={cap} tone={status.tone} /> : null}<StatusPill tone={status.tone}>{status.word}</StatusPill></>}
            />
          )
        })}
      </RecordList>

      <SectionLabel>{`Standing grants · ${String(s.risk.grants.filter(g => !g.revoked).length)} live`}</SectionLabel>
      <RecordList>{s.risk.grants.map(g => <GrantRow key={g.id} g={g} s={s} />)}</RecordList>
    </>
  )
}

// ── 3. Door ────────────────────────────────────────────────────────────────────────────────────────────────────

const DECISION: Record<Crossing['decision'], { word: string; tone: Tone }> = {
  allow: { word: 'allowed', tone: 'mint' },
  ask: { word: 'asked', tone: 'gold' },
  deny: { word: 'refused', tone: 'muted' },
}

export function DoorView({ s }: ViewProps) {
  const tally = (d: Crossing['decision']) => s.door.crossings.filter(c => c.decision === d).length
  return (
    <>
      <StatTiles tiles={[
        { name: 'Allowed', value: tally('allow'), tone: 'mint' },
        { name: 'Asked you', value: tally('ask'), tone: 'gold' },
        { name: 'Refused', value: tally('deny') },
      ]} />
      <SectionLabel>Auma's recent crossings</SectionLabel>
      <RecordList>
        {s.door.crossings.map(c => (
          <RecordRow
            key={c.call_id}
            tone={DECISION[c.decision].tone}
            title={<><Mono>{c.tool}</Mono> · {c.subject}</>}
            summary={`${c.class} · ${c.reason} · ${relative(c.at_ms, s.now_ms)}`}
            end={<StatusPill tone={DECISION[c.decision].tone}>{DECISION[c.decision].word}</StatusPill>}
          >
            <FieldTable rows={[
              ['call_id', c.call_id],
              ['tool', c.tool],
              ['class', c.class],
              ['decision', c.decision],
              ['reason', c.reason],
              ['digest_sha256', c.digest_sha256],
              ['grant', c.grant ?? 'none'],
              ['at', when(c.at_ms)],
            ]} />
          </RecordRow>
        ))}
      </RecordList>
      <SectionLabel>{`Allowlisted hosts · ${String(s.door.net.hosts.length)}`}</SectionLabel>
      <RecordList>
        {s.door.net.hosts.map(host => (
          <RecordRow tone="muted" key={host} title={host} summary={`https · port ${s.door.net.ports.join(', ')}`} end={<StatusPill tone="mint">net</StatusPill>} />
        ))}
      </RecordList>
      <FieldTable rows={[
        ['ports', s.door.net.ports.join(', ')],
        ['max_bytes', count(s.door.net.max_bytes)],
        ['timeout_ms', count(s.door.net.timeout_ms)],
        ['allow_http', String(s.door.net.allow_http)],
      ]} />
      <Owner origin={s.owner_origin} tone="mint" link={{ verb: 'Change the hosts', route: null }} />
    </>
  )
}

// ── 4. Plugins ─────────────────────────────────────────────────────────────────────────────────────────────────

export function PluginsView({ s }: ViewProps) {
  const p = s.plugins
  return (
    <>
      <Lead>{`The engine loads exactly this set, set ${short(p.set_sha256)}. A plugin whose bytes differ does not load until you approve the new set.`}</Lead>
      {p.waiting.length === 0 ? null : (
        <>
          <SectionLabel>{`Changed and waiting · ${String(p.waiting.length)}`}</SectionLabel>
          <RecordList>
            {p.waiting.map(change => (
              <RecordRow key={change.name} tone="gold" title={change.name} summary={`${short(change.approved_digest ?? 'new')} → ${short(change.offered_digest)}`} end={<StatusPill tone="gold">waiting</StatusPill>}>
                <FieldTable rows={[
                  ['name', change.name],
                  ['approved', change.approved_digest ?? 'none (new plugin)'],
                  ['offered', change.offered_digest],
                  ['proposal', change.proposal],
                ]} />
                <Owner origin={s.owner_origin} tone="gold" link={{ verb: 'Review with passkey', route: `/approval/${change.proposal}` }} />
              </RecordRow>
            ))}
          </RecordList>
        </>
      )}
      <SectionLabel>{`Approved set · ${String(p.plugins.length)}`}</SectionLabel>
      <RecordList>
        {p.plugins.map(plugin => (
          <RecordRow
            key={plugin.name}
            tone={plugin.authority ? 'violet' : 'muted'}
            title={plugin.name}
            summary={short(plugin.digest)}
            end={<>{plugin.authority ? <StatusPill tone="violet">authority</StatusPill> : null}<StatusPill tone={plugin.state === 'active' ? 'mint' : 'muted'}>{plugin.state}</StatusPill></>}
          >
            <FieldTable rows={[['name', plugin.name], ['digest', plugin.digest], ['authority', String(plugin.authority)], ['state', plugin.state]]} />
          </RecordRow>
        ))}
      </RecordList>
    </>
  )
}

// ── 5. Model & spending ────────────────────────────────────────────────────────────────────────────────────────

export function ModelView({ s }: ViewProps) {
  const m = s.model
  const b = m.budget
  const left = Math.max(0, b.total_cap_microusd - m.used_microusd)
  return (
    <>
      <StatTiles tiles={[
        { name: 'Key', value: <Mono>{m.key_fingerprint}</Mono>, tone: m.key_stage === 'active' ? 'mint' : 'gold' },
        { name: 'Spent', value: usd(m.used_microusd), tone: 'gold' },
        { name: 'Left', value: usd(left), tone: 'mint' },
        { name: 'Calls', value: `${count(m.used_requests)} / ${count(b.max_requests)}` },
      ]} />
      <RecordRow tone="muted" title={`${usd(m.used_microusd)} of ${usd(b.total_cap_microusd)}`} summary={`ends ${relative(b.expires_at_ms, s.now_ms)} · ${when(b.expires_at_ms)}`} end={<Meter used={m.used_microusd} cap={b.total_cap_microusd} tone="gold" />} />
      <SectionLabel>Budget terms</SectionLabel>
      <FieldTable rows={[
        ['provider', b.provider],
        ['models', b.models.join(', ')],
        ['total_cap', `${usd(b.total_cap_microusd)} (${count(b.total_cap_microusd)} µ$)`],
        ['per_request_cap', usd(b.per_request_cap_microusd)],
        ['max_requests', count(b.max_requests)],
        ['input / Mtok', usd(b.prices.input_microusd_per_mtok)],
        ['output / Mtok', usd(b.prices.output_microusd_per_mtok)],
        ['cache read / Mtok', usd(b.prices.cache_read_microusd_per_mtok)],
        ['key stage', m.key_stage],
        ['budget_sha256', b.budget_sha256],
      ]} />
      <Owner origin={s.owner_origin} tone="gold" link={{ verb: 'New budget or key', route: null }} />
      <SectionLabel>Per-call receipts</SectionLabel>
      <RecordList>
        {m.receipts.map(r => (
          <RecordRow
            key={r.request_id}
            tone={r.outcome === 'completed' ? 'mint' : 'muted'}
            title={<>{r.model} · {count(r.usage.input_tokens)} in · {count(r.usage.output_tokens)} out</>}
            summary={`${relative(r.started_at_ms, s.now_ms)}${r.detail === '' ? '' : ` · ${r.detail}`}`}
            end={<><Mono>{r.cost_unknown ? '?' : usd(r.charged_microusd)}</Mono><StatusPill tone={r.outcome === 'completed' ? 'mint' : 'muted'}>{r.outcome}</StatusPill></>}
          >
            <FieldTable rows={[
              ['request_id', r.request_id],
              ['model', r.model],
              ['reported_model', r.reported_model === '' ? '(none)' : r.reported_model],
              ['charged', `${usd(r.charged_microusd)} (${count(r.charged_microusd)} µ$)${r.cost_unknown ? ', cost unknown' : ''}`],
              ['reserved', usd(r.reserved_microusd)],
              ['cache read', count(r.usage.cache_read_input_tokens)],
              ['took', `${String(Math.round((r.ended_at_ms - r.started_at_ms) / 100) / 10)} s`],
              ['request_sha256', r.request_sha256],
            ]} />
          </RecordRow>
        ))}
      </RecordList>
    </>
  )
}

// ── 6. Memory ──────────────────────────────────────────────────────────────────────────────────────────────────

export function MemoryView({ s }: ViewProps) {
  const m = s.memory
  const nowS = s.now_ms / 1000
  return (
    <>
      <SectionLabel>Auma's self note · aukora:self</SectionLabel>
      {m.self_note === null ? <Lead>No self note yet.</Lead> : (
        <>
          <Quote>{m.self_note.text}</Quote>
          <Lead>{`Written by ${m.self_note.author_name}, ${m.self_note.capture}, ${relative(m.self_note.created_at * 1000, s.now_ms)}. Only you can write it.`}</Lead>
        </>
      )}
      <SectionLabel>{`Agents · ${String(m.agents.length)}`}</SectionLabel>
      <RecordList>
        {m.agents.map(agent => (
          <RecordRow tone="muted"
            key={agent.name}
            title={agent.name}
            summary={`reads and writes: ${agent.scopes.map(scope => scope === '*' ? 'every lane' : scope).join(', ')} · ${short(agent.pubkey)}`}
            end={<>
              {agent.owner ? <StatusPill tone="violet">owner</StatusPill> : null}
              {agent.quarantined ? <StatusPill tone="red">quarantined</StatusPill> : null}
              {agent.revoked_at !== null ? <StatusPill tone="muted" title={`since ${relative(agent.revoked_at * 1000, s.now_ms)}`}>revoked</StatusPill> : null}
              {!agent.owner && !agent.quarantined && agent.revoked_at === null ? <StatusPill tone="mint">active</StatusPill> : null}
            </>}
          />
        ))}
      </RecordList>
      <SectionLabel>{`Quarantined notes · ${String(m.quarantined.length)}`}</SectionLabel>
      <RecordList>
        {m.quarantined.map(q => (
          <RecordRow tone="muted" key={q.id} title={`${q.author_name} · ${short(q.id)}`} summary={`text withheld · statement ${short(q.statement_hash)} · ${relative(q.created_at * 1000, s.now_ms)}`} end={<StatusPill tone="red">quarantined</StatusPill>} />
        ))}
      </RecordList>
      <Owner origin={s.owner_origin} tone="mint" link={{ verb: 'Quarantine or release a source', route: null }} />
      <SectionLabel>Recent writes</SectionLabel>
      <RecordList>
        {m.recent.map(n => (
          <RecordRow key={n.id} tone="mint" title={n.subject} summary={`${n.author_name} · ${n.lane} · ${relative(n.created_at * 1000, s.now_ms)}`} end={<StatusPill tone="muted">{n.capture}</StatusPill>}>
            <Quote>{n.text}</Quote>
            <FieldTable rows={[['id', n.id], ['seq', String(n.seq)], ['lane', n.lane], ['privacy', n.privacy], ['review', n.review], ['created_at', `${String(n.created_at)} (${relative(n.created_at * 1000, nowS * 1000)})`]]} />
          </RecordRow>
        ))}
      </RecordList>
    </>
  )
}

// ── 7. Releases ────────────────────────────────────────────────────────────────────────────────────────────────

export function verdictTone(verdict: VerifierVerdict): Tone {
  if (verdict === 'VERIFIED') return 'mint'
  if (verdict === 'UNCHECKED') return 'gold'
  return 'red'
}

export function ReleasesView({ s }: ViewProps) {
  const r = s.releases
  const v = r.verifier
  return (
    <>
      <SectionLabel>The node's record</SectionLabel>
      <RecordRow tone="muted"
        title={<>aukora-verify · {count(v.rows)} rows</>}
        summary={`checked ${relative(v.checked_at_ms, s.now_ms)}`}
        end={<StatusPill tone={verdictTone(v.verdict)}>{v.verdict}</StatusPill>}
      />
      {v.findings.length === 0 ? null : (
        <RecordList>{v.findings.map(f => <RecordRow tone="muted" key={f.code} title={<Mono>{f.code}</Mono>} summary={f.plain} />)}</RecordList>
      )}
      <FieldTable rows={[
        ['pinned_identity', String(v.observations.pinned_identity)],
        ['covering_checkpoint', String(v.observations.covering_checkpoint)],
        ['consistency', v.observations.consistency],
      ]} />
      <SectionLabel>Installed release</SectionLabel>
      <StatTiles tiles={[
        { name: 'Commit', value: <Mono>{r.installed.commit.slice(0, 7)}</Mono> },
        { name: 'Floor', value: r.installed.is_floor ? 'approved' : 'not yet', tone: r.installed.is_floor ? 'mint' : 'gold' },
        { name: 'Rebuilt', value: r.installed.reproduce, tone: r.installed.reproduce === 'identical' ? 'mint' : 'red' },
      ]} />
      <FieldTable rows={[
        ['release_sha256', r.installed.release_sha256],
        ['commit', r.installed.commit],
        ['target', r.installed.target],
        ['toolchain', r.installed.toolchain],
        ['files', String(r.installed.files)],
      ]} />
      <SectionLabel>{`Approved builds · ${String(r.builds.length)}`}</SectionLabel>
      <RecordList>
        {r.builds.map(b => (
          <RecordRow key={b.manifest_sha256} tone={b.release_sha256 === r.installed.release_sha256 ? 'violet' : 'muted'} title={<>commit <Mono>{b.commit.slice(0, 7)}</Mono></>}
            summary={`release ${short(b.release_sha256)} · ${relative(b.approved_at_ms, s.now_ms)}`}
            end={b.release_sha256 === r.installed.release_sha256 ? <StatusPill tone="violet">installed</StatusPill> : <StatusPill tone="muted">earlier</StatusPill>}>
            <FieldTable rows={[
              ['manifest_sha256', b.manifest_sha256],
              ['release_sha256', b.release_sha256],
              ['chain_sha256', b.chain_sha256],
              ['base_release', b.base_release_sha256],
              ['commit', b.commit],
            ]} />
          </RecordRow>
        ))}
      </RecordList>
    </>
  )
}

// ── 8. Devices & identity ──────────────────────────────────────────────────────────────────────────────────────

export function DevicesView({ s }: ViewProps) {
  const d = s.devices
  return (
    <>
      <SectionLabel>AUMLOK</SectionLabel>
      <StatTiles tiles={[
        { name: 'Binding', value: d.aumlok.state, tone: d.aumlok.state === 'BOUND' ? 'mint' : 'gold' },
        { name: 'Epoch', value: d.aumlok.epoch },
        { name: 'Handle', value: d.aumlok.handle ?? '—' },
      ]} />
      <FieldTable rows={[
        ['subject', d.aumlok.subject],
        ['activeControlDigest', d.aumlok.activeControlDigest],
        ['approvalKeyDid', d.aumlok.approvalKeyDid],
        ['custodyClass', d.aumlok.custodyClass],
        ['revoked', String(d.aumlok.revoked)],
      ]} />
      <Owner origin={s.owner_origin} tone="mint" link={{ verb: 'Refresh the phrase', route: '/phrase/refresh' }} />
      <SectionLabel>{`Passkeys · ${String(d.passkeys.length)}`}</SectionLabel>
      <RecordList>
        {d.passkeys.map(p => (
          <RecordRow key={p.credential_id} tone="blue" title={p.label} summary={`${p.algorithm} · used ${String(p.sign_counter)} times`} end={<StatusPill tone="blue">{`epoch ${String(p.epoch)}`}</StatusPill>}>
            <FieldTable rows={[
              ['credential_id', p.credential_id],
              ['algorithm', p.algorithm],
              ['relying_party', p.relying_party],
              ['owner_origin', p.owner_origin],
              ['sign_counter', String(p.sign_counter)],
            ]} />
          </RecordRow>
        ))}
      </RecordList>
      <Owner origin={s.owner_origin} tone="blue" link={{ verb: 'Add a passkey', route: '/passkey' }} />
      <SectionLabel>{`Paired devices · ${String(d.devices.length)}`}</SectionLabel>
      <RecordList>
        {d.devices.map(dev => (
          <RecordRow key={dev.device_key} tone={dev.copresence.verdict === 'CONSISTENT_CLAIMED' ? 'mint' : 'gold'} title={dev.label}
            summary={`${dev.copresence.label} · ${dev.copresence.method} · paired ${relative(dev.paired_at_ms, s.now_ms)}`}
            end={<StatusPill tone={dev.copresence.verdict === 'CONSISTENT_CLAIMED' ? 'mint' : 'gold'}>{dev.copresence.verdict}</StatusPill>}>
            <FieldTable title="Co-presence receipt" rows={[
              ['device_key', dev.device_key],
              ['scope', dev.scope],
              ['epoch', String(dev.epoch)],
              ['format', dev.copresence.format],
              ['method', dev.copresence.method],
              ['t_a', when(dev.copresence.t_a_ms)],
              ['t_b', `${when(dev.copresence.t_b_ms)} (+${String((dev.copresence.t_b_ms - dev.copresence.t_a_ms) / 1000)} s)`],
            ]} />
            <Owner origin={s.owner_origin} tone="gold" link={{ verb: 'Unpair', route: null }} />
          </RecordRow>
        ))}
      </RecordList>
      <Owner origin={s.owner_origin} tone="mint" link={{ verb: 'Pair a device', route: '/witness' }} />
    </>
  )
}

/** The view under each portal. */
export function CategoryView({ id, s }: { readonly id: CategoryId; readonly s: SovereigntySnapshot }): ReactNode {
  switch (id) {
    case 'approvals': return <ApprovalsView s={s} />
    case 'risk': return <RiskView s={s} />
    case 'door': return <DoorView s={s} />
    case 'plugins': return <PluginsView s={s} />
    case 'model': return <ModelView s={s} />
    case 'memory': return <MemoryView s={s} />
    case 'releases': return <ReleasesView s={s} />
    case 'devices': return <DevicesView s={s} />
  }
}
