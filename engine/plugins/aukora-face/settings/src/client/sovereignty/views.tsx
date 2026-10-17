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
import { Facts, Label, Meter, OwnerAction, Pill, Plain, Row, Rows, Stat } from './parts.tsx'
import css from './Sovereignty.module.css'

type ViewProps = { readonly s: SovereigntySnapshot }

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
    <Row
      tone={stateTone(item.state)}
      title={targetWords(item)}
      sub={`${item.target} · ${relative(at, s.now_ms)}`}
      end={<Pill tone={stateTone(item.state)}>{item.state}</Pill>}
    >
      <p className={css.quote}>{item.card.says}</p>
      {item.card.model_note === '' ? null : <p className={css.lead}>{item.card.model_note}</p>}
      <Facts title="The card" rows={[
        ['risk', item.card.risk],
        ...item.card.facts.map(([k, v]) => [k, v] as const),
        ['display_sha256', item.display_sha256],
        ['proposal', item.proposal],
        ['raised', when(item.created_at_ms)],
      ]} />
      {auth === null ? null : (
        <Facts title="What the passkey signed" rows={[
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
        <Facts title="Receipt" rows={[
          ['state', item.state],
          ['receipt_hash', item.receipt_hash],
          ['settled', item.settled_at_ms === null ? '' : when(item.settled_at_ms)],
        ]} />
      )}
      {group === 'waiting' ? (
        <>
          <p className={css.lead}>Expires {relative(item.expires_at_ms, s.now_ms)}.</p>
          <OwnerAction origin={s.owner_origin} tone="gold" link={{ verb: 'Review with passkey', route: `/approval/${item.proposal}` }} />
        </>
      ) : null}
    </Row>
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
            <Label>{`${words[group]} · ${String(items.length)}`}</Label>
            {items.length === 0
              ? <p className={css.lead}>Nothing here.</p>
              : <Rows>{items.map(item => <ApprovalRow key={item.proposal} item={item} s={s} />)}</Rows>}
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
    <Row
      tone={tone}
      title={<><span className={css.mono}>{g.class}</span> · {g.scope.join(', ')}</>}
      sub={g.revoked ? 'revoked' : `${String(used)} of ${String(g.per_day)} today · ends ${relative(g.expires_at, s.now_ms)}`}
      end={<>{live ? <Meter used={used} cap={g.per_day} tone="mint" /> : null}<Pill tone={tone}>{state}</Pill></>}
    >
      <Facts title="The grant" rows={[
        ['id', g.id],
        ['class', g.class],
        ['scope', g.scope.join(' · ')],
        ['per_day', String(g.per_day)],
        ['not_before', when(g.not_before)],
        ['expires_at', when(g.expires_at)],
        ['nonce', g.nonce],
      ]} />
      {live ? <OwnerAction origin={s.owner_origin} tone="mint" link={{ verb: 'Revoke', route: null }} /> : null}
    </Row>
  )
}

export function RiskView({ s }: ViewProps) {
  const setting = s.risk.policy.setting
  return (
    <>
      <Label>Laya slider</Label>
      <div className={css.notches} role="img" aria-label={`Level ${String(SETTING_FACTS[setting].level)}: ${SETTING_FACTS[setting].label}`}>
        {SLIDER_SETTINGS.map(name => (
          <div key={name} className={css.notch} data-tone={SETTING_FACTS[name].tone} aria-current={name === setting ? 'true' : 'false'}>
            <span className={css.notchDot} />
            <b>{`${String(SETTING_FACTS[name].level)} · ${name}`}</b>
            <span>{SETTING_FACTS[name].label}</span>
          </div>
        ))}
      </div>
      <p className={css.lead}>
        {`Policy ${short(s.risk.policy.policy_sha256)}${s.risk.policy.is_starter ? ' (the pinned starter)' : ''}. Moving right needs your passkey; moving left applies at once.`}
      </p>
      <OwnerAction origin={s.owner_origin} tone={SETTING_FACTS[setting].tone} link={{ verb: 'Move the slider', route: null }} />

      <Label>Each kind of crossing, today</Label>
      <Rows>
        {CLASS_FACTS.map(({ class: cls, plain }) => {
          const status = classStatus(s, cls)
          const cap = s.risk.policy.classes.find(c => c.class === cls)?.per_day ?? 0
          const used = s.risk.usage.per_class[cls] ?? 0
          return (
            <Plain
              key={cls}
              title={<><span className={css.mono}>{cls}</span> · {plain}</>}
              sub={cap > 0 ? `${status.why} · ${String(used)} of ${String(cap)} today` : status.why}
              end={<>{cap > 0 ? <Meter used={used} cap={cap} tone={status.tone} /> : null}<Pill tone={status.tone}>{status.word}</Pill></>}
            />
          )
        })}
      </Rows>

      <Label>{`Standing grants · ${String(s.risk.grants.filter(g => !g.revoked).length)} live`}</Label>
      <Rows>{s.risk.grants.map(g => <GrantRow key={g.id} g={g} s={s} />)}</Rows>
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
      <div className={css.split}>
        <Stat name="Allowed" value={tally('allow')} tone="mint" />
        <Stat name="Asked you" value={tally('ask')} tone="gold" />
        <Stat name="Refused" value={tally('deny')} />
      </div>
      <Label>Auma's recent crossings</Label>
      <Rows>
        {s.door.crossings.map(c => (
          <Row
            key={c.call_id}
            tone={DECISION[c.decision].tone}
            title={<><span className={css.mono}>{c.tool}</span> · {c.subject}</>}
            sub={`${c.class} · ${c.reason} · ${relative(c.at_ms, s.now_ms)}`}
            end={<Pill tone={DECISION[c.decision].tone}>{DECISION[c.decision].word}</Pill>}
          >
            <Facts rows={[
              ['call_id', c.call_id],
              ['tool', c.tool],
              ['class', c.class],
              ['decision', c.decision],
              ['reason', c.reason],
              ['digest_sha256', c.digest_sha256],
              ['grant', c.grant ?? 'none'],
              ['at', when(c.at_ms)],
            ]} />
          </Row>
        ))}
      </Rows>
      <Label>{`Allowlisted hosts · ${String(s.door.net.hosts.length)}`}</Label>
      <Rows>
        {s.door.net.hosts.map(host => (
          <Plain key={host} title={host} sub={`https · port ${s.door.net.ports.join(', ')}`} end={<Pill tone="mint">net</Pill>} />
        ))}
      </Rows>
      <Facts rows={[
        ['ports', s.door.net.ports.join(', ')],
        ['max_bytes', count(s.door.net.max_bytes)],
        ['timeout_ms', count(s.door.net.timeout_ms)],
        ['allow_http', String(s.door.net.allow_http)],
      ]} />
      <OwnerAction origin={s.owner_origin} tone="mint" link={{ verb: 'Change the hosts', route: null }} />
    </>
  )
}

// ── 4. Plugins ─────────────────────────────────────────────────────────────────────────────────────────────────

export function PluginsView({ s }: ViewProps) {
  const p = s.plugins
  return (
    <>
      <p className={css.lead}>{`The engine loads exactly this set, set ${short(p.set_sha256)}. A plugin whose bytes differ does not load until you approve the new set.`}</p>
      {p.waiting.length === 0 ? null : (
        <>
          <Label>{`Changed and waiting · ${String(p.waiting.length)}`}</Label>
          <Rows>
            {p.waiting.map(change => (
              <Row key={change.name} tone="gold" title={change.name} sub={`${short(change.approved_digest ?? 'new')} → ${short(change.offered_digest)}`} end={<Pill tone="gold">waiting</Pill>}>
                <Facts rows={[
                  ['name', change.name],
                  ['approved', change.approved_digest ?? 'none (new plugin)'],
                  ['offered', change.offered_digest],
                  ['proposal', change.proposal],
                ]} />
                <OwnerAction origin={s.owner_origin} tone="gold" link={{ verb: 'Review with passkey', route: `/approval/${change.proposal}` }} />
              </Row>
            ))}
          </Rows>
        </>
      )}
      <Label>{`Approved set · ${String(p.plugins.length)}`}</Label>
      <Rows>
        {p.plugins.map(plugin => (
          <Row
            key={plugin.name}
            tone={plugin.authority ? 'violet' : 'muted'}
            title={plugin.name}
            sub={short(plugin.digest)}
            end={<>{plugin.authority ? <Pill tone="violet">authority</Pill> : null}<Pill tone={plugin.state === 'active' ? 'mint' : 'muted'}>{plugin.state}</Pill></>}
          >
            <Facts rows={[['name', plugin.name], ['digest', plugin.digest], ['authority', String(plugin.authority)], ['state', plugin.state]]} />
          </Row>
        ))}
      </Rows>
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
      <div className={css.split}>
        <Stat name="Key" value={<span className={css.mono}>{m.key_fingerprint}</span>} tone={m.key_stage === 'active' ? 'mint' : 'gold'} />
        <Stat name="Spent" value={usd(m.used_microusd)} tone="gold" />
        <Stat name="Left" value={usd(left)} tone="mint" />
        <Stat name="Calls" value={`${count(m.used_requests)} / ${count(b.max_requests)}`} />
      </div>
      <Plain title={`${usd(m.used_microusd)} of ${usd(b.total_cap_microusd)}`} sub={`ends ${relative(b.expires_at_ms, s.now_ms)} · ${when(b.expires_at_ms)}`} end={<Meter used={m.used_microusd} cap={b.total_cap_microusd} tone="gold" />} />
      <Label>Budget terms</Label>
      <Facts rows={[
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
      <OwnerAction origin={s.owner_origin} tone="gold" link={{ verb: 'New budget or key', route: null }} />
      <Label>Per-call receipts</Label>
      <Rows>
        {m.receipts.map(r => (
          <Row
            key={r.request_id}
            tone={r.outcome === 'completed' ? 'mint' : 'muted'}
            title={<>{r.model} · {count(r.usage.input_tokens)} in · {count(r.usage.output_tokens)} out</>}
            sub={`${relative(r.started_at_ms, s.now_ms)}${r.detail === '' ? '' : ` · ${r.detail}`}`}
            end={<><span className={css.mono}>{r.cost_unknown ? '?' : usd(r.charged_microusd)}</span><Pill tone={r.outcome === 'completed' ? 'mint' : 'muted'}>{r.outcome}</Pill></>}
          >
            <Facts rows={[
              ['request_id', r.request_id],
              ['model', r.model],
              ['reported_model', r.reported_model === '' ? '(none)' : r.reported_model],
              ['charged', `${usd(r.charged_microusd)} (${count(r.charged_microusd)} µ$)${r.cost_unknown ? ', cost unknown' : ''}`],
              ['reserved', usd(r.reserved_microusd)],
              ['cache read', count(r.usage.cache_read_input_tokens)],
              ['took', `${String(Math.round((r.ended_at_ms - r.started_at_ms) / 100) / 10)} s`],
              ['request_sha256', r.request_sha256],
            ]} />
          </Row>
        ))}
      </Rows>
    </>
  )
}

// ── 6. Memory ──────────────────────────────────────────────────────────────────────────────────────────────────

export function MemoryView({ s }: ViewProps) {
  const m = s.memory
  const nowS = s.now_ms / 1000
  return (
    <>
      <Label>Auma's self note · aukora:self</Label>
      {m.self_note === null ? <p className={css.lead}>No self note yet.</p> : (
        <>
          <p className={css.quote}>{m.self_note.text}</p>
          <p className={css.lead}>{`Written by ${m.self_note.author_name}, ${m.self_note.capture}, ${relative(m.self_note.created_at * 1000, s.now_ms)}. Only you can write it.`}</p>
        </>
      )}
      <Label>{`Agents · ${String(m.agents.length)}`}</Label>
      <Rows>
        {m.agents.map(agent => (
          <Plain
            key={agent.name}
            title={agent.name}
            sub={`reads and writes: ${agent.scopes.map(scope => scope === '*' ? 'every lane' : scope).join(', ')} · ${short(agent.pubkey)}`}
            end={<>
              {agent.owner ? <Pill tone="violet">owner</Pill> : null}
              {agent.quarantined ? <Pill tone="red">quarantined</Pill> : null}
              {agent.revoked_at !== null ? <Pill tone="muted" title={`since ${relative(agent.revoked_at * 1000, s.now_ms)}`}>revoked</Pill> : null}
              {!agent.owner && !agent.quarantined && agent.revoked_at === null ? <Pill tone="mint">active</Pill> : null}
            </>}
          />
        ))}
      </Rows>
      <Label>{`Quarantined notes · ${String(m.quarantined.length)}`}</Label>
      <Rows>
        {m.quarantined.map(q => (
          <Plain key={q.id} title={`${q.author_name} · ${short(q.id)}`} sub={`text withheld · statement ${short(q.statement_hash)} · ${relative(q.created_at * 1000, s.now_ms)}`} end={<Pill tone="red">quarantined</Pill>} />
        ))}
      </Rows>
      <OwnerAction origin={s.owner_origin} tone="mint" link={{ verb: 'Quarantine or release a source', route: null }} />
      <Label>Recent writes</Label>
      <Rows>
        {m.recent.map(n => (
          <Row key={n.id} tone="mint" title={n.subject} sub={`${n.author_name} · ${n.lane} · ${relative(n.created_at * 1000, s.now_ms)}`} end={<Pill tone="muted">{n.capture}</Pill>}>
            <p className={css.quote}>{n.text}</p>
            <Facts rows={[['id', n.id], ['seq', String(n.seq)], ['lane', n.lane], ['privacy', n.privacy], ['review', n.review], ['created_at', `${String(n.created_at)} (${relative(n.created_at * 1000, nowS * 1000)})`]]} />
          </Row>
        ))}
      </Rows>
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
      <Label>The node's record</Label>
      <Plain
        title={<>aukora-verify · {count(v.rows)} rows</>}
        sub={`checked ${relative(v.checked_at_ms, s.now_ms)}`}
        end={<Pill tone={verdictTone(v.verdict)}>{v.verdict}</Pill>}
      />
      {v.findings.length === 0 ? null : (
        <Rows>{v.findings.map(f => <Plain key={f.code} title={<span className={css.mono}>{f.code}</span>} sub={f.plain} />)}</Rows>
      )}
      <Facts rows={[
        ['pinned_identity', String(v.observations.pinned_identity)],
        ['covering_checkpoint', String(v.observations.covering_checkpoint)],
        ['consistency', v.observations.consistency],
      ]} />
      <Label>Installed release</Label>
      <div className={css.split}>
        <Stat name="Commit" value={<span className={css.mono}>{r.installed.commit.slice(0, 7)}</span>} />
        <Stat name="Floor" value={r.installed.is_floor ? 'approved' : 'not yet'} tone={r.installed.is_floor ? 'mint' : 'gold'} />
        <Stat name="Rebuilt" value={r.installed.reproduce} tone={r.installed.reproduce === 'identical' ? 'mint' : 'red'} />
      </div>
      <Facts rows={[
        ['release_sha256', r.installed.release_sha256],
        ['commit', r.installed.commit],
        ['target', r.installed.target],
        ['toolchain', r.installed.toolchain],
        ['files', String(r.installed.files)],
      ]} />
      <Label>{`Approved builds · ${String(r.builds.length)}`}</Label>
      <Rows>
        {r.builds.map(b => (
          <Row key={b.manifest_sha256} tone={b.release_sha256 === r.installed.release_sha256 ? 'violet' : 'muted'} title={<>commit <span className={css.mono}>{b.commit.slice(0, 7)}</span></>}
            sub={`release ${short(b.release_sha256)} · ${relative(b.approved_at_ms, s.now_ms)}`}
            end={b.release_sha256 === r.installed.release_sha256 ? <Pill tone="violet">installed</Pill> : <Pill tone="muted">earlier</Pill>}>
            <Facts rows={[
              ['manifest_sha256', b.manifest_sha256],
              ['release_sha256', b.release_sha256],
              ['chain_sha256', b.chain_sha256],
              ['base_release', b.base_release_sha256],
              ['commit', b.commit],
            ]} />
          </Row>
        ))}
      </Rows>
    </>
  )
}

// ── 8. Devices & identity ──────────────────────────────────────────────────────────────────────────────────────

export function DevicesView({ s }: ViewProps) {
  const d = s.devices
  return (
    <>
      <Label>AUMLOK</Label>
      <div className={css.split}>
        <Stat name="Binding" value={d.aumlok.state} tone={d.aumlok.state === 'BOUND' ? 'mint' : 'gold'} />
        <Stat name="Epoch" value={d.aumlok.epoch} />
        <Stat name="Handle" value={d.aumlok.handle ?? '—'} />
      </div>
      <Facts rows={[
        ['subject', d.aumlok.subject],
        ['activeControlDigest', d.aumlok.activeControlDigest],
        ['approvalKeyDid', d.aumlok.approvalKeyDid],
        ['custodyClass', d.aumlok.custodyClass],
        ['revoked', String(d.aumlok.revoked)],
      ]} />
      <OwnerAction origin={s.owner_origin} tone="mint" link={{ verb: 'Refresh the phrase', route: '/phrase/refresh' }} />
      <Label>{`Passkeys · ${String(d.passkeys.length)}`}</Label>
      <Rows>
        {d.passkeys.map(p => (
          <Row key={p.credential_id} tone="blue" title={p.label} sub={`${p.algorithm} · used ${String(p.sign_counter)} times`} end={<Pill tone="blue">{`epoch ${String(p.epoch)}`}</Pill>}>
            <Facts rows={[
              ['credential_id', p.credential_id],
              ['algorithm', p.algorithm],
              ['relying_party', p.relying_party],
              ['owner_origin', p.owner_origin],
              ['sign_counter', String(p.sign_counter)],
            ]} />
          </Row>
        ))}
      </Rows>
      <OwnerAction origin={s.owner_origin} tone="blue" link={{ verb: 'Add a passkey', route: '/passkey' }} />
      <Label>{`Paired devices · ${String(d.devices.length)}`}</Label>
      <Rows>
        {d.devices.map(dev => (
          <Row key={dev.device_key} tone={dev.copresence.verdict === 'CONSISTENT_CLAIMED' ? 'mint' : 'gold'} title={dev.label}
            sub={`${dev.copresence.label} · ${dev.copresence.method} · paired ${relative(dev.paired_at_ms, s.now_ms)}`}
            end={<Pill tone={dev.copresence.verdict === 'CONSISTENT_CLAIMED' ? 'mint' : 'gold'}>{dev.copresence.verdict}</Pill>}>
            <Facts title="Co-presence receipt" rows={[
              ['device_key', dev.device_key],
              ['scope', dev.scope],
              ['epoch', String(dev.epoch)],
              ['format', dev.copresence.format],
              ['method', dev.copresence.method],
              ['t_a', when(dev.copresence.t_a_ms)],
              ['t_b', `${when(dev.copresence.t_b_ms)} (+${String((dev.copresence.t_b_ms - dev.copresence.t_a_ms) / 1000)} s)`],
            ]} />
            <OwnerAction origin={s.owner_origin} tone="gold" link={{ verb: 'Unpair', route: null }} />
          </Row>
        ))}
      </Rows>
      <OwnerAction origin={s.owner_origin} tone="mint" link={{ verb: 'Pair a device', route: '/witness' }} />
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
