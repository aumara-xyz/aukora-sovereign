// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * SOVEREIGNTY: everything the system governs, in eight portals, read-only.
 *
 * Peter, 2026-10-17: "In the system apps, there should be something where it shows all in portal buttons, so
 * they're all categorized. You open it, and then there's stuff in there. It just shows all the stuff that was
 * approved or not approved."
 *
 * NAVIGATION (SPATIAL-DESIGN-RULES 4c and 7): the home is a grid of portal buttons. A portal telescopes open to the
 * whole lane in place and its own header closes it again; there is no back arrow. The open portal is the surface's
 * target (`openSurface('sovereignty', id)`), so the shell remembers it like any other surface state.
 *
 * READ-ONLY: this surface runs inside the engine's origin. It reads one snapshot and renders it. It has no verb;
 * every change is an `OwnerAction`, a link to the owner origin where the owner's passkey decides.
 */
import { useEffect, useMemo } from 'react'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { PortalButton } from '@aukora/face-layout/client'
import type { CategoryId, SovereigntySnapshot, Tone } from './model.ts'
import { CATEGORY_IDS, SETTING_FACTS, SOVEREIGNTY_COPY, SOVEREIGNTY_SURFACE, accentOf } from './model.ts'
import { readSovereigntyStub } from './stub.ts'
import { approvalGroup, usd } from './format.ts'
import { CategoryIcon, LockIcon, Pill } from './parts.tsx'
import { CategoryView, verdictTone } from './views.tsx'
import { isEditableTarget } from '../escape.ts'
import css from './Sovereignty.module.css'

/** Full props for the Sovereignty surface. */
export type SovereigntySurfaceProps = PropsRuntime<'shell.surface'>

interface Face {
  readonly title: string
  readonly tone: Tone
  readonly summary: string
  /** A count or word worth seeing before opening; null when there is nothing to flag. */
  readonly flag: { readonly text: string; readonly tone: Tone } | null
}

/** What each portal says on its face, from the same snapshot its view renders. */
export function faceOf(id: CategoryId, s: SovereigntySnapshot): Face {
  switch (id) {
    case 'approvals': {
      const n = (g: 'waiting' | 'approved' | 'declined') => s.approvals.filter(a => approvalGroup(a.state) === g).length
      const waiting = n('waiting')
      return { title: 'Approvals', tone: 'gold', summary: `${String(waiting)} waiting · ${String(n('approved'))} approved · ${String(n('declined'))} declined`,
        flag: waiting > 0 ? { text: String(waiting), tone: 'gold' } : null }
    }
    case 'risk': {
      const level = SETTING_FACTS[s.risk.policy.setting]
      const live = s.risk.grants.filter(g => !g.revoked && g.not_before <= s.now_ms && s.now_ms < g.expires_at).length
      return { title: 'Risk', tone: level.tone, summary: `${level.label} · ${String(live)} live grants`,
        flag: { text: `level ${String(level.level)}`, tone: level.tone } }
    }
    case 'door': {
      const tally = (d: string) => s.door.crossings.filter(c => c.decision === d).length
      return { title: 'Door', tone: 'mint', summary: `${String(tally('allow'))} allowed · ${String(tally('ask'))} asked · ${String(tally('deny'))} refused · ${String(s.door.net.hosts.length)} hosts`, flag: null }
    }
    case 'plugins': {
      const waiting = s.plugins.waiting.length
      return { title: 'Plugins', tone: 'violet', summary: `${String(s.plugins.plugins.length)} approved · ${String(waiting)} changed and waiting`,
        flag: waiting > 0 ? { text: String(waiting), tone: 'gold' } : null }
    }
    case 'model':
      return { title: 'Model & spending', tone: 'gold', summary: `${usd(s.model.used_microusd)} of ${usd(s.model.budget.total_cap_microusd)} · key ${s.model.key_fingerprint}`,
        flag: s.model.key_stage === 'active' ? null : { text: 'key waiting', tone: 'gold' } }
    case 'memory': {
      const q = s.memory.quarantined.length
      return { title: 'Memory', tone: 'mint', summary: `${String(s.memory.agents.length)} agents · ${String(q)} quarantined · self note ${s.memory.self_note === null ? 'empty' : 'set'}`,
        flag: q > 0 ? { text: String(q), tone: 'red' } : null }
    }
    case 'releases':
      return { title: 'Releases', tone: 'violet', summary: `release ${s.releases.installed.commit.slice(0, 7)} · ${String(s.releases.builds.length)} approved builds`,
        flag: { text: s.releases.verifier.verdict, tone: verdictTone(s.releases.verifier.verdict) } }
    case 'devices':
      return { title: 'Devices & identity', tone: 'blue', summary: `AUMLOK ${s.devices.aumlok.state} · ${String(s.devices.passkeys.length)} passkey · ${String(s.devices.devices.length)} devices`, flag: null }
  }
}

function isCategory(value: string | undefined): value is CategoryId {
  return value !== undefined && (CATEGORY_IDS as readonly string[]).includes(value)
}

/**
 * Render the always-mounted Sovereignty surface.
 * @param props - composed shell-surface props.
 * @returns the surface element tree.
 */
export function SovereigntySurface({ activeSurface, surfaceTarget, openSurface, closeSurface }: SovereigntySurfaceProps) {
  const active = activeSurface === SOVEREIGNTY_SURFACE
  // ONE READ, THEN ONLY RENDERING. The stub today; a node-backed reader of the same shape later.
  const s = useMemo(() => readSovereigntyStub(), [])
  const open = isCategory(surfaceTarget) ? surfaceTarget : null

  useEffect(() => {
    if (!active) return
    // Escape closes the open portal first, then the surface, like the settings surface (and never from a field).
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || isEditableTarget(event.target)) return
      event.preventDefault()
      if (open === null) closeSurface()
      else openSurface(SOVEREIGNTY_SURFACE)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => { document.removeEventListener('keydown', onKeyDown) }
  }, [active, open, closeSurface, openSurface])

  const shown = open === null ? CATEGORY_IDS : CATEGORY_IDS.filter(id => id === open)
  return (
    <section className={css.surface} hidden={!active} data-sovereignty-surface data-sovereignty-open={open ?? 'home'}>
      {active ? (
        <div className={css.canvas}>
          <header className={css.hero}>
            <div className={css.heroCopy}>
              <p className={css.eyebrow}>{SOVEREIGNTY_COPY.eyebrow}</p>
              <h2 className={css.title}>{SOVEREIGNTY_COPY.title}</h2>
            </div>
            <div className={css.badges}>
              <span className={css.badge} data-sovereignty-read-only title={SOVEREIGNTY_COPY.footnote}><LockIcon />{SOVEREIGNTY_COPY.readOnly}</span>
              {s.source === 'stub' ? <span className={`${css.badge} ${css.badgeStub}`} data-sovereignty-source="stub">{SOVEREIGNTY_COPY.stub}</span> : null}
            </div>
          </header>
          <ul className={css.grid} data-open={open === null ? 'no' : 'yes'}>
            {shown.map((id) => {
              const face = faceOf(id, s)
              return (
                <li key={id} className={css.cell} data-sovereignty-category={id}>
                  <PortalButton
                    variant={accentOf(face.tone)}
                    className={css.portal}
                    buttonClassName={css.portalHead}
                    contentClassName={css.detail}
                    expanded={open === id}
                    onExpandedChange={(next) => { openSurface(SOVEREIGNTY_SURFACE, next ? id : undefined) }}
                    icon={<span className={css.icon}><CategoryIcon id={id} /></span>}
                    title={<span data-sov-title>{face.title}</span>}
                    subtitle={<span data-sov-sub>{face.summary}</span>}
                    trailing={face.flag === null ? null : <Pill tone={face.flag.tone}>{face.flag.text}</Pill>}
                  >
                    <CategoryView id={id} s={s} />
                  </PortalButton>
                </li>
              )
            })}
          </ul>
          <p className={css.footnote}><LockIcon />{SOVEREIGNTY_COPY.footnote}</p>
        </div>
      ) : null}
    </section>
  )
}
