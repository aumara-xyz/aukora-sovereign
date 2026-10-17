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
 * state; the shell's target only deep-links into one. Opening a portal never resizes a lane.
 *
 * READ-ONLY: this surface runs inside the engine's origin. It reads one snapshot and renders it. It has no verb;
 * every change is an `OwnerAction`, a link to the owner origin where the owner's passkey decides.
 */
import { useEffect, useMemo, useState } from 'react'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { AppHeader, AppSurface, Footnote, PortalButton, PortalCell, PortalGrid, StatusPill } from '@aukora/face-layout/client'
import type { CategoryId, SovereigntySnapshot, Tone } from './model.ts'
import { CATEGORY_IDS, SETTING_FACTS, SOVEREIGNTY_COPY, SOVEREIGNTY_SURFACE } from './model.ts'
import { readSovereigntyStub } from './stub.ts'
import { approvalGroup, usd } from './format.ts'
import { CategoryView, verdictTone } from './views.tsx'
import { isEditableTarget } from '../escape.ts'

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
export function SovereigntySurface({ activeSurface, surfaceTarget, closeSurface }: SovereigntySurfaceProps) {
  const active = activeSurface === SOVEREIGNTY_SURFACE
  // ONE READ, THEN ONLY RENDERING. The stub today; a node-backed reader of the same shape later.
  const s = useMemo(() => readSovereigntyStub(), [])
  // THE OPEN PORTAL IS THIS SURFACE'S OWN STATE, NOT THE SHELL'S. Opening a portal must never move a lane, and a
  // portal is not a navigation: it never goes through the shell's `openSurface` (which, until the rule-3 fix, set
  // the pane preset and snapped a one-third lane to two-thirds). The shell's target is read once as a deep link (a menu or
  // another app may open `sovereignty/<id>`), and from then on the portal opens and closes inside the current lane.
  const [open, setOpen] = useState<CategoryId | null>(isCategory(surfaceTarget) ? surfaceTarget : null)
  useEffect(() => { if (isCategory(surfaceTarget)) setOpen(surfaceTarget) }, [surfaceTarget])

  useEffect(() => {
    if (!active) return
    // Escape closes the open portal first, then the surface, like the settings surface (and never from a field).
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || isEditableTarget(event.target)) return
      event.preventDefault()
      if (open === null) closeSurface()
      else setOpen(null)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => { document.removeEventListener('keydown', onKeyDown) }
  }, [active, open, closeSurface])

  const shown = open === null ? CATEGORY_IDS : CATEGORY_IDS.filter(id => id === open)
  return (
    <AppSurface active={active} data-sovereignty-surface="" data-sovereignty-open={open ?? 'home'}>
      <AppHeader
        eyebrow={SOVEREIGNTY_COPY.eyebrow}
        title={SOVEREIGNTY_COPY.title}
        tone="violet"
        badges={[
          { text: SOVEREIGNTY_COPY.readOnly, icon: 'lock', title: SOVEREIGNTY_COPY.footnote },
          ...(s.source === 'stub' ? [{ text: SOVEREIGNTY_COPY.stub, tone: 'gold' as const }] : []),
        ]}
      />
      <PortalGrid open={open !== null}>
        {shown.map((id) => {
          const face = faceOf(id, s)
          return (
            <PortalCell key={id} data-sovereignty-category={id}>
              <PortalButton
                tone={face.tone}
                icon={id}
                title={face.title}
                summary={face.summary}
                expanded={open === id}
                onToggle={(next) => { setOpen(next ? id : null) }}
                badge={face.flag === null ? null : <StatusPill tone={face.flag.tone}>{face.flag.text}</StatusPill>}
              >
                <CategoryView id={id} s={s} />
              </PortalButton>
            </PortalCell>
          )
        })}
      </PortalGrid>
      <Footnote>{SOVEREIGNTY_COPY.footnote}</Footnote>
    </AppSurface>
  )
}
