// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * AURA COHERENCE: the node's living state on the Pentora (replaces Prime's tesseract).
 *
 * The Pentora turns at the centre; the node's 110 health cells sit where canon pins them on its geometry (see
 * model.ts and PentoraFigure.tsx). Below it, one portal per organ, and one for the corners they share, built from the
 * spatial primitives only, with every check canon registers and its state.
 *
 * READ-ONLY. Stub data only in the preview (the one preview switch); on a node every cell is Undetermined (no report
 * reaches the view yet) and the view says "Not connected yet". Nothing here can change anything.
 */
import { useEffect, useMemo, useState } from 'react'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import {
  AppHeader, AppSurface, FieldTable, Footnote, isPreviewComposition, Lead, PortalButton, PortalCell, PortalGrid,
  RecordList, RecordRow, SectionLabel, StatTiles, StatusPill, type Tone,
} from '@aukora/face-layout/client'
import type { AuraHealthView, CellReport, CellState, Tally } from './model.ts'
import {
  AURA_COPY, AURA_SURFACE, ORGANS, ORGAN_FACTS, cornersOf, organTally, placeOf, postureOf, privateOf, wholeTally, absentHealth,
} from './model.ts'
import { CHECKS, CORNERS, CORNER_CELLS, CUBES, type OrganWire } from './tables.ts'
import { readAuraStub, stepStub } from './stub.ts'
import { PentoraFigure } from './PentoraFigure.tsx'
import { isEditableTarget } from '../escape.ts'

export type AuraPentoraSurfaceProps = PropsRuntime<'shell.surface'>

const CELL_TONE: Readonly<Record<CellState, Tone>> = { verified: 'mint', undetermined: 'gold', failed: 'red' }
const STEP_MS = 3500

function ago(ms: number | null): string {
  if (ms === null) return 'never observed'
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000))
  return s < 60 ? `${String(s)} s ago` : s < 3600 ? `${String(Math.round(s / 60))} min ago` : `${String(Math.round(s / 3600))} h ago`
}

function tallyWords(t: Tally): string {
  return `${String(t.verified)} verified · ${String(t.undetermined)} undetermined · ${String(t.failed)} failed`
}

function tallyPill(t: Tally, connected: boolean) {
  if (!connected) return <StatusPill tone="muted">{AURA_COPY.notConnected}</StatusPill>
  if (t.failed > 0) return <StatusPill tone="red">{`${String(t.failed)} failed`}</StatusPill>
  if (t.undetermined > 0) return <StatusPill tone="gold">{`${String(t.undetermined)} unknown`}</StatusPill>
  return <StatusPill tone="mint">verified</StatusPill>
}

function CellPill({ report, connected }: { readonly report: CellReport; readonly connected: boolean }) {
  return connected ? <StatusPill tone={CELL_TONE[report.cell]}>{report.cell}</StatusPill> : <StatusPill tone="muted">not connected</StatusPill>
}

function OrganDetail({ organ, view, connected }: { readonly organ: OrganWire; readonly view: AuraHealthView; readonly connected: boolean }) {
  const cube = CUBES[ORGANS.indexOf(organ)]!
  const reports = privateOf(view, organ)
  const t = organTally(view, organ)
  return (
    <>
      <Lead>{connected ? `Covers ${ORGAN_FACTS[organ].covers}.` : AURA_COPY.emptyLead}</Lead>
      {connected ? <StatTiles tiles={[
        { name: 'Verified', value: t.verified, tone: 'mint' },
        { name: 'Undetermined', value: t.undetermined, tone: 'gold' },
        { name: 'Failed', value: t.failed, tone: t.failed > 0 ? 'red' : 'muted' },
      ]} /> : null}
      <SectionLabel>18 private checks · its edges and faces</SectionLabel>
      <RecordList>
        {CHECKS.filter(check => check.organ === organ).map((check, k) => {
          const report = reports[k]!
          return (
            <RecordRow key={check.source} tone={connected ? CELL_TONE[report.cell] : 'muted'} title={check.invariant} rowTitle={check.invariant}
              summary={`${check.source} · ${placeOf(organ, check.index)}`} status={<CellPill report={report} connected={connected} />}>
              <FieldTable rows={[
                ['check', `${organ} #${String(check.index)}`],
                ['invariant', check.invariant],
                ['source', check.source],
                ['cell', connected ? report.cell : 'undetermined (no report reaches the view)'],
                ['reason', report.reason],
                ['observed', connected ? ago(report.observed_at_ms) : '—'],
                ['freshness limit', `${String(check.freshness_ms / 1000)} s`],
                ['on the Pentora', `${placeOf(organ, check.index)}, cell ${String(cube.private[check.index - 1])}`],
              ]} />
            </RecordRow>
          )
        })}
      </RecordList>
      <SectionLabel>8 shared corners · its vertices</SectionLabel>
      <RecordList>
        {cornersOf(organ).map((index) => {
          const corner = CORNERS[index - 1]!
          const report = view.corners[index - 1]!
          return (
            <RecordRow key={index} tone={connected ? CELL_TONE[report.cell] : 'muted'} title={corner.invariant} rowTitle={corner.invariant}
              summary={`${corner.pair} · corner ${String(index)}`} status={<CellPill report={report} connected={connected} />}>
              <FieldTable rows={[
                ['corner', String(index)],
                ['pair', corner.pair],
                ['sources', corner.sources.join(' · ')],
                ['cell', connected ? report.cell : 'undetermined (no report reaches the view)'],
                ['reason', report.reason],
                ['observed', connected ? ago(report.observed_at_ms) : '—'],
                ['on the Pentora', `vertex, cell ${String(CORNER_CELLS[index - 1])}`],
              ]} />
            </RecordRow>
          )
        })}
      </RecordList>
    </>
  )
}

/**
 * Render the always-mounted Aura Coherence surface.
 * @param props - composed shell-surface props.
 * @returns the surface element tree.
 */
export function AuraPentoraSurface({ activeSurface, closeSurface }: AuraPentoraSurfaceProps) {
  const active = activeSurface === AURA_SURFACE
  const preview = useMemo(() => isPreviewComposition(), [])
  const [view, setView] = useState<AuraHealthView>(() => (preview ? readAuraStub(Date.now()) : absentHealth()))
  const [open, setOpen] = useState<number | null>(null)
  const connected = view.source === 'stub' || view.sequence > 0

  // PREVIEW ONLY: a new observation every few seconds, so the preview shows what recent activity looks like.
  useEffect(() => {
    if (!preview || !active) return
    let step = 0
    const timer = setInterval(() => { setView(current => stepStub(current, Date.now(), step++)) }, STEP_MS)
    return () => { clearInterval(timer) }
  }, [preview, active])

  useEffect(() => {
    if (!active) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || isEditableTarget(event.target)) return
      event.preventDefault()
      if (open === null) closeSurface()
      else setOpen(null)
    }
    document.addEventListener('keydown', onKeyDown)
    return () => { document.removeEventListener('keydown', onKeyDown) }
  }, [active, open, closeSurface])

  const posture = postureOf(view)
  const whole = wholeTally(view)
  const cells = ORGANS.length
  const shown = open === null ? [...ORGANS.keys(), cells] : [open]
  return (
    <AppSurface active={active} data-aura-coherence-surface="" data-aura-posture={posture.tone}>
      <AppHeader
        eyebrow={AURA_COPY.eyebrow}
        title={AURA_COPY.title}
        tone="violet"
        badges={[
          { text: AURA_COPY.readOnly, icon: 'lock', title: AURA_COPY.footnote },
          ...(view.source === 'stub' ? [{ text: AURA_COPY.stub, tone: 'gold' as const }] : []),
          { text: posture.word, tone: posture.tone },
        ]}
      />
      <PentoraFigure view={view} active={active} focus={open !== null && open < cells ? open : null} />
      <Lead>{AURA_COPY.legend}</Lead>
      <PortalGrid open={open !== null}>
        {shown.map((slot) => {
          if (slot === cells) {
            const t: Tally = {
              verified: view.corners.filter(c => c.cell === 'verified').length,
              undetermined: view.corners.filter(c => c.cell === 'undetermined').length,
              failed: view.corners.filter(c => c.cell === 'failed').length,
            }
            return (
              <PortalCell key="corners" data-aura-portal="corners">
                <PortalButton tone="muted" icon="aura" title="Shared corners"
                  summary={connected ? `20 corners · ${tallyWords(t)}` : `${AURA_COPY.notConnected} · 20 corners`}
                  badge={tallyPill(t, connected)} expanded={open === cells} onToggle={next => { setOpen(next ? cells : null) }}>
                  <Lead>Where two organs meet, each reports the same fact from its side; the corner is verified only when both agree.</Lead>
                  <RecordList>
                    {CORNERS.map((corner, k) => {
                      const report = view.corners[k]!
                      return <RecordRow key={corner.index} tone={connected ? CELL_TONE[report.cell] : 'muted'} title={corner.invariant} rowTitle={corner.invariant}
                        summary={`${corner.pair} · ${corner.sources.join(' · ')}`} status={<CellPill report={report} connected={connected} />} />
                    })}
                  </RecordList>
                </PortalButton>
              </PortalCell>
            )
          }
          const organ = ORGANS[slot]!
          const facts = ORGAN_FACTS[organ]
          const t = organTally(view, organ)
          return (
            <PortalCell key={organ} data-aura-portal={organ}>
              <PortalButton tone={facts.tone} icon={facts.icon} title={facts.title}
                summary={connected ? tallyWords(t) : `${AURA_COPY.notConnected} · 26 cells`}
                badge={tallyPill(t, connected)} expanded={open === slot} onToggle={next => { setOpen(next ? slot : null) }}>
                <OrganDetail organ={organ} view={view} connected={connected} />
              </PortalButton>
            </PortalCell>
          )
        })}
      </PortalGrid>
      <Footnote>{connected ? `${AURA_COPY.footnote} Snapshot ${String(view.sequence)}, epoch ${String(view.epoch)}: ${tallyWords(whole)}.` : AURA_COPY.footnote}</Footnote>
    </AppSurface>
  )
}
