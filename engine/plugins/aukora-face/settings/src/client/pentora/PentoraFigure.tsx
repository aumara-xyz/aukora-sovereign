// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * THE PENTORA, ALIVE: five cubes turning slowly, in the onboarding finale's visual language (the same projection,
 * lean, roll and breath as portal/pentora-lock.ts), with the node's health drawn on its own geometry.
 *
 *   edge          a private check (the edge's midpoint cell): bright when verified, faint and dashed when
 *                 undetermined, red when failed; its glow pulses while its check was observed in the last 20 s
 *   face dot      a private check at a face centre (6 per cube), same colours
 *   corner dot    one of the 20 corners two organs share: white when verified, hollow when undetermined, red failed
 *   cube colour   the organ (AUMLOK gold, Gate & Aura blue, Kira violet, Network mint, Body silver)
 *   cube drift    coherence: a cube whose cells are all verified sits locked in true (the onboarding lock); the
 *                 more of its cells are undetermined or failed, the further it drifts out of true
 *
 * CHEAP: one SVG of 120 lines and 110 dots; React renders the structure and the states once per snapshot, and a
 * requestAnimationFrame loop at 30 frames a second only moves coordinates. It stops while the surface is hidden or
 * the page is in the background, and under reduced motion it draws one still frame and never animates.
 */
import { useEffect, useMemo, useRef } from 'react'
import type { AuraHealthView, CellReport } from './model.ts'
import { ORGANS, ORGAN_FACTS, PULSE_WINDOW_MS, organTally } from './model.ts'
import { CORNER_CELLS, CUBES, POINTS } from './tables.ts'
import css from './Pentora.module.css'

const TILT = 0.5
const FRAME_MS = 1000 / 30

type Projected = readonly [number, number]

const radius = Math.max(...CUBES.flatMap(cube => cube.corners).map(g => Math.hypot(...(POINTS[g] ?? [0, 0, 0]))))
const scale = 76 / radius

function project(g: number, angle: number, size: number, tilt: number, roll: number, breath: number): Projected {
  const [x, y, z] = POINTS[g] ?? [0, 0, 0]
  const c = Math.cos(angle), s = Math.sin(angle)
  const turned = -x * s + z * c
  const tilted = y * Math.cos(tilt) - turned * Math.sin(tilt)
  const depth = y * Math.sin(tilt) + turned * Math.cos(tilt)
  const near = size / (1 - depth / (radius * 4.5))
  const px = (x * c + z * s) * scale * near, py = -tilted * scale * near
  return [(px * Math.cos(roll) - py * Math.sin(roll)) * breath, (px * Math.sin(roll) + py * Math.cos(roll)) * breath]
}

function useStill(): boolean {
  return useMemo(() => {
    try { return typeof matchMedia === 'function' && matchMedia('(prefers-reduced-motion: reduce)').matches } catch { return false }
  }, [])
}

/**
 * Draw the health snapshot on the Pentora.
 * @param props.view - the snapshot (stub in the preview; all-undetermined on a node).
 * @param props.active - false while the surface is hidden: the loop stops.
 * @param props.focus - the organ whose portal is open: its cube stays lit, the others step back.
 */
export function PentoraFigure({ view, active, focus }: {
  readonly view: AuraHealthView
  readonly active: boolean
  readonly focus: number | null
}) {
  const svgRef = useRef<SVGSVGElement | null>(null)
  const viewRef = useRef(view)
  viewRef.current = view
  const still = useStill()

  // Per-cube private reports, for the edge and face states.
  const reportOf = (cube: number, global: number): CellReport | undefined => {
    const slot = CUBES[cube]?.private.indexOf(global) ?? -1
    return slot < 0 ? undefined : view.private[cube * 18 + slot]
  }

  useEffect(() => {
    const svg = svgRef.current
    if (svg === null) return
    const edges = Array.from(svg.querySelectorAll<SVGLineElement>('line[data-a]'))
    const dots = Array.from(svg.querySelectorAll<SVGCircleElement>('circle[data-g]'))
    let frame = 0
    let last = 0
    let angle = 0.7
    const born = performance.now()
    const draw = (now: number, moving: boolean) => {
      const t = now - born
      const ramp = moving ? Math.min(1, t / 3500) : 0
      const tilt = TILT + 0.32 * Math.sin(t / 4700) * ramp
      const roll = 0.24 * Math.sin(t / 7300 + 1) * ramp
      const breath = 1 + 0.035 * Math.sin(t / 1900) * ramp
      const fresh = viewRef.current
      const offsets = ORGANS.map((organ, c) => {
        // COHERENCE: all verified = locked in true (0); undetermined cells loosen it a little, failed ones a lot.
        const tally = organTally(fresh, organ)
        const drift = Math.min(1, (tally.undetermined * 0.5 + tally.failed * 3) / 26) * Math.max(ramp, still ? 1 : 0)
        return [
          drift * 0.075 * Math.sin(t * 0.0007 * (1 + 0.31 * c) + c * 1.7),
          1 + drift * 0.035 * Math.cos(t * 0.0009 + c * 2.3),
        ] as const
      })
      const at = (g: number, cube: number): Projected => {
        const [turn, size] = offsets[cube] ?? [0, 1]
        return project(g, angle + turn, size, tilt, roll, breath)
      }
      for (const line of edges) {
        const cube = Number(line.dataset.cube)
        const [x1, y1] = at(Number(line.dataset.a), cube)
        const [x2, y2] = at(Number(line.dataset.b), cube)
        line.setAttribute('x1', x1.toFixed(2))
        line.setAttribute('y1', y1.toFixed(2))
        line.setAttribute('x2', x2.toFixed(2))
        line.setAttribute('y2', y2.toFixed(2))
        if (line.dataset.layer === 'glow') {
          // RECENT ACTIVITY: the glow swells and fades while the edge's check was observed in the last 20 seconds.
          const seen = fresh.private[Number(line.dataset.slot)]?.observed_at_ms ?? null
          const since = seen === null ? Infinity : Date.now() - seen
          const pulse = moving && since < PULSE_WINDOW_MS ? (1 - since / PULSE_WINDOW_MS) * (0.55 + 0.45 * Math.sin(t / 260)) : 0
          line.style.strokeOpacity = pulse > 0 ? String(0.09 + 0.5 * pulse) : ''
          line.style.strokeWidth = pulse > 0 ? `${String(6 + 8 * pulse)}px` : ''
        }
      }
      for (const dot of dots) {
        const g = Number(dot.dataset.g)
        const [x1, y1] = at(g, Number(dot.dataset.cube))
        // A corner belongs to two cubes: it sits between where each of them puts it (the same place when both are true).
        const [x2, y2] = dot.dataset.cube2 === undefined ? [x1, y1] : at(g, Number(dot.dataset.cube2))
        dot.setAttribute('cx', ((x1 + x2) / 2).toFixed(2))
        dot.setAttribute('cy', ((y1 + y2) / 2).toFixed(2))
      }
    }
    draw(still ? born + 9000 : born, still)
    if (still || !active) return
    const tick = (now: number) => {
      frame = requestAnimationFrame(tick)
      if (document.hidden || now - last < FRAME_MS) return
      angle += (last === 0 ? 0 : now - last) * 0.55 / 6400
      last = now
      draw(now, true)
    }
    frame = requestAnimationFrame(tick)
    return () => { cancelAnimationFrame(frame) }
  }, [active, still])

  return (
    <figure className={css.figure} data-still={still ? 'yes' : 'no'} aria-label="The Pentora: five organs as five interlocking cubes, coloured by their health checks">
      <svg ref={svgRef} className={css.svg} viewBox="-92 -92 184 184" aria-hidden="true" focusable="false">
        {CUBES.map((cube, c) => {
          const organ = ORGANS[c] ?? 'body'
          return (
            <g key={organ} className={css.organ} data-organ={organ} data-dim={focus !== null && focus !== c ? 'yes' : 'no'}>
            <g className={css.cube} data-tone={ORGAN_FACTS[organ].tone} style={{ animationDelay: `${String(0.1 + c * 0.16)}s` }}>
              {(['glow', 'edge'] as const).map(layer => cube.edges.map(([a, b], e) => {
                const mid = cube.edgeMidpoints[e] ?? -1
                const slot = c * 18 + (cube.private.indexOf(mid))
                return <line key={`${layer}-${String(e)}`} className={layer === 'glow' ? css.glow : css.edge} data-layer={layer}
                  data-cube={c} data-a={a} data-b={b} data-slot={slot} data-state={reportOf(c, mid)?.cell ?? 'undetermined'}
                  vectorEffect="non-scaling-stroke" />
              }))}
              {cube.faceCentres.map(g => <circle key={g} className={css.face} data-g={g} data-cube={c} r="1.7"
                data-state={reportOf(c, g)?.cell ?? 'undetermined'} />)}
            </g>
            </g>
          )
        })}
        <g className={css.corners}>
          {CORNER_CELLS.map((g, k) => {
            const owners = CUBES.flatMap((each, c) => (each.corners.includes(g) ? [c] : []))
            return <circle key={g} className={css.corner} data-g={g} data-cube={owners[0]} data-cube2={owners[1]} r="1.9"
              data-state={view.corners[k]?.cell ?? 'undetermined'} />
          })}
        </g>
      </svg>
    </figure>
  )
}
