// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * THE SPATIAL PRIMITIVES (Peter, 2026-10-17): every portal, record, field block, stat, pill and owner action in the
 * face is one of these, and they only emit the markup `primitives.css` styles. Measurements live in that file.
 *
 *   AppSurface + AppHeader       an app's lane surface, its eyebrow, title and badges
 *   PortalGrid / PortalCell      the home grid (two columns at two-thirds, one at one-third)
 *   PortalButton                 icon tile, title, one-line summary, optional badge, + / − expander; opens in place
 *   PortalDetail / DetailSection the opened state's body and its small-caps sections
 *   RecordRow / RecordList       the nested, smaller portal (status pill + expander), or a static row
 *   FieldTable                   the fine-lined key/value block
 *   StatTiles, StatusPill, Meter, LevelScale, Quote, Lead
 *   LockedAction                 the lock pill that opens the owner origin; never an action in place
 */
import { useId, useState } from 'react'
import type { ButtonHTMLAttributes, HTMLAttributes, ReactNode } from 'react'
import { AkIcon, type IconName } from './icons.tsx'

/** The four-level palette, plus red (quarantine, failure) and muted (nothing to say). */
export type Tone = 'mint' | 'blue' | 'violet' | 'gold' | 'red' | 'muted'

const cx = (...values: (string | false | null | undefined)[]) => values.filter(Boolean).join(' ')
const tone = (value: Tone | undefined) => (value === undefined ? undefined : `ak-tone-${value}`)

/** The 30px tile every portal carries. */
export function IconTile({ icon }: { readonly icon: IconName | ReactNode }) {
  return <span className="ak-icon-tile">{typeof icon === 'string' ? <AkIcon name={icon as IconName} /> : icon}</span>
}

// ── App surface and header ─────────────────────────────────────────────────────────────────────────────────────

export function AppSurface({ active, tone: t, children, ...data }: {
  readonly active: boolean
  readonly tone?: Tone
  readonly children: ReactNode
} & Record<`data-${string}`, string | undefined>) {
  return <section {...data} className={cx('ak-app', tone(t))} hidden={!active}>{active ? <div className="ak-canvas">{children}</div> : null}</section>
}

export interface Badge { readonly text: string; readonly tone?: Tone; readonly icon?: IconName; readonly title?: string }

/** The eyebrow (mono caps, in the app's tone), the title (light caps) and the badges on the right. */
export function AppHeader({ eyebrow, title, tone: t, badges = [] }: {
  readonly eyebrow: string
  readonly title: string
  readonly tone?: Tone
  readonly badges?: readonly Badge[]
}) {
  return (
    <header className={cx('ak-header', tone(t))}>
      <div className="ak-header__copy">
        <p className="ak-header__eyebrow">{eyebrow}</p>
        <h2 className="ak-header__title">{title}</h2>
      </div>
      {badges.length === 0 ? null : (
        <div className="ak-header__badges">
          {badges.map(badge => (
            <span key={badge.text} className={cx('ak-badge', tone(badge.tone))} title={badge.title}>
              {badge.icon === undefined ? null : <AkIcon name={badge.icon} />}{badge.text}
            </span>
          ))}
        </div>
      )}
    </header>
  )
}

export function Footnote({ children }: { readonly children: ReactNode }) {
  return <p className="ak-footnote"><AkIcon name="lock" />{children}</p>
}

// ── Portals ────────────────────────────────────────────────────────────────────────────────────────────────────

export function PortalGrid({ open, children }: { readonly open: boolean; readonly children: ReactNode }) {
  return <ul className="ak-grid" data-open={open ? 'yes' : 'no'}>{children}</ul>
}

export function PortalCell({ children, ...data }: { readonly children: ReactNode } & Record<`data-${string}`, string | undefined>) {
  return <li {...data}>{children}</li>
}

/** The layout primitives' old accent names, still accepted (Prime's memory app passes them). */
type LegacyAccent = 'blue' | 'green' | 'purple' | 'gold' | 'red-warning'
const LEGACY: Record<LegacyAccent, Tone> = { 'blue': 'blue', 'green': 'mint', 'purple': 'violet', 'gold': 'gold', 'red-warning': 'red' }

export interface PortalButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'title' | 'children' | 'onToggle'> {
  readonly tone?: Tone
  /** The glyph in the 30px tile. Every new portal passes one. */
  readonly icon?: IconName | ReactNode
  readonly title: ReactNode
  /** One line; ellipsis beyond it. Without it the button is the one-line height. */
  readonly summary?: ReactNode
  /** A status pill, count or meter shown before the expander. */
  readonly badge?: ReactNode
  /** Controlled open state; omit for a self-contained disclosure. */
  readonly expanded?: boolean
  readonly defaultExpanded?: boolean
  readonly onToggle?: (open: boolean) => void
  /** A launcher in a right-hand menu: margins for the stack, `aria-current` while its app is open. */
  readonly menu?: boolean
  /** What opens below the header (rendered inside `PortalDetail`). A launcher has none. */
  readonly children?: ReactNode
  // The previous PortalButton's props (Prime's memory app uses them). A caller that passes any of these gets the same
  // frame, tile and expander, with a header that may grow past the standard height so long text is never cut.
  readonly variant?: LegacyAccent
  readonly subtitle?: ReactNode
  readonly trailing?: ReactNode
  readonly showIndicator?: boolean
  readonly onExpandedChange?: (open: boolean) => void
  readonly buttonClassName?: string | undefined
  readonly contentClassName?: string | undefined
  readonly containerProps?: HTMLAttributes<HTMLDivElement> & { [name: `data-${string}`]: string | number | boolean | undefined }
  readonly contentProps?: HTMLAttributes<HTMLDivElement>
}

/** The portal button. It opens in place, inside the lane it is in; it never resizes a lane. */
export function PortalButton({
  tone: t, icon, title, summary, badge, expanded, defaultExpanded = false, onToggle, menu = false, children, className, onClick,
  variant, subtitle, trailing, showIndicator = true, onExpandedChange, buttonClassName, contentClassName, containerProps, contentProps,
  ...button
}: PortalButtonProps) {
  const [local, setLocal] = useState(defaultExpanded)
  const open = expanded ?? local
  const bodyId = useId()
  const legacy = variant !== undefined || subtitle !== undefined || trailing !== undefined || containerProps !== undefined
  const line = summary ?? subtitle
  const twoLine = line !== undefined && line !== null && line !== ''
  const opens = children !== undefined
  return (
    <div
      {...containerProps}
      className={cx('ak-portal', tone(t ?? (variant === undefined ? 'blue' : LEGACY[variant])), !twoLine && 'ak-portal--one-line',
        legacy && 'ak-portal--free', menu && 'ak-portal--menu', className, containerProps?.className)}
      data-open={open ? 'yes' : 'no'}
    >
      <button
        {...button}
        type="button"
        className={cx('ak-portal__head', buttonClassName)}
        aria-expanded={opens ? open : undefined}
        aria-controls={opens ? bodyId : undefined}
        aria-current={menu && open ? 'page' : undefined}
        onClick={(event) => {
          onClick?.(event)
          if (event.defaultPrevented) return
          if (expanded === undefined) setLocal(!open)
          onToggle?.(!open)
          onExpandedChange?.(!open)
        }}
      >
        {icon === undefined || icon === null ? null : <IconTile icon={icon} />}
        <span className="ak-portal__copy">
          <span className="ak-portal__title">{title}</span>
          {twoLine ? <span className="ak-portal__summary">{line}</span> : null}
        </span>
        <span className="ak-portal__end">
          {badge}{trailing}
          {showIndicator ? <span className="ak-expander" aria-hidden="true">{open ? '−' : '+'}</span> : null}
        </span>
      </button>
      {opens && open ? <PortalDetail id={bodyId} className={contentClassName} props={contentProps}>{children}</PortalDetail> : null}
    </div>
  )
}

/** The opened state's body: 16px inset, 4px rhythm, glides in. */
export function PortalDetail({ id, className, props, children }: {
  readonly id?: string
  readonly className?: string | undefined
  readonly props?: HTMLAttributes<HTMLDivElement> | undefined
  readonly children: ReactNode
}) {
  return <div {...props} className={cx('ak-portal__body', className)} id={id}>{children}</div>
}

/** A small-caps section label and what sits under it. */
export function DetailSection({ label, children }: { readonly label: string; readonly children: ReactNode }) {
  return <section><p className="ak-label">{label}</p>{children}</section>
}

export function SectionLabel({ children }: { readonly children: ReactNode }) {
  return <p className="ak-label">{children}</p>
}

// ── Record rows ────────────────────────────────────────────────────────────────────────────────────────────────

export function RecordList({ children }: { readonly children: ReactNode }) {
  return <ul className="ak-rows">{children}</ul>
}

/**
 * The nested, smaller portal: title, one-line summary, a status pill (and anything else short) and the expander.
 * Without children it is a static row: a hairline frame, no expander, nothing to open.
 */
export function RecordRow({ tone: t, title, summary, status, end, children, rowTitle }: {
  readonly tone: Tone
  readonly title: ReactNode
  readonly summary?: ReactNode
  readonly status?: ReactNode
  readonly end?: ReactNode
  readonly children?: ReactNode
  /** Full text for the tooltip when the one-line summary is cut. */
  readonly rowTitle?: string
}) {
  const [open, setOpen] = useState(false)
  const bodyId = useId()
  const copy = (
    <span className="ak-row__copy">
      <span className="ak-row__title">{title}</span>
      {summary === undefined ? null : <span className="ak-row__summary">{summary}</span>}
    </span>
  )
  const trailing = <span className="ak-row__end">{end}{status}{children === undefined ? null : <span className="ak-expander" aria-hidden="true">{open ? '−' : '+'}</span>}</span>
  if (children === undefined) {
    return <li className={cx('ak-row', 'ak-row--static', tone(t))} title={rowTitle}><div className="ak-row__head">{copy}{trailing}</div></li>
  }
  return (
    <li className={cx('ak-row', tone(t))} data-open={open ? 'yes' : 'no'}>
      <button type="button" className="ak-row__head" aria-expanded={open} aria-controls={bodyId} title={rowTitle} onClick={() => { setOpen(!open) }}>
        {copy}{trailing}
      </button>
      {open ? <div className="ak-row__body" id={bodyId}>{children}</div> : null}
    </li>
  )
}

// ── Fields, stats, pills, meters ───────────────────────────────────────────────────────────────────────────────

/** Names left, exact values right in monospace, never truncated. */
export function FieldTable({ title, rows }: { readonly title?: string; readonly rows: readonly (readonly [string, ReactNode])[] }) {
  return (
    <>
      {title === undefined ? null : <p className="ak-fields__title">{title}</p>}
      <dl className="ak-fields">
        {rows.map(([name, value]) => [<dt key={`${name}-k`}>{name}</dt>, <dd key={`${name}-v`}>{value}</dd>])}
      </dl>
    </>
  )
}

export interface StatTile { readonly name: string; readonly value: ReactNode; readonly tone?: Tone }

export function StatTiles({ tiles }: { readonly tiles: readonly StatTile[] }) {
  return (
    <div className="ak-stats">
      {tiles.map(tile => (
        <div key={tile.name} className={cx('ak-stat', tone(tile.tone))}>
          <span className="ak-stat__name">{tile.name}</span>
          <b className="ak-stat__value">{tile.value}</b>
        </div>
      ))}
    </div>
  )
}

export function StatusPill({ tone: t, children, title }: { readonly tone: Tone; readonly children: ReactNode; readonly title?: string }) {
  return <span className={cx('ak-pill', tone(t))} title={title}>{children}</span>
}

export function Meter({ used, cap, tone: t }: { readonly used: number; readonly cap: number; readonly tone: Tone }) {
  const share = cap <= 0 ? 0 : Math.min(1, Math.max(0, used / cap))
  return (
    <span className={cx('ak-meter', tone(t))} role="img" aria-label={`${String(used)} of ${String(cap)}`}>
      <i style={{ width: `${String(Math.round(share * 100))}%` }} />
    </span>
  )
}

export interface Level { readonly key: string; readonly name: string; readonly label: string; readonly tone: Tone }

/** A read-only row of levels with the current one lit (the Laya slider, shown, not moved). */
export function LevelScale({ levels, current, label }: { readonly levels: readonly Level[]; readonly current: string; readonly label: string }) {
  return (
    <div className="ak-scale" role="img" aria-label={label}>
      {levels.map(level => (
        <div key={level.key} className={cx('ak-scale__notch', tone(level.tone))} aria-current={level.key === current ? 'true' : 'false'}>
          <span className="ak-scale__dot" />
          <b>{level.name}</b>
          <span>{level.label}</span>
        </div>
      ))}
    </div>
  )
}

export function Quote({ children, tone: t }: { readonly children: ReactNode; readonly tone?: Tone }) {
  return <p className={cx('ak-quote', tone(t))}>{children}</p>
}

export function Lead({ children }: { readonly children: ReactNode }) {
  return <p className="ak-lead">{children}</p>
}

export function Mono({ children }: { readonly children: ReactNode }) {
  return <span className="ak-mono">{children}</span>
}

// ── The locked action ──────────────────────────────────────────────────────────────────────────────────────────

/**
 * THE ONLY CONTROL THAT CHANGES ANYTHING, AND IT CHANGES NOTHING HERE. A link to the owner origin, where the owner's
 * passkey screen shows its own card. A surface in the engine's origin never approves, revokes or writes in place.
 */
export function LockedAction({ verb, href, tone: t, note, title }: {
  readonly verb: string
  readonly href: string
  readonly tone: Tone
  readonly note: string
  readonly title?: string
}) {
  return (
    <div className="ak-actionrow">
      <a className={cx('ak-action', tone(t))} href={href} target="_blank" rel="noopener noreferrer" title={title ?? href}>
        <AkIcon name="lock" />{verb}<AkIcon name="out" />
      </a>
      <span className="ak-action__note">{note}</span>
    </div>
  )
}
