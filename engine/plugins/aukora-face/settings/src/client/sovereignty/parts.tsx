// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * The small pieces every Sovereignty portal is built from. The cards are the layout primitives (`PortalButton`,
 * `ActionButton`); nothing here holds a verb. `OwnerAction` is the one control that "does" anything, and what it
 * does is navigate to the owner origin, where the owner's passkey decides.
 */
import type { ReactNode } from 'react'
import { ActionButton, PortalButton } from '@aukora/face-layout/client'
import type { CategoryId, OwnerLink, Tone } from './model.ts'
import { SOVEREIGNTY_COPY, accentOf } from './model.ts'
import { ownerHref } from './format.ts'
import css from './Sovereignty.module.css'

const STROKE = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.4, strokeLinecap: 'round', strokeLinejoin: 'round' } as const

export function LockIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><rect x="5" y="11" width="14" height="9" rx="2.5" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>
}

function OutIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><path d="M9 6h9v9" /><path d="M18 6 7 17" /></svg>
}

/** One hairline glyph per portal, white until the card's colour takes it. */
export function CategoryIcon({ id }: { readonly id: CategoryId }) {
  switch (id) {
    case 'approvals':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><circle cx="12" cy="12" r="8" /><path d="m8.5 12.2 2.4 2.4 4.6-5" /></svg>
    case 'risk':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><path d="M4 12h16" /><circle cx="10" cy="12" r="2.6" /><path d="M4 7h4M4 17h2M16 7h4M18 17h2" /></svg>
    case 'door':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><path d="M6 20V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v15" /><path d="M4 20h16" /><circle cx="14.5" cy="12.5" r=".8" /></svg>
    case 'plugins':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><path d="M9 3v4M15 3v4" /><path d="M6 7h12v4a6 6 0 0 1-12 0Z" /><path d="M12 17v4" /></svg>
    case 'model':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><path d="M12 3c.6 4.8 3.2 7.4 8 8-4.8.6-7.4 3.2-8 8-.6-4.8-3.2-7.4-8-8 4.8-.6 7.4-3.2 8-8Z" /></svg>
    case 'memory':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><circle cx="7" cy="8" r="2.2" /><circle cx="17" cy="7" r="2.2" /><circle cx="12" cy="17" r="2.2" /><path d="m8.8 9.4 2 5.6M15.6 8.8l-2.4 6.2M9.2 7.8l5.6-.6" /></svg>
    case 'releases':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9Z" /><path d="m4 7.5 8 4.5 8-4.5M12 12v9" /></svg>
    case 'devices':
      return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}><rect x="3" y="5" width="13" height="10" rx="1.5" /><path d="M2 18h15" /><rect x="17.5" y="9" width="4.5" height="10" rx="1.2" /></svg>
  }
}

/** A status word in a hairline pill, in one of the four colours (or muted). */
export function Pill({ tone, children, title }: { readonly tone: Tone; readonly children: ReactNode; readonly title?: string }) {
  return <span className={css.pill} data-tone={tone} title={title}>{children}</span>
}

/** A small caps section label inside a portal. */
export function Label({ children }: { readonly children: ReactNode }) {
  return <p className={css.label}>{children}</p>
}

/** The exact fields of a record: names left, values right in monospace, never truncated. */
export function Facts({ title, rows }: { readonly title?: string; readonly rows: readonly (readonly [string, ReactNode])[] }) {
  return (
    <>
      {title === undefined ? null : <p className={css.factsTitle}>{title}</p>}
      <dl className={css.facts}>
        {rows.map(([name, value]) => [
          <dt key={`${name}-k`}>{name}</dt>,
          <dd key={`${name}-v`}>{value}</dd>,
        ])}
      </dl>
    </>
  )
}

/** Used of a daily or total cap: a hairline track, the fill in the row's colour. */
export function Meter({ used, cap, tone }: { readonly used: number; readonly cap: number; readonly tone: Tone }) {
  const share = cap <= 0 ? 0 : Math.min(1, used / cap)
  return (
    <span className={css.meter} data-tone={tone} role="img" aria-label={`${String(used)} of ${String(cap)}`}>
      <i style={{ width: `${String(Math.round(share * 100))}%` }} />
    </span>
  )
}

/** A row that has nothing below it. */
export function Plain({ title, sub, end }: { readonly title: ReactNode; readonly sub?: ReactNode; readonly end?: ReactNode }) {
  return (
    <li className={css.plain}>
      <span className={css.plainMain}>
        <span className={css.plainTitle}>{title}</span>
        {sub === undefined ? null : <span className={css.plainSub}>{sub}</span>}
      </span>
      {end === undefined ? null : <span className={css.plainEnd}>{end}</span>}
    </li>
  )
}

/** A row with a record below it: a nested portal that telescopes open in place. */
export function Row({ title, sub, end, tone, children }: {
  readonly title: ReactNode
  readonly sub: ReactNode
  readonly end?: ReactNode
  readonly tone: Tone
  readonly children: ReactNode
}) {
  return (
    <li>
      <PortalButton
        variant={accentOf(tone)}
        className={css.row}
        buttonClassName={css.rowHead}
        contentClassName={css.rowBody}
        title={<span data-sov-title>{title}</span>}
        subtitle={<span data-sov-sub>{sub}</span>}
        trailing={end}
      >
        {children}
      </PortalButton>
    </li>
  )
}

/**
 * THE ONLY CONTROL THAT LEADS ANYWHERE. A link to the owner origin, never a request from here: this view runs in
 * the engine's origin and must not be able to approve, revoke or change anything, so a change is always the owner
 * opening their passkey screen on the owner origin, which shows its own card for the owner to check.
 */
export function OwnerAction({ link, origin, tone }: { readonly link: OwnerLink; readonly origin: string; readonly tone: Tone }) {
  return (
    <div className={css.owner} data-sov-owner-route={link.route ?? 'none'}>
      <ActionButton
        variant={accentOf(tone)}
        className={css.ownerButton}
        href={ownerHref(origin, link.route)}
        target="_blank"
        rel="noopener noreferrer"
        title={link.route === null ? SOVEREIGNTY_COPY.noRoute : `${origin}${link.route}`}
      >
        <LockIcon />
        {link.verb}
        <OutIcon />
      </ActionButton>
      <span className={css.ownerNote}>{link.route === null ? SOVEREIGNTY_COPY.noRoute : SOVEREIGNTY_COPY.ownerNote}</span>
    </div>
  )
}

export function Rows({ children }: { readonly children: ReactNode }) {
  return <ul className={css.rows}>{children}</ul>
}

export function Stat({ name, value, tone }: { readonly name: string; readonly value: ReactNode; readonly tone?: Tone }) {
  return <div className={css.stat} data-tone={tone}><span>{name}</span><b>{value}</b></div>
}
