// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * The primitives' glyphs: one hairline icon per portal, 24-unit grid, 1.4 stroke, round caps, `currentColor` (the
 * tile sets the tone). A portal always carries one; `general` is the fallback for anything without its own.
 */
import type { ReactElement } from 'react'

const STROKE = { fill: 'none', stroke: 'currentColor', strokeWidth: 1.4, strokeLinecap: 'round', strokeLinejoin: 'round' } as const

/** Every glyph name the primitives know. */
export const ICON_NAMES = [
  'approvals', 'risk', 'door', 'plugins', 'model', 'memory', 'releases', 'devices', 'sovereignty', 'aumlok',
  'identity', 'aura', 'general', 'presets', 'archive', 'thread', 'app', 'lock', 'out',
] as const
export type IconName = typeof ICON_NAMES[number]

const PATHS: Record<IconName, ReactElement> = {
  approvals: <><circle cx="12" cy="12" r="8" /><path d="m8.5 12.2 2.4 2.4 4.6-5" /></>,
  risk: <><path d="M4 12h16" /><circle cx="10" cy="12" r="2.6" /><path d="M4 7h4M4 17h2M16 7h4M18 17h2" /></>,
  door: <><path d="M6 20V5a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v15" /><path d="M4 20h16" /><circle cx="14.5" cy="12.5" r=".8" /></>,
  plugins: <><path d="M9 3v4M15 3v4" /><path d="M6 7h12v4a6 6 0 0 1-12 0Z" /><path d="M12 17v4" /></>,
  model: <path d="M12 3c.6 4.8 3.2 7.4 8 8-4.8.6-7.4 3.2-8 8-.6-4.8-3.2-7.4-8-8 4.8-.6 7.4-3.2 8-8Z" />,
  memory: <><circle cx="7" cy="8" r="2.2" /><circle cx="17" cy="7" r="2.2" /><circle cx="12" cy="17" r="2.2" /><path d="m8.8 9.4 2 5.6M15.6 8.8l-2.4 6.2M9.2 7.8l5.6-.6" /></>,
  releases: <><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9Z" /><path d="m4 7.5 8 4.5 8-4.5M12 12v9" /></>,
  devices: <><rect x="3" y="5" width="13" height="10" rx="1.5" /><path d="M2 18h15" /><rect x="17.5" y="9" width="4.5" height="10" rx="1.2" /></>,
  sovereignty: <><path d="M12 3 5 6v5c0 4.4 2.9 8.2 7 10 4.1-1.8 7-5.6 7-10V6Z" /><path d="m9 12 2 2 4-4" /></>,
  aumlok: <><rect x="5" y="10.5" width="14" height="9.5" rx="2.5" /><path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" /><path d="M12 14v2.5" /></>,
  identity: <><rect x="3.5" y="5" width="17" height="14" rx="2.5" /><circle cx="9" cy="11" r="2.2" /><path d="M5.8 16.2c.7-1.6 1.9-2.4 3.2-2.4s2.5.8 3.2 2.4M14.5 10h3.5M14.5 13.5h3.5" /></>,
  aura: <><circle cx="12" cy="12" r="3" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="9" opacity=".6" /></>,
  general: <><path d="M5 7h9M18 7h1M5 17h1M10 17h9" /><circle cx="16" cy="7" r="2" /><circle cx="8" cy="17" r="2" /></>,
  presets: <><circle cx="9" cy="8" r="3" /><path d="M3.5 19c.8-3 3-4.6 5.5-4.6 1.3 0 2.5.4 3.4 1.2" /><circle cx="17.5" cy="16.5" r="2.2" /><path d="M17.5 12.5v1.8M17.5 18.7v1.8M21.5 16.5h-1.8M15.3 16.5h-1.8" /></>,
  archive: <><rect x="3.5" y="4.5" width="17" height="4" rx="1" /><path d="M5 8.5V19a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V8.5M10 12.5h4" /></>,
  thread: <><path d="M5 6.5A2.5 2.5 0 0 1 7.5 4h9A2.5 2.5 0 0 1 19 6.5v7a2.5 2.5 0 0 1-2.5 2.5H11l-4.5 4v-4h0A1.5 1.5 0 0 1 5 14.5Z" /></>,
  app: <><rect x="4" y="4" width="6.5" height="6.5" rx="1.8" /><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.8" /><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.8" /><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.8" /></>,
  lock: <><rect x="5" y="11" width="14" height="9" rx="2.5" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></>,
  out: <><path d="M9 6h9v9" /><path d="M18 6 7 17" /></>,
}

/** One glyph, sized by its container (16px in a tile, 11-12px in a pill or action). */
export function AkIcon({ name }: { readonly name: IconName }) {
  return <svg viewBox="0 0 24 24" aria-hidden="true" {...STROKE}>{PATHS[name]}</svg>
}
