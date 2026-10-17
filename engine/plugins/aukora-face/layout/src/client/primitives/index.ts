// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/** The spatial primitives: components plus the framework-neutral stylesheet they emit markup for. */
import './primitives.css'
// The face's skin: the same look on surfaces it does not render itself (Prime's copied menus and thread rows).
import './skin-face.css'
// One colour per right-hand tab: triangle mint, square blue, circle violet; threads mint.
import './skin-tabs.css'
// The stock harness (its settings sections, popups, modals) in the same look, by CSS alone.
import './skin-harness.css'

export {
  AppHeader, AppSurface, DetailSection, FieldTable, Footnote, IconTile, Lead, LevelScale, LockedAction, Meter, Mono,
  PortalButton, PortalCell, PortalDetail, PortalGrid, Quote, RecordList, RecordRow, SectionLabel, StatTiles, StatusPill,
} from './components.tsx'
export type { Badge, Level, PortalButtonProps, StatTile, Tone } from './components.tsx'
export { AkIcon, ICON_NAMES } from './icons.tsx'
export type { IconName } from './icons.tsx'
