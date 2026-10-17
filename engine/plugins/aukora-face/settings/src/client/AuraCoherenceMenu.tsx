// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/** Aura Coherence entry in the shell's right-side System menu. */
import type { PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { PortalButton } from '@aukora/face-layout/client'

/** Full props for the standalone Aura Coherence System launcher. */
export type AuraCoherenceMenuProps =
  PropsRuntime<'shell.menu.system'>
  & PropsLocale<'settings'>

/**
 * Open the standalone Aura Coherence surface (a launcher portal: icon tile, left-justified, +/−).
 * @param props - System-menu owner share and localized copy.
 * @returns the Aura Coherence launcher.
 */
export function AuraCoherenceMenu({
  activeSurface,
  openSurface,
  closeSurface,
  t,
}: AuraCoherenceMenuProps) {
  return (
    <PortalButton
      menu
      tone="blue"
      icon="aura"
      iconTone="violet"
      title={t('aura.trigger')}
      summary={t('aura.menu')}
      expanded={activeSurface === 'aura-coherence'}
      onToggle={(open) => { if (open) openSurface('aura-coherence'); else closeSurface() }}
    />
  )
}
