// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/** The Sovereignty entry in the System menu: a launcher portal (left-justified, standard height, icon tile, +/−). */
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { PortalButton } from '@aukora/face-layout/client'
import { SOVEREIGNTY_COPY, SOVEREIGNTY_SURFACE } from './model.ts'

/** Full props for the Sovereignty System launcher. */
export type SovereigntyMenuProps = PropsRuntime<'shell.menu.system'>

/**
 * Open the Sovereignty view in the centre lane; while it is open the launcher shows − and closes it.
 * @param props - System-menu owner share.
 * @returns the Sovereignty launcher.
 */
export function SovereigntyMenu({ activeSurface, openSurface, closeSurface }: SovereigntyMenuProps) {
  return (
    <PortalButton
      menu
      tone="blue"
      icon="sovereignty"
      data-sovereignty-launcher=""
      title={SOVEREIGNTY_COPY.menuTitle}
      summary={SOVEREIGNTY_COPY.menuDescription}
      expanded={activeSurface === SOVEREIGNTY_SURFACE}
      onToggle={(open) => { if (open) openSurface(SOVEREIGNTY_SURFACE); else closeSurface() }}
    />
  )
}
