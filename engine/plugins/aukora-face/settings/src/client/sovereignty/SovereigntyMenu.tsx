// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/** The Sovereignty entry in the shell's right-side System menu: one card, like its siblings. */
import clsx from 'clsx'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import css from '../SettingsRoot.module.css'
import { SOVEREIGNTY_COPY, SOVEREIGNTY_SURFACE } from './model.ts'

/** Full props for the Sovereignty System launcher. */
export type SovereigntyMenuProps = PropsRuntime<'shell.menu.system'>

/**
 * Open the Sovereignty view in the centre lane, at its home grid.
 * @param props - System-menu owner share.
 * @returns the Sovereignty launcher button.
 */
export function SovereigntyMenu({ activeSurface, openSurface }: SovereigntyMenuProps) {
  const active = activeSurface === SOVEREIGNTY_SURFACE
  return (
    <button
      type="button"
      data-sovereignty-launcher
      className={clsx(css.menuItem, active && css.menuItemActive)}
      aria-current={active ? 'page' : undefined}
      onClick={() => { openSurface(SOVEREIGNTY_SURFACE) }}
    >
      <span className={css.systemMenuCopy}>
        <strong>{SOVEREIGNTY_COPY.menuTitle}</strong>
        <span>{SOVEREIGNTY_COPY.menuDescription}</span>
      </span>
    </button>
  )
}
