/** AUMLOK entry in the shell's right-side System menu: a launcher portal (icon tile, left-justified, +/−). */
import type { PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import { PortalButton } from '@aukora/face-layout/client'

/** Full props for the standalone AUMLOK System launcher. */
export type AumlokMenuProps =
  PropsRuntime<'shell.menu.system'>
  & PropsLocale<'aumlok'>

/**
 * Open the standalone AUMLOK preview.
 * @param props - System-menu owner share and localized copy.
 * @returns the AUMLOK launcher.
 */
export function AumlokMenu({ activeSurface, openSurface, closeSurface, t }: AumlokMenuProps) {
  return (
    <PortalButton
      menu
      tone="blue"
      icon="aumlok"
      data-aumlok-launcher=""
      title={t('menu.title')}
      summary={t('menu.description')}
      expanded={activeSurface === 'aumlok'}
      onToggle={(open) => { if (open) openSurface('aumlok'); else closeSurface() }}
    />
  )
}
