/** Settings-section entries in the shell's right-side System menu: one launcher portal per section. */
import { PortalButton, type IconName } from '@aukora/face-layout/client'
import type { SettingsMenuComponentProps } from './shell-contract.ts'

/** The glyph for each known section; a section added later gets the general one. */
const ICON: Readonly<Record<string, IconName>> = {
  'general': 'general', 'models': 'model', 'plugins': 'plugins', 'agent-presets': 'presets', 'archived': 'archive',
}

/**
 * Render every registered settings section as a direct System-menu launcher.
 * @param props - composed system-menu props.
 * @returns the settings section launchers.
 */
export function SettingsMenu({
  activeSurface,
  surfaceTarget,
  openSurface,
  closeSurface,
  useSections,
}: SettingsMenuComponentProps) {
  const rows = useSections(snapshot => snapshot)
  const selected = rows.find(row => row.id === surfaceTarget) ?? rows[0]
  return (
    <>
      {rows.map((row) => {
        const active = activeSurface === 'settings' && row.id === selected?.id
        return (
          <PortalButton
            key={row.id}
            menu
            tone="blue"
            icon={ICON[row.id] ?? 'general'}
            data-settings-section={row.id}
            aria-label={row.label}
            title={row.label}
            expanded={active}
            onToggle={(open) => { if (open) openSurface('settings', row.id); else closeSurface() }}
          />
        )
      })}
    </>
  )
}
