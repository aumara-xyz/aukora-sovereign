/** Settings-section entries in the shell's right-side System menu: one launcher portal per section. */
import { PortalButton, type IconName, type Tone } from '@aukora/face-layout/client'
import type { SettingsMenuComponentProps } from './shell-contract.ts'

/** The glyph for each known section; a section added later gets the general one. */
const ICON: Readonly<Record<string, IconName>> = {
  'general': 'general', 'models': 'model', 'plugins': 'plugins', 'agent-presets': 'presets', 'archived': 'archive',
}

/** Each section's icon colour, continuing the System column's mint, blue, violet, gold run (border stays blue). */
const ICON_TONE: Readonly<Record<string, Tone>> = {
  'general': 'gold', 'models': 'mint', 'plugins': 'blue', 'agent-presets': 'violet', 'archived': 'gold',
}

/** One line under each section's name (every launcher is the two-line form). English until the locale lands. */
const SUMMARY: Readonly<Record<string, string>> = {
  'general': 'language, look and defaults',
  'models': 'model providers and keys',
  'plugins': 'what the harness ships',
  'agent-presets': 'how the agent works',
  'archived': 'sessions you put away',
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
            iconTone={ICON_TONE[row.id] ?? 'gold'}
            data-settings-section={row.id}
            aria-label={row.label}
            title={row.label}
            summary={SUMMARY[row.id] ?? 'settings'}
            expanded={active}
            onToggle={(open) => { if (open) openSurface('settings', row.id); else closeSurface() }}
          />
        )
      })}
    </>
  )
}
