import { useEffect, useId, useRef, useState, useSyncExternalStore } from 'react'
import type { CSSProperties } from 'react'
import type { Context as ClientContext } from '@deepseek-ai/cordis'
import type { SessionId } from '@deepseek-ai/dsh-session/types'
import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type {} from '@deepseek-ai/dsh-client-ui-conversation/client'
import type {} from '@deepseek-ai/dsh-api-remotes/client'
import { NS } from './locales.ts'
import type { LayoutKey } from './locales.ts'
import { createFaceLocalLaya, createNodeRequestLaya, LAYA_SETTINGS, layaRank, PREVIEW_APPROVE_MS } from './laya.ts'
import { isPreviewComposition, ownerOrigin } from './composition.ts'
import { LockedAction } from './primitives/index.ts'
import type { LayaService, LayaSetting } from './laya.ts'
import { createFaceLocalVision } from './vision.ts'
import type { VisionService } from './vision.ts'
import css from './ComposerControls.module.css'

type ChosenMode = 'read-only' | 'workspace-write'
interface ControlsInjected {
  selectMode(mode: ChosenMode): Promise<void>
  /** The seam to whatever holds the owner's Laya setting (see `laya.ts`). */
  laya: LayaService
  /** The seam to whatever holds the Vision choice (see `vision.ts`). */
  vision: VisionService
  /** True on a node: the slider is a request that opens the owner origin, not a setting. */
  request: boolean
}
type Props = PropsRuntime<'conversation.input.permission'> & InjectFace<ControlsInjected> & PropsLocale<'layout'>

const noteName: Record<LayaSetting, LayoutKey> = {
  ask: 'laya.ask', risky: 'laya.risky', limits: 'laya.limits', trusted: 'laya.trusted',
}

/** The lock inside the knob while a loosening waits for the owner's passkey. */
function LockGlyph() {
  return <svg className={css.lock} viewBox="0 0 8 8" aria-hidden="true">
    <rect x="1.2" y="3.6" width="5.6" height="3.6" rx=".8" /><path d="M2.4 3.6V2.6a1.6 1.6 0 0 1 3.2 0v1" />
  </svg>
}

/** An open eye (on) or the same eye struck through (off). */
function EyeIcon({ on }: { on: boolean }) {
  return <svg className={css.eyeIcon} viewBox="0 0 16 16" aria-hidden="true">
    <path d="M1 8s2.6-5 7-5 7 5 7 5-2.6 5-7 5-7-5-7-5z" /><circle cx="8" cy="8" r="2.2" />
    {!on && <path d="M2.5 13.5 13.5 2.5" />}
  </svg>
}

/**
 * The composer's controls, all on one row: a small Chat | Build switch with the one word it shows, the Risk slider
 * while Build is on, and the Vision eye. The switch follows the host projection; unavailable controls never invent
 * a selection. A host mode this app does not offer (full access) parks the knob in the middle rather than naming it.
 */
export function ComposerControls({ locked, selectMode, laya, vision, request, useProjection, sessionId, t }: Props) {
  const state = useProjection('aukoraComposerMode')
  const setting = useSyncExternalStore(laya.subscribe, laya.getState)
  const seeing = useSyncExternalStore(vision.subscribe, vision.getState)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(false)
  const generation = useRef(0)
  const modeHintId = useId()
  const layaHintId = useId()
  useEffect(() => {
    generation.current++
    setBusy(false)
    setError(false)
    return () => { generation.current++ }
  }, [sessionId])
  const choose = async (mode: ChosenMode): Promise<void> => {
    if (busy || locked || state?.available !== true || state.mode === mode) return
    const submittedGeneration = generation.current
    setBusy(true)
    setError(false)
    try { await selectMode(mode) }
    catch { if (generation.current === submittedGeneration) setError(true) }
    finally { if (generation.current === submittedGeneration) setBusy(false) }
  }
  const disabled = state === undefined || !state.available || locked || busy
  const building = state?.mode === 'workspace-write'
  const chatting = state?.mode === 'read-only'
  const word = building ? t('composer.build') : chatting ? t('composer.chat') : '—'
  const modeHint = state === undefined ? t('composer.modeUnknown')
    : !state.available ? t('composer.modeUnavailable') : building ? t('composer.buildTip')
      : chatting ? t('composer.chatTip') : t('composer.hostOutside')

  // The knob rests on the requested notch at once. It differs from the applied one only while a loosening waits.
  const applied = layaRank(setting.applied)
  const requested = layaRank(setting.requested)
  const pending = requested > applied
  const label = `${requested + 1} · ${t(noteName[setting.requested])}`
  const asking = setting.note === 'needs-owner' && setting.asked !== undefined
  const status = pending ? t('laya.pending') : setting.note === 'approved-preview' ? t('laya.approvedPreview')
    : asking ? t('laya.needsOwner') : ''
  // On a node the slider is a request until a node-backed service exists, and the control says so in its hint.
  const layaHint = [status, request ? t('laya.requestOnly') : '', t('laya.reason')].filter(Boolean).join(' ')

  return <div className={css.controls} aria-busy={busy} data-composer-mode={state?.mode ?? 'unknown'}>
    <button type="button" role="switch" className={css.switch} aria-checked={building} aria-label={t('composer.mode')}
      aria-describedby={modeHintId} title={modeHint} disabled={disabled} data-error={error || undefined}
      data-state={building ? 'build' : chatting ? 'chat' : 'other'}
      onClick={() => { void choose(building ? 'read-only' : chatting ? 'workspace-write' : 'read-only') }}>
      <span className={css.rail} aria-hidden="true"><span className={css.knob} /></span>
      <span className={css.word}>{word}</span>
      <span id={modeHintId} className={css.srOnly}>{modeHint}</span>
    </button>
    {building && <span className={css.laya} style={{ '--at': requested } as CSSProperties}
      data-notch={setting.requested} data-pending={pending || undefined} data-locked={locked || undefined} title={`${label}. ${layaHint}`}>
      <span className={css.layaSlider}>
        <span className={css.track} aria-hidden="true">
          <span className={css.fill} />
          {LAYA_SETTINGS.map((name, index) => <span key={name} className={css.notch} style={{ '--at': index } as CSSProperties} />)}
          <span className={css.dot}>{pending && <LockGlyph />}</span>
        </span>
        <input className={css.range} type="range" min="0" max={LAYA_SETTINGS.length - 1} step="1" value={requested}
          aria-label={t('laya.label')} aria-valuetext={status ? `${label}. ${status}` : label} aria-describedby={layaHintId}
          disabled={locked}
          onChange={event => {
            const next = LAYA_SETTINGS[Number(event.currentTarget.value)]
            // The knob follows the requested setting, which the service reports back; native drag/key feedback must
            // not move it ahead of that.
            event.currentTarget.value = String(requested)
            if (next !== undefined) void laya.request(next)
          }} />
        {setting.note === 'approved-preview' && <span className={css.bubble} role="status">{t('laya.approvedPreview')}</span>}
        {asking && <span className={css.request} role="status" data-laya-asked={setting.asked}>
          <LockedAction verb={t('laya.needsOwner')} tone="blue" href={ownerOrigin()} note={t('laya.requestOnly')}
            title={`${ownerOrigin()} · ${String(layaRank(setting.asked ?? setting.applied) + 1)} · ${t(noteName[setting.asked ?? setting.applied])}`} />
        </span>}
      </span>
      <span className={css.name}>{t('laya.label')}</span>
      <span id={layaHintId} className={css.srOnly}>{layaHint}</span>
    </span>}
    {/* VISION. One click toggles. `vision` is the seam to Prime's `aukora-eye` plugin (3673b98, plugins/aukora-eye),
        whose one tool `aukora_see` this switches for the session once the plugin is ported; until then the choice is
        only remembered (see vision.ts). */}
    <button type="button" className={css.eye} aria-pressed={seeing} aria-label={seeing ? t('composer.visionOn') : t('composer.visionOff')}
      title={`${seeing ? t('composer.visionOn') : t('composer.visionOff')} ${t('composer.visionNote')}`} disabled={locked}
      onClick={() => { vision.set(!seeing) }}><EyeIcon on={seeing} /></button>
    <span className={css.srOnly} role="alert">{error ? t('composer.failed') : ''}</span>
  </div>
}

/**
 * Replace the existing permission seat and inspect the canonical command's host outcome.
 * @param ctx - client root context.
 * @param laya - where the owner's Laya setting lives; the face-local service until the node holds it.
 * @param vision - where the Vision choice lives; the face-local service until `aukora-eye` is ported.
 */
export function installComposerControls(
  ctx: ClientContext, laya?: LayaService, vision: VisionService = createFaceLocalVision(),
): void {
  // THE PREVIEW SWITCH DECIDES (composition.ts). Only the preview composition gets the face-local slider that approves a
  // loosening by itself; on a node every move is a request that opens the owner origin, and nothing changes here.
  const preview = isPreviewComposition()
  const service = laya ?? (preview ? createFaceLocalLaya({ previewApproveMs: PREVIEW_APPROVE_MS }) : createNodeRequestLaya())
  const request = laya === undefined && !preview
  ctx.slots.inject('conversation.input.permission', () => ctx.slots.register({
    name: 'conversation.input.permission', priority: -10, locale: NS,
    inject: (sessionId: SessionId): ControlsInjected => ({
      laya: service,
      vision,
      request,
      selectMode: async mode => {
        const result = await ctx.remote.commands.execute(sessionId, `/aukora-mode ${mode}`, [])
        if (!result.ok || result.value?.result.kind !== 'success') {
          throw new Error('Mode change unavailable')
        }
      },
    }),
  }, ComposerControls))
}
