// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Aumara and Peter Viviani
/**
 * THE MODELS PAGE ON A SOVEREIGN NODE (Settings → Models). It stands in for the harness's own Models section
 * (`ui-settings-models`, switched off by the authority overlay, deploy/engine/authority.patch.yml row 3), whose key
 * form would store the key in the engine. Same place, same words at the top, one provider row: DeepSeek, its dot
 * showing the model broker's real standing, and Edit, which opens the node's own key page on the shell origin in a new
 * tab. See `model-key.ts` for why the key never touches this origin.
 */
import { useEffect, useState } from 'react'
import { IconTile, isPreviewComposition, StatusPill } from '@aukora/face-layout/client'
import type { PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import {
  keyPageHref, MODEL_KEY_STATUS_PATH, parseStanding, POLL_MS, rowView, shellOrigin, type ModelKeyStanding,
} from './model-key.ts'
import css from './ModelsSection.module.css'

/** PREVIEW ONLY: the preview composition's flag may carry `modelKey` (a standing) to look at each state. */
function previewStanding(): ModelKeyStanding {
  const flag = (globalThis as { __AUKORA_PREVIEW__?: { modelKey?: unknown } }).__AUKORA_PREVIEW__
  const wanted = flag?.modelKey
  if (typeof wanted === 'object' && wanted !== null) return parseStanding(200, wanted)
  return { state: 'none' }
}

async function readStanding(signal: AbortSignal): Promise<ModelKeyStanding> {
  if (isPreviewComposition()) return previewStanding()
  try {
    const reply = await fetch(MODEL_KEY_STATUS_PATH, {
      method: 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal,
      headers: { accept: 'application/json' },
    })
    const json = reply.headers.get('content-type')?.startsWith('application/json') === true
    return parseStanding(reply.status, json ? await reply.json() as unknown : undefined)
  } catch {
    return { state: 'unknown' }
  }
}

/** The broker's standing, read now, every few seconds, and again whenever this tab comes back into view. */
function useStanding(): ModelKeyStanding {
  const [standing, setStanding] = useState<ModelKeyStanding>({ state: 'unknown' })
  useEffect(() => {
    const abort = new AbortController()
    let timer: ReturnType<typeof setTimeout> | undefined
    const read = async () => {
      if (timer !== undefined) clearTimeout(timer)
      timer = undefined
      const next = await readStanding(abort.signal)
      if (abort.signal.aborted) return
      setStanding(previous => (JSON.stringify(previous) === JSON.stringify(next) ? previous : next))
      timer = setTimeout(() => { void read() }, POLL_MS)
    }
    const shown = () => { if (document.visibilityState === 'visible') void read() }
    void read()
    document.addEventListener('visibilitychange', shown)
    window.addEventListener('focus', shown)
    return () => {
      abort.abort()
      if (timer !== undefined) clearTimeout(timer)
      document.removeEventListener('visibilitychange', shown)
      window.removeEventListener('focus', shown)
    }
  }, [])
  return standing
}

const OUT = (
  <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth={1.4} strokeLinecap="round" strokeLinejoin="round">
    <path d="M9 6h9v9" /><path d="M18 6 7 17" />
  </svg>
)

export function ModelsSection(_props: PropsRuntime<'settings.section'>) {
  const standing = useStanding()
  const view = rowView(standing)
  const href = keyPageHref(globalThis.location)
  const shell = shellOrigin(globalThis.location).replace(/^https?:\/\//, '')
  return (
    <div className={css.section} data-models-section="sovereign">
      <h2>Models</h2>
      <p>Enter your API keys to use models from the following providers.</p>
      <ul className="ak-rows">
        <li className={`ak-row ak-tone-${view.tone} ${css.provider}`} data-provider="deepseek" data-key-state={standing.state}>
          <div className="ak-row__head" title={view.summary}>
            <IconTile icon="model" tone="mint" />
            <span className="ak-row__copy">
              <span className="ak-row__title">DeepSeek<i className={css.dot} aria-hidden="true" /></span>
              <span className="ak-row__summary">{view.summary}</span>
            </span>
            <span className="ak-row__end"><StatusPill tone={view.tone}>{view.pill}</StatusPill></span>
          </div>
          {view.actionable
            ? (
              <div className="ak-row__body">
                <div className="ak-actionrow">
                  <a className="ak-action ak-tone-mint" href={href} target="_blank" rel="noopener noreferrer"
                    title={`${shell}/engine/model-key`}>
                    {view.action}{OUT}
                  </a>
                  <span className="ak-action__note">Opens your node&apos;s own key page; the key never enters the engine.</span>
                </div>
              </div>
              )
            : null}
        </li>
      </ul>
      <p className={css.note}>
        Your key is typed on your node&apos;s own page and kept by its model broker, outside the engine; your passkey
        approves each new key. More providers come through your node&apos;s broker later.
      </p>
    </div>
  )
}
