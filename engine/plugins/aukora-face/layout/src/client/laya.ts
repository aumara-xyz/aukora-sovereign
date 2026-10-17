/**
 * The Laya slider's setting and the one seam it crosses to reach the node.
 *
 * The first three notches are the `SliderSetting`s of `crates/laya/src/standing.rs`, in the same order and with the
 * same wire names (`ask`, `risky`, `limits`). The fourth, `trusted`, is Peter's (2026-10-17) and does not exist in Rust
 * yet (see PORT-NOTES): grantable classes clear inside a live standing grant with no daily count. There is still no
 * "approve everything" notch: plugin installs, persistence, interactive terminals and unknown actions ask under every
 * setting, `trusted` included (`slider.rs`, "A class that cannot be granted ... asks under every setting").
 *
 * Rust owns the truth. A setting that loosens (moves right) is a critical proposal that needs the owner's passkey
 * (`SliderSetting::loosens`, `SliderPolicy::proposal`); tightening is immediate. This file only mirrors that rule so
 * the control can say it before the node does.
 *
 * THE SEAM is `LayaService`. The face asks it for a setting and renders whatever state it reports. The face-local
 * service below is what runs until the node is wired: it keeps the chosen setting in this browser, reports a
 * loosening as waiting for the passkey and, for the preview only, approves it after a moment (there is no node to hold
 * the passkey). A node-backed service replaces `createFaceLocalLaya` in `installComposerControls` and nothing in the
 * component changes: `request` submits the setting to the door (the policy proposal for a loosening, a direct write
 * for a tightening), `getState` follows the node's applied policy, and it never approves a loosening itself.
 */

/** The wire names of the notches, tightest first (`trusted` is not yet a Rust `SliderSetting`). */
export const LAYA_SETTINGS = ['ask', 'risky', 'limits', 'trusted'] as const
export type LayaSetting = typeof LAYA_SETTINGS[number]

/** The setting a new owner starts on: the pinned starter policy sits at "only risky things". */
export const LAYA_DEFAULT: LayaSetting = 'risky'

/** Mirror of `SliderSetting::rank`: a higher rank clears more without asking. */
export function layaRank(setting: LayaSetting): number {
  return LAYA_SETTINGS.indexOf(setting)
}

/** Mirror of `SliderSetting::loosens`: moving to `next` from `previous` needs the owner's passkey. */
export function layaLoosens(next: LayaSetting, previous: LayaSetting): boolean {
  return layaRank(next) > layaRank(previous)
}

/**
 * What the control shows. `requested` is where the knob is. `applied` is the setting in force: it differs from
 * `requested` only while a loosening waits for the owner's passkey on the node. `note` is a short-lived remark about
 * the last change; today only the face-local preview sets it.
 */
export interface LayaState {
  readonly applied: LayaSetting
  readonly requested: LayaSetting
  readonly note: 'approved-preview' | null
}

/** What the door answered: the setting is in force, or it is a loosening that waits for the passkey. */
export type LayaOutcome = 'applied' | 'needs-passkey'

/**
 * The seam between the slider and whatever holds the owner's setting.
 *
 * A node-backed service MUST NEVER approve a loosening by itself: `applied` moves up only when the node reports the
 * owner's passkey approved it. The face-local service below is the one that approves on a timer, and only because
 * there is no node to ask.
 */
export interface LayaService {
  /** The current state; a new object whenever it changes, so it can serve `useSyncExternalStore`. */
  getState(): LayaState
  /** Listen for changes; returns the unsubscribe. */
  subscribe(listener: () => void): () => void
  /** Ask for a setting. Tightening, or choosing the applied setting again, applies at once and clears any waiting loosening. */
  request(setting: LayaSetting): Promise<LayaOutcome>
}

/** The slice of `Storage` the face-local service uses; a missing or throwing store just means nothing persists. */
export interface LayaStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

export const LAYA_STORAGE_KEY = 'aukora.face.laya.v1'

function isSetting(value: unknown): value is LayaSetting {
  return typeof value === 'string' && (LAYA_SETTINGS as readonly string[]).includes(value)
}

/** Read the stored state, falling back to the default for anything missing, malformed or inconsistent. */
function load(storage: LayaStorage | undefined): LayaState {
  const fallback: LayaState = { applied: LAYA_DEFAULT, requested: LAYA_DEFAULT, note: null }
  try {
    const raw = storage?.getItem(LAYA_STORAGE_KEY)
    if (raw === null || raw === undefined) return fallback
    const value = JSON.parse(raw) as { applied?: unknown; requested?: unknown }
    if (!isSetting(value.applied) || !isSetting(value.requested)) return fallback
    // A stored request below the applied setting cannot be waiting for a passkey: the knob rests on what is in force.
    return { applied: value.applied, requested: layaLoosens(value.requested, value.applied) ? value.requested : value.applied, note: null }
  } catch {
    return fallback
  }
}

/** How long the face-local preview waits before it approves a loosening in place of the owner's passkey. */
export const PREVIEW_APPROVE_MS = 1500
/** How long the "approved (preview)" remark stays. */
const NOTE_MS = 2500

export interface FaceLocalLayaOptions {
  /** Storage for the setting; defaults to the browser's `localStorage` when there is one. */
  storage?: LayaStorage | undefined
  /** PREVIEW ONLY: approve a waiting loosening after this many ms. 0 never approves (the loosening waits). */
  previewApproveMs?: number
}

/**
 * The face-local service: the chosen setting lives in this browser because there is no node to hold it. With no
 * node there is also nobody to hold the passkey, so, for the preview alone, a loosening is approved after
 * `PREVIEW_APPROVE_MS` and the state says so (`note: 'approved-preview'`). A service backed by the node never does this.
 */
export function createFaceLocalLaya(options: FaceLocalLayaOptions = {}): LayaService {
  const storage = 'storage' in options ? options.storage : browserStorage()
  const approveMs = options.previewApproveMs ?? PREVIEW_APPROVE_MS
  let state = load(storage)
  let approve: ReturnType<typeof setTimeout> | undefined
  let noteTimer: ReturnType<typeof setTimeout> | undefined
  const listeners = new Set<() => void>()
  const set = (next: LayaState): void => {
    state = next
    try { storage?.setItem(LAYA_STORAGE_KEY, JSON.stringify({ applied: next.applied, requested: next.requested })) } catch { /* nothing persists; the session still works */ }
    for (const listener of listeners) listener()
  }
  const settle = (): void => {
    clearTimeout(approve)
    approve = undefined
    if (approveMs <= 0 || !layaLoosens(state.requested, state.applied)) return
    const wanted = state.requested
    approve = setTimeout(() => {
      approve = undefined
      if (state.requested !== wanted || !layaLoosens(wanted, state.applied)) return
      set({ applied: wanted, requested: wanted, note: 'approved-preview' })
      clearTimeout(noteTimer)
      noteTimer = setTimeout(() => {
        if (state.note !== null) { state = { ...state, note: null }; for (const listener of listeners) listener() }
      }, NOTE_MS)
    }, approveMs)
  }
  settle()
  return {
    getState: () => state,
    subscribe(listener) {
      listeners.add(listener)
      return () => { listeners.delete(listener) }
    },
    request(setting) {
      clearTimeout(noteTimer)
      if (layaLoosens(setting, state.applied)) {
        if (state.requested !== setting || state.note !== null) set({ applied: state.applied, requested: setting, note: null })
        settle()
        return Promise.resolve('needs-passkey')
      }
      set({ applied: setting, requested: setting, note: null })
      settle()
      return Promise.resolve('applied')
    },
  }
}

function browserStorage(): LayaStorage | undefined {
  try { return globalThis.localStorage } catch { return undefined }
}
