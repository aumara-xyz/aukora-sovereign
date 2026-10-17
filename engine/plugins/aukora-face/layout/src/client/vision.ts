/**
 * The Vision toggle's state and its seam.
 *
 * Vision is the model's own look at the running app. Prime's `aukora-eye` plugin (3673b98, `plugins/aukora-eye`)
 * registers one tool, `aukora_see`; a node-backed `VisionService` is what turns that tool on and off for the session.
 * Until that plugin is ported, the face-local service below only remembers the owner's choice in this browser: it
 * switches nothing on the node.
 */

/** The seam between the eye button and whatever holds the choice. */
export interface VisionService {
  /** Whether vision is on. */
  getState(): boolean
  /** Listen for changes; returns the unsubscribe. */
  subscribe(listener: () => void): () => void
  /** Turn vision on or off. */
  set(on: boolean): void
}

/** The slice of `Storage` the face-local service uses; a missing or throwing store just means nothing persists. */
export interface VisionStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
}

export const VISION_STORAGE_KEY = 'aukora.face.vision.v1'

/** The face-local service: vision starts off, and the choice lives in this browser. */
export function createFaceLocalVision(storage: VisionStorage | undefined = browserStorage()): VisionService {
  let on = false
  try { on = storage?.getItem(VISION_STORAGE_KEY) === 'on' } catch { /* nothing persists */ }
  const listeners = new Set<() => void>()
  return {
    getState: () => on,
    subscribe(listener) {
      listeners.add(listener)
      return () => { listeners.delete(listener) }
    },
    set(next) {
      if (next === on) return
      on = next
      try { storage?.setItem(VISION_STORAGE_KEY, next ? 'on' : 'off') } catch { /* the choice still holds for this page */ }
      for (const listener of listeners) listener()
    },
  }
}

function browserStorage(): VisionStorage | undefined {
  try { return globalThis.localStorage } catch { return undefined }
}
