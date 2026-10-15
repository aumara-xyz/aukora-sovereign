// SPDX-License-Identifier: AGPL-3.0-or-later

export const APPROVAL_POLL_INTERVAL_MS = 1_000;
export const MAX_APPROVAL_NOTIFICATIONS = 10_000;

export type ApprovalNotification = {
  readonly proposal: string;
  readonly expires_at_ms: number;
};

export type ApprovalSnapshot = {
  readonly sequence: number;
  readonly proposals: readonly ApprovalNotification[];
};

export type ApprovalNotificationOptions = {
  /** The host returns one complete, session-scoped snapshot after pagination. */
  readonly pending: (signal: AbortSignal) => Promise<unknown>;
  /** This callback is supplied by the approved top-level shell composition. */
  readonly openOwner: (route: `/approval/${string}`) => void;
  readonly ownerBusy: () => boolean;
  readonly signal?: AbortSignal;
  readonly onRefusal?: (code: string) => void;
};

export interface ApprovalNotifications {
  refresh(): void;
  ownerNotice(notice: unknown): void;
  dispose(): void;
}

function refuse(reason: string): never {
  throw new Error(`frontdoor:${reason}`);
}

function exactRecord(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)
    || Object.keys(value).length !== keys.length
    || keys.some(key => !Object.prototype.hasOwnProperty.call(value, key))) refuse("approval-snapshot-invalid");
  return value as Record<string, unknown>;
}

function safeUnsigned(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function snapshot(value: unknown): ApprovalSnapshot {
  const record = exactRecord(value, ["proposals", "sequence"]);
  if (!safeUnsigned(record.sequence) || !Array.isArray(record.proposals)
    || record.proposals.length > MAX_APPROVAL_NOTIFICATIONS) refuse("approval-snapshot-invalid");
  const ids = new Set<string>();
  const proposals: ApprovalNotification[] = [];
  for (const item of record.proposals) {
    const proposal = exactRecord(item, ["expires_at_ms", "proposal"]);
    if (typeof proposal.proposal !== "string" || !/^[0-9a-f]{32}$/.test(proposal.proposal)
      || !safeUnsigned(proposal.expires_at_ms) || ids.has(proposal.proposal)) {
      refuse("approval-snapshot-invalid");
    }
    ids.add(proposal.proposal);
    proposals.push({ proposal: proposal.proposal, expires_at_ms: proposal.expires_at_ms });
  }
  return { sequence: record.sequence, proposals };
}

function now(): number {
  const value = Date.now();
  if (!safeUnsigned(value)) refuse("approval-clock-invalid");
  return value;
}

function failureCode(error: unknown): string {
  if (error instanceof Error && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(error.message)) return error.message;
  return "frontdoor:approval-notification-unavailable";
}

/** Mount only from the shell composition; the module creates no frame or transport. */
export function startApprovalNotifications(options: ApprovalNotificationOptions): ApprovalNotifications {
  if (window.top !== window.self) refuse("approval-shell-required");
  if (!options || typeof options.pending !== "function" || typeof options.openOwner !== "function"
    || typeof options.ownerBusy !== "function"
    || (options.onRefusal !== undefined && typeof options.onRefusal !== "function")) {
    refuse("approval-configuration-invalid");
  }

  const abort = new AbortController();
  const shown = new Set<string>();
  let lastSequence: number | null = null;
  let candidates: ApprovalNotification[] = [];
  let active: string | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let inFlight = false;
  let requested = 0;
  let disposed = false;

  const report = (error: unknown): void => {
    try { options.onRefusal?.(failureCode(error)); } catch { /* Reporting does not advance the queue. */ }
  };

  const clearTimer = (): void => {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
  };

  const openNext = (): void => {
    if (disposed || active !== null) return;
    try {
      const busy = options.ownerBusy();
      if (typeof busy !== "boolean") refuse("approval-configuration-invalid");
      if (busy) return;
      const at = now();
      candidates = candidates.filter(item => item.expires_at_ms > at && !shown.has(item.proposal));
      const next = candidates[0];
      if (!next) return;
      active = next.proposal;
      try { options.openOwner(`/approval/${next.proposal}`); }
      catch (error) { active = null; throw error; }
      shown.add(next.proposal);
      candidates = candidates.filter(item => item.proposal !== next.proposal);
    } catch (error) { report(error); }
  };

  const accept = (value: unknown): void => {
    const next = snapshot(value);
    const at = now();
    if (lastSequence !== null && next.sequence < lastSequence) refuse("approval-sequence-rollback");
    const present = new Set(next.proposals.map(item => item.proposal));
    for (const proposal of shown) if (!present.has(proposal)) shown.delete(proposal);
    lastSequence = next.sequence;
    candidates = next.proposals.filter(item => item.expires_at_ms > at
      && !shown.has(item.proposal) && item.proposal !== active);
    openNext();
  };

  const poll = async (): Promise<void> => {
    if (disposed || inFlight) return;
    clearTimer();
    inFlight = true;
    const generation = requested;
    try {
      const value = await options.pending(abort.signal);
      if (!disposed) {
        if (generation === requested) accept(value);
        else candidates = [];
      }
    } catch (error) {
      if (!disposed) { candidates = []; report(error); }
    } finally {
      inFlight = false;
      if (!disposed) {
        if (generation !== requested) void poll();
        else timer = setTimeout(() => { void poll(); }, APPROVAL_POLL_INTERVAL_MS);
      }
    }
  };

  const refresh = (): void => {
    if (disposed) return;
    requested += 1;
    candidates = [];
    clearTimer();
    void poll();
  };

  const ownerNotice = (notice: unknown): void => {
    if (disposed) return;
    if (!notice || typeof notice !== "object" || Array.isArray(notice)) refuse("approval-notice-invalid");
    const value = notice as Record<string, unknown>;
    const keys = Object.keys(value);
    if (keys.length === 1 && keys.includes("kind") && (value.kind === "closed" || value.kind === "complete")) {
      active = null;
      refresh();
      return;
    }
    if (keys.length === 2 && keys.includes("code") && keys.includes("kind") && value.kind === "refusal"
      && typeof value.code === "string" && /^[a-z][a-z0-9_-]*:[a-z0-9-]+$/.test(value.code)) {
      report(new Error(value.code));
      return;
    }
    refuse("approval-notice-invalid");
  };

  const dispose = (): void => {
    if (disposed) return;
    disposed = true;
    clearTimer();
    abort.abort();
    options.signal?.removeEventListener("abort", dispose);
    candidates = [];
    lastSequence = null;
    shown.clear();
    active = null;
  };

  if (options.signal?.aborted) dispose();
  else {
    options.signal?.addEventListener("abort", dispose, { once: true });
    refresh();
  }
  return { refresh, ownerNotice, dispose };
}
