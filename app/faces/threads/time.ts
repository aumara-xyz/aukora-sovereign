// SPDX-License-Identifier: AGPL-3.0-or-later
// Clock text. Every time here is the node's informational millisecond stamp; the session sequence is the order.

const MINUTE = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

const full = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const short = new Intl.DateTimeFormat(undefined, { timeStyle: "short" });

function date(ms: number): Date | null {
  const value = new Date(ms);
  return Number.isFinite(value.getTime()) ? value : null;
}

// Compact distance from now, as the thread list shows it: now, 5min, 2h, 3d, 2mo, 1y.
export function ago(ms: number, now: number): string {
  const gap = Math.max(0, now - ms);
  if (gap < MINUTE) return "now";
  if (gap < HOUR) return `${Math.floor(gap / MINUTE)}min`;
  if (gap < DAY) return `${Math.floor(gap / HOUR)}h`;
  if (gap < 30 * DAY) return `${Math.floor(gap / DAY)}d`;
  if (gap < 365 * DAY) return `${Math.floor(gap / (30 * DAY))}mo`;
  return `${Math.floor(gap / (365 * DAY))}y`;
}

export function stamp(ms: number): string {
  const value = date(ms);
  return value ? full.format(value) : "time not readable";
}

export function clock(ms: number): string {
  const value = date(ms);
  return value ? short.format(value) : "";
}

export function iso(ms: number): string | null {
  return date(ms)?.toISOString() ?? null;
}
