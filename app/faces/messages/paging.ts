// SPDX-License-Identifier: AGPL-3.0-or-later
import type { Page } from "./model.js";

// A contact refresh is one complete snapshot. Later pages must arrive before the
// caller can remove retained rows that are absent from the refreshed book.
// A book this large is not one owner's contacts: stop instead of growing without bound.
export const MAX_SNAPSHOT_PAGES = 400;

export async function readAllPages<T>(
  read: (before: string | null) => Promise<Page<T>>, key: (item: T) => string,
): Promise<readonly T[]> {
  const items: T[] = [];
  const keys = new Set<string>();
  const cursors = new Set<string>();
  let before: string | null = null;
  for (let pages = 0; ; pages++) {
    if (pages >= MAX_SNAPSHOT_PAGES) throw new Error("app:invalid-reply");
    const page = await read(before);
    for (const item of page.items) {
      const id = key(item);
      if (keys.has(id)) throw new Error("app:invalid-reply");
      keys.add(id);
      items.push(item);
    }
    if (page.next === null) return items;
    if (page.items.length === 0 || cursors.has(page.next)) throw new Error("app:invalid-reply");
    cursors.add(page.next);
    before = page.next;
  }
}
