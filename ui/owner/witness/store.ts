// SPDX-License-Identifier: AGPL-3.0-or-later
import { checkpoint } from "./codec.js";
import { assertActive } from "./contracts.js";
import type { BrowserCheckpoint, WitnessStore } from "./contracts.js";

const DATABASE = "aukora-owner-browser-witness";
const HEADS = "heads";

function unavailable(): Error {
  return new Error("witness:store-unavailable");
}

function open(factory: IDBFactory, signal: AbortSignal): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let request: IDBOpenDBRequest;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", aborted);
      reject(error);
    };
    const aborted = (): void => fail(new Error("witness:aborted"));
    try {
      assertActive(signal);
      signal.addEventListener("abort", aborted, { once: true });
      request = factory.open(DATABASE, 1);
    } catch {
      fail(signal.aborted ? new Error("witness:aborted") : unavailable());
      return;
    }
    request.onblocked = () => fail(unavailable());
    request.onerror = () => fail(signal.aborted ? new Error("witness:aborted") : unavailable());
    request.onupgradeneeded = () => {
      if (settled || signal.aborted) {
        request.transaction?.abort();
        return;
      }
      try {
        if (!request.result.objectStoreNames.contains(HEADS)) {
          request.result.createObjectStore(HEADS);
        }
      } catch {
        try { request.transaction?.abort(); } catch { /* The upgrade has already stopped. */ }
        fail(unavailable());
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => db.close();
      if (settled || signal.aborted) {
        db.close();
        if (!settled) aborted();
        return;
      }
      settled = true;
      signal.removeEventListener("abort", aborted);
      resolve(db);
    };
  });
}

function transact<T>(
  db: IDBDatabase,
  mode: IDBTransactionMode,
  signal: AbortSignal,
  begin: (store: IDBObjectStore, result: (value: T) => void, fail: () => void) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    let transaction: IDBTransaction;
    try {
      assertActive(signal);
      transaction = db.transaction(HEADS, mode);
    } catch {
      reject(signal.aborted ? new Error("witness:aborted") : unavailable());
      return;
    }
    let settled = false;
    let ready = false;
    let value: T;
    const fail = (error: Error): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener("abort", aborted);
      try { transaction.abort(); } catch { /* No active transaction remains. */ }
      reject(error);
    };
    const aborted = (): void => fail(new Error("witness:aborted"));
    const failed = (): void => fail(signal.aborted ? new Error("witness:aborted") : unavailable());
    transaction.onerror = failed;
    transaction.onabort = failed;
    transaction.oncomplete = () => {
      if (settled) return;
      if (signal.aborted) { aborted(); return; }
      if (!ready) { failed(); return; }
      settled = true;
      signal.removeEventListener("abort", aborted);
      resolve(value);
    };
    signal.addEventListener("abort", aborted, { once: true });
    try {
      assertActive(signal);
      begin(transaction.objectStore(HEADS), result => {
        assertActive(signal);
        value = result;
        ready = true;
      }, failed);
    } catch {
      failed();
    }
  });
}

function identical(left: BrowserCheckpoint, right: BrowserCheckpoint): boolean {
  return left.schema === right.schema && left.leafConvention === right.leafConvention
    && left.treeSize === right.treeSize && left.root === right.root;
}

export function createBrowserWitnessStore(scope: string, factory: IDBFactory = indexedDB): WitnessStore {
  if (typeof scope !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(scope)) {
    throw new Error("witness:invalid-scope");
  }
  return Object.freeze({
    async load(signal: AbortSignal): Promise<unknown | null> {
      const db = await open(factory, signal);
      try {
        return await transact<unknown | null>(db, "readonly", signal, (store, result, fail) => {
          const request = store.openCursor(scope);
          request.onsuccess = () => {
            try {
              result(request.result === null ? null : request.result.value);
            } catch { fail(); }
          };
        });
      } finally { db.close(); }
    },
    async replace(
      expected: BrowserCheckpoint | null, next: BrowserCheckpoint, signal: AbortSignal,
    ): Promise<"stored" | "changed"> {
      assertActive(signal);
      let previous: BrowserCheckpoint | null;
      let replacement: BrowserCheckpoint;
      try {
        previous = expected === null ? null : checkpoint(expected);
        replacement = checkpoint(next);
      } catch { throw unavailable(); }
      const db = await open(factory, signal);
      try {
        return await transact<"stored" | "changed">(db, "readwrite", signal, (store, result, fail) => {
          const request = store.openCursor(scope);
          request.onsuccess = () => {
            try {
              assertActive(signal);
              const cursor = request.result;
              const current = cursor === null ? null : checkpoint(cursor.value);
              const matches = previous === null ? current === null
                : current !== null && identical(previous, current);
              if (!matches) { result("changed"); return; }
              store.put(replacement, scope);
              result("stored");
            } catch { fail(); }
          };
        });
      } finally { db.close(); }
    },
  });
}
