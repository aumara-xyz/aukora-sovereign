// SPDX-License-Identifier: AGPL-3.0-or-later
import type { AttemptStore, ExchangeMethod } from "./contracts.ts";
import { checkAbort, hex, refuse } from "./bytes.ts";

type Entry = { id: string; sequence: number; method: ExchangeMethod; outcome: "pending" | "bloom" | "refused" | "cancelled" };
export class IndexedAttempts implements AttemptStore {
  private readonly database: Promise<IDBDatabase>;
  constructor(name = "aukora.copresence.attempts.v1") {
    this.database = new Promise((resolve, reject) => {
      const request = indexedDB.open(name, 1);
      request.onupgradeneeded = () => {
        request.result.createObjectStore("attempts", { keyPath: "id" });
        request.result.createObjectStore("meta");
        request.result.createObjectStore("receipts");
      };
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(new Error("copresence:attempt-storage"));
      request.onblocked = () => reject(new Error("copresence:attempt-storage"));
    });
  }
  async reserve(method: ExchangeMethod, signal: AbortSignal): Promise<string> {
    checkAbort(signal);
    const db = await this.database;
    checkAbort(signal);
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(["attempts", "meta"], "readwrite", { durability: "strict" });
      const meta = transaction.objectStore("meta");
      const read = meta.get("sequence");
      let id = "";
      read.onsuccess = () => {
        const sequence = (read.result ?? 0) + 1;
        if (!Number.isSafeInteger(sequence)) { transaction.abort(); return; }
        id = `${sequence}.${hex(crypto.getRandomValues(new Uint8Array(16)))}`;
        const entry: Entry = { id, sequence, method, outcome: "pending" };
        transaction.objectStore("attempts").add(entry);
        meta.put(sequence, "sequence");
      };
      transaction.oncomplete = () => resolve(id);
      transaction.onerror = transaction.onabort = () => reject(new Error("copresence:attempt-storage"));
    });
  }
  async finish(id: string, outcome: "bloom" | "refused" | "cancelled", signal: AbortSignal): Promise<void> {
    checkAbort(signal);
    const db = await this.database;
    return new Promise((resolve, reject) => {
      const transaction = db.transaction("attempts", "readwrite", { durability: "strict" });
      const store = transaction.objectStore("attempts");
      const request = store.get(id);
      request.onsuccess = () => {
        const entry = request.result as Entry | undefined;
        if (!entry || entry.outcome !== "pending") { transaction.abort(); return; }
        store.put({ ...entry, outcome });
      };
      transaction.oncomplete = () => resolve();
      transaction.onerror = transaction.onabort = () => reject(new Error("copresence:attempt-storage"));
    });
  }
  async consumeReceipt(digest: string, signal: AbortSignal): Promise<void> {
    checkAbort(signal);
    const db = await this.database;
    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction("receipts", "readwrite", { durability: "strict" });
      transaction.objectStore("receipts").add(true, digest);
      transaction.oncomplete = () => resolve();
      transaction.onerror = transaction.onabort = () => reject(new Error("copresence:receipt-replay"));
    });
  }
}
export function ticket(id: string): { sequence: number; session: string } {
  const match = /^([1-9][0-9]*)\.([0-9a-f]{32})$/.exec(id);
  if (!match || !Number.isSafeInteger(Number(match[1]))) refuse("attempt-id");
  return { sequence: Number(match[1]), session: match[2] };
}
