// SPDX-License-Identifier: AGPL-3.0-or-later
// This device's own co-presence key: P-256 ECDSA made by WebCrypto with a non-extractable private half, kept in
// IndexedDB on this origin. The node learns only the public half (raw SEC1, 65 bytes), first when pairing starts or
// joins, then bound into the context both devices sign. Clearing this site's data forgets the key; the next pairing
// makes a new one and the device list shows it as a new device.
import { hex, refuse } from "../bytes.js";

export type DeviceKey = { readonly keys: CryptoKeyPair; readonly publicKey: string };
export const OWNER_DEVICE_STORE = "aukora.copresence.device.owner.v1";
export const PHONE_DEVICE_STORE = "aukora.copresence.device.phone.v1";

function database(name: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(name, 1);
    request.onupgradeneeded = () => { request.result.createObjectStore("key"); };
    request.onsuccess = () => resolve(request.result);
    request.onerror = request.onblocked = () => reject(new Error("copresence:device-key-storage"));
  });
}

function read(db: IDBDatabase): Promise<CryptoKeyPair | undefined> {
  return new Promise((resolve, reject) => {
    const request = db.transaction("key", "readonly").objectStore("key").get("device");
    request.onsuccess = () => resolve(request.result as CryptoKeyPair | undefined);
    request.onerror = () => reject(new Error("copresence:device-key-storage"));
  });
}

// `add` refuses an existing key, so two tabs racing to create one keep whichever landed first.
function add(db: IDBDatabase, keys: CryptoKeyPair): Promise<void> {
  return new Promise((resolve, reject) => {
    const transaction = db.transaction("key", "readwrite", { durability: "strict" });
    transaction.objectStore("key").add(keys, "device");
    transaction.oncomplete = () => resolve();
    transaction.onerror = transaction.onabort = () => reject(new Error("copresence:device-key-exists"));
  });
}

function usable(keys: CryptoKeyPair | undefined): keys is CryptoKeyPair {
  return !!keys && keys.privateKey instanceof CryptoKey && keys.publicKey instanceof CryptoKey
    && keys.privateKey.extractable === false && keys.privateKey.algorithm.name === "ECDSA";
}

export async function deviceKey(store: string): Promise<DeviceKey> {
  const db = await database(store);
  try {
    let keys = await read(db);
    if (!usable(keys)) {
      const made = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
      try { await add(db, made); } catch { /* another tab stored one first */ }
      keys = await read(db);
    }
    if (!usable(keys)) refuse("device-key-storage");
    const raw = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
    if (raw.length !== 65 || raw[0] !== 4) refuse("device-key");
    return { keys, publicKey: hex(raw) };
  } finally {
    db.close();
  }
}
