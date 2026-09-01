import { v4 as uuidv4 } from "uuid";
import { generateDeviceKey } from "./index.web";

const DB_NAME = "voult";
const DB_VERSION = 2;
const STORE_NAME = "device_key";
const ENVELOPE_STORE_NAME = "device_envelope";

// Records are keyed by vault id so multiple vaults can coexist in one browser
// profile without overwriting each other's device key or vault-key envelope.
const recordKeyForVault = (vaultId: string) => `vault:${vaultId}`;

export interface DeviceKeyRecord {
  device_id: string;
  key: CryptoKey;
  key_version: number;
  created_at: string;
}

/** The device-wrapped vault-key envelope, persisted locally next to the device key. */
export interface DeviceEnvelopeRecord {
  device_id: string;
  wrapped_vault_key: string;
  wrapped_vault_key_iv: string;
  crypto_version: number;
  updated_at: string;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
      if (!db.objectStoreNames.contains(ENVELOPE_STORE_NAME)) {
        db.createObjectStore(ENVELOPE_STORE_NAME);
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

const isDeviceKeyRecord = (value: unknown): boolean =>
  !!value &&
  typeof (value as DeviceKeyRecord).device_id === "string" &&
  (value as DeviceKeyRecord).key instanceof CryptoKey;

const isEnvelopeRecord = (value: unknown): boolean =>
  !!value &&
  typeof (value as DeviceEnvelopeRecord).device_id === "string" &&
  typeof (value as DeviceEnvelopeRecord).wrapped_vault_key === "string" &&
  typeof (value as DeviceEnvelopeRecord).wrapped_vault_key_iv === "string" &&
  typeof (value as DeviceEnvelopeRecord).crypto_version === "number";

async function putRecord(db: IDBDatabase, storeName: string, vaultId: string, record: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).put(record, recordKeyForVault(vaultId));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function deleteRecord(db: IDBDatabase, storeName: string, vaultId: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).delete(recordKeyForVault(vaultId));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Returns the persisted browser device key for this vault, or null. */
export async function getDeviceKey(vaultId: string): Promise<DeviceKeyRecord | null> {
  if (typeof indexedDB === "undefined") return null;
  const db = await openDb();
  try {
    return await new Promise<DeviceKeyRecord | null>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).get(recordKeyForVault(vaultId));
      request.onsuccess = () => {
        const value = request.result;
        resolve(value && isDeviceKeyRecord(value) ? (value as DeviceKeyRecord) : null);
      };
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

/**
 * Returns the browser device key for this vault, creating and persisting one
 * if missing. One key per (browser profile, vault). Non-exportable AES-GCM,
 * never leaves the client.
 */
export async function getOrCreateDeviceKey(vaultId: string): Promise<DeviceKeyRecord> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this environment.");
  }
  const db = await openDb();
  try {
    const existing = await new Promise<DeviceKeyRecord | null>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const request = tx.objectStore(STORE_NAME).get(recordKeyForVault(vaultId));
      request.onsuccess = () => {
        const value = request.result;
        resolve(value && isDeviceKeyRecord(value) ? (value as DeviceKeyRecord) : null);
      };
      request.onerror = () => reject(request.error);
    });
    if (existing) return existing;

    const record: DeviceKeyRecord = {
      device_id: uuidv4(),
      key: await generateDeviceKey(),
      key_version: 1,
      created_at: new Date().toISOString(),
    };
    await putRecord(db, STORE_NAME, vaultId, record);
    return record;
  } finally {
    db.close();
  }
}

/** Returns the locally stored device-wrapped vault-key envelope for this vault, or null. */
export async function getDeviceEnvelope(vaultId: string): Promise<DeviceEnvelopeRecord | null> {
  if (typeof indexedDB === "undefined") return null;
  const db = await openDb();
  try {
    return await new Promise<DeviceEnvelopeRecord | null>((resolve, reject) => {
      const tx = db.transaction(ENVELOPE_STORE_NAME, "readonly");
      const request = tx.objectStore(ENVELOPE_STORE_NAME).get(recordKeyForVault(vaultId));
      request.onsuccess = () => {
        const value = request.result;
        resolve(value && isEnvelopeRecord(value) ? (value as DeviceEnvelopeRecord) : null);
      };
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

/** Stores this vault's device-wrapped vault-key envelope locally (never sent to the server). */
export async function saveDeviceEnvelope(
  vaultId: string,
  record: Omit<DeviceEnvelopeRecord, "updated_at">,
): Promise<void> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this environment.");
  }
  const db = await openDb();
  try {
    await putRecord(db, ENVELOPE_STORE_NAME, vaultId, {
      ...record,
      updated_at: new Date().toISOString(),
    });
  } finally {
    db.close();
  }
}

/**
 * Deletes only this vault's local device key and wrapped envelope (used on
 * logout of this vault). Other vaults' records are left untouched so they can
 * still auto-unlock later.
 */
export async function deleteDeviceKey(vaultId: string): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  const db = await openDb();
  try {
    await deleteRecord(db, STORE_NAME, vaultId);
    await deleteRecord(db, ENVELOPE_STORE_NAME, vaultId);
  } finally {
    db.close();
  }
}
