import { v4 as uuidv4 } from "uuid";
import { generateDeviceKey } from "./index.web";

const DB_NAME = "voult";
const DB_VERSION = 2;
const STORE_NAME = "device_key";
const ENVELOPE_STORE_NAME = "device_envelope";

// Records are keyed by authenticated user id so multiple accounts can coexist
// in one browser profile without overwriting each other's device key or
// vault-key envelope. The legacy single-record key ("current") is migrated to
// the logging-in user's namespace on first read.
const recordKeyForUser = (userId: string) => `user:${userId}`;
const LEGACY_RECORD_KEY = "current";

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

/**
 * Reads the user's record, migrating the legacy global "current" record into
 * this user's namespace on first encounter (pre-namespacing installs keep
 * their device identity instead of re-enrolling). Returns null when neither
 * exists.
 */
async function readMigrated<T>(
  db: IDBDatabase,
  storeName: string,
  userId: string,
  validate: (value: unknown) => boolean,
): Promise<T | null> {
  const legacyValue = await new Promise<any>((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    const store = tx.objectStore(storeName);
    const request = store.get(LEGACY_RECORD_KEY);
    request.onsuccess = () => {
      const value = request.result ?? null;
      // Re-home the legacy record under this user's key within the same
      // transaction, then remove the global key so a later account's login
      // can't claim someone else's device identity.
      if (value && validate(value)) {
        try {
          store.put(structuredCloneIfPossible(value), recordKeyForUser(userId));
          store.delete(LEGACY_RECORD_KEY);
          console.info("Migrated legacy local device record to per-user namespace");
        } catch {
          // CryptoKey values may resist structured cloning in some browsers;
          // leave the legacy record in place rather than corrupting it.
        }
      }
      resolve(value);
    };
    request.onerror = () => reject(request.error);
  });
  if (legacyValue && validate(legacyValue)) {
    return legacyValue as T;
  }

  return new Promise<T | null>((resolve, reject) => {
    const tx = db.transaction(storeName, "readonly");
    const request = tx.objectStore(storeName).get(recordKeyForUser(userId));
    request.onsuccess = () => {
      const value = request.result;
      resolve(value && validate(value) ? (value as T) : null);
    };
    request.onerror = () => reject(request.error);
  });
}

// structuredClone keeps CryptoKey objects intact when re-putting a record read
// in an earlier transaction; fall back to the raw value where unavailable.
function structuredCloneIfPossible<T>(value: T): T {
  try {
    return typeof structuredClone === "function" ? structuredClone(value) : value;
  } catch {
    return value;
  }
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

async function putRecord(db: IDBDatabase, storeName: string, userId: string, record: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).put(record, recordKeyForUser(userId));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function deleteRecord(db: IDBDatabase, storeName: string, userId: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, "readwrite");
    tx.objectStore(storeName).delete(recordKeyForUser(userId));
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Returns the persisted browser device key for this account, or null. */
export async function getDeviceKey(userId: string): Promise<DeviceKeyRecord | null> {
  if (typeof indexedDB === "undefined") return null;
  const db = await openDb();
  try {
    return await readMigrated<DeviceKeyRecord>(db, STORE_NAME, userId, isDeviceKeyRecord);
  } finally {
    db.close();
  }
}

/**
 * Returns the browser device key for this account, creating and persisting one
 * if missing. One key per (browser profile, account). Non-exportable AES-GCM,
 * never leaves the client.
 */
export async function getOrCreateDeviceKey(userId: string): Promise<DeviceKeyRecord> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this environment.");
  }
  const db = await openDb();
  try {
    const existing = await readMigrated<DeviceKeyRecord>(db, STORE_NAME, userId, isDeviceKeyRecord);
    if (existing) return existing;

    const record: DeviceKeyRecord = {
      device_id: uuidv4(),
      key: await generateDeviceKey(),
      key_version: 1,
      created_at: new Date().toISOString(),
    };
    await putRecord(db, STORE_NAME, userId, record);
    return record;
  } finally {
    db.close();
  }
}

/** Returns the locally stored device-wrapped vault-key envelope for this account, or null. */
export async function getDeviceEnvelope(userId: string): Promise<DeviceEnvelopeRecord | null> {
  if (typeof indexedDB === "undefined") return null;
  const db = await openDb();
  try {
    return await readMigrated<DeviceEnvelopeRecord>(db, ENVELOPE_STORE_NAME, userId, isEnvelopeRecord);
  } finally {
    db.close();
  }
}

/** Stores this account's device-wrapped vault-key envelope locally (never sent to the server). */
export async function saveDeviceEnvelope(
  userId: string,
  record: Omit<DeviceEnvelopeRecord, "updated_at">,
): Promise<void> {
  if (typeof indexedDB === "undefined") {
    throw new Error("IndexedDB is not available in this environment.");
  }
  const db = await openDb();
  try {
    await putRecord(db, ENVELOPE_STORE_NAME, userId, {
      ...record,
      updated_at: new Date().toISOString(),
    });
  } finally {
    db.close();
  }
}

/**
 * Deletes only this account's local device key and wrapped envelope (used on
 * logout of this device). Other accounts' records are left untouched so they
 * can still auto-unlock later.
 */
export async function deleteDeviceKey(userId: string): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  const db = await openDb();
  try {
    await deleteRecord(db, STORE_NAME, userId);
    await deleteRecord(db, ENVELOPE_STORE_NAME, userId);
  } finally {
    db.close();
  }
}
