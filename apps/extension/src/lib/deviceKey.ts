// Device key + envelope storage for the extension service worker.
//
// Same record shape and `vault:<id>` key scheme as the web app's
// `device-key.ts`, but backed by IndexedDB (the only worker-side store that
// can hold non-exportable CryptoKey handles — chrome.storage is JSON-only and
// cannot persist keys). DB name differs (`voult-ext`) so the extension never
// touches the web app's origin-bound database.

import { generateDeviceKey } from "@voult/vault-core";

const DB_NAME = "voult-ext";
const DB_VERSION = 1;
const KEY_STORE = "device_key";
const ENVELOPE_STORE = "device_envelope";

const recordKeyForVault = (vaultId: string) => `vault:${vaultId}`;

export interface DeviceKeyRecord {
  device_id: string;
  key: CryptoKey;
  key_version: number;
  created_at: string;
}

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
      if (!db.objectStoreNames.contains(KEY_STORE)) db.createObjectStore(KEY_STORE);
      if (!db.objectStoreNames.contains(ENVELOPE_STORE)) db.createObjectStore(ENVELOPE_STORE);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function getRecord<T>(store: string, vaultId: string): Promise<T | null> {
  const db = await openDb();
  try {
    return await new Promise<T | null>((resolve, reject) => {
      const tx = db.transaction(store, "readonly");
      const req = tx.objectStore(store).get(recordKeyForVault(vaultId));
      req.onsuccess = () => resolve((req.result as T | undefined) ?? null);
      req.onerror = () => reject(req.error);
    });
  } finally {
    db.close();
  }
}

async function putRecord(store: string, vaultId: string, record: unknown): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(store, "readwrite");
      tx.objectStore(store).put(record, recordKeyForVault(vaultId));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}

const isDeviceKeyRecord = (v: unknown): v is DeviceKeyRecord =>
  !!v &&
  typeof (v as DeviceKeyRecord).device_id === "string" &&
  (v as DeviceKeyRecord).key instanceof CryptoKey;

const isEnvelopeRecord = (v: unknown): v is DeviceEnvelopeRecord =>
  !!v &&
  typeof (v as DeviceEnvelopeRecord).device_id === "string" &&
  typeof (v as DeviceEnvelopeRecord).wrapped_vault_key === "string";

function newDeviceId(): string {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const b = new Uint8Array(16);
  globalThis.crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** This vault's device key, or null when never enrolled on this browser. */
export async function getDeviceKey(vaultId: string): Promise<DeviceKeyRecord | null> {
  const rec = await getRecord<unknown>(KEY_STORE, vaultId);
  return rec && isDeviceKeyRecord(rec) ? rec : null;
}

/** This vault's device key, creating + persisting one when missing. */
export async function getOrCreateDeviceKey(vaultId: string): Promise<DeviceKeyRecord> {
  const existing = await getDeviceKey(vaultId);
  if (existing) return existing;
  const record: DeviceKeyRecord = {
    device_id: newDeviceId(),
    key: await generateDeviceKey(),
    key_version: 1,
    created_at: new Date().toISOString(),
  };
  await putRecord(KEY_STORE, vaultId, record);
  return record;
}

/** This vault's locally stored device-wrapped vault-key envelope, or null. */
export async function getDeviceEnvelope(vaultId: string): Promise<DeviceEnvelopeRecord | null> {
  const rec = await getRecord<unknown>(ENVELOPE_STORE, vaultId);
  return rec && isEnvelopeRecord(rec) ? rec : null;
}

/** Stores this vault's device envelope locally (never sent to the server). */
export async function saveDeviceEnvelope(
  vaultId: string,
  record: Omit<DeviceEnvelopeRecord, "updated_at">,
): Promise<void> {
  await putRecord(ENVELOPE_STORE, vaultId, { ...record, updated_at: new Date().toISOString() });
}

/** Deletes only this vault's device key + envelope; others are untouched. */
export async function deleteDeviceRecords(vaultId: string): Promise<void> {
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction([KEY_STORE, ENVELOPE_STORE], "readwrite");
      tx.objectStore(KEY_STORE).delete(recordKeyForVault(vaultId));
      tx.objectStore(ENVELOPE_STORE).delete(recordKeyForVault(vaultId));
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
}
