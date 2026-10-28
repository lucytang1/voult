/**
 * The one IndexedDB database this browser uses for vault-adjacent local state.
 *
 * Why a shared opener instead of each module calling `indexedDB.open` itself:
 * IndexedDB upgrades are driven by a single global version number, and every
 * connection has to declare the same version. Two modules bumping that number
 * independently would silently race — whichever opened first would win, and the
 * other would fail with `VersionError`. One opener, one upgrade path, one place
 * to add a store.
 *
 * Nothing here is key material for the vault: the device key lives in
 * `device_key` (non-extractable, per vault) and the icon cache in `favicons`
 * (display bytes only). Both are namespaced per vault by their record keys.
 */
export const VOULT_DB_NAME = "voult";

/**
 * Bump only when a store or index changes. v3 added `favicons` (an index on
 * `vault_id` for per-vault purge).
 */
export const VOULT_DB_VERSION = 3;

/** Non-extractable AES-GCM device key, keyed `vault:<vaultId>`. */
export const DEVICE_KEY_STORE = "device_key";
/** Device-wrapped vault-key envelope, keyed `vault:<vaultId>`. */
export const DEVICE_ENVELOPE_STORE = "device_envelope";
/** Cached site icons, keyed `<vaultId>\n<iconUrl>`, indexed by `vault_id`. */
export const FAVICON_STORE = "favicons";
/** Index used to delete every icon belonging to one vault in a single pass. */
export const FAVICON_VAULT_INDEX = "vault_id";

export function hasIndexedDb(): boolean {
  return typeof indexedDB !== "undefined";
}

/**
 * Opens (and if necessary upgrades) the shared database. Callers close the
 * handle they get back — these are short-lived transactions, not long-lived
 * connections, so no handle is left open while the vault is locked.
 */
export function openVaultDb(): Promise<IDBDatabase> {
  if (!hasIndexedDb()) {
    return Promise.reject(new Error("IndexedDB is not available in this environment."));
  }
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(VOULT_DB_NAME, VOULT_DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      // Idempotent creation: a fresh profile creates everything, an existing
      // profile only gets the stores it is missing (v2 -> v3 adds `favicons`).
      if (!db.objectStoreNames.contains(DEVICE_KEY_STORE)) {
        db.createObjectStore(DEVICE_KEY_STORE);
      }
      if (!db.objectStoreNames.contains(DEVICE_ENVELOPE_STORE)) {
        db.createObjectStore(DEVICE_ENVELOPE_STORE);
      }
      if (!db.objectStoreNames.contains(FAVICON_STORE)) {
        const store = db.createObjectStore(FAVICON_STORE);
        store.createIndex(FAVICON_VAULT_INDEX, "vault_id", { unique: false });
      } else {
        // A profile that somehow has the store without its index (an older
        // build of this file) still gets the purge path working.
        const store = request.transaction?.objectStore(FAVICON_STORE);
        if (store && !store.indexNames.contains(FAVICON_VAULT_INDEX)) {
          store.createIndex(FAVICON_VAULT_INDEX, "vault_id", { unique: false });
        }
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () =>
      reject(new Error("IndexedDB upgrade blocked by another open connection."));
  });
}
