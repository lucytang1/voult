/**
 * Handle for the currently-open per-vault OPFS database.
 *
 * Each vault gets its own SQLite file (see init-db.ts), so the handle is
 * always paired with the vault id it was opened for. `sql()` fails closed when
 * no database is open — callers must not be able to write intents into a
 * vault-agnostic store.
 */
let dbId: string | null = null;
let currentVaultId: string | null = null;

export function setDb(id: string, vaultId: string) {
  dbId = id;
  currentVaultId = vaultId;
}

/** Returns the open handle's id without throwing (used by closeSQLite). */
export function peekDbId(): string | null {
  return dbId;
}

export function getDbId() {
  if (!dbId) throw new Error("DB not initialized");
  return dbId;
}

export function getCurrentVaultId() {
  if (!currentVaultId) throw new Error("DB not initialized");
  return currentVaultId;
}

export function resetDb() {
  dbId = null;
  currentVaultId = null;
}
