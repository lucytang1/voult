/**
 * Handle for the currently-open per-user OPFS database.
 *
 * Each authenticated account gets its own SQLite file (see init-db.ts), so the
 * handle is always paired with the user id it was opened for. `sql()` fails
 * closed when no database is open — callers must not be able to write intents
 * into an account-agnostic store.
 */
let dbId: string | null = null;
let currentUserId: string | null = null;

export function setDb(id: string, userId: string) {
  dbId = id;
  currentUserId = userId;
}

/** Returns the open handle's id without throwing (used by closeSQLite). */
export function peekDbId(): string | null {
  return dbId;
}

export function getDbId() {
  if (!dbId) throw new Error("DB not initialized");
  return dbId;
}

export function getCurrentUserId() {
  if (!currentUserId) throw new Error("DB not initialized");
  return currentUserId;
}

export function resetDb() {
  dbId = null;
  currentUserId = null;
}
