import { initWorker } from './sqlite-worker';
import { up } from './migrations';
import { setDb, resetDb, peekDbId } from './db';

/**
 * Per-user OPFS databases: isolation is enforced at the storage layer, so a
 * pending intent from account A is physically unreachable while account B is
 * signed in. User ids are server-issued UUIDs; validate before embedding one
 * in a filename.
 */
const USER_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function initSQLite(userId: string): Promise<void> {
  if (!USER_ID_PATTERN.test(userId)) {
    throw new Error("Refusing to open per-user SQLite without a valid user id");
  }

  // The sqlite-wasm worker holds at most one open database handle at a time
  // here; make sure any previously-opened account's file is released before
  // opening this one so handles never straddle accounts.
  await closeSQLite();

  const promiser = await initWorker();

  const config = await promiser('config-get', {});
  console.log('SQLite version:', config.result.version.libVersion);

  const openResponse = await promiser('open', {
    filename: `file:voult-${userId}.db?vfs=opfs`,
  });

  setDb(openResponse.dbId, userId);
  console.log('Database opened:', openResponse.result.filename);

  const result = await up();
  console.log('Migrations applied:', result.result, result.rows);
}

/** Closes the currently-open per-user database (no-op if none is open). */
export async function closeSQLite(): Promise<void> {
  const dbId = peekDbId();
  if (!dbId) return;
  try {
    const promiser = await initWorker();
    await promiser('close', { dbId });
  } catch (e) {
    console.warn("Failed to close SQLite database cleanly", e);
  } finally {
    // Always drop the handle reference — a failed close must not leave the
    // next account writing through a stale id.
    resetDb();
  }
}
