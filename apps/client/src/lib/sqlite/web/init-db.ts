import { initWorker } from './sqlite-worker';
import { up } from './migrations';
import { setDb, resetDb, peekDbId } from './db';
import { upsertVaultId } from './services/client-state-service';


/**
 * Per-vault OPFS databases: isolation is enforced at the storage layer, so a
 * pending intent from another vault is physically unreachable. The vault id is
 * validated before embedding it in a filename.
 */
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function initSQLite(vaultId: string): Promise<void> {
  if (!UUID_PATTERN.test(vaultId)) {
    throw new Error("Refusing to open SQLite without a valid vault id");
  }

  // The sqlite-wasm worker holds at most one open database handle at a time
  // here; make sure any previously-opened vault's file is released before
  // opening this one so handles never straddle vaults.
  await closeSQLite();

  const promiser = await initWorker();

  const config = await promiser('config-get', {});
  console.log('SQLite version:', config.result.version.libVersion);

  const openResponse = await promiser('open', {
    filename: `file:voult-${vaultId}.db?vfs=opfs`,
  });

  setDb(openResponse.dbId, vaultId);
  console.log('Database opened:', openResponse.result.filename);

  const result = await up();
  await upsertVaultId(vaultId);
  console.log('Migrations applied:', result.result, result.rows);
}

/** Closes the currently-open per-vault database (no-op if none is open). */
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
    // next vault writing through a stale id.
    resetDb();
  }
}
