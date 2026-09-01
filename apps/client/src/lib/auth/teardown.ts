import { QueryClient } from "@tanstack/react-query";
import { useAppStore, clearSessionState } from "../state";
import { closeSQLite } from "../sqlite/web/init-db";
import { deleteDeviceKey } from "../crypto/device-key";

/**
 * Central teardown path for server-forced session expiry (401
 * SESSION_REQUIRED). Ordering matters:
 *
 * 1. Capture the vault id BEFORE any state is wiped.
 * 2. Close this vault's SQLite database so no further intent/state writes can
 *    land after teardown begins — pending intents stay durable on that vault's
 *    own OPFS file for its next unlock.
 * 3. Delete only this vault's device key + envelope records for the expired
 *    session; other vaults' records in the same browser profile are untouched.
 * 4. Wipe volatile session state and (when available) the query cache.
 *
 * There is no explicit logout action — authenticated states are locked /
 * unlocked, and unauthenticated is reached only via session expiry or removal.
 */
export async function teardownVaultSession(queryClient?: QueryClient) {
  const vaultId = useAppStore.getState().session?.vaultId ?? null;

  await closeSQLite();
  if (vaultId) {
    try {
      await deleteDeviceKey(vaultId);
    } catch (e) {
      console.error("Failed to delete device secrets on session expiry", e);
    }
  }

  clearSessionState();
  queryClient?.clear();
}

/**
 * Storage release for LOCK (not logout): close this vault's database so the
 * handle can't be used while keys are wiped. Intents remain durable on disk
 * and keep a valid base_version for unlock; the device key/envelope are kept
 * so reload can auto-restore.
 */
export async function lockVaultStorage() {
  await closeSQLite();
}
