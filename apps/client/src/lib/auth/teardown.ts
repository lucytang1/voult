import { QueryClient } from "@tanstack/react-query";
import { useAppStore, loseServerSession, clearSessionState } from "../state";
import { closeSQLite } from "../sqlite/web/init-db";
import { deleteDeviceKey } from "../crypto/device-key";
import { deleteVaultFavicons, forgetVaultFavicons } from "../favicon";

/**
 * Central handler for a server-forced session expiry (401 SESSION_REQUIRED).
 *
 * A dead cookie is an authorization fact, not a lock. The vault key and
 * plaintext live only in this device's memory; they are not server state and
 * must survive losing access to the server. So:
 *
 * 1. An **unlocked** vault stays unlocked: keys, plaintext, this vault's SQLite
 *    handle, and ciphertext caches are all kept. Only `serverSession` becomes
 *    `missing`, which pauses sync/cloud work until reauthentication.
 * 2. A **locked** vault stays locked and keeps its real lock reason; its SQLite
 *    handle is already closed and its query cache is cleared (nothing to
 *    render). This also drops the now-meaningless session object.
 *
 * The device key and envelope are never deleted here. Deleting them would
 * downgrade every cookie expiry into a mandatory password re-entry for no
 * security gain — the material is useless without the master password and is
 * namespaced per vault.
 *
 * A real sign-out (clearing app data, or the user revoking this device) still
 * deletes the device material; that is `signOutOfVault`'s job.
 */
export async function teardownVaultSession(queryClient?: QueryClient) {
  const { vault } = useAppStore.getState();
  const stillUnlocked = vault.status === "unlocked";

  if (!stillUnlocked) {
    await closeSQLite();
  }
  loseServerSession();
  if (!stillUnlocked) queryClient?.clear();

  console.info(
    stillUnlocked
      ? "Server session expired; vault stays unlocked, server features paused"
      : "Server session expired; vault stays selected and locked",
  );
}

/**
 * Another surface switched this browser's session to a different vault.
 *
 * Unlike `teardownVaultSession`, this really does end local access to the
 * selected vault: the identity in the cookie has changed, so continuing to
 * render vault A's plaintext under a session for vault B is exactly the
 * cross-vault contamination the selection epoch guards against. The device
 * material is kept (the user may switch back), but the selection is cleared and
 * the new vault is adopted locked on its next unlock.
 */
export async function abandonVaultSelection(queryClient?: QueryClient) {
  const { vault } = useAppStore.getState();
  const abandonedVaultId = vault.status === "no_vault" ? null : vault.vaultId;
  await closeSQLite();
  clearSessionState();
  queryClient?.clear();
  // Icons are vault-derived display bytes: dropping the selection must not
  // leave another vault's rows rendering while the new vault loads, but the
  // on-disk records stay (the user may switch back).
  if (abandonedVaultId) forgetVaultFavicons(abandonedVaultId);
  console.info("Selected vault abandoned after a server-side vault switch");
}

/**
 * A real sign-out from this device: deselect the vault, wipe keys/plaintext,
 * close its SQLite handle, drop the query cache, and delete *this vault's*
 * device key + envelope.
 *
 * Distinct from `teardownVaultSession`, which handles a merely-expired cookie
 * and deliberately keeps the device material so the next unlock stays local.
 *
 * There is no routine user-facing logout button — the plan is explicit that
 * switching and creating vaults are the supported ways to change the selected
 * vault. This exists for the cases where the local material must actually go:
 * the user revoking this device, or clearing app data. Callers must be certain
 * the user asked for it, because unlike cookie expiry this is irreversible
 * without the master password.
 */
export async function signOutOfVault(queryClient?: QueryClient, vaultId?: string | null) {
  // Capture before any wipe, and scope the deletion to this vault so other
  // vaults in the same browser profile keep their own device records.
  const state = useAppStore.getState();
  const target = vaultId ?? (state.vault.status === "no_vault" ? null : state.vault.vaultId);

  await closeSQLite();
  if (target) {
    try {
      await deleteDeviceKey(target);
    } catch (e) {
      // Non-fatal: the session and keys are already gone, and a stale device
      // record is inert without the master password. Surface it rather than
      // pretending the device was fully revoked.
      console.error("Failed to delete device secrets during sign-out", e);
    }
    try {
      // Icons are vault-derived display data kept on disk for warm reloads;
      // a deliberate sign-out is the one path that must remove them.
      await deleteVaultFavicons(target);
    } catch (e) {
      console.error("Failed to delete cached icons during sign-out", e);
    }
  }
  clearSessionState();
  queryClient?.clear();
  console.info("Signed out; device unlock material removed for this vault");
}

/**
 * Storage release for LOCK (not sign-out): close this vault's database so the
 * handle can't be used while keys are wiped. Intents remain durable on disk
 * and keep a valid base_version for unlock; the device key/envelope are kept
 * so reload can auto-restore.
 */
export async function lockVaultStorage() {
  await closeSQLite();
}
