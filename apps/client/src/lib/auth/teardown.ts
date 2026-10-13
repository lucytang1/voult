import { QueryClient } from "@tanstack/react-query";
import { useAppStore, loseServerSession, clearSessionState } from "../state";
import { closeSQLite } from "../sqlite/web/init-db";
import { deleteDeviceKey } from "../crypto/device-key";

/**
 * Central teardown path for server-forced session expiry (401
 * SESSION_REQUIRED). Ordering matters:
 *
 * 1. Close this vault's SQLite database so no further intent/state writes can
 *    land after teardown begins — pending intents stay durable on that vault's
 *    own OPFS file for its next unlock.
 * 2. Wipe keys/plaintext and mark the server session missing, **retaining the
 *    vault selection** (see `loseServerSession`).
 * 3. Drop the ciphertext query cache so no decrypted or encrypted vault body
 *    outlives the session.
 *
 * M2 behaviour change — the device key and envelope are NO LONGER deleted.
 *
 * Previously this path called `deleteDeviceKey(vaultId)`, on the theory that a
 * dead session should not leave unlock material behind. That conflated the
 * cookie with the device: the cookie is the server's authorization to talk to
 * it, while the device key is a *local* secret that the user never chose to
 * per-session. Deleting it meant an expired cookie silently downgraded the
 * vault from "unlock with one tap" to "type your master password", every time,
 * for no security gain — the material is useless without the master password,
 * and it is namespaced per-vault so it cannot leak across vaults.
 *
 * Retaining it is safe *because* it is paired with a password-gated re-auth:
 * the lock screen re-establishes the session via `reauthenticateVaultSession`
 * (the existing verifier flow, never the password itself) and only then can the
 * key be used for anything. What we must not do is device-unlock silently on
 * session loss and then assume protected API access exists — the password path
 * is what re-establishes that, and it is explicit.
 *
 * A real sign-out (clearing app data, or the user revoking this device) still
 * deletes the device material; that is `clearSessionState`'s caller's job, not
 * this path's.
 */
export async function teardownVaultSession(queryClient?: QueryClient) {
  await closeSQLite();
  loseServerSession();
  queryClient?.clear();
  console.info("Server session expired; vault stays selected and locked");
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
