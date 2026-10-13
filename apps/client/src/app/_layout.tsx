import { QueryClientProvider } from '@tanstack/react-query';
import { Slot } from "expo-router";
import "../../global.css";
import { initSQLite } from "../lib/sqlite/web/init-db";
import { useSessionSync } from "../lib/sync/use-session-sync";
import { useEffect } from "react";
import {
  selectVaultSession,
  commitVaultUnlock,
  updateDecryptedVault,
  updateLockEpoch,
  updateVaultVersion,
  readLockRecordForSelection,
  markServerSessionUnknown,
} from "../lib/state";
import { selectedVaultId } from "../lib/state/vault-state";
import { readSelectedVaultId } from "../lib/state/selection-store";
import { getWebAutolockMinutes } from "../lib/settings";
import { decideRestore } from "../lib/state/vault-state";
import { unlockWithDevice } from "../lib/auth/flows";
import { getDeviceKey } from "../lib/crypto/device-key";
import { useAutolock } from "../lib/auth/use-autolock";
import { fetchSession } from "../lib/queries/session/query";
import { queryClient } from "../lib/queries/client";
import { router } from 'expo-router';

/**
 * M2 bootstrap.
 *
 * The organizing idea: the *persisted selection* decides which vault this is,
 * and the *cookie* only decides what we are allowed to call. They are separate
 * facts, so this runs three cases instead of two:
 *
 *   1. No persisted selection      -> landing (`/`). Nothing to restore.
 *   2. Selection + live cookie     -> restore locked, or device-unlock if the
 *                                     lock record permits it.
 *   3. Selection + no/!valid cookie-> stay on *that vault's* lock screen. The
 *                                     user re-authenticates with their master
 *                                     password. We do NOT fall back to landing:
 *                                     an expired cookie must not erase identity.
 *
 * Case 3 is the M2 behaviour change. Before, a missing session returned early
 * and left the user on the landing page looking like a fresh install.
 *
 * SQLite stays closed throughout — it opens only for a vault we actually hold a
 * key for, and the lock screen reopens it after a successful unlock.
 */
export default function RootLayout() {
  // Cross-surface consistency: check-on-use session sync (focus/visible) +
  // same-origin BroadcastChannel. No interval poller — the extension converges
  // via its own popup-open / pre-fill / alarm-tick checks (see plan).
  useSessionSync(queryClient);
  useAutolock();

  useEffect(() => {
    const bootstrap = async () => {
      // Skip auto-restore while handling the provider-neutral OAuth callback —
      // the vault chooser at /vault handles that UX.
      if (typeof window !== "undefined" && window.location.search.includes("cloud_state")) {
        return;
      }

      try {
        // Case 1: nothing was ever selected (fresh profile, or app data removed).
        const persistedVaultId = readSelectedVaultId();
        if (!persistedVaultId) {
          // A cookie may still name a vault if another surface authenticated
          // this browser; adopt it so the user lands on /lock, not /.
          try {
            const sessionData = await fetchSession();
            selectVaultSession({
              vaultId: sessionData.vault_id,
              cryptoVersion: sessionData.crypto_version,
            });
            updateLockEpoch(sessionData.lock_epoch ?? 0);
            router.navigate("/lock" as any);
          } catch {
            console.log("No persisted selection and no session — showing landing");
          }
          return;
        }

        // Probe the cookie. This determines authorization only; it cannot
        // decide whether a vault is selected.
        let sessionData: Awaited<ReturnType<typeof fetchSession>> | null = null;
        let transportFailed = false;
        try {
          sessionData = await fetchSession();
        } catch {
          transportFailed = true;
        }

        // The cookie names a different vault than the one we have selected —
        // another surface switched. Follow the cookie: it is authoritative for
        // which vault this session may address.
        if (sessionData && sessionData.vault_id !== persistedVaultId) {
          console.info(
            `Session names vault ${sessionData.vault_id}, not the selected ${persistedVaultId}; adopting session vault`,
          );
          selectVaultSession({
            vaultId: sessionData.vault_id,
            cryptoVersion: sessionData.crypto_version,
          });
          updateLockEpoch(sessionData.lock_epoch ?? 0);
          router.navigate("/lock" as any);
          return;
        }

        // Case 3: selected, but no usable cookie.
        if (!sessionData) {
          if (transportFailed) {
            // Offline / server down is NOT the same as "your session expired".
            // Mark it unknown rather than missing so the UI can say so, and do
            // not delete anything on the strength of a failed request.
            console.info("Selected vault found but server unreachable; staying locked");
          }
          // Re-establish the selection locally so /lock renders for this vault.
          // serverSession stays "unknown"; the 401 interceptor will mark it
          // "missing" if a real SESSION_REQUIRED arrives.
          selectVaultSession({
            vaultId: persistedVaultId,
            cryptoVersion: 0,
          });
          if (transportFailed) markServerSessionUnknown();
          router.navigate("/lock" as any);
          return;
        }

        // Case 2: selection + live cookie.
        const lockRecord = readLockRecordForSelection();
        const hasDeviceKey = !!(await getDeviceKey(persistedVaultId).catch(() => null));
        const decision = decideRestore({
          selectedVaultId: persistedVaultId,
          record: lockRecord,
          autolockMinutes: getWebAutolockMinutes(),
          hasDeviceKey,
        });

        if (decision.kind === "device_unlock") {
          try {
            const unlocked = await unlockWithDevice();
            if (unlocked) {
              selectVaultSession(unlocked.session);
              commitVaultUnlock(unlocked.vaultKey);
              updateLockEpoch(unlocked.lockEpoch);
              updateDecryptedVault(unlocked.decryptedVault);
              updateVaultVersion(unlocked.version);
              await initSQLite(unlocked.session.vaultId);
              router.navigate("/home" as any);
              return;
            }
          } catch (e) {
            console.log("Device unlock failed, falling back to password unlock", e);
          }
        }

        // Restore the selection for /lock. No key installed, no DB opened.
        selectVaultSession({
          vaultId: sessionData.vault_id,
          cryptoVersion: sessionData.crypto_version,
        });
        updateLockEpoch(sessionData.lock_epoch ?? 0);
        router.navigate("/lock" as any);
      } catch (e) {
        console.error("Bootstrap error", e);
      }
    };
    bootstrap();
  }, []);

  return (
    <QueryClientProvider client={queryClient}>
      <Slot />
    </QueryClientProvider>
  );
}