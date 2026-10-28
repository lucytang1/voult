import { QueryClientProvider } from '@tanstack/react-query';
import { Slot } from "expo-router";
import "../../global.css";
import { initSQLite } from "../lib/sqlite/web/init-db";
import { useSessionSync } from "../lib/sync/use-session-sync";
import { StrictMode, useEffect, useRef, useState } from "react";
import {
  selectVaultSession,
  commitVaultUnlock,
  updateDecryptedVault,
  updateLockEpoch,
  updateVaultVersion,
  readLockRecordForSelection,
  markServerSessionUnknown,
} from "../lib/state";
import { BootSplash } from "../lib/components/boot-splash";
import { selectedVaultId } from "../lib/state/vault-state";
import { readLastActivity, migrateLockPolicy, readSelectedVaultId } from "../lib/state/selection-store";
import { getWebAutolockMinutes } from "../lib/settings";
import { decideRestore } from "../lib/state/vault-state";
import { unlockWithDevice } from "../lib/auth/flows";
import { getDeviceKey, getDeviceEnvelope } from "../lib/crypto/device-key";
import { useAutolock } from "../lib/auth/use-autolock";
import { fetchSession } from "../lib/queries/session/query";
import { isSessionRequired } from "../lib/queries/http";
import { queryClient } from "../lib/queries/client";
import { router } from 'expo-router';

/**
 * Bootstrap.
 *
 * The organizing idea: the *persisted selection* decides which vault this is,
 * the *lock policy* decides whether local access may be restored, and the
 * *cookie* only decides what we are allowed to call. They are separate facts.
 *
 *   1. No persisted selection      -> landing (`/`). Nothing to restore.
 *   2. Selection + policy allows   -> device unlock when a cookie lets us fetch
 *                                     the vault; if the cookie is missing or the
 *                                     server is unreachable, stay on that vault's
 *                                     lock screen and preserve device material.
 *   3. Selection + policy holds    -> stay on that vault's lock screen for an
 *                                     explicit unlock.
 *
 * A missing cookie never erases the selection and never rewrites the lock
 * record: an expired session is an authorization fact, not a user lock.
 *
 * SQLite stays closed throughout — it opens only for a vault we actually hold a
 * key for, and the lock screen reopens it after a successful unlock.
 *
 * Nothing renders while this decides: the splash holds the routes until the
 * destination above has been committed, so a reload cannot paint the landing
 * first and then redirect.
 */
export default function RootLayout() {
  // Cross-surface consistency: check-on-use session sync (focus/visible) +
  // same-origin BroadcastChannel. No interval poller — the extension converges
  // via its own popup-open / pre-fill / alarm-tick checks (see plan).
  useSessionSync(queryClient);
  useAutolock();

  // Startup gate: the routes stay unmounted until the bootstrap below has
  // committed its destination. Local state, not the store, on purpose — the
  // store is app data (and is re-created by Fast Refresh when its module
  // changes), while this is a one-shot lifecycle fact about this mount.
  const [bootReady, setBootReady] = useState(false);

  // React's StrictMode mounts, tears down, and remounts every component once in
  // development, which double-invokes effects. The bootstrap below must not run
  // twice: it can call `initSQLite`, which closes the current OPFS handle before
  // opening the next one, so two interleaved runs can leave a leaked handle and a
  // stale `dbId`. A ref survives the simulated remount (the component instance is
  // the same), so it is the correct guard — a module-level flag would also
  // suppress a genuine re-bootstrap after a real remount.
  const bootstrapped = useRef(false);

  useEffect(() => {
    if (bootstrapped.current) return;
    bootstrapped.current = true;
    const bootstrap = async () => {
      try {
        // Skip auto-restore while handling the provider-neutral OAuth callback —
        // the vault chooser at /vault handles that UX.
        if (typeof window !== "undefined" && window.location.search.includes("cloud_state")) {
          return;
        }

        // An explicit recovery link wins over every restore rule below.
        // `?recover=<vault_id>` is how a stranded user (or the extension) reaches
        // the recovery screen: it must not be bounced to /lock or /home by the
        // bootstrap, because those screens assume a working password path.
        if (typeof window !== "undefined") {
          const recoverTarget = new URLSearchParams(window.location.search).get("recover");
          if (recoverTarget) {
            console.info("Bootstrap: explicit recovery link, skipping auto-restore");
            router.navigate(`/recover?recover=${encodeURIComponent(recoverTarget)}` as any);
            return;
          }
        }

        // One-time: drop legacy `peer` records created by the build that
        // published idle locks as global (see selection-store).
        migrateLockPolicy();

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
        // decide whether a vault is selected, and it cannot decide whether the
        // user's lock policy permits a restore.
        let sessionData: Awaited<ReturnType<typeof fetchSession>> | null = null;
        let sessionMissing = false;
        let transportFailed = false;
        try {
          sessionData = await fetchSession();
        } catch (e) {
          if (isSessionRequired(e)) sessionMissing = true;
          else transportFailed = true;
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

        // The lock decision is about *local* access and the user's timer, so it
        // is computed before considering the cookie. A dead cookie can only
        // stop the fetch that a device unlock needs; it is not itself a lock
        // reason and must not rewrite the persisted record.
        const autolockMinutes = getWebAutolockMinutes();
        const lockRecord = readLockRecordForSelection(persistedVaultId);
        const lastActivityAt = readLastActivity(persistedVaultId);
        // A silent restore needs BOTH halves of the local device material: the
        // non-extractable device key *and* the envelope it wrapped the vault key
        // into. A key with no envelope (an origin that has only ever been opened
        // with the master password) has nothing to unwrap, so it must not make
        // the policy promise a restore it cannot perform.
        const deviceKey = await getDeviceKey(persistedVaultId).catch(() => null);
        const deviceEnvelope = deviceKey
          ? await getDeviceEnvelope(persistedVaultId).catch(() => null)
          : null;
        const hasDeviceMaterial = !!(
          deviceKey &&
          deviceEnvelope &&
          deviceEnvelope.device_id === deviceKey.device_id
        );
        const decision = decideRestore({
          selectedVaultId: persistedVaultId,
          record: lockRecord,
          autolockMinutes,
          hasDeviceMaterial,
          lastActivityAt,
        });
        // Non-secret diagnostics: the exact inputs and outcome of the restore
        // policy. This is the first thing to check when a vault "unexpectedly"
        // opens locked (timer elapsed vs. a genuine manual/peer lock).
        console.info("Restore decision", {
          outcome: decision.kind,
          reason: decision.kind === "stay_locked" ? decision.reason : undefined,
          autolockMinutes,
          idleMs: lastActivityAt === null ? null : Date.now() - lastActivityAt,
          lockRecord: lockRecord ? { reason: lockRecord.reason, lockedAt: lockRecord.lockedAt } : null,
          hasDeviceMaterial,
          serverSession: sessionData ? "active" : sessionMissing ? "missing" : "unreachable",
        });

        if (decision.kind === "device_unlock") {
          if (!sessionData) {
            // Policy allows a restore, but fetching the vault needs a valid
            // cookie. Keep the selection and device material; the lock screen
            // asks for the master password (reauthentication), and does not
            // pretend the vault was locked or the device lost.
            console.info(
              sessionMissing
                ? "Vault may restore but the server session is missing; password required"
                : "Vault may restore but the server is unreachable",
            );
          } else {
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
        } else if (decision.kind === "stay_locked") {
          console.info(`Restart stays locked (${decision.reason})`);
        }

        // Restore the selection for /lock. No key installed, no DB opened.
        selectVaultSession(
          {
            vaultId: persistedVaultId,
            cryptoVersion: sessionData?.crypto_version ?? 0,
          },
          {
            serverSession: sessionData ? "active" : sessionMissing ? "missing" : "unknown",
          },
        );
        if (sessionData) updateLockEpoch(sessionData.lock_epoch ?? 0);
        if (transportFailed) markServerSessionUnknown();
        router.navigate("/lock" as any);
      } catch (e) {
        console.error("Bootstrap error", e);
      } finally {
        // Hand the app to the router only now. Every branch above has already
        // committed its route, and a thrown error still releases the gate so
        // the router guard — not a permanently spinning splash — owns recovery.
        setBootReady(true);
      }
    };
    bootstrap();
  }, []);

  // Hold the routes until the bootstrap has decided. Rendering `Slot` earlier
  // is what made a reload paint the landing at `/` for a moment before the
  // redirect; the store's initial `no_vault` was never the answer, just the
  // absence of one. This also makes the prerendered HTML a splash rather than a
  // route's markup (see `web.output: "static"` in app.json).
  if (!bootReady) {
    return (
      <StrictMode>
        <BootSplash />
      </StrictMode>
    );
  }

  return (
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <Slot />
      </QueryClientProvider>
    </StrictMode>
  );
}