import { useEffect, useRef } from "react";
import { router } from "expo-router";
import type { QueryClient } from "@tanstack/react-query";
import { fetchSession } from "../queries/session/query";
import { isNetworkError, isSessionRequired } from "../queries/http";
import { teardownVaultSession, lockVaultStorage as closeVaultDb } from "../auth/teardown";
import {
  lockVaultStorage as lockVaultKeys,
  markServerSessionActive,
  markServerSessionUnknown,
  updateLockEpoch,
  useAppStore,
} from "../state";
import {
  postSessionEvent,
  subscribeSessionEvents,
  type SessionBroadcast,
} from "./session-channel";

/**
 * Cross-surface session sync for the web app (M1/M2 of
 * plans/session-consistency.md).
 *
 * No interval poller by design: the check runs on window focus, tab
 * visibility, and network reconnect (check-on-use), plus instantly on
 * same-origin BroadcastChannel events from other tabs. The extension cannot
 * see this channel (different origin), so web ↔ extension convergence always
 * flows through the server `lock_epoch` counter:
 *
 * - `POST /lock` (our own lock, or the extension's) bumps the epoch.
 * - Our next check observes `lock_epoch > lockEpoch` and wipes local keys.
 * - Unlock is per-device and never propagates: each side re-unwraps locally.
 *
 * Rules applied on every successful GET /session:
 * - 401 SESSION_REQUIRED → wipe keys/plaintext, close this vault's DB, mark the
 *   server session missing — but keep the vault *selected* and route to /lock
 *   for it. The selection and local device envelope survive; the master
 *   password re-authenticates (see `reauthenticateAndUnlock`). This is the M2
 *   change from routing to `/` and deleting the device key.
 * - transport error → mark the session unknown, change nothing else. A network
 *   outage is not evidence that the cookie is invalid.
 * - `vault_id` mismatch → another surface switched vaults → teardown the old
 *   vault and land with no selection; the new vault is adopted locked on its
 *   next unlock, never auto-unlocked.
 * - epoch bump → lock now (wipe keys, close this vault's DB, drop ciphertext
 *   cache, route to /lock). Unknown local epoch (null) adopts without wiping.
 */
export function useSessionSync(queryClient?: QueryClient) {
  const inFlight = useRef(false);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const applyPeerLock = async (vaultId: string, epoch: number) => {
      const { session, lockEpoch } = useAppStore.getState();
      if (!session || session.vaultId !== vaultId) return;
      if (lockEpoch !== null && epoch <= lockEpoch) return;
      updateLockEpoch(epoch);
      // Already locked: epoch converged, nothing secret left to wipe.
      if (useAppStore.getState().vault.status !== "unlocked") return;
      lockVaultKeys(null, "peer");
      queryClient?.removeQueries({ queryKey: ["vault"] });
      queryClient?.removeQueries({ queryKey: ["favicon", vaultId] });
      queryClient?.removeQueries({ queryKey: ["cloud"] });
      await closeVaultDb();
      postSessionEvent("locked", vaultId, epoch);
      router.replace("/lock" as any);
    };

    /**
     * M2: the session is gone, but the vault selection is not.
     *
     * This used to tear everything down and route to `/`, which made an expired
     * cookie indistinguishable from a fresh install — the user lost their place
     * in the app and had to rediscover their vault. Now teardown keeps the
     * selection, and we route to `/lock` for *this* vault, where the master
     * password re-establishes the session.
     */
    const applySessionLost = async () => {
      const { vault } = useAppStore.getState();
      if (vault.status === "no_vault") return;
      await teardownVaultSession(queryClient);
      postSessionEvent("locked", null, null);
      router.replace("/lock" as any);
    };

    const checkSession = async () => {
      const local = useAppStore.getState();
      if (!local.session) return;
      if (inFlight.current) return;
      inFlight.current = true;
      try {
        const remote = await fetchSession();
        const current = useAppStore.getState();
        if (!current.session) return;
        markServerSessionActive();

        // Single-vault invariant: the cookie now names a different vault
        // (peer logged in elsewhere). Tear down ours; adopt nothing.
        if (remote.vault_id !== current.session.vaultId) {
          const leftVaultId = current.session.vaultId;
          await teardownVaultSession(queryClient);
          postSessionEvent("vault-switch", leftVaultId, current.lockEpoch);
          router.replace("/" as any);
          return;
        }

        const epoch = remote.lock_epoch ?? 0;
        if (current.lockEpoch === null) {
          updateLockEpoch(epoch);
          return;
        }
        if (epoch > current.lockEpoch) {
          await applyPeerLock(current.session.vaultId, epoch);
        }
      } catch (e) {
        if (isSessionRequired(e)) {
          await applySessionLost();
        } else if (isNetworkError(e)) {
          // Offline is a normal state for the intent queue, and it says nothing
          // about whether the cookie is valid. Record it as unknown rather than
          // missing so no teardown is triggered on a failed request.
          markServerSessionUnknown();
        }
        // Other errors (e.g. 404) leave state untouched; the lock screen's
        // unlock attempt surfaces them.
      } finally {
        inFlight.current = false;
      }
    };

    const onBroadcast = (event: SessionBroadcast) => {
      switch (event.type) {
        case "locked":
          if (event.vaultId && event.lockEpoch !== null) {
            void applyPeerLock(event.vaultId, event.lockEpoch);
          } else {
            void checkSession();
          }
          break;
        case "logged-out":
          void applySessionLost();
          break;
        case "vault-switch":
          // Authoritative re-check: the cookie is the source of truth.
          void checkSession();
          break;
      }
    };

    const onFocus = () => void checkSession();
    const onVisible = () => {
      if (document.visibilityState === "visible") void checkSession();
    };
    const onOnline = () => void checkSession();

    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("online", onOnline);
    const unsubscribe = subscribeSessionEvents(onBroadcast);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("online", onOnline);
      unsubscribe();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}
