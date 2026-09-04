import { useEffect, useRef } from "react";
import { router } from "expo-router";
import type { QueryClient } from "@tanstack/react-query";
import { fetchSession } from "../queries/session/query";
import { isSessionRequired } from "../queries/http";
import { teardownVaultSession, lockVaultStorage as closeVaultDb } from "../auth/teardown";
import {
  lockVaultStorage as lockVaultKeys,
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
 * - 401 SESSION_REQUIRED → full scoped teardown (single-vault invariant: a
 *   dead session can never leak one vault's local data into another's).
 * - `vault_id` mismatch → another surface switched vaults → teardown the old
 *   vault and land unauthenticated; the new vault is adopted locked on its
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
      if (useAppStore.getState().isLocked) return;
      lockVaultKeys(null);
      queryClient?.removeQueries({ queryKey: ["vault"] });
      await closeVaultDb();
      postSessionEvent("locked", vaultId, epoch);
      router.replace("/lock" as any);
    };

    const applyLoggedOut = async () => {
      if (!useAppStore.getState().session) return;
      await teardownVaultSession(queryClient);
      router.replace("/" as any);
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
          postSessionEvent("logged-out", null, null);
          await applyLoggedOut();
        }
        // Network errors are ignored: offline is a normal state for the
        // intent queue, and unlock paths stay usable while disconnected.
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
          void applyLoggedOut();
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
