import { useEffect, useRef } from "react";
import { router } from "expo-router";
import type { QueryClient } from "@tanstack/react-query";
import { fetchSession } from "../queries/session/query";
import { isNetworkError, isSessionRequired } from "../queries/http";
import { teardownVaultSession, abandonVaultSelection, lockVaultStorage as closeVaultDb } from "../auth/teardown";
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
 * Cross-surface session sync for the web app.
 *
 * No interval poller by design: the check runs on window focus, tab
 * visibility, and network reconnect (check-on-use), plus instantly on
 * same-origin BroadcastChannel events from other tabs. The extension cannot
 * see this channel (different origin), so web ↔ extension convergence always
 * flows through the server `lock_epoch` counter:
 *
 * - `POST /lock` (a deliberate manual lock on either surface) bumps the epoch.
 *   Timed/idle locks never publish, because web and extension have independent
 *   timeouts; otherwise the shorter timer would effectively govern both.
 * - Our next check observes `lock_epoch > lockEpoch` and wipes local keys.
 * - Unlock is per-device and never propagates: each side re-unwraps locally.
 *
 * Rules applied on every successful GET /session:
 * - 401 SESSION_REQUIRED → mark server access missing. An unlocked vault stays
 *   unlocked (local use continues, sync pauses); a locked vault stays locked
 *   with its real lock reason. Selection and device envelope survive. This is
 *   NOT a lock and must never be broadcast as one.
 * - transport error → leave everything untouched. A network outage is not
 *   evidence that the cookie is invalid.
 * - `vault_id` mismatch → another surface switched vaults → abandon this
 *   selection and land at the chooser; the new vault is adopted locked on its
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
      queryClient?.removeQueries({ queryKey: ["cloud"] });
      await closeVaultDb();
      postSessionEvent("locked", vaultId, epoch);
      router.replace("/lock" as any);
    };

    /**
     * A definitive 401, not a lock.
     *
     * An unlocked vault keeps its key and plaintext: the cookie authorizes
     * server calls, it does not own local access. Only a vault that is already
     * locked goes back to `/lock`; an unlocked one stays where it is and simply
     * loses sync until the user reauthenticates.
     */
    const applySessionLost = async () => {
      const { vault } = useAppStore.getState();
      if (vault.status === "no_vault") return;
      const wasUnlocked = vault.status === "unlocked";
      await teardownVaultSession(queryClient);
      // Deliberately no `postSessionEvent("locked", ...)`: announcing a lock
      // would make peers wipe keys for a decision the user never made.
      if (!wasUnlocked) router.replace("/lock" as any);
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
        // (peer logged in elsewhere). Abandon our selection and its keys; the
        // other vault is adopted locked on its next unlock, never here.
        if (remote.vault_id !== current.session.vaultId) {
          const leftVaultId = current.session.vaultId;
          await abandonVaultSelection(queryClient);
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
