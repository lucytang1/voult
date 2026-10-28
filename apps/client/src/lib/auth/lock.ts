import { router } from "expo-router";
import type { QueryClient } from "@tanstack/react-query";
import {
  lockVaultStorage as lockVaultKeys,
  setLockMetadata,
  updateLockEpoch,
  useAppStore,
} from "../state";
import type { LockMetadata } from "../state/type";
import { lockVaultStorage as closeVaultDb } from "./teardown";
import { postLock } from "../queries/session/query";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import type { SaltResponse } from "../queries/cryptoParams/api.schema";
import type { VaultResponse } from "../queries/vault/api.schema";
import { postSessionEvent } from "../sync/session-channel";
import { describeAutolock, getWebAutolockMinutes } from "../settings";

/** The password-wrapped envelope fields we capture so /lock needs no round-trip. */
interface WrappedVaultKeyEnvelope {
  vault_key_wrap?: string | null;
  vault_key_wrap_iv?: string | null;
}

export interface LockOptions {
  /**
   * The shared query client. Optional so callers outside a QueryClientProvider
   * (the root layout) can still lock; pass it to also purge ciphertext caches.
   */
  queryClient?: QueryClient | null;
  /**
   * Current vault metadata, when the caller already has it. When omitted we
   * read it from the ["vault"] query cache before wiping it.
   */
  vault?: WrappedVaultKeyEnvelope | null;
  /** Why we are locking — drives the persisted lock reason and log line. */
  reason: "manual" | "idle";
}

/**
 * The single lock path for the web app, shared by the "Lock Voult" button and
 * the autolock watchdog so both produce identical state.
 *
 * **Local first, network second.** The vault is locked in memory before any
 * request is attempted; the `/lock` peer signal is only for a *deliberate*
 * (manual) lock. An offline or failing server must never leave this vault
 * visibly open.
 *
 * Timed/idle locks deliberately do NOT publish: web and extension have separate
 * timers, so one surface's idle timeout must not force the other to lock (and,
 * worse, record a `peer` lock that holds across restarts). Each surface
 * enforces its own deadline; only an explicit lock is global.
 *
 * Order:
 *
 *  1. Read the password-wrapped envelope out of the query cache while it still
 *     exists (non-secret server metadata, needed to re-derive the key locally).
 *  2. Wipe the key/plaintext, persist the lock reason, drop ciphertext caches,
 *     close this vault's SQLite handle, and route to the lock screen. Nothing
 *     here awaits the network.
 *  3. Best-effort: cache salt/iterations + envelope so the next password unlock
 *     needs no round-trip. If this fails, unlock falls back to fetching them
 *     through the still-valid session.
 *  4. For a manual lock only: `POST /lock` bumps the server `lock_epoch` so
 *     peers lock on their next check, and a same-origin BroadcastChannel event
 *     reaches other tabs immediately. Failure only delays peers.
 */
export async function lockVaultNow(options: LockOptions): Promise<void> {
  const { queryClient, reason } = options;
  const { session, vault } = useAppStore.getState();
  if (!session) return;
  // Already locked: nothing secret is left in memory and the epoch is
  // converged. Re-locking would only bump the epoch for no reason.
  if (vault.status !== "unlocked") return;

  const vaultId = session.vaultId;

  // The ["vault"] cache holds VaultResponse, so the envelope lives under .vault.
  const envelope =
    options.vault ??
    ((queryClient?.getQueriesData<VaultResponse>({ queryKey: ["vault"] })[0]?.[1]
      ?.vault as WrappedVaultKeyEnvelope | undefined) ?? null);
  // Crypto params are usually cached by the lock screen / home already.
  const cachedParams =
    queryClient?.getQueriesData<SaltResponse>({ queryKey: ["cryptoParams", vaultId] })[0]?.[1] ??
    null;

  // 1. Lock locally. No await before the wipe except closing the DB handle.
  lockVaultKeys(null, reason === "idle" ? "autolock" : "manual");
  queryClient?.removeQueries({ queryKey: ["vault"] });
  queryClient?.removeQueries({ queryKey: ["cloud"] });
  await closeVaultDb();
  router.replace("/lock" as any);

  // 2. Capture unlock metadata, but only if we are still on this locked vault.
  // A fast unlock/switch in between must not have stale metadata installed.
  try {
    const params = cachedParams ?? (await fetchCryptoParams(vaultId));
    const current = useAppStore.getState();
    if (
      envelope?.vault_key_wrap &&
      envelope?.vault_key_wrap_iv &&
      current.vault.status === "locked" &&
      current.vault.vaultId === vaultId
    ) {
      const metadata: LockMetadata = {
        salt: params.salt,
        iterations: params.iterations,
        vaultKeyWrap: envelope.vault_key_wrap,
        vaultKeyWrapIv: envelope.vault_key_wrap_iv,
      };
      setLockMetadata(metadata);
    }
  } catch (e) {
    // Non-fatal: unlock will fall back to fetching these via the session.
    console.warn("Failed to capture lock metadata", e);
  }

  // 3. Publish only a deliberate lock — peers converge on their next check.
  // An idle/timer lock is this surface's own decision (the surfaces have
  // separate timeouts) and must not force the other into a `peer` lock.
  if (reason === "manual") {
    try {
      const { lock_epoch } = await postLock();
      updateLockEpoch(lock_epoch);
      postSessionEvent("locked", vaultId, lock_epoch);
    } catch (e) {
      console.warn("Failed to publish lock, locked locally only", e);
    }
  } else {
    // Same-origin tabs share the activity timestamp and evaluate the same
    // deadline independently, so an idle lock needs no broadcast either.
    console.info("Auto-lock is local to this surface; peers are not notified");
  }

  console.info(
    reason === "idle"
      ? `Vault auto-locked after ${describeAutolock(getWebAutolockMinutes())} of inactivity`
      : "Vault locked manually",
  );
}
