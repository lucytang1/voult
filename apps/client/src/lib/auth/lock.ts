import { router } from "expo-router";
import type { QueryClient } from "@tanstack/react-query";
import { lockVaultStorage as lockVaultKeys, updateLockEpoch, useAppStore } from "../state";
import type { LockMetadata } from "../state/type";
import { lockVaultStorage as closeVaultDb } from "./teardown";
import { postLock } from "../queries/session/query";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
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
   * read it from the ["vault"] query cache so an idle-triggered lock captures
   * the same unlock metadata as the manual button.
   */
  vault?: WrappedVaultKeyEnvelope | null;
  /** Why we are locking — only used for the log line. */
  reason: "manual" | "idle";
}

/**
 * The single lock path for the web app, shared by the "Lock Voult" button and
 * the autolock watchdog so both produce identical state.
 *
 * Order matters and is deliberate:
 *
 *  1. Capture unlock metadata (salt / iterations / wrapped vault key) *first*,
 *     while the vault is still unlocked, so /lock can re-derive the key
 *     locally. Failure here is non-fatal: unlock falls back to fetching these
 *     from the server via the still-valid session.
 *  2. Publish the lock (POST /lock bumps the server `lock_epoch`, and the
 *     BroadcastChannel tells sibling tabs). Best-effort — an offline lock
 *     still locks this tab and converges later. Note this is a *global* lock:
 *     an idle timeout in the web app also locks the extension, which is the
 *     safe direction for a credential store.
 *  3. Only then wipe: local keys, ciphertext from the query cache, and this
 *     vault's SQLite handle (intents stay durable on its own OPFS file).
 */
export async function lockVaultNow(options: LockOptions): Promise<void> {
  const { queryClient, reason } = options;
  const { session, isLocked } = useAppStore.getState();
  if (!session) return;
  // Already locked: nothing secret is left in memory and the epoch is
  // converged. Re-locking would only bump the epoch for no reason.
  if (isLocked) return;

  // The ["vault"] cache holds VaultResponse, so the envelope lives under .vault.
  // Read it here rather than forcing every caller to thread it through — an
  // idle lock fires with no component holding useGetVault's data.
  const vault =
    options.vault ??
    ((queryClient?.getQueriesData<VaultResponse>({ queryKey: ["vault"] })[0]?.[1]
      ?.vault as WrappedVaultKeyEnvelope | undefined) ?? null);

  let metadata: LockMetadata | null = null;
  try {
    const params = await fetchCryptoParams(session.vaultId);
    if (vault?.vault_key_wrap && vault?.vault_key_wrap_iv) {
      metadata = {
        salt: params.salt,
        iterations: params.iterations,
        vaultKeyWrap: vault.vault_key_wrap,
        vaultKeyWrapIv: vault.vault_key_wrap_iv,
      };
    }
  } catch (e) {
    // Non-fatal: unlock will fall back to fetching these from the server.
    console.warn("Failed to capture lock metadata", e);
  }

  try {
    const { lock_epoch } = await postLock();
    updateLockEpoch(lock_epoch);
    postSessionEvent("locked", session.vaultId, lock_epoch);
  } catch (e) {
    console.warn("Failed to publish lock, locked locally only", e);
  }

  lockVaultKeys(metadata);
  queryClient?.removeQueries({ queryKey: ["vault"] });
  queryClient?.removeQueries({ queryKey: ["favicon", session.vaultId] });
  queryClient?.removeQueries({ queryKey: ["google"] });
  await closeVaultDb();

  console.info(
    reason === "idle"
      ? `Vault auto-locked after ${describeAutolock(getWebAutolockMinutes())} of inactivity`
      : "Vault locked manually",
  );
  router.replace("/lock" as any);
}
