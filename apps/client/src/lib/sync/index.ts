import { useAppStore } from "../state";
import { updateDecryptedVault, updateVaultVersion } from "../state";
import {
  getlocalVaultVersion,
  upsertVaultVersion,
} from "../sqlite/web/services/client-state-service";
import {
  fetchPendingIntents,
  markIntentsSynced,
  markIntentError,
} from "../sqlite/web/services/intent-service";
import { b64, decrypt, encrypt } from "../crypto/index.web";
import { VaultItem } from "../state/type";
import { updateVault, fetchVault } from "../queries/vault/query";
import { isNetworkError } from "../queries/http";
import { mergeVault } from "./merge";

const MAX_SYNC_RETRIES = 3;

//returns the decrypted vault and vault version from the server
const loadVaultFromServer = async (
  vaultKey: CryptoKey,
) => {
  const response = await fetchVault();
  const decryptedVault = await decrypt(
    response.vault.vault,
    response.vault.vaultiv,
    vaultKey,
  );
  const parsedVault = JSON.parse(decryptedVault) as { items?: VaultItem[] };
  return { items: parsedVault.items ?? [], version: response.vault.version };
};

const loadItemsFromResponse = async (
  response: Awaited<ReturnType<typeof updateVault>>,
  vaultKey: CryptoKey,
) => {
  const syncedVaultJson = await decrypt(
    response.vault,
    response.vaultiv,
    vaultKey,
  );
  const parsed = JSON.parse(syncedVaultJson) as { items?: VaultItem[] };
  return parsed.items ?? [];
};

//updates the vault state with the server snapshot
const adoptServerSnapshot = async (items: VaultItem[], version: number) => {
  updateDecryptedVault({ items });
  updateVaultVersion(version);
  await upsertVaultVersion(version);
};

const isVersionConflict = (error: unknown) =>
  (error as { response?: { status?: number } })?.response?.status === 409;

export async function sync() {
  const { vaultKey, session } = useAppStore.getState();

  if (!vaultKey || !session) {
    console.error("Sync prerequisites are missing");
    return;
  }

  // Pin the account this sync run belongs to. If the session changes
  // mid-flight (logout, account switch, server-forced 401), abort instead of
  // uploading or resolving another account's intents.
  const syncUserId = session.user.id;
  const sessionChanged = () =>
    useAppStore.getState().session?.user.id !== syncUserId;

  for (let attempt = 1; attempt <= MAX_SYNC_RETRIES; attempt++) {
    if (sessionChanged()) {
      console.warn("Sync aborted: session changed mid-run", { userId: syncUserId });
      return;
    }
    // Server unreachable is a normal offline state, not an error: pending
    // intents stay queued in the local DB and this run simply ends. A later
    // trigger (network reconnect / focus) will retry.
    let serverSnapshot;
    try {
      serverSnapshot = await loadVaultFromServer(vaultKey);
    } catch (error) {
      if (isNetworkError(error)) {
        console.info("[Sync] Server unreachable; intents remain queued for next online sync");
        return;
      }
      throw error;
    }
    const { items: serverItems, version: serverVersion } = serverSnapshot;
    const localVersion = await getlocalVaultVersion();
    const pendingIntents = await fetchPendingIntents();

    // Server ahead (or rolled back) with no local edits: adopt the snapshot.
    if (!pendingIntents.length) {
      if (localVersion !== serverVersion) {
        await adoptServerSnapshot(serverItems, serverVersion);
      }
      return;
    }

    // Replay local intents on top of the server snapshot (idempotent, per-op).
    const merged = await mergeVault(serverItems, pendingIntents, vaultKey);

    if (merged.quarantinedIds.length) {
      await Promise.all(
        merged.quarantinedIds.map((id) =>
          markIntentError(id, "intent could not be applied and was quarantined"),
        ),
      );
    }

    // Nothing changed (all intents were already reflected, dropped, or
    // quarantined): adopt the snapshot and clear the resolved intents.
    if (!merged.changed) {
      await adoptServerSnapshot(serverItems, serverVersion);
      if (merged.resolvedIds.length) {
        await markIntentsSynced(merged.resolvedIds);
      }
      return;
    }

    const encryptedVault = await encrypt(
      JSON.stringify({ items: merged.items }),
      vaultKey,
    );
    if (sessionChanged()) {
      console.warn("Sync aborted before push: session changed mid-run", { userId: syncUserId });
      return;
    }
    let response: Awaited<ReturnType<typeof updateVault>>;
    try {
      response = await updateVault({
        vault: b64(encryptedVault.cipher),
        vaultiv: b64(encryptedVault.iv),
        version: serverVersion,
      });
    } catch (error) {
      if (isNetworkError(error)) {
        console.info("[Sync] Server unreachable; intents remain queued for next online sync");
        return;
      }
      if (isVersionConflict(error)) {
        // Another device pushed between our fetch and our push — reconcile
        // against the new snapshot in the next loop iteration.
        console.warn("Sync version conflict, retrying", { attempt });
        continue;
      }
      console.error("Failed to update vault on server", error);
      return;
    }

    // Success: adopt the server's stored vault, advance the base version,
    // and mark the merged intents synced.
    if (sessionChanged()) {
      console.warn("Sync aborted after push: session changed mid-run", { userId: syncUserId });
      return;
    }
    const syncedItems = await loadItemsFromResponse(response, vaultKey);
    await adoptServerSnapshot(syncedItems, response.version);
    await markIntentsSynced(merged.resolvedIds);
    return;
  }

  console.warn("Sync exceeded max retries; intents remain pending for the next trigger");
}
