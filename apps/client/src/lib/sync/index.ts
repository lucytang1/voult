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
import { b64, decrypt, encrypt, getAuthVerifierB64 } from "../crypto/index.web";
import { VaultItem } from "../state/type";
import { updateVault, fetchVault } from "../queries/vault/query";
import { VaultRequest } from "../queries/vault/api.schema";
import { mergeVault } from "./merge";

const MAX_SYNC_RETRIES = 3;

//returns the decrypted vault and vault version from the server
const loadVaultFromServer = async (
  request: VaultRequest,
  encKey: CryptoKey,
) => {
  const response = await fetchVault(request);
  const decryptedVault = await decrypt(
    response.vault.vault,
    response.vault.vaultiv,
    encKey,
  );
  const parsedVault = JSON.parse(decryptedVault) as { items?: VaultItem[] };
  return { items: parsedVault.items ?? [], version: response.vault.version };
};

const loadItemsFromResponse = async (
  response: Awaited<ReturnType<typeof updateVault>>,
  encKey: CryptoKey,
) => {
  const syncedVaultJson = await decrypt(
    response.vault,
    response.vaultiv,
    encKey,
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
  //load keys and email
  const authKey = useAppStore.getState().authKey;
  const encKey = useAppStore.getState().encryptionKey;
  const email = globalThis.localStorage.getItem("email") || "";

  if (!authKey || !encKey || !email) {
    console.error("Sync prerequisites are missing");
    return;
  }

  const authKeyB64 = await getAuthVerifierB64(authKey);
  const request = { email, user_key: authKeyB64 };

  for (let attempt = 1; attempt <= MAX_SYNC_RETRIES; attempt++) {
    const { items: serverItems, version: serverVersion } =
      await loadVaultFromServer(request, encKey);
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
    const merged = await mergeVault(serverItems, pendingIntents, encKey);

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
      encKey,
    );
    let response: Awaited<ReturnType<typeof updateVault>>;
    try {
      response = await updateVault({
        email,
        user_key: authKeyB64,
        vault: b64(encryptedVault.cipher),
        vaultiv: b64(encryptedVault.iv),
        version: serverVersion,
      });
    } catch (error) {
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
    const syncedItems = await loadItemsFromResponse(response, encKey);
    await adoptServerSnapshot(syncedItems, response.version);
    await markIntentsSynced(merged.resolvedIds);
    return;
  }

  console.warn("Sync exceeded max retries; intents remain pending for the next trigger");
}
