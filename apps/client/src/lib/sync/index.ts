// TEST COMMENT: this edit was made by Claude on 2026-08-05
import { useAppStore } from "../state";
import { updateDecryptedVault, updateVaultVersion } from "../state";
import { getlocalVaultVersion } from "../sqlite/web/services/client-state-service";
import { upsertVaultVersion } from "../sqlite/web/services/client-state-service";
import { fetchPendingIntents, markIntentsSynced } from "../sqlite/web/services/intent-service";
import { b64, decrypt, encrypt, getAuthVerifierB64 } from "../crypto/index.web";
import { QueryClient } from "@tanstack/react-query";
import { DecryptedVault, VaultItemSchema } from "../state/type";
import { updateVault, fetchVault } from "../queries/vault/query";
import { VaultRequest } from "../queries/vault/api.schema";

const loadVaultFromServer = async (request: VaultRequest) => {
  // fetch the vault and its version from the server
  const response = await fetchVault(request);
  const encKey = useAppStore.getState().encryptionKey;
  if (!encKey) {
    throw new Error("Encryption key is not set");
  }
  //decrypt the vault
  const decryptedVault = await decrypt(response.vault.vault, response.vault.vaultiv, encKey);
  // parse the decrypted vault into a typed object
  const parsedVault = JSON.parse(decryptedVault) as DecryptedVault;
  return { parsedVault, version: response.vault.version };
}

export async function sync(queryClient: QueryClient) {
  const authKey = useAppStore.getState().authKey;
  const encKey = useAppStore.getState().encryptionKey;
  const email = globalThis.localStorage.getItem("email") || "";

  if (!authKey || !encKey || !email) {
    console.error("Sync prerequisites are missing");
    return;
  }

  // 1. Fetch the vault and its version from the server
  const authKeyB64 = await getAuthVerifierB64(authKey);
  const { parsedVault, version: serverVersion } = await loadVaultFromServer({
    email,
    user_key: authKeyB64,
  });

  // 2. The local sqlite version is the source of truth — abort unless the server agrees
  const localVersion = await getlocalVaultVersion();
  if ((localVersion ?? 0) !== serverVersion) {
    console.warn("Sync aborted: vault version mismatch", { localVersion, serverVersion });
    return;
  }

  // 3. Nothing to push if there are no pending intents
  const pendingIntents = await fetchPendingIntents();
  if (!pendingIntents.length) {
    return;
  }

  // 4. Apply the pending create intents on top of the decrypted server vault
  const mutableVault = {
    items: parsedVault?.items ? [...parsedVault.items] : [],
  };
  const successfullyAppliedIntentIds: string[] = [];

  for (const intent of pendingIntents) {
    if (intent.operation !== "create") {
      console.error(`Sync does not support operation "${intent.operation}" yet`);
      return;
    }

    let decryptedIntent: string;
    try {
      decryptedIntent = await decrypt(intent.payload, intent.payload_iv, encKey);
    } catch (error) {
      console.error("Failed to decrypt intent payload", intent.id, error);
      continue;
    }

    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(decryptedIntent);
    } catch (error) {
      console.error("Failed to JSON parse decrypted intent payload", intent.id, error);
      return;
    }

    const parsedIntentpayload = VaultItemSchema.safeParse(parsedJson);
    if (!parsedIntentpayload.success) {
      console.error("Failed to parse intent payload", parsedIntentpayload.error);
      return;
    }
    mutableVault.items.push(parsedIntentpayload.data);
    successfullyAppliedIntentIds.push(intent.id);
  }

  if (!successfullyAppliedIntentIds.length) {
    console.warn("Sync aborted: no pending intents were applied");
    return;
  }

  // 5. Encrypt the merged vault and push it with the local sqlite version as the base
  const encryptedVault = await encrypt(JSON.stringify(mutableVault), encKey);
  let response: Awaited<ReturnType<typeof updateVault>>;
  try {
    response = await updateVault({
      email,
      user_key: authKeyB64,
      vault: b64(encryptedVault.cipher),
      vaultiv: b64(encryptedVault.iv),
      version: localVersion ?? 0,
    });
  } catch (error) {
    console.error("Failed to update vault on server", error);
    return;
  }

  // 6. On success, refresh local state from the server's stored vault
  let syncedVaultJson: string;
  try {
    syncedVaultJson = await decrypt(response.vault, response.vaultiv, encKey);
  } catch (error) {
    console.error("Failed to decrypt synced vault response", error);
    return;
  }

  let parsedSyncedVault: { items?: unknown[] };
  try {
    parsedSyncedVault = JSON.parse(syncedVaultJson) as { items?: unknown[] };
  } catch (error) {
    console.error("Failed to parse synced vault response JSON", error);
    return;
  }
  const parsedItems = VaultItemSchema.array().safeParse(parsedSyncedVault.items);
  if (!parsedItems.success) {
    console.error("Invalid synced vault payload shape", parsedItems.error);
    return;
  }
  updateDecryptedVault({ items: parsedItems.data });
  updateVaultVersion(response.version);
  await upsertVaultVersion(response.version);
  await markIntentsSynced(successfullyAppliedIntentIds);
}
