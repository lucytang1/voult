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
  const response = await fetchVault(request);
  const encKey = useAppStore.getState().encryptionKey;
  if (!encKey) {
    throw new Error("Encryption key is not set");
  }
  const decryptedVault = await decrypt(response.vault.vault, response.vault.vaultiv, encKey);
  const parsedVault = JSON.parse(decryptedVault) as DecryptedVault;
  useAppStore.setState({ decryptedVault: parsedVault });
  return response;
}

export async function sync(queryClient: QueryClient) {
  const localVersion = await getlocalVaultVersion();
  const pendingIntents = await fetchPendingIntents();
  const authKey = useAppStore.getState().authKey;
  const encKey = useAppStore.getState().encryptionKey;
  const email = globalThis.localStorage.getItem("email") || "";

  if (!authKey || !encKey || !email) {
    console.error("Sync prerequisites are missing");
    return;
  }
  if (!pendingIntents.length) {
    return;
  }

  const authKeyB64 = await getAuthVerifierB64(authKey);
  await loadVaultFromServer({ email, user_key: authKeyB64 });

  const decryptedVault = useAppStore.getState().decryptedVault;
  const mutableVault = {
    items: decryptedVault?.items ? [...decryptedVault.items] : [],
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
  console.log("mutableVault", mutableVault);

  const encryptedVault = await encrypt(JSON.stringify(mutableVault), encKey);
  const nextBaseVersion = localVersion ?? 0;
  console.log("updateVault request", {
    email,
    user_key: authKeyB64,
    vault: b64(encryptedVault.cipher),
    vaultiv: b64(encryptedVault.iv),
    version: nextBaseVersion,
  });
  let response: Awaited<ReturnType<typeof updateVault>> ;
  try {
    response = await updateVault({
      email,
      user_key: authKeyB64,
      vault: b64(encryptedVault.cipher),
      vaultiv: b64(encryptedVault.iv),
      version: nextBaseVersion,
    });
  } catch (error) {
    console.error("Failed to update vault on server", error);
    return;
  }
  console.log("response", response);

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