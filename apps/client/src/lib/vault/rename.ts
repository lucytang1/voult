/**
 * Renaming a vault.
 *
 * The name lives inside the encrypted document, and the document is written by
 * sync — not by the screen. So a rename is queued the same way an item change
 * is: encrypt `{ name }` under the vault key, write a durable `rename` intent,
 * update the in-memory document optimistically, and let the scheduler push it.
 *
 * That ordering is what makes renaming work offline. The intent survives a
 * lock/reload in SQLite; the pending-name marker keeps the new label on the
 * lock screen and in the chooser until the server document agrees.
 *
 * The name is NOT identity. Nothing here touches `vaultId`, storage namespacing,
 * the session, or any envelope.
 */

import { b64, encrypt } from "../crypto/index.web";
import { getOrCreateDeviceKey } from "../crypto/device-key";
import { createIntent } from "../sqlite/web/services/intent-service";
import { selectedVaultId } from "../state/vault-state";
import { useAppStore, updateVaultName } from "../state";
import { syncScheduler } from "../sync/sync-scheduler";
import { normalizeVaultName, setPendingVaultName } from "./name";

/**
 * Durable-first rename.
 *
 * The intent is written before the UI changes, so a failure to persist (closed
 * database, no session) leaves the screen showing the old name rather than a
 * label that would vanish on reload. After that the optimistic update and the
 * pending marker make the change immediate.
 *
 * @returns the normalized name that was applied.
 */
export async function renameVault(name: string): Promise<string> {
  const normalized = normalizeVaultName(name);
  if (!normalized) {
    throw new Error("Vault names must be between 1 and 48 characters.");
  }

  const { vault, decryptedVault } = useAppStore.getState();
  if (vault.status !== "unlocked") {
    throw new Error("Unlock the vault before renaming it.");
  }
  const vaultId = selectedVaultId(vault);
  if (!vaultId) {
    throw new Error("No vault is selected.");
  }
  if (decryptedVault?.name === normalized) {
    return normalized;
  }

  const encrypted = await encrypt(JSON.stringify({ name: normalized }), vault.vaultKey);
  const device = await getOrCreateDeviceKey(vaultId);

  // Durable write first — this is the step that must not be skipped.
  await createIntent("rename", {
    payload: b64(encrypted.cipher),
    payloadIv: b64(encrypted.iv),
    deviceId: device.device_id,
  });

  setPendingVaultName(vaultId, normalized);
  updateVaultName(normalized);
  syncScheduler.requestSync("intent-created");

  console.info("Vault rename queued");
  return normalized;
}
