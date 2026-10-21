/**
 * Folder operations and helpers.
 *
 * Folders live inside the encrypted vault document, so every mutation here is a
 * durable-first intent exactly like `lib/vault/rename.ts`: encrypt under the
 * vault key, write an intent row, update the in-memory document optimistically,
 * then ask the scheduler to push. A failed durable write leaves the UI showing
 * the old state rather than a label that vanishes on reload.
 *
 * A folder is a label, never identity: nothing here touches `vaultId`, storage
 * namespacing, the session, or any envelope.
 */

import { b64, encrypt } from "../crypto/index.web";
import { getOrCreateDeviceKey } from "../crypto/device-key";
import { createIntent } from "../sqlite/web/services/intent-service";
import { selectedVaultId } from "../state/vault-state";
import {
  useAppStore,
  addVaultFolder,
  updateVaultFolderName,
  removeVaultFolder,
  moveVaultItemToFolder,
} from "../state";
import { syncScheduler } from "../sync/sync-scheduler";
import { normalizeFolderName } from "@voult/vault-core";
import {
  DEFAULT_FOLDER_ID,
  DEFAULT_FOLDER_NAME,
  type Folder,
  type VaultItem,
} from "@voult/vault-core";
import type { DecryptedVault } from "../state/type";

export { DEFAULT_FOLDER_ID, DEFAULT_FOLDER_NAME, normalizeFolderName };
export type { Folder };

/** A bucket that is never stored: items with no / dangling folderId. */
export const UNFILED_LABEL = "Unfiled";

export function folderNameFor(doc: DecryptedVault | null, item: VaultItem): string {
  if (!doc) return UNFILED_LABEL;
  const folder = doc.folders.find((f) => f.id === item.folderId);
  return folder ? folder.name : UNFILED_LABEL;
}

export function itemsInFolder(doc: DecryptedVault | null, folderId: string | null): VaultItem[] {
  if (!doc) return [];
  if (folderId === null) {
    // Unfiled bucket.
    const known = new Set(doc.folders.map((f) => f.id));
    return doc.items.filter((it) => !it.folderId || !known.has(it.folderId));
  }
  return doc.items.filter((it) => it.folderId === folderId);
}

export function countByFolder(doc: DecryptedVault | null): {
  all: number;
  unfiled: number;
  byId: Record<string, number>;
} {
  const byId: Record<string, number> = {};
  let unfiled = 0;
  if (!doc) return { all: 0, unfiled: 0, byId };
  const known = new Set(doc.folders.map((f) => f.id));
  for (const it of doc.items) {
    if (!it.folderId || !known.has(it.folderId)) {
      unfiled++;
    } else {
      byId[it.folderId] = (byId[it.folderId] ?? 0) + 1;
    }
  }
  return { all: doc.items.length, unfiled, byId };
}

export async function createFolder(name: string): Promise<Folder> {
  const normalized = normalizeFolderName(name);
  if (!normalized) {
    throw new Error("Folder names must be between 1 and 48 characters.");
  }
  const { vault, decryptedVault } = useAppStore.getState();
  if (vault.status !== "unlocked") {
    throw new Error("Unlock the vault before creating a folder.");
  }
  const vaultId = selectedVaultId(vault);
  if (!vaultId) throw new Error("No vault is selected.");

  // Duplicate name guard (case-insensitive) is a UI-level rule; the merge
  // tolerates duplicates that arise from concurrent creates.
  const dup = (decryptedVault?.folders ?? []).some(
    (f) => f.name.toLowerCase() === normalized.toLowerCase(),
  );
  if (dup) {
    throw new Error("A folder with that name already exists.");
  }

  const folder: Folder = { id: crypto.randomUUID(), name: normalized };

  const encrypted = await encrypt(JSON.stringify({ id: folder.id, name: normalized }), vault.vaultKey);
  const device = await getOrCreateDeviceKey(vaultId);

  await createIntent("createFolder", {
    payload: b64(encrypted.cipher),
    payloadIv: b64(encrypted.iv),
    deviceId: device.device_id,
  });

  addVaultFolder(folder);
  syncScheduler.requestSync("intent-created");
  console.info("Folder creation queued");
  return folder;
}

export async function renameFolder(folderId: string, name: string): Promise<void> {
  const normalized = normalizeFolderName(name);
  if (!normalized) {
    throw new Error("Folder names must be between 1 and 48 characters.");
  }
  const { vault, decryptedVault } = useAppStore.getState();
  if (vault.status !== "unlocked") {
    throw new Error("Unlock the vault before renaming a folder.");
  }
  const vaultId = selectedVaultId(vault);
  if (!vaultId) throw new Error("No vault is selected.");

  const dup = (decryptedVault?.folders ?? []).some(
    (f) => f.id !== folderId && f.name.toLowerCase() === normalized.toLowerCase(),
  );
  if (dup) {
    throw new Error("A folder with that name already exists.");
  }

  const encrypted = await encrypt(JSON.stringify({ id: folderId, name: normalized }), vault.vaultKey);
  const device = await getOrCreateDeviceKey(vaultId);

  await createIntent("renameFolder", {
    payload: b64(encrypted.cipher),
    payloadIv: b64(encrypted.iv),
    deviceId: device.device_id,
  });

  updateVaultFolderName(folderId, normalized);
  syncScheduler.requestSync("intent-created");
  console.info("Folder rename queued");
}

export async function deleteFolder(folderId: string): Promise<void> {
  const { vault, decryptedVault } = useAppStore.getState();
  if (vault.status !== "unlocked") {
    throw new Error("Unlock the vault before deleting a folder.");
  }
  const vaultId = selectedVaultId(vault);
  if (!vaultId) throw new Error("No vault is selected.");

  const encrypted = await encrypt(JSON.stringify({ id: folderId }), vault.vaultKey);
  const device = await getOrCreateDeviceKey(vaultId);

  await createIntent("deleteFolder", {
    payload: b64(encrypted.cipher),
    payloadIv: b64(encrypted.iv),
    deviceId: device.device_id,
  });

  removeVaultFolder(folderId);
  syncScheduler.requestSync("intent-created");
  console.info("Folder deletion queued");
}

export async function moveItemToFolder(itemId: string, folderId: string): Promise<void> {
  const { vault } = useAppStore.getState();
  if (vault.status !== "unlocked") {
    throw new Error("Unlock the vault before moving an item.");
  }
  const vaultId = selectedVaultId(vault);
  if (!vaultId) throw new Error("No vault is selected.");

  const payload = { id: itemId, fields: { folderId } };

  const encrypted = await encrypt(JSON.stringify(payload), vault.vaultKey);
  const device = await getOrCreateDeviceKey(vaultId);

  await createIntent("update", {
    payload: b64(encrypted.cipher),
    payloadIv: b64(encrypted.iv),
    deviceId: device.device_id,
  });

  moveVaultItemToFolder(itemId, folderId);
  syncScheduler.requestSync("intent-created");
}