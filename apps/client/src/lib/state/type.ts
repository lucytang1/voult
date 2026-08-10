import * as z from "zod";

export const VaultItemSchema = z.object({
  id: z.uuid(),
  site: z.string(),
  username: z.string(),
  password: z.string(),
})

export type VaultItem = z.infer<typeof VaultItemSchema>;

// Payload shapes for update/delete intents. Create intents carry a full
// VaultItem (VaultItemSchema). Update intents carry only the changed fields so
// two devices editing different fields of the same entry both survive a merge.


export interface DecryptedVault {
    items: VaultItem[];
}

export interface AppState  {
  encryptionKey: CryptoKey | null,
  authKey: CryptoKey | null,
  decryptedVault: DecryptedVault | null,
  vaultVersion: number | null,
  isSyncing: boolean,
}
