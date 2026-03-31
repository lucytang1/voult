import * as z from "zod";

export const VaultItemSchema = z.object({
  site: z.string(),
  username: z.string(),
  password: z.string(),
})

export type VaultItem = z.infer<typeof VaultItemSchema>;

export interface DecryptedVault {
    items: VaultItem[];
}

export interface AppState  {
  encryptionKey: CryptoKey | null,
  authKey: CryptoKey | null,
  decryptedVault: DecryptedVault | null,
  vaultVersion: number | null,
}