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


export const VAULT_DOCUMENT_FORMAT_VERSION = 1;

export interface DecryptedVault {
    formatVersion: number;
    vaultId: string;
    items: VaultItem[];
}

/**
 * The active session, scoped to a single vault. There is no account/user object
 * — `vaultId` is the only identity and the session cookie carries only it.
 */
export interface SessionState {
    vaultId: string;
    cryptoVersion: number;
}

/** The portable encrypted object stored by a cloud provider in later phases. */
export interface VoultPackage {
  packageFormatVersion: number;
  vaultId: string;
  logicalRevision: number;
  cryptoVersion: number;
  cryptoParameters: { salt: string; iterations: number };
  snapshot: { ciphertext: string; iv: string };
  passwordKeyEnvelope: { wrappedVaultKey: string; iv: string };
}



/**
 * Material needed to re-derive the vault key locally when unlocking after a
 * lock. Captured in memory at lock time so unlock needs no extra round-trips;
 * all values are zero-knowledge-safe (salt/iterations/wrapped key are things
 * the server already knows).
 */
export interface LockMetadata {
  salt: string;
  iterations: number;
  vaultKeyWrap: string;
  vaultKeyWrapIv: string;
}

/** The three top-level app states. */
export type AuthState = "not_authenticated" | "locked" | "unlocked";

export interface AppState  {
  vaultKey: CryptoKey | null,
  authKey: CryptoKey | null,
  session: SessionState | null,
  decryptedVault: DecryptedVault | null,
  vaultVersion: number | null,
  isLocked: boolean,
  isSyncing: boolean,
  lockMetadata: LockMetadata | null,
}
