// Re-exported from @voult/vault-core (single source of truth shared with the
// MV3 extension). Import sites across the app are unchanged; the canonical
// definitions (VaultItem + origin, sync op schemas, session/lock types) live
// in packages/vault-core/src/schema.ts.
import type {
  SessionState,
  DecryptedVault,
  LockMetadata,
} from "@voult/vault-core";
export {
  VaultItemSchema,
  UpdateVaultItemSchema,
  DeleteVaultItemSchema,
  CreateVaultItemSchema,
  VAULT_DOCUMENT_FORMAT_VERSION,
} from "@voult/vault-core";
export type {
  VaultItem,
  CreateVaultItem,
  UpdateVaultItem,
  DeleteVaultItem,
  DecryptedVault,
  SessionState,
  LockMetadata,
  AuthState,
} from "@voult/vault-core";

// VoultPackage is web-app-local (cloud-package modeling); it stays here until
// a second consumer needs it.
export interface VoultPackage {
  packageFormatVersion: number;
  vaultId: string;
  logicalRevision: number;
  cryptoVersion: number;
  cryptoParameters: { salt: string; iterations: number };
  snapshot: { ciphertext: string; iv: string };
  passwordKeyEnvelope: { wrappedVaultKey: string; iv: string };
}

/** Zustand store shape (web-app-local; the extension mirrors a subset). */
export interface AppState {
  vaultKey: CryptoKey | null;
  authKey: CryptoKey | null;
  session: SessionState | null;
  decryptedVault: DecryptedVault | null;
  vaultVersion: number | null;
  // Last server lock_epoch converged to (null = unknown / no session).
  // Survives lock (a lock publishes a new epoch); cleared with the session.
  lockEpoch: number | null;
  isLocked: boolean;
  isSyncing: boolean;
  lockMetadata: LockMetadata | null;
}