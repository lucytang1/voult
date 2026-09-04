// Public surface of @voult/vault-core. Keep this list tight: only the
// pure vault logic shared by the Expo web app and the MV3 extension.

export {
  CRYPTO_VERSION,
  PBKDF2_ITERATIONS,
  b64,
  fromB64,
  newSaltB64,
  uuid,
  computeAuthVerifier,
  getAuthVerifierB64,
  encrypt,
  decrypt,
  generateVaultKeyRaw,
  importVaultKey,
  wrapKeyBytes,
  unwrapKeyBytes,
  generateDeviceKey,
  derivePasswordWrappingKey,
  createAuthKey,
} from "./crypto.js";

export {
  VaultItemSchema,
  UpdateVaultItemSchema,
  DeleteVaultItemSchema,
  CreateVaultItemSchema,
  VAULT_DOCUMENT_FORMAT_VERSION,
} from "./schema.js";
export type {
  VaultItem,
  CreateVaultItem,
  UpdateVaultItem,
  DeleteVaultItem,
  DecryptedVault,
  SessionState,
  LockMetadata,
  AuthState,
  VaultResponse,
  UpdateVaultRequest,
  UpdateVaultResponse,
} from "./schema.js";

export { mergeVault } from "./merge.js";
export type { MergeVaultResult, PendingIntent } from "./merge.js";

export {
  isValidVaultId,
  canonicalizeOrigin,
  originOfUrl,
  rankOriginMatch,
} from "./origin.js";
export type { OriginMatchRank } from "./origin.js";
