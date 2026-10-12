// Re-exported from @voult/vault-core (single source of truth shared with the
// MV3 extension). Canonical WebCrypto implementation lives in
// packages/vault-core/src/crypto.ts. This module path is kept stable so all
// existing `../crypto/index.web` imports keep working.
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
} from "@voult/vault-core";
