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
  RECOVERY_SECRET_BYTES,
  RECOVERY_KEY_CHARS,
  RECOVERY_WRAP_INFO,
  RECOVERY_VERIFY_LABEL,
  RECOVERY_PROOF_LABEL,
  generateRecoverySecret,
  formatRecoveryKey,
  parseRecoveryKey,
  deriveRecoveryWrapKey,
  computeRecoveryVerifier,
  computeRecoveryProof,
  recoveryAad,
} from "@voult/vault-core";

// The recovery artifact — the PDF that carries a recovery key. Format lives in
// vault-core; the browser plumbing is in `lib/auth/recovery-file.ts`.
export {
  buildRecoveryPdf,
  parseRecoveryPdf,
  recoveryPdfFileName,
  serializePayload,
  RecoveryPdfError,
  RECOVERY_PDF_MAGIC,
  RECOVERY_PDF_MAX_BYTES,
} from "@voult/vault-core";
export type {
  BuildRecoveryPdfOptions,
  RecoveryPdfPayload,
  RecoveryPdfErrorCode,
} from "@voult/vault-core";
