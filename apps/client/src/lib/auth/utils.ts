import { createAuthKey, derivePasswordWrappingKey, getAuthVerifierB64 } from "../crypto/index.web";
import {
  wrapKeyBytes,
  b64,
  newSaltB64,
  CRYPTO_VERSION,
  generateRecoverySecret,
  formatRecoveryKey,
  deriveRecoveryWrapKey,
  computeRecoveryVerifier,
  recoveryAad
} from "../crypto/index.web";
import {
  getOrCreateDeviceKey,
  saveDeviceEnvelope,
} from "../crypto/device-key";

import type { SessionState, DecryptedVault, VaultItem } from "../state/type";
import { DEFAULT_VAULT_NAME, normalizeVaultName } from "../vault/name";

/**
 * Parse a decrypted vault document into the store's `DecryptedVault`.
 *
 * `vaultId` is REQUIRED and must be the id of the vault the plaintext was just
 * read from. It is not a label — it is the identity the store verifies before
 * installing a document (`switchVaultOpen` refuses a `decryptedVault.vaultId`
 * that differs from the requested vault, so the wrong key under a selection can
 * never render). A defaulted parameter here silently produced `""` and turned
 * that guard into a guaranteed throw on every list-driven vault open, so the
 * id must be passed explicitly by every caller.
 *
 * The display name is optional in stored documents: vaults created before
 * names existed simply decode to the default, and become renameable in place.
 * The name is never part of the identity check above.
 */
export function parseVaultJson(plain: string, vaultId: string): DecryptedVault {
  const parsed = JSON.parse(plain) as { name?: unknown; items?: VaultItem[] };
  const name =
    typeof parsed.name === "string" ? normalizeVaultName(parsed.name) ?? DEFAULT_VAULT_NAME : DEFAULT_VAULT_NAME;
  return { formatVersion: 1, vaultId, name, items: parsed.items ?? [] };
}

export interface UnlockedSession {
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
  // Server lock_epoch observed at unlock time. Consumers store it via
  // updateLockEpoch so the session-sync check can detect a peer's later lock.
  lockEpoch: number;
}

/** Derive the vaultVerifier + password wrapping key for a password. */
export async function derivePasswordKeys(password: string, salt: string, iterations: number) {
  const authKey = await createAuthKey(password, salt, iterations);
  const wrappingKey = await derivePasswordWrappingKey(password, salt, iterations);
  const vaultVerifier = await getAuthVerifierB64(authKey);
  return { wrappingKey, vaultVerifier };
}

/** Persist device secrets (deviceKey and deviceKey wrapped vaultKey) to the device storage. */
export async function persistDeviceSecrets(vaultKeyRaw: Uint8Array, vaultId: string) {
  const device = await getOrCreateDeviceKey(vaultId);
  const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, device.key);
  await saveDeviceEnvelope(vaultId, {
    device_id: device.device_id,
    wrapped_vault_key: b64(cipher),
    wrapped_vault_key_iv: b64(iv),
    crypto_version: CRYPTO_VERSION,
  });
}

export interface RecoveryMaterial {
  /** HMAC-SHA256(K_rec, "recovery-verify-v1"), raw bytes. */
  recoveryVerifier: Uint8Array;
  /** HKDF salt for K_rec, base64. */
  recoverySalt: string;
  /** AES-GCM envelope of the raw vault key, base64. */
  recoveryWrap: string;
  recoveryWrapIv: string;
  /** `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX` — shown to the user once. */
  recoveryKey: string;
}

/**
 * Mints a vault's recovery material: a fresh 160-bit secret, its HKDF salt and
 * verifier, and an AES-GCM envelope holding `vaultKeyRaw` under K_rec.
 *
 * Shared by every path that CREATES a vault on this server — the create flow and
 * the cloud/Drive import — so the recovery construction cannot drift between
 * them. There is deliberately no other producer: recovery is a mandatory
 * property of a vault from the moment it exists, never something switched on
 * later.
 *
 * Two properties are load-bearing:
 *   - The envelope wraps `vaultKeyRaw` DIRECTLY, never a password-derived key
 *     (Rule R1). Rotating the password therefore leaves recovery intact.
 *   - It is bound to `vaultId` via AAD, so the envelope cannot be lifted onto
 *     another vault's row.
 *
 * The raw secret is zeroed here, before returning: from this point the only
 * copy in existence is `recoveryKey` and whatever the user writes down.
 */
export async function generateRecoveryMaterial(
  vaultKeyRaw: Uint8Array,
  vaultId: string,
): Promise<RecoveryMaterial> {
  const secret = generateRecoverySecret();
  const salt = newSaltB64();
  const kRec = await deriveRecoveryWrapKey(secret, salt);
  const verifier = await computeRecoveryVerifier(secret, salt);
  const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, kRec, recoveryAad(vaultId));

  // Render for display, then wipe the raw bytes from memory.
  const recoveryKey = formatRecoveryKey(secret);
  secret.fill(0);

  return {
    recoveryVerifier: verifier,
    recoverySalt: salt,
    recoveryWrap: b64(cipher),
    recoveryWrapIv: b64(iv),
    recoveryKey,
  };
}
