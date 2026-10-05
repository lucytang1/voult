import { createAuthKey, derivePasswordWrappingKey, getAuthVerifierB64 } from "../crypto/index.web";
import {
  wrapKeyBytes,
  b64,
  CRYPTO_VERSION
} from "../crypto/index.web";
import {
  getOrCreateDeviceKey,
  saveDeviceEnvelope,
} from "../crypto/device-key";

import type { SessionState, DecryptedVault, VaultItem } from "../state/type";

export function parseVaultJson(plain: string, vaultId = ""): DecryptedVault {
  const parsed = JSON.parse(plain) as { items?: VaultItem[] };
  return { formatVersion: 1, vaultId, items: parsed.items ?? [] };
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
