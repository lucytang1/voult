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

export function parseVaultJson(plain: string): DecryptedVault {
  const parsed = JSON.parse(plain) as { items?: VaultItem[] };
  return { items: parsed.items ?? [] };
}

export interface UnlockedSession {
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
}

/** Derive the userKey + password wrapping key for a password. */
export async function derivePasswordKeys(password: string, salt: string, iterations: number) {
  const authKey = await createAuthKey(password, salt, iterations);
  const wrappingKey = await derivePasswordWrappingKey(password, salt, iterations);
  const userKey = await getAuthVerifierB64(authKey);
  return { wrappingKey, userKey };
}

/** Persist device secrets (deviceKey and deviceKey wrapped vaultKey) to the device storage. */
export async function persistDeviceSecrets(vaultKeyRaw: Uint8Array, userId: string) {
  const device = await getOrCreateDeviceKey(userId);
  const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, device.key);
  await saveDeviceEnvelope(userId, {
    device_id: device.device_id,
    wrapped_vault_key: b64(cipher),
    wrapped_vault_key_iv: b64(iv),
    crypto_version: CRYPTO_VERSION,
  });
}
