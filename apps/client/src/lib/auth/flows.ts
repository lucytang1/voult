import {
  CRYPTO_VERSION,
  PBKDF2_ITERATIONS,
  b64,
  createAuthKey,
  decrypt,
  derivePasswordWrappingKey,
  getAuthVerifierB64,
  importVaultKey,
  unwrapKeyBytes,
  wrapKeyBytes,
} from "../crypto/index.web";
import {
  getDeviceEnvelope,
  getDeviceKey,
  getOrCreateDeviceKey,
  saveDeviceEnvelope,
} from "../crypto/device-key";
import { fetchSession } from "../queries/session/query";
import { fetchVault } from "../queries/vault/query";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import {
  getAuthState,
  setVaultKey,
  useAppStore,
} from "../state";
import type { SessionState, DecryptedVault, VaultItem } from "../state/type";

export interface UnlockedSession {
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
  // Server lock_epoch observed at unlock time (see POST /api/lock).
  lockEpoch: number;
}

function parseVaultJson(plain: string, vaultId: string): DecryptedVault {
  const parsed = JSON.parse(plain) as { items?: VaultItem[] };
  return { formatVersion: 1, vaultId, items: parsed.items ?? [] };
}

/** Derive the vaultVerifier + password wrapping key for a password. */
async function derivePasswordKeys(password: string, salt: string, iterations: number) {
  const authKey = await createAuthKey(password, salt, iterations);
  const wrappingKey = await derivePasswordWrappingKey(password, salt, iterations);
  const vaultVerifier = await getAuthVerifierB64(authKey);
  return { authKey, wrappingKey, vaultVerifier };
}

/** Wrap the vault key with the persisted browser device key and store the envelope locally. */
async function persistDeviceEnvelope(vaultKeyRaw: Uint8Array, vaultId: string) {
  const device = await getOrCreateDeviceKey(vaultId);
  const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, device.key);
  await saveDeviceEnvelope(vaultId, {
    device_id: device.device_id,
    wrapped_vault_key: b64(cipher),
    wrapped_vault_key_iv: b64(iv),
    crypto_version: CRYPTO_VERSION,
  });
}


/**
 * Existing-session unlock after reload:
 * 1. Call /session using the session cookie.
 * 2. Load the local device key for this vault.
 * 3. Read the locally stored device-wrapped vault-key envelope.
 * 4. Unwrap and import the vault key locally.
 * 5. Fetch and decrypt the vault.
 *
 * Returns null when there is no valid session or the local device key /
 * envelope is missing — the caller should show the recovery/login screen.
 */
export async function unlockWithDevice(): Promise<UnlockedSession | null> {
  const sessionData = await fetchSession();
  const vaultId = sessionData.vault_id;
  // Device key + envelope are namespaced per vault, so loading by vault id
  // already prevents cross-vault unlock; the device_id match below is defense
  // in depth against a stale envelope for a re-enrolled device.
  const device = await getDeviceKey(vaultId);
  if (!device) return null;

  const envelope = await getDeviceEnvelope(vaultId);
  if (!envelope || envelope.device_id !== device.device_id) return null;

  const vaultKeyRaw = await unwrapKeyBytes(
    envelope.wrapped_vault_key,
    envelope.wrapped_vault_key_iv,
    device.key,
  );
  const vaultKey = await importVaultKey(vaultKeyRaw);

  const vaultData = await fetchVault();
  const vault = vaultData.vault;
  const plain = await decrypt(vault.vault, vault.vaultiv, vaultKey);

  return {
    session: {
      vaultId,
      cryptoVersion: vault.crypto_version,
    },
    vaultKey,
    decryptedVault: parseVaultJson(plain, vaultId),
    version: vault.version,
    lockEpoch: sessionData.lock_epoch ?? 0,
  };
}

/**
 * Unlock after a lock (session still alive). Re-derives the password wrapping
 * key locally from the master password + salt/iterations, then unwraps the
 * vault key. Wrong passwords fail at AES-GCM unwrap (throws) — no server
 * verification needed, so nothing about the attempt leaves the device.
 *
 * Prefers the lock metadata captured in memory at lock time; if unavailable
 * (e.g. the tab reloaded), falls back to fetching crypto params + wrapped key
 * from the server using the still-valid session.
 */
export async function unlockWithPassword(password: string): Promise<void> {
  if (getAuthState() !== "locked") {
    throw new Error("Vault is not locked.");
  }
  const { session, lockMetadata } = useAppStore.getState();
  if (!session) throw new Error("No active session.");

  let salt = lockMetadata?.salt;
  let iterations = lockMetadata?.iterations;
  let wrap = lockMetadata?.vaultKeyWrap;
  let wrapIv = lockMetadata?.vaultKeyWrapIv;

  if (!salt || !iterations || !wrap || !wrapIv) {
    // Metadata lost (reload): refetch from server via session.
    const params = await fetchCryptoParams(session.vaultId);
    const vaultData = await fetchVault();
    const vault = vaultData.vault;
    if (!vault.vault_key_wrap || !vault.vault_key_wrap_iv) {
      throw new Error("Vault key material unavailable for unlock.");
    }
    salt = params.salt;
    iterations = params.iterations;
    wrap = vault.vault_key_wrap;
    wrapIv = vault.vault_key_wrap_iv;
  }

  const wrappingKey = await derivePasswordWrappingKey(password, salt!, iterations!);
  try {
    const vaultKeyRaw = await unwrapKeyBytes(wrap!, wrapIv!, wrappingKey);
    const vaultKey = await importVaultKey(vaultKeyRaw);
    setVaultKey(vaultKey);
    console.info("Vault unlocked with password");
  } catch {
    // AES-GCM decryption failure == wrong master password.
    throw new Error("Incorrect password.");
  }
  // vaultVersion is intentionally left untouched so pending sync intents
  // keep a valid base_version across lock/unlock.
}
