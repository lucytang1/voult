import {
  CRYPTO_VERSION,
  PBKDF2_ITERATIONS,
  b64,
  createAuthKey,
  createLoginPayload,
  decrypt,
  derivePasswordWrappingKey,
  encrypt,
  generateVaultKeyRaw,
  getAuthVerifierB64,
  importVaultKey,
  newSaltB64,
  unwrapKeyBytes,
  wrapKeyBytes,
} from "../crypto/index.web";
import {
  getDeviceEnvelope,
  getDeviceKey,
  getOrCreateDeviceKey,
  saveDeviceEnvelope,
} from "../crypto/device-key";
import { login } from "../queries/logIn/query";
import { register as signupRequest } from "../queries/SignUp/query";
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
}

function parseVaultJson(plain: string): DecryptedVault {
  const parsed = JSON.parse(plain) as { items?: VaultItem[] };
  return { items: parsed.items ?? [] };
}

/** Derive the auth verifier + password wrapping key for a password. */
async function derivePasswordKeys(password: string, salt: string, iterations: number) {
  const authKey = await createAuthKey(password, salt, iterations);
  const wrappingKey = await derivePasswordWrappingKey(password, salt, iterations);
  const userKey = await getAuthVerifierB64(authKey);
  return { authKey, wrappingKey, userKey };
}

/** Wrap the vault key with the persisted browser device key and store the envelope locally. */
async function persistDeviceEnvelope(vaultKeyRaw: Uint8Array, userId: string) {
  const device = await getOrCreateDeviceKey(userId);
  const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, device.key);
  await saveDeviceEnvelope(userId, {
    device_id: device.device_id,
    wrapped_vault_key: b64(cipher),
    wrapped_vault_key_iv: b64(iv),
    crypto_version: CRYPTO_VERSION,
  });
}


/**
 * Existing-session unlock after reload:
 * 1. Call /session using the session cookie.
 * 2. Load the local device key by device_id.
 * 3. Read the locally stored device-wrapped vault-key envelope.
 * 4. Unwrap and import the vault key locally.
 * 5. Fetch and decrypt the vault.
 *
 * Returns null when there is no valid session or the local device key /
 * envelope is missing — the caller should show the recovery/login screen.
 */
export async function unlockWithDevice(): Promise<UnlockedSession | null> {
  const sessionData = await fetchSession();
  const userId = sessionData.user.id;
  // Device key + envelope are namespaced per account, so loading by user id
  // already prevents cross-account unlock; the device_id match below is
  // defense in depth against a stale envelope for a re-registered device.
  const device = await getDeviceKey(userId);
  if (!device) return null;

  const envelope = await getDeviceEnvelope(userId);
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
      user: sessionData.user,
      cryptoVersion: vault.crypto_version,
    },
    vaultKey,
    decryptedVault: parseVaultJson(plain),
    version: vault.version,
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
    const params = await fetchCryptoParams(session.user.email);
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
