import {
  PBKDF2_ITERATIONS,
  CRYPTO_VERSION,
  newSaltB64,
  generateVaultKeyRaw,
  importVaultKey,
  encrypt,
  wrapKeyBytes,
  b64,
  uuid,
} from "../../crypto/index.web";
import { UnlockedSession, persistDeviceSecrets, derivePasswordKeys, parseVaultJson } from "../utils";
import { register as signupRequest } from "../../queries/SignUp/query";
import { fetchSession } from "../../queries/session/query";

/**
 * Signup flow — vault-scoped, no account/user:
 * 1. Generate a client-side vault ID (stable, embedded in the encrypted doc).
 * 2. Generate a random vault key.
 * 3. Derive the vaultVerifier and password wrapping key.
 * 4. Encrypt the starter vault with the vault key.
 * 5. Wrap the vault key with the password wrapping key (envelope).
 * 6. Send the encrypted vault + verifier + KDF metadata + envelope to /register.
 * 7. The server establishes the session for this vault.
 * 8. Store the device envelope locally (IndexedDB), namespaced by vault.
 */
export async function signupFlow(
  password: string,
  vaultJson: string,
): Promise<UnlockedSession> {
  // The vault ID is generated client-side and never derived from any identity.
  const vaultId = uuid();
  const salt = newSaltB64();
  const { vaultVerifier, wrappingKey } = await derivePasswordKeys(password, salt, PBKDF2_ITERATIONS);

  const vaultKeyRaw = generateVaultKeyRaw();
  const vaultKey = await importVaultKey(vaultKeyRaw);

  const encryptedVault = await encrypt(vaultJson, vaultKey);

  const { cipher: wrappedCipher, iv: wrappedIv } = await wrapKeyBytes(
    vaultKeyRaw,
    wrappingKey,
  );

  const response = await signupRequest({
    vault_id: vaultId,
    vault_verifier: vaultVerifier,
    salt,
    iterations: PBKDF2_ITERATIONS,
    vaultiv: b64(encryptedVault.iv),
    vault: b64(encryptedVault.cipher),
    crypto_version: CRYPTO_VERSION,
    vault_key_wrap: b64(wrappedCipher),
    vault_key_wrap_iv: b64(wrappedIv),
  });

  // Persist the device envelope only after the server assigns the vault id.
  await persistDeviceSecrets(vaultKeyRaw, response.vault_id);

  // A fresh vault starts at lock_epoch 0; read it back so the session-sync
  // check has a baseline. Best-effort — unlock is valid regardless.
  let lockEpoch = 0;
  try {
    const session = await fetchSession();
    lockEpoch = session.lock_epoch ?? 0;
  } catch {
    // Offline/legacy server — sync check converges later.
  }

  return {
    session: {
      vaultId: response.vault_id,
      cryptoVersion: CRYPTO_VERSION,
    },
    vaultKey,
    decryptedVault: parseVaultJson(vaultJson),
    version: 1,
    lockEpoch,
  };
}

export async function createAccountFlow(...a:any){ throw new Error('deprecated'); }
