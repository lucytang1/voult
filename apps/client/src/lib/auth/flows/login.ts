import {
  decrypt,
  importVaultKey,
  unwrapKeyBytes,
} from "../../crypto/index.web";
import { derivePasswordKeys, persistDeviceSecrets, UnlockedSession, parseVaultJson } from "../utils";
import { login } from "../../queries/logIn/query";
import { fetchSession } from "../../queries/session/query";
import { fetchVault } from "../../queries/vault/query";

/**
 * New password login (unlock) flow — vault-scoped, no account/user:
 * 1. Derive the vaultVerifier and password wrapping key locally.
 * 2. Send { vault_id, vault_verifier } to /auth — receives the session cookie
 *    plus salt/iterations/crypto_version and the password-wrapped vault-key
 *    envelope (never the key itself).
 * 3. Fetch the encrypted vault.
 * 4. Unwrap and import the vault key locally.
 * 5. Ensure a device key exists and store the device envelope locally.
 * 6. Fetch and decrypt the vault.
 */
export async function passwordLoginFlow(
  vaultId: string,
  password: string,
  salt: string,
  iterations: number,
): Promise<UnlockedSession> {
  // Derive the vaultVerifier and password wrapping key locally — the master
  // password and derived keys never leave the client.
  const { wrappingKey, vaultVerifier } = await derivePasswordKeys(password, salt, iterations);
  const authResponse = await login({ vault_id: vaultId, vault_verifier: vaultVerifier });

  const vaultData = await fetchVault();
  const vault = vaultData.vault;

  if (!vault.vault_key_wrap || !vault.vault_key_wrap_iv) {
    throw new Error("vault is missing the password-wrapped vault key envelope");
  }

  // Unwrap the vault key using the password wrapping key.
  const vaultKeyRaw = await unwrapKeyBytes(
    vault.vault_key_wrap,
    vault.vault_key_wrap_iv,
    wrappingKey,
  );

  const vaultKey = await importVaultKey(vaultKeyRaw);

  // Persist the device secrets, namespaced to the vault that just unlocked.
  await persistDeviceSecrets(vaultKeyRaw, vaultId);

  const plain = await decrypt(vault.vault, vault.vaultiv, vaultKey);
  // Record the server lock epoch at unlock time so a peer's later lock
  // (epoch bump) is detectable. Best-effort: a fresh vault is at epoch 0.
  let lockEpoch = 0;
  try {
    const session = await fetchSession();
    lockEpoch = session.lock_epoch ?? 0;
  } catch {
    // Offline/legacy server — unlock still valid; sync check converges later.
  }
  return {
    session: {
      vaultId,
      cryptoVersion: vault.crypto_version,
    },
    vaultKey,
    decryptedVault: parseVaultJson(plain),
    version: vault.version,
    lockEpoch,
  };
}
