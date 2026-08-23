import {
  decrypt,
  importVaultKey,
  unwrapKeyBytes,
} from "../../crypto/index.web";
import { derivePasswordKeys, persistDeviceSecrets, UnlockedSession, parseVaultJson } from "../utils";
import { login } from "../../queries/logIn/query";
import { fetchVault } from "../../queries/vault/query";

/**
 * New password login flow:
 * 1. Fetch crypto parameters by email (caller).
 * 2. Derive the user_key and send it to /auth.
 * 3. Receive the session cookie.
 * 4. Derive the password wrapping key locally.
 * 5. Fetch the encrypted vault and password-wrapped vault-key envelope.
 * 6. Unwrap and import the vault key locally.
 * 7. Ensure a device key exists and store the device envelope locally.
 * 8. Fetch and decrypt the vault.
 */
export async function passwordLoginFlow(
  email: string,
  password: string,
  salt: string,
  iterations: number,
): Promise<UnlockedSession> {
  // Derive the user_key and password wrapping key.
  const { wrappingKey, userKey } = await derivePasswordKeys(password, salt, iterations);
  // login request
  const authResponse = await login({ email, user_key: userKey });

  //fetch vault and metadata from the server
  const vaultData = await fetchVault();
  const vault = vaultData.vault;

  if (!vault.vault_key_wrap || !vault.vault_key_wrap_iv) {
    throw new Error("vault is missing the password-wrapped vault key envelope");
  }

  // unwrap the vault key using the password wrapping key.
  const vaultKeyRaw = await unwrapKeyBytes(
    vault.vault_key_wrap,
    vault.vault_key_wrap_iv,
    wrappingKey,
  );

  // import the unwrapped vault key.
  const vaultKey = await importVaultKey(vaultKeyRaw);

  // persist the device secrets (vault key and wrapping key), namespaced to
  // the account that just authenticated.
  await persistDeviceSecrets(vaultKeyRaw, authResponse.user.id);

  // decrypt the vault using the unwrapped vault key.
  const plain = await decrypt(vault.vault, vault.vaultiv, vaultKey);
  return {
    session: {
      user: authResponse.user,
      cryptoVersion: vault.crypto_version,
    },
    vaultKey,
    decryptedVault: parseVaultJson(plain),
    version: vault.version,
  };
}
