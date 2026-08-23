import {
  PBKDF2_ITERATIONS,
  CRYPTO_VERSION,
  newSaltB64,
  generateVaultKeyRaw,
  importVaultKey,
  encrypt,
  wrapKeyBytes,
  b64,

} from "../../crypto/index.web";
import { UnlockedSession, persistDeviceSecrets, derivePasswordKeys, parseVaultJson } from "../utils";
import { register as signupRequest } from "../../queries/SignUp/query";

/**
 * Signup flow:
 * 1. Generate a random vault key.
 * 2. Derive the userKey and password wrapping key.
 * 3. Generate and persist the browser device key.
 * 4. Encrypt the starter vault with the vault key.
 * 5. Wrap the vault key with the password wrapping key.
 * 6. Wrap the vault key with the device key.
 * 7. Send the encrypted vault and password envelope to /register.
 * 8. The server establishes the session.
 * 9. Store the device envelope locally (IndexedDB).
 */
export async function signupFlow(
  email: string,
  password: string,
  vaultJson: string,
): Promise<UnlockedSession> {
  //generate a random salt for userKey and password wrapKeyBytes derivation
  const salt = newSaltB64();
  //generate the keys for password-based encryption
  const { userKey, wrappingKey } = await derivePasswordKeys(password, salt, PBKDF2_ITERATIONS);

  //generate a random vault key
  const vaultKeyRaw = generateVaultKeyRaw();
  //import the random key as a CryptoKey object
  const vaultKey = await importVaultKey(vaultKeyRaw);

  //encrypt the vault using the vault key
  const encryptedVault = await encrypt(vaultJson, vaultKey);

  //wrapt the vault key using the wrapping key
  const { cipher: wrappedCipher, iv: wrappedIv } = await wrapKeyBytes(
    vaultKeyRaw,
    wrappingKey,
  );

  //Send the signup request to the server
  const response = await signupRequest({
    email,
    user_key: userKey,
    salt,
    iterations: PBKDF2_ITERATIONS,
    vaultiv: b64(encryptedVault.iv),
    vault: b64(encryptedVault.cipher),
    crypto_version: CRYPTO_VERSION,
    vault_key_wrap: b64(wrappedCipher),
    vault_key_wrap_iv: b64(wrappedIv),
  });

  // Persist the device secrets only after the server assigns the account id —
  // device key + envelope are namespaced per user, so this must happen after
  // registration (moving it here is safe: nothing above depends on it).
  await persistDeviceSecrets(vaultKeyRaw, response.user.id);

  return {
    session: {
      user: { id: response.user.id, email },
      cryptoVersion: CRYPTO_VERSION,
    },
    vaultKey,
    decryptedVault: parseVaultJson(vaultJson),
    version: 1,
  };
}
