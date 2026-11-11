import {
  decrypt,
  derivePasswordKeys,
  importVaultKey,
  unwrapKeyBytes,
} from "../../crypto/index.web";
import { persistDeviceSecrets, UnlockedSession, parseVaultJson } from "../utils";
import { login } from "../../queries/logIn/query";
import { fetchSession } from "../../queries/session/query";
import { fetchVault } from "../../queries/vault/query";
import { fetchCryptoParams } from "../../queries/cryptoParams/query";
import type { LoginResponse } from "../../queries/logIn/api.schema";
import { kdfEquals } from "@voult/vault-core";
import { maybeUpgradeKdf } from "../kdf-upgrade";

/**
 * New password login (unlock) flow — vault-scoped, no account/user:
 * 1. Fetch the vault's salt + KDF profile.
 * 2. Derive the verifier and password wrapping key locally (one Argon2 run).
 * 3. Send { vault_id, vault_verifier } to /auth — receives the session cookie
 *    plus the password-wrapped vault-key envelope (never the key itself).
 * 4. Fetch and decrypt the vault.
 * 5. Unwrap and import the vault key locally.
 * 6. Ensure a device key exists and store the device envelope locally.
 *
 * The parameters are fetched here rather than passed in: every caller needs
 * them immediately before this call, and owning the fetch is what lets the flow
 * retry once when another device rotated the credential between the params read
 * and /auth.
 */
export async function passwordLoginFlow(
  vaultId: string,
  password: string,
): Promise<UnlockedSession> {
  let params = await fetchCryptoParams(vaultId);
  let credential = await derivePasswordKeys(password, params.salt, params.kdf);

  let authResponse: LoginResponse;
  try {
    authResponse = await login({ vault_id: vaultId, vault_verifier: credential.vaultVerifier });
  } catch (e) {
    // A 401 here is a wrong password *unless* the credential rotated after we
    // read the params. Refetch and retry once only when it actually changed.
    const fresh = await fetchCryptoParams(vaultId);
    if (fresh.salt === params.salt && kdfEquals(fresh.kdf, params.kdf)) throw e;
    params = fresh;
    credential = await derivePasswordKeys(password, fresh.salt, fresh.kdf);
    authResponse = await login({ vault_id: vaultId, vault_verifier: credential.vaultVerifier });
  }

  if (authResponse.vault_id !== vaultId) {
    throw new Error("Unexpected vault returned while logging in.");
  }
  if (!authResponse.vault_key_wrap || !authResponse.vault_key_wrap_iv) {
    throw new Error("vault is missing the password-wrapped vault key envelope");
  }
  // Defensive: the keys we derived must correspond to the snapshot `/auth`
  // validated. If the profile moved in between, unwrapping would fail with an
  // opaque GCM error.
  if (authResponse.salt !== params.salt || !kdfEquals(authResponse.kdf, params.kdf)) {
    throw new Error("Vault credential changed during unlock. Try again.");
  }

  // Use the envelope that accompanied the verifier we just proved. Re-fetching
  // it would open a window where a concurrent rotation makes the pair
  // inconsistent.
  const vaultData = await fetchVault();
  const vault = vaultData.vault;

  const vaultKeyRaw = await unwrapKeyBytes(
    authResponse.vault_key_wrap,
    authResponse.vault_key_wrap_iv,
    credential.wrappingKey,
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

  // Opportunistic profile upgrade, after the session exists. A failure never
  // fails the login; the copy is zeroed when the attempt settles.
  const upgradeKey = vaultKeyRaw.slice();
  void maybeUpgradeKdf({
    vaultId,
    password,
    currentKdf: params.kdf,
    currentVerifier: credential.vaultVerifier,
    vaultKeyRaw: upgradeKey,
  });
  vaultKeyRaw.fill(0);

  return {
    session: {
      vaultId,
      cryptoVersion: vault.crypto_version,
    },
    vaultKey,
    // The document is stamped with the vault we authenticated as — the store's
    // switch guard rejects a mismatched id, so an unstamped document would make
    // every open fail here rather than silently install under the wrong vault.
    decryptedVault: parseVaultJson(plain, vaultId),
    version: vault.version,
    lockEpoch,
  };
}
