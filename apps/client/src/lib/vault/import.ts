import { passwordLoginFlow } from "../auth/flows/login";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import type { UnlockedSession } from "../auth/flows";
import {
  MAX_VAULT_CIPHERTEXT_BYTES,
  createAuthKey,
  getAuthVerifierB64,
  derivePasswordWrappingKey,
  importVaultKey,
  unwrapKeyBytes,
  decrypt,
  assertKdfParams,
  parseBase64Exact,
  decodedBase64Length,
  SALT_BYTES,
  IV_BYTES,
  VERIFIER_BYTES,
  KEY_WRAP_BYTES,
  MIN_VAULT_CIPHERTEXT_BYTES,
  SUPPORTED_CRYPTO_VERSION,
} from "../crypto/index.web";
import { persistDeviceSecrets } from "../auth/utils";
import { submitRegistration } from "./registration";
import type { RegisterRequest } from "../queries/SignUp/api.schema";
import { readCloudVaultPending, readCloudVault } from "../cloud/api";
import type { VoultPackage } from "../state/type";
import { DEFAULT_VAULT_NAME, normalizeVaultName } from "./name";
import { parseVaultDocument } from "@voult/vault-core";

/**
 * Imports a vault from a cloud provider (Google Drive today).
 *
 * Two situations, both ending in an unlocked session:
 *
 *   - The vault is already on this server: the master password is all that is
 *     needed, so this is the normal `passwordLoginFlow`.
 *   - The vault exists only as an encrypted package on the provider: it does NOT
 *     exist on this server yet. The package is fetched, the master password is
 *     verified locally by unwrapping the vault key and decrypting the snapshot,
 *     and the vault is then registered here.
 *
 * Registration uses the recovery material the package carries — the SAME
 * recovery envelope and salt the vault was created with. It does not mint a new
 * secret, so the recovery file the user already saved at creation keeps working
 * against this server too. There is no recovery step here: recovery is a
 * property of the vault from creation, and a restore is not a new vault.
 */

export async function importVaultFromCloud(args: {
  vaultId: string;
  fileId?: string;
  masterPassword: string;
  pendingState?: string;
}): Promise<UnlockedSession> {
  // If we have a pending Drive token (Case 1, no session), skip the server
  // DB check entirely — vault is not on this server yet, and calling
  // GET /get_crypto_params will just log a VAULT_NOT_FOUND error.
  const shouldTryServerFirst = !args.pendingState;
  if (shouldTryServerFirst) {
    try {
      const params = await fetchCryptoParams(args.vaultId);
      return await passwordLoginFlow(
        args.vaultId,
        args.masterPassword,
        params.salt,
        params.iterations,
      );
    } catch (e: any) {
      const code = e?.response?.data?.code as string | undefined;
      // Only fallback on VAULT_NOT_FOUND; other errors (network, etc.) bubble up.
      if (code !== "VAULT_NOT_FOUND") throw e;
      if (!args.fileId) throw new Error("Drive file id required to import vault not on server");
    }
  } else {
    if (!args.fileId) throw new Error("Drive file id required to import vault not on server");
  }

  // Fallback: vault not on server — fetch encrypted package from Drive.
  // Use pendingState token if we have no session (Case 1), else session-bound read.
  let pkgB64: string;
  if (args.pendingState) {
    const res = await readCloudVaultPending(args.pendingState, args.fileId!);
    pkgB64 = res.package;
  } else {
    const res = await readCloudVault({ file_id: args.fileId });
    pkgB64 = res.package;
  }

  // Package is base64-encoded JSON bytes.
  let pkgJson: string;
  try {
    pkgJson = atob(pkgB64);
  } catch {
    // If not base64, treat as raw JSON
    pkgJson = pkgB64;
  }
  let pkg: VoultPackage;
  try {
    pkg = JSON.parse(pkgJson) as VoultPackage;
  } catch {
    // Some servers return bytes that were base64 of raw bytes that themselves are JSON
    // Try decoding as UTF-8 bytes
    try {
      const bytes = Uint8Array.from(atob(pkgB64), (c) => c.charCodeAt(0));
      pkgJson = new TextDecoder().decode(bytes);
      pkg = JSON.parse(pkgJson) as VoultPackage;
    } catch (err2: any) {
      throw new Error("Downloaded Google package is invalid JSON: " + (err2?.message || String(err2)));
    }
  }

  if (pkg.vaultId !== args.vaultId) {
    throw new Error(`Package vaultId mismatch: expected ${args.vaultId}, got ${pkg.vaultId}`);
  }

  // Exact shapes BEFORE any derivation. The package is a file the user picked;
  // `iterations: 2147483647` would otherwise pin the tab in PBKDF2 with no
  // cancel, and a short/oversized envelope would only be refused later by
  // /register — after the expensive part.
  if (pkg.cryptoVersion !== SUPPORTED_CRYPTO_VERSION) {
    throw new Error(`Unsupported backup crypto version: ${String(pkg.cryptoVersion)}.`);
  }
  const salt = pkg.cryptoParameters?.salt;
  const iterations = pkg.cryptoParameters?.iterations;
  if (!salt || iterations === undefined) {
    throw new Error("Package missing crypto parameters");
  }
  if (!parseBase64Exact(salt, SALT_BYTES)) {
    throw new Error("Backup has an invalid KDF salt.");
  }
  assertKdfParams(SALT_BYTES, iterations);

  const snapshot = pkg.snapshot;
  const ciphertextLen = snapshot ? decodedBase64Length(snapshot.ciphertext) : null;
  if (
    !snapshot ||
    ciphertextLen === null ||
    ciphertextLen < MIN_VAULT_CIPHERTEXT_BYTES ||
    ciphertextLen > MAX_VAULT_CIPHERTEXT_BYTES ||
    !parseBase64Exact(snapshot.iv, IV_BYTES)
  ) {
    throw new Error("Backup has an invalid vault snapshot.");
  }

  const passwordEnvelope = pkg.passwordKeyEnvelope;
  if (
    !passwordEnvelope ||
    !parseBase64Exact(passwordEnvelope.wrappedVaultKey, KEY_WRAP_BYTES) ||
    !parseBase64Exact(passwordEnvelope.iv, IV_BYTES)
  ) {
    throw new Error("Backup has an invalid password envelope.");
  }

  // The recovery envelope is what lets this restore keep the vault's existing
  // recovery key. A package without it is not a package we can restore without
  // silently changing the user's recovery material, so refuse it.
  const recovery = pkg.recoveryEnvelope;
  if (
    !recovery ||
    !parseBase64Exact(recovery.salt, SALT_BYTES) ||
    !parseBase64Exact(recovery.verifier, VERIFIER_BYTES) ||
    !parseBase64Exact(recovery.wrappedVaultKey, KEY_WRAP_BYTES) ||
    !parseBase64Exact(recovery.iv, IV_BYTES)
  ) {
    throw new Error(
      "That backup has no valid recovery material, so it cannot be restored without changing the vault's recovery key.",
    );
  }

  // Verify master password locally: derive wrapping key and unwrap vault key.
  let vaultKeyRaw: Uint8Array;
  let vaultKey: CryptoKey;
  try {
    const wrappingKey = await derivePasswordWrappingKey(args.masterPassword, salt, iterations);
    vaultKeyRaw = await unwrapKeyBytes(
      pkg.passwordKeyEnvelope.wrappedVaultKey,
      pkg.passwordKeyEnvelope.iv,
      wrappingKey
    );
    vaultKey = await importVaultKey(vaultKeyRaw);
  } catch {
    throw new Error("Incorrect password.");
  }

  // Decrypt snapshot to validate and get decrypted vault items.
  let plain: string;
  try {
    plain = await decrypt(pkg.snapshot.ciphertext, pkg.snapshot.iv, vaultKey);
  } catch {
    throw new Error("Incorrect password.");
  }
  let decryptedVault: { name?: unknown; folders?: any[]; items?: any[] };
  try {
    decryptedVault = JSON.parse(plain) as { name?: unknown; folders?: any[]; items?: any[] };
  } catch {
    throw new Error("Package snapshot decrypt produced invalid JSON");
  }

  // Derive verifier for registration. The recovery material comes straight from
  // the package — no `generateRecoveryMaterial` here, so the vault keeps the one
  // recovery key it was created with.
  const authKey = await createAuthKey(args.masterPassword, salt, iterations);
  const vaultVerifier = await getAuthVerifierB64(authKey);

  // Parse through the shared decoder so legacy packages (no `folders` key) are
  // interpreted as a single Personal folder, identically to every other surface.
  const parsedDoc = parseVaultDocument(plain);
  const parsedItems = parsedDoc.items;
  const name = parsedDoc.name;
  const parsedFolders = parsedDoc.folders;

  const request: RegisterRequest = {
    vault_id: pkg.vaultId,
    vault_verifier: vaultVerifier,
    salt,
    iterations,
    vault: pkg.snapshot.ciphertext,
    vaultiv: pkg.snapshot.iv,
    crypto_version: pkg.cryptoVersion ?? 2,
    vault_key_wrap: pkg.passwordKeyEnvelope.wrappedVaultKey,
    vault_key_wrap_iv: pkg.passwordKeyEnvelope.iv,
    recovery_verifier: recovery.verifier,
    recovery_salt: recovery.salt,
    recovery_wrap: recovery.wrappedVaultKey,
    recovery_wrap_iv: recovery.iv,
  };

  console.info("Vault package verified locally; registering it on this server");

  try {
    const { lockEpoch } = await submitRegistration(request);
    // Persist the device envelope so the next unlock is a local unwrap.
    await persistDeviceSecrets(vaultKeyRaw, pkg.vaultId);
    return {
      session: {
        vaultId: pkg.vaultId,
        cryptoVersion: pkg.cryptoVersion ?? 2,
      },
      vaultKey,
      decryptedVault: { formatVersion: 1, vaultId: pkg.vaultId, name, folders: parsedFolders, items: parsedItems },
      // `/register` creates the row at version 1, regardless of the revision the
      // backup was mirrored at on its source server. The local document version
      // must match the server's, or the next sync's base_version is wrong.
      version: 1,
      lockEpoch,
    };
  } catch (regErr: any) {
    const regCode = regErr?.response?.data?.code as string | undefined;
    if (regCode !== "VAULT_EXISTS") throw regErr;
    // Registered concurrently on another device between the package read and
    // this write. That row is authoritative and already carries the same
    // recovery material (it came from the same package lineage), so a normal
    // login is the right outcome.
    const params = await fetchCryptoParams(pkg.vaultId);
    return passwordLoginFlow(pkg.vaultId, args.masterPassword, params.salt, params.iterations);
  }
}
