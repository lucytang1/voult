import { passwordLoginFlow } from "../auth/flows/login";
import type { UnlockedSession } from "../auth/flows";
import {
  derivePasswordKeys,
  importVaultKey,
  unwrapKeyBytes,
  decrypt,
} from "../crypto/index.web";
import { isKnownKdf } from "@voult/vault-core";
import { persistDeviceSecrets } from "../auth/utils";
import { maybeUpgradeKdf } from "../auth/kdf-upgrade";
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
      // `passwordLoginFlow` fetches the params itself; a VAULT_NOT_FOUND from
      // that fetch is what tells us to fall back to the provider copy.
      return await passwordLoginFlow(args.vaultId, args.masterPassword);
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
  // Format 3 replaced the KDF iteration integer with the self-describing
  // descriptor. There is no v2 adapter: no package in the wild predates this,
  // and a loud rejection beats misparsing.
  if (pkg.packageFormatVersion !== 3) {
    throw new Error(
      `That backup was made by an unsupported version (format ${pkg.packageFormatVersion}).`,
    );
  }
  const salt = pkg.cryptoParameters?.salt;
  const kdf = pkg.cryptoParameters?.kdf;
  if (!salt || !kdf) throw new Error("Package missing crypto parameters");
  if (!isKnownKdf(kdf)) {
    throw new Error(
      "That backup uses a password protection profile this version of Voult does not know.",
    );
  }
  if (!pkg.snapshot?.ciphertext || !pkg.snapshot?.iv) throw new Error("Package missing snapshot");
  if (!pkg.passwordKeyEnvelope?.wrappedVaultKey || !pkg.passwordKeyEnvelope?.iv) {
    throw new Error("Package missing password envelope");
  }
  // The recovery envelope is what lets this restore keep the vault's existing
  // recovery key. A package without it is not a package we can restore without
  // silently changing the user's recovery material, so refuse it.
  const recovery = pkg.recoveryEnvelope;
  if (!recovery?.salt || !recovery.verifier || !recovery.wrappedVaultKey || !recovery.iv) {
    throw new Error(
      "That backup has no recovery material, so it cannot be restored without changing the vault's recovery key.",
    );
  }

  // Verify master password locally: derive the credential and unwrap the vault
  // key. One Argon2 run gives both the wrapping key and the verifier.
  let vaultKeyRaw: Uint8Array;
  let vaultKey: CryptoKey;
  let credential: Awaited<ReturnType<typeof derivePasswordKeys>>;
  try {
    credential = await derivePasswordKeys(args.masterPassword, salt, kdf);
    vaultKeyRaw = await unwrapKeyBytes(
      pkg.passwordKeyEnvelope.wrappedVaultKey,
      pkg.passwordKeyEnvelope.iv,
      credential.wrappingKey
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

  // The recovery material comes straight from the package — no
  // `generateRecoveryMaterial` here, so the vault keeps the one recovery key it
  // was created with. The verifier comes from the credential already derived.
  const vaultVerifier = credential.vaultVerifier;

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
    kdf,
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
    // The package may carry a lower rung than this device calibrates. Upgrade
    // after registration, best-effort: a failure leaves the restored vault at
    // its package profile and the next password unlock retries.
    const upgradeKey = vaultKeyRaw.slice();
    void maybeUpgradeKdf({
      vaultId: pkg.vaultId,
      password: args.masterPassword,
      currentKdf: kdf,
      currentVerifier: credential.vaultVerifier,
      vaultKeyRaw: upgradeKey,
    });
    vaultKeyRaw.fill(0);
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
    return passwordLoginFlow(pkg.vaultId, args.masterPassword);
  }
}
