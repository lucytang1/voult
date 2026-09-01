import { passwordLoginFlow } from "../auth/flows/login";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import type { UnlockedSession } from "../auth/flows";
import { http } from "../queries/http";
import {
  createAuthKey,
  getAuthVerifierB64,
  derivePasswordWrappingKey,
  importVaultKey,
  unwrapKeyBytes,
  decrypt,
} from "../crypto/index.web";
import { persistDeviceSecrets } from "../auth/utils";
import { register } from "../queries/SignUp/query";
import { readGoogleVaultPending, readGoogleVault } from "../google/api";
import type { VoultPackage } from "../state/type";

/**
 * Imports a vault from Google Drive.
 *
 * Case 1 (no session, pending OAuth): vault may NOT exist on this server's DB
 * yet — it only exists as an encrypted VoultPackage on Drive. The old code
 * called GET /get_crypto_params which returns VAULT_NOT_FOUND. Fix: on
 * VAULT_NOT_FOUND, fetch the Drive package via pendingState/fileId (or
 * session-bound read), verify the master password locally by unwrapping the
 * vault key + decrypting the snapshot, then register the vault on this server
 * so future logins succeed.
 *
 * If the vault already exists on server, the fast path just does the normal
 * passwordLoginFlow (server verifier check + device envelope).
 */
export async function importVaultFromGoogle(args: {
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
      return await passwordLoginFlow(args.vaultId, args.masterPassword, params.salt, params.iterations);
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
    const res = await readGoogleVaultPending(args.pendingState, args.fileId!);
    pkgB64 = res.package;
  } else {
    const res = await readGoogleVault({ file_id: args.fileId });
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
  const salt = pkg.cryptoParameters?.salt;
  const iterations = pkg.cryptoParameters?.iterations;
  if (!salt || !iterations) throw new Error("Package missing crypto parameters");
  if (!pkg.snapshot?.ciphertext || !pkg.snapshot?.iv) throw new Error("Package missing snapshot");
  if (!pkg.passwordKeyEnvelope?.wrappedVaultKey || !pkg.passwordKeyEnvelope?.iv) {
    throw new Error("Package missing password envelope");
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
  let decryptedVault: { items?: any[] };
  try {
    decryptedVault = JSON.parse(plain) as { items?: any[] };
  } catch {
    throw new Error("Package snapshot decrypt produced invalid JSON");
  }

  // Derive verifier for registration / login.
  const authKey = await createAuthKey(args.masterPassword, salt, iterations);
  const vaultVerifier = await getAuthVerifierB64(authKey);

  // Try to register this vault on this server instance so future
  // get_crypto_params / get_vault succeed. If it already exists (race),
  // fall back to password login.
  try {
    await register({
      vault_id: pkg.vaultId,
      vault_verifier: vaultVerifier,
      salt,
      iterations,
      vault: pkg.snapshot.ciphertext,
      vaultiv: pkg.snapshot.iv,
      crypto_version: pkg.cryptoVersion ?? 2,
      vault_key_wrap: pkg.passwordKeyEnvelope.wrappedVaultKey,
      vault_key_wrap_iv: pkg.passwordKeyEnvelope.iv,
    });
  } catch (regErr: any) {
    const regCode = regErr?.response?.data?.code as string | undefined;
    if (regCode === "VAULT_EXISTS") {
      // Vault was created concurrently — just login normally.
      const params = await fetchCryptoParams(args.vaultId);
      return await passwordLoginFlow(args.vaultId, args.masterPassword, params.salt, params.iterations);
    }
    // If register failed for other reason, but we already decrypted the package,
    // treat the Drive package as the local vault and still create a session
    // locally? We must have a server session for the app to be "unlocked",
    // so rethrow.
    throw regErr;
  }

  // Persist device envelope for silent unlock next time.
  await persistDeviceSecrets(vaultKeyRaw, pkg.vaultId);

  // Build UnlockedSession from the Drive-decrypted data.
  const parsedItems = Array.isArray(decryptedVault.items) ? decryptedVault.items : [];
  return {
    session: { vaultId: pkg.vaultId, cryptoVersion: pkg.cryptoVersion ?? 2 },
    vaultKey,
    decryptedVault: { formatVersion: 1, vaultId: pkg.vaultId, items: parsedItems },
    version: pkg.logicalRevision ?? 1,
  };
}
