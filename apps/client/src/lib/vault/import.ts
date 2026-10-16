import { passwordLoginFlow } from "../auth/flows/login";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import type { UnlockedSession } from "../auth/flows";
import {
  createAuthKey,
  getAuthVerifierB64,
  derivePasswordWrappingKey,
  importVaultKey,
  unwrapKeyBytes,
  decrypt,
  b64,
} from "../crypto/index.web";
import { persistDeviceSecrets, generateRecoveryMaterial } from "../auth/utils";
import { register } from "../queries/SignUp/query";
import type { RegisterRequest, RegisterResponse } from "../queries/SignUp/api.schema";
import { readCloudVaultPending, readCloudVault } from "../cloud/api";
import { commitVaultRegistration, type PendingVaultRegistration } from "./registration";
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
/**
 * Result of inspecting the cloud vault.
 *
 * Two genuinely different situations, and conflating them is what caused the
 * bug this module was restructured to fix:
 *
 *   - `unlocked` — the vault was already on this server, so the master password
 *     was all that was needed and its recovery file has been dealt with before.
 *   - `pending_registration` — the vault lived only as a Drive package. It does
 *     NOT exist on this server yet, and it must not come into existence until
 *     the user has a recovery file for it. Hence a *pending* value rather than
 *     an unlocked session: there is genuinely nothing to unlock yet.
 */
export type CloudImportOutcome =
  | { kind: "unlocked"; session: UnlockedSession }
  | { kind: "pending_registration"; pending: PendingVaultRegistration };

export async function importVaultFromCloud(args: {
  vaultId: string;
  fileId?: string;
  masterPassword: string;
  pendingState?: string;
}): Promise<CloudImportOutcome> {
  // If we have a pending Drive token (Case 1, no session), skip the server
  // DB check entirely — vault is not on this server yet, and calling
  // GET /get_crypto_params will just log a VAULT_NOT_FOUND error.
  const shouldTryServerFirst = !args.pendingState;
  if (shouldTryServerFirst) {
    try {
      const params = await fetchCryptoParams(args.vaultId);
      const session = await passwordLoginFlow(
        args.vaultId,
        args.masterPassword,
        params.salt,
        params.iterations,
      );
      return { kind: "unlocked", session };
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

  // Recovery material for the row we are about to create here.
  //
  // The package deliberately carries only a `passwordKeyEnvelope` — recovery is
  // per-vault and was never bundled, precisely so a compromised provider backup
  // does not hand over a second route into the key. So a restore has to MINT a
  // fresh recovery secret on this device. The user is handed the file through
  // the same one-time interstitial as the create flow, BEFORE anything is
  // registered.
  const recovery = await generateRecoveryMaterial(vaultKeyRaw, pkg.vaultId);

  const parsedItems = Array.isArray(decryptedVault.items) ? decryptedVault.items : [];

  console.info("Vault package verified locally; nothing has been registered yet");

  // Nothing has been sent to the server. The caller shows the recovery file,
  // and only then calls `finishCloudImport`.
  return {
    kind: "pending_registration",
    pending: {
      vaultId: pkg.vaultId,
      cryptoVersion: pkg.cryptoVersion ?? 2,
      version: pkg.logicalRevision ?? 1,
      request: {
        vault_id: pkg.vaultId,
        vault_verifier: vaultVerifier,
        salt,
        iterations,
        vault: pkg.snapshot.ciphertext,
        vaultiv: pkg.snapshot.iv,
        crypto_version: pkg.cryptoVersion ?? 2,
        vault_key_wrap: pkg.passwordKeyEnvelope.wrappedVaultKey,
        vault_key_wrap_iv: pkg.passwordKeyEnvelope.iv,
        recovery_verifier: b64(recovery.recoveryVerifier),
        recovery_salt: recovery.recoverySalt,
        recovery_wrap: recovery.recoveryWrap,
        recovery_wrap_iv: recovery.recoveryWrapIv,
      },
      vaultKey,
      vaultKeyRaw,
      decryptedVault: { formatVersion: 1, vaultId: pkg.vaultId, items: parsedItems },
      recoveryKey: recovery.recoveryKey,
    },
  };
}

/**
 * Registers a restored vault — the second half, run once the user has the
 * recovery file.
 *
 * Owns the VAULT_EXISTS race: another device may have registered this vault id
 * between the fetch and the commit. That is not an error to surface, it is the
 * server telling us to log in normally instead — the vault already exists, it
 * already has recovery, and the file we just minted is for a vault that was
 * never created here.
 */
export async function finishCloudImport(
  pending: PendingVaultRegistration,
  sendRegistration: (payload: RegisterRequest) => Promise<RegisterResponse> = register,
  masterPassword?: string,
): Promise<UnlockedSession> {
  try {
    const committed = await commitVaultRegistration(pending, sendRegistration);
    // Persist device envelope for silent unlock next time.
    await persistDeviceSecrets(pending.vaultKeyRaw, pending.vaultId);
    return {
      session: committed.session,
      vaultKey: committed.vaultKey,
      decryptedVault: committed.decryptedVault,
      version: committed.version,
      lockEpoch: committed.lockEpoch,
    };
  } catch (regErr: any) {
    const regCode = regErr?.response?.data?.code as string | undefined;
    if (regCode !== "VAULT_EXISTS") throw regErr;
    // Created concurrently on another device — fall back to a normal login. The
    // concurrent row is authoritative and carries its own recovery material;
    // the file minted above belongs to nothing and is discarded with `pending`.
    if (!masterPassword) throw regErr;
    const params = await fetchCryptoParams(pending.vaultId);
    return passwordLoginFlow(
      pending.vaultId,
      masterPassword,
      params.salt,
      params.iterations,
    );
  }
}
