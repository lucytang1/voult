import { passwordLoginFlow } from "../auth/flows/login";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import type { UnlockedSession } from "../auth/flows";

/**
 * Imports a vault that was restored from Google Drive (pending OAuth flow or
 * an existing cloud-backed vault). The vault id is taken from the Drive
 * package; the master password is used to derive the vaultVerifier and unwrap
 * the vault key locally. The Drive file is the cross-device authority, so the
 * server-backed vault already matches it — establishing the session fetches
 * and decrypts that snapshot.
 */
export async function importVaultFromGoogle(args: {
  vaultId: string;
  fileId?: string;
  masterPassword: string;
}): Promise<UnlockedSession> {
  const params = await fetchCryptoParams(args.vaultId);
  return passwordLoginFlow(args.vaultId, args.masterPassword, params.salt, params.iterations);
}
