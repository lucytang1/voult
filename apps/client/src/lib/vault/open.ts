import { passwordLoginFlow } from "../auth/flows/login";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import type { UnlockedSession } from "../auth/flows";

/**
 * Opens (unlocks) a vault by its id. Requires the master password: crypto
 * params are fetched client-side, then the vaultVerifier is derived locally and
 * sent to /auth — the server never sees the password or keys.
 */
export async function openVaultFlow(args: {
  vaultId: string;
  masterPassword?: string;
}): Promise<UnlockedSession> {
  if (!args.masterPassword) {
    throw new Error("Master password required to open vault");
  }
  const params = await fetchCryptoParams(args.vaultId);
  return passwordLoginFlow(args.vaultId, args.masterPassword, params.salt, params.iterations);
}

/**
 * Returns true when opening `target` would switch away from an already-open
 * `current` vault (so the caller can warn before discarding the open one).
 */
export function requiresSwitchConfirmation(
  current: string | null | undefined,
  target: { vault_id: string },
): boolean {
  return !!current && current !== target.vault_id;
}
