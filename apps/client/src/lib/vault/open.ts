import { passwordLoginFlow } from "../auth/flows/login";
import type { UnlockedSession } from "../auth/flows";

/**
 * Opens (unlocks) a vault by its id. Requires the master password: the flow
 * fetches the vault's salt/profile itself, derives the vaultVerifier locally and
 * sends it to /auth — the server never sees the password or keys.
 */
export async function openVaultFlow(args: {
  vaultId: string;
  masterPassword?: string;
}): Promise<UnlockedSession> {
  if (!args.masterPassword) {
    throw new Error("Master password required to open vault");
  }
  return passwordLoginFlow(args.vaultId, args.masterPassword);
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
