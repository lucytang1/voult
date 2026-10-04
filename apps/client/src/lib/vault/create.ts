import { v4 as uuidv4 } from "uuid";
import { signupFlow } from "../auth/flows/signup";
import type { SessionState, DecryptedVault } from "../state/type";

/**
 * Creates a brand-new local vault (Flow C): generates the vault id and
 * encrypted starter document client-side, registers it with the server, and
 * establishes the session. No email or account is involved.
 */
export async function createVaultFlow(
  password: string,
  starter: { items: { id: string; site: string; username: string; password: string }[] } = { items: [] },
): Promise<{
  vaultId: string;
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
  lockEpoch: number;
}> {
  const json = JSON.stringify({ items: starter.items });
  const unlocked = await signupFlow(password, json);
  return {
    vaultId: unlocked.session.vaultId,
    session: unlocked.session,
    vaultKey: unlocked.vaultKey,
    decryptedVault: unlocked.decryptedVault,
    version: unlocked.version,
    lockEpoch: unlocked.lockEpoch,
  };
}

// Kept for any legacy callers expecting a uuid helper.
export const newVaultId = () => uuidv4();
