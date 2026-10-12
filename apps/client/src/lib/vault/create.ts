import { v4 as uuidv4 } from "uuid";
import { signupFlow } from "../auth/flows/signup";
import type { SessionState, DecryptedVault, VaultItem } from "../state/type";
import type { RegisterRequest, RegisterResponse } from "../queries/SignUp/api.schema";
import { register } from "../queries/SignUp/query";

/**
 * Creates a brand-new local vault (Flow C): generates the vault id and
 * encrypted starter document client-side, registers it with the server, and
 * establishes the session. No email or account is involved.
 */
export async function createVaultFlow(
  password: string,
  // Typed as VaultItem so a starter item can't drift out of the schema (an
  // item missing `sso` is fine — it defaults to [] — but a stale field name
  // would silently produce an item the vault rejects at serialize time).
  starter: { items: VaultItem[] } = { items: [] },
  sendRegistration: (payload: RegisterRequest) => Promise<RegisterResponse> = register,
): Promise<{
  vaultId: string;
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
  lockEpoch: number;
}> {
  const json = JSON.stringify({ items: starter.items });
  const unlocked = await signupFlow(password, json, sendRegistration);
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
