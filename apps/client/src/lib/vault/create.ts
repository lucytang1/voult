import { v4 as uuidv4 } from "uuid";
import { prepareSignupFlow } from "../auth/flows/signup";
import type { PendingVaultRegistration } from "./registration";
import { cacheVaultName, DEFAULT_VAULT_NAME } from "./name";

/**
 * Creates a brand-new vault (Flow C) — the local half only.
 *
 * Everything here is client-side and synchronous with respect to the server:
 * nothing is registered, no session exists, and the server has never heard of
 * this vault. The caller must:
 *
 *   1. Hand `recoveryKey` to the interstitial and let the user save the
 *      recovery FILE — this is the first step, not an afterthought.
 *   2. Call `commitVaultRegistration(prepared)` once they have it. That is the
 *      single `POST /register`, and it is what makes the vault exist.
 *
 * Reload between the two and there is nothing to clean up: no row, no session,
 * no orphaned key material on the server. The user starts again.
 *
 * The device key is deliberately NOT enrolled here, and never before the file
 * is saved. A vault that has a working device key but a recovery file the user
 * never received looks fine right up until the day it matters.
 */
export async function prepareVaultFlow(
    password: string,
    name: string = DEFAULT_VAULT_NAME,
): Promise<PendingVaultRegistration> {
    const prepared = await prepareSignupFlow(password, name);
    // The document does not exist in the store until the commit succeeds, but
    // the interstitial (and any chooser entry rendered meanwhile) already needs
    // a label. Cache it now; the store will refresh it from the document.
    cacheVaultName(prepared.vaultId, prepared.decryptedVault.name);
    return prepared;
}

// Kept for any legacy callers expecting a uuid helper.
export const newVaultId = () => uuidv4();

export type { PendingVaultRegistration };
export type CreateVaultResult = import("./registration").CommittedVault;