import { startCloudAuth, redirectToCloudAuth, listCloudProviders, listCloudCredentials, persistCloudBinding } from "./api";
import { fetchPendingIntents } from "../sqlite/web/services/intent-service";

/**
 * Build an encrypted VoultPackage for a local vault.
 * Uses the local vault's encrypted snapshot and envelope (server never sees plaintext).
 * The vault must be unlocked and its local snapshot in a known state.
 * For Phase 3 we simply use the current server snapshot; pending intents are preserved.
 */
/**
 * Ensure the selected provider is connected; if not, start OAuth and redirect.
 * Returns true if already connected, false if redirect initiated.
 */
export async function ensureCloudConnected(vaultId: string, providerKind: string): Promise<boolean> {
  const credentials = await listCloudCredentials();
  if (credentials.some((credential) => credential.kind === providerKind)) return true;

  const providers = await listCloudProviders();
  if (!providers.some((provider) => provider.kind === providerKind)) {
    throw new Error("Cloud backup is not configured on this server.");
  }

  // Not connected – start auth
  const { auth_url } = await startCloudAuth(providerKind);
  redirectToCloudAuth(auth_url);
  return false; // page will navigate away
}

/**
 * Enable Google Drive sync for an existing local vault (§6.3).
 * Requires vault unlocked and local snapshot in known state.
 * Merges/flushes pending intents before enrollment per spec; idempotent after lost response.
 */
export async function enableCloudForVault(vaultId: string, providerKind: string): Promise<{
  fileId: string;
  remoteRevision: string;
}> {
  // Ensure connected
  const connected = await ensureCloudConnected(vaultId, providerKind);
  if (!connected) {
    throw new Error("Redirecting to cloud provider authorization...");
  }

  // §6.3: Require vault unlocked and flush pending intents into snapshot before enrollment
  // Preserve unresolved intents if local error occurs – we do a best-effort sync, but never clear intents before success
  try {
    const pending = await fetchPendingIntents().catch(() => []);
    if (pending.length > 0) {
      console.info(`Enable sync: ${pending.length} pending intents – merging before upload`);
      // Use existing sync engine to flush (replays onto server snapshot and pushes)
      const { sync } = await import("../sync/index");
      await sync().catch((e) => {
        console.warn("Pre-enrollment sync failed, proceeding with current snapshot", e);
      });
    }
  } catch (e) {
    console.warn("Failed to check pending intents before enrollment", e);
  }

  // The switch route selects the requested provider explicitly and uses only
  // server-held ciphertext, so it cannot accidentally write through the prior
  // active binding when switching providers.
  let result;
  try {
    result = await persistCloudBinding({ vault_id: vaultId, provider: providerKind });
  } catch (error: any) {
    // A saved refresh token may have been revoked since it was retained. Only
    // an explicit auth-required response starts consent again; transient API
    // failures remain visible and do not create an OAuth loop.
    if (error?.response?.data?.code !== "PROVIDER_AUTH_REQUIRED") throw error;
    const { auth_url } = await startCloudAuth(providerKind);
    redirectToCloudAuth(auth_url);
    throw new Error("Redirecting to cloud provider authorization...");
  }
  return { fileId: result.remote_file_id, remoteRevision: result.remote_revision ?? "" };
}

/**
 * Create a new local vault and immediately connect Google Drive (§6.2).
 * Local vault must become usable before/during authorization; if Google fails, keep local vault.
 */
export async function createAndConnectCloud(
  createLocalVaultFn: () => Promise<{ vaultId: string }>,
  providerKind: string
): Promise<{ vaultId: string; fileId?: string; error?: string }> {
  const { vaultId } = await createLocalVaultFn();

  try {
    const result = await enableCloudForVault(vaultId, providerKind);
    return { vaultId, fileId: result.fileId };
  } catch (e) {
    // Keep local vault intact, offer retry/continue local-only per spec
    const msg = e instanceof Error ? e.message : String(e);
    if (msg.includes("Redirecting")) {
      // Auth redirect already initiated – don't treat as error
      return { vaultId };
    }
    console.warn("Failed to create remote vault, keeping local vault", e);
    return { vaultId, error: msg };
  }
}
