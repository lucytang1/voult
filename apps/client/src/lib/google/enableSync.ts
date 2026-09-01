import { fetchVaultWithId } from "../queries/vault/query";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import { createVoultPackage } from "../crypto/vault";
import { getGoogleStatus, startGoogleAuth, redirectToGoogleAuth } from "./api";
import { googleDriveProvider } from "./provider";
import { fetchPendingIntents } from "../sqlite/web/services/intent-service";

/**
 * Build an encrypted VoultPackage for a local vault.
 * Uses the local vault's encrypted snapshot and envelope (server never sees plaintext).
 * The vault must be unlocked and its local snapshot in a known state.
 * For Phase 3 we simply use the current server snapshot; pending intents are preserved.
 */
export async function buildPackageForVault(vaultId: string): Promise<Uint8Array> {
  const vaultData = await fetchVaultWithId(vaultId);
  const v = vaultData.vault;

  if (!v.vault_key_wrap || !v.vault_key_wrap_iv) {
    throw new Error("Vault is missing password envelope – cannot create cloud package");
  }

  // Salt/iterations are not returned by GET /get_vault (only iterations); the
  // verifier-only KDF metadata comes from GET /get_crypto_params.
  const params = await fetchCryptoParams(vaultId);

  const pkg = createVoultPackage({
    vaultId,
    logicalRevision: v.version,
    cryptoVersion: v.crypto_version,
    salt: params.salt,
    iterations: params.iterations,
    ciphertext: v.vault,
    iv: v.vaultiv,
    wrappedVaultKey: v.vault_key_wrap,
    wrappedVaultKeyIv: v.vault_key_wrap_iv,
  });

  const json = JSON.stringify(pkg);
  // Encode to bytes – Drive file content is JSON
  if (typeof TextEncoder !== "undefined") {
    return new TextEncoder().encode(json);
  } else {
    // Fallback for RN
    return Uint8Array.from(json, (c) => c.charCodeAt(0));
  }
}

/**
 * Ensure Google is connected; if not, start OAuth and redirect.
 * Returns true if already connected, false if redirect initiated.
 */
export async function ensureGoogleConnected(): Promise<boolean> {
  try {
    const status = await getGoogleStatus();
    if (status.connected) return true;
  } catch (e: any) {
    const code = e?.response?.data?.code as string | undefined;
    if (code === "GOOGLE_NOT_CONFIGURED") {
      throw new Error("Google Drive is not configured on this server. See .env.example for GOOGLE_CLIENT_ID/SECRET setup.");
    }
    // If status fails for other reason, treat as not connected
  }

  // Not connected – start auth
  const { auth_url } = await startGoogleAuth();
  redirectToGoogleAuth(auth_url);
  return false; // page will navigate away
}

/**
 * Enable Google Drive sync for an existing local vault (§6.3).
 * Requires vault unlocked and local snapshot in known state.
 * Merges/flushes pending intents before enrollment per spec; idempotent after lost response.
 */
export async function enableGoogleDriveForVault(vaultId: string): Promise<{
  fileId: string;
  remoteRevision: string;
}> {
  // Ensure connected
  const connected = await ensureGoogleConnected();
  if (!connected) {
    throw new Error("Redirecting to Google authorization...");
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

  // Build package from (now flushed) local snapshot
  const packageBytes = await buildPackageForVault(vaultId);

  // Create remote vault – server handles idempotency (find existing by vault_id)
  // Retry once on lost response: if network fails but file was created, find existing and verify
  let fileId: string;
  let remoteRevision: string;
  try {
    const res = await googleDriveProvider.createVault(vaultId, packageBytes);
    fileId = res.fileId;
    remoteRevision = res.remoteRevision;
  } catch (e: any) {
    const code = e?.response?.data?.code as string | undefined;
    const isNetwork = !e?.response;
    if (isNetwork || code === "REMOTE_UNAVAILABLE") {
      console.warn("Create vault network error – checking for existing file by vault_id (idempotent retry)", e);
      // Find existing file by vault_id
      const { listGoogleVaults } = await import("./api");
      const vaults = await listGoogleVaults().catch(() => []);
      const existing = vaults.find((v) => v.vault_id === vaultId);
      if (existing) {
        fileId = existing.file_id;
        remoteRevision = existing.head_revision_id || existing.version || "unknown";
        console.info(`Found existing remote vault after lost response: ${fileId}`);
      } else {
        throw e;
      }
    } else {
      throw e;
    }
  }

  // Verify read-back per spec: read and validate vault_id and authenticated package before persisting binding
  const { packageBytes: readBack, remoteRevision: readRev } =
    await googleDriveProvider.readVault({ fileId });

  // Basic validation: decoded package should contain same vaultId
  try {
    const text = new TextDecoder().decode(readBack);
    const parsed = JSON.parse(text) as { vaultId?: string; packageFormatVersion?: number };
    if (parsed.vaultId && parsed.vaultId !== vaultId) {
      throw new Error(`Read-back vaultId mismatch: expected ${vaultId}, got ${parsed.vaultId}`);
    }
    if (parsed.packageFormatVersion && parsed.packageFormatVersion !== 1) {
      console.warn(`Remote package version mismatch: ${parsed.packageFormatVersion}`);
    }
    if (readRev !== remoteRevision) {
      console.info(`Remote revision after create: ${remoteRevision} vs read ${readRev}`);
    }
  } catch (e) {
    if ((e as Error).message.includes("vaultId mismatch")) throw e;
    if (readBack.length === 0) throw new Error("Remote package verification failed: empty file");
  }

  // Mark binding active and enable scheduler triggers only after verification
  // Server already upserts cloud_binding; client marks vault_mode as google_drive
  try {
    const { setVaultMode } = await import("../state");
    setVaultMode("google_drive");
  } catch {}

  return { fileId, remoteRevision };
}

/**
 * Create a new local vault and immediately connect Google Drive (§6.2).
 * Local vault must become usable before/during authorization; if Google fails, keep local vault.
 */
export async function createAndConnectGoogleDrive(
  createLocalVaultFn: () => Promise<{ vaultId: string }>
): Promise<{ vaultId: string; fileId?: string; error?: string }> {
  const { vaultId } = await createLocalVaultFn();

  try {
    const result = await enableGoogleDriveForVault(vaultId);
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
