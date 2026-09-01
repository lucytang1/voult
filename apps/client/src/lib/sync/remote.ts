import { VaultItem } from "../state/type";
import { decrypt, encrypt, b64 } from "../crypto/index.web";
import { VAULT_FORMAT_VERSION, createVoultPackage } from "../crypto/vault";
import { fetchVault, fetchVaultWithId, updateVault } from "../queries/vault/query";
import { fetchCryptoParams } from "../queries/cryptoParams/query";
import { getGoogleBinding } from "../google/api";
import { googleDriveProvider } from "../google/provider";
import { isNetworkError } from "../queries/http";

/**
 * Provider-neutral remote interface for sync (§8)
 * Local server is per-device cache; Google Drive revision is cross-device authority.
 */

export interface RemoteSnapshot {
  items: VaultItem[];
  remoteRevision: string; // for Google: headRevisionId|version, for local: version as string
  version: number; // logicalRevision for package / vault.version for local
  packageBytes?: Uint8Array; // raw package for Google
  fileId?: string;
}

export interface VaultRemote {
  kind: "local" | "google_drive";
  read(vaultKey: CryptoKey, vaultId: string): Promise<RemoteSnapshot>;
  write(
    items: VaultItem[],
    vaultKey: CryptoKey,
    vaultId: string,
    baseRevision: string
  ): Promise<{ remoteRevision: string; version: number }>;
}

class LocalRemote implements VaultRemote {
  kind: "local" = "local" as const;
  async read(vaultKey: CryptoKey, vaultId: string): Promise<RemoteSnapshot> {
    // Use vaultId-scoped fetch if provided, else default
    const response = vaultId ? await fetchVaultWithId(vaultId) : await fetchVault();
    const plain = await decrypt(response.vault.vault, response.vault.vaultiv, vaultKey);
    let items: VaultItem[] = [];
    try {
      const parsed = JSON.parse(plain) as { items?: VaultItem[] };
      items = parsed.items ?? [];
    } catch {
      items = [];
    }
    return {
      items,
      remoteRevision: String(response.vault.version),
      version: response.vault.version,
    };
  }

  async write(items: VaultItem[], vaultKey: CryptoKey, vaultId: string, baseRevision: string): Promise<{ remoteRevision: string; version: number }> {
    const doc = vaultId
      ? { formatVersion: VAULT_FORMAT_VERSION, vaultId, items }
      : { items };
    const enc = await encrypt(JSON.stringify(doc), vaultKey);
    const res = await updateVault({
      vault: b64(enc.cipher),
      vaultiv: b64(enc.iv),
      version: Number(baseRevision),
    });
    return { remoteRevision: String(res.version), version: res.version };
  }
}

class GoogleRemote implements VaultRemote {
  kind: "google_drive" = "google_drive" as const;

  async read(vaultKey: CryptoKey, vaultId: string): Promise<RemoteSnapshot> {
    // Read package from Drive via local transport
    const { packageBytes, remoteRevision, fileId } = await googleDriveProvider.readVault({ vaultId });
    const text = new TextDecoder().decode(packageBytes);
    let pkg: any;
    try {
      pkg = JSON.parse(text);
    } catch (e) {
      throw new Error("Downloaded Google package is invalid JSON");
    }
    if (pkg.vaultId !== vaultId) {
      throw new Error(`Package vaultId mismatch: expected ${vaultId}, got ${pkg.vaultId}`);
    }
    // Snapshot is encrypted
    const snapshot = pkg.snapshot as { ciphertext: string; iv: string };
    if (!snapshot?.ciphertext || !snapshot?.iv) throw new Error("Package missing snapshot");
    const plain = await decrypt(snapshot.ciphertext, snapshot.iv, vaultKey);
    let items: VaultItem[] = [];
    try {
      const parsed = JSON.parse(plain) as { items?: VaultItem[]; vaultId?: string };
      items = parsed.items ?? [];
    } catch {
      items = [];
    }
    return {
      items,
      remoteRevision,
      version: pkg.logicalRevision ?? 0,
      packageBytes,
      fileId,
    };
  }

  async write(items: VaultItem[], vaultKey: CryptoKey, vaultId: string, baseRevision: string): Promise<{ remoteRevision: string; version: number }> {
    // Need to fetch current package to preserve crypto params and envelope, then update snapshot and logicalRevision
    // Fetch current to get crypto params
    let currentPkg: any = null;
    let fileId: string | undefined;
    try {
      const { packageBytes, remoteRevision: curRev, fileId: fid } = await googleDriveProvider.readVault({ vaultId });
      fileId = fid;
      const text = new TextDecoder().decode(packageBytes);
      currentPkg = JSON.parse(text);
      // Verify revision matches baseRevision for CAS
      if (String(curRev) !== String(baseRevision)) {
        throw Object.assign(new Error("REMOTE_CONFLICT"), { code: "REMOTE_CONFLICT", response: { status: 409 } });
      }
    } catch (e: any) {
      if (e?.code === "REMOTE_CONFLICT" || e?.response?.status === 409) throw e;
      // If read fails, try to build from local vault cache as fallback
      const vaultData = await fetchVaultWithId(vaultId);
      const params = await fetchCryptoParams(vaultId);
      currentPkg = {
        vaultId,
        packageFormatVersion: 1,
        logicalRevision: vaultData.vault.version,
        cryptoVersion: vaultData.vault.crypto_version,
        cryptoParameters: { salt: params.salt, iterations: params.iterations },
        snapshot: { ciphertext: vaultData.vault.vault, iv: vaultData.vault.vaultiv },
        passwordKeyEnvelope: { wrappedVaultKey: vaultData.vault.vault_key_wrap!, iv: vaultData.vault.vault_key_wrap_iv! },
      };
      // Try to get fileId from binding if read failed due to network but package exists
      try {
        const binding = await getGoogleBinding(vaultId);
        fileId = binding.drive_file_id || undefined;
      } catch {}
    }

    if (!fileId) {
      // Fallback to binding lookup
      try {
        const binding = await getGoogleBinding(vaultId);
        fileId = binding.drive_file_id || undefined;
      } catch {}
    }
    if (!fileId) throw new Error("No Drive fileId for vault – cannot replace");

    // Build new snapshot
    const doc = { formatVersion: VAULT_FORMAT_VERSION, vaultId, items };
    const enc = await encrypt(JSON.stringify(doc), vaultKey);
    const newPkg = {
      ...currentPkg,
      vaultId,
      logicalRevision: (currentPkg.logicalRevision ?? 0) + 1,
      snapshot: { ciphertext: b64(enc.cipher), iv: b64(enc.iv) },
    };
    const newBytes = new TextEncoder().encode(JSON.stringify(newPkg));

    const res = await googleDriveProvider.replaceVault({ fileId }, newBytes, baseRevision);
    return { remoteRevision: res.remoteRevision, version: newPkg.logicalRevision };
  }
}

export async function getVaultRemote(vaultId: string): Promise<VaultRemote> {
  // Check if vault is cloud-backed via binding
  try {
    const binding = await getGoogleBinding(vaultId);
    if (binding.drive_file_id) {
      // Also check Google status is connected?
      return new GoogleRemote();
    }
  } catch {
    // No binding or not connected – fallback to local
  }
  return new LocalRemote();
}

export function isGoogleRemoteError(error: unknown): boolean {
  const code = (error as any)?.response?.data?.code as string | undefined;
  return code === "PROVIDER_AUTH_REQUIRED" || code === "REMOTE_CONFLICT" || code === "REMOTE_UNAVAILABLE" || code === "VAULT_NOT_FOUND";
}
