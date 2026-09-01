// Provider-neutral interface §4.3
// Google Drive is behind this adapter, not inside merge logic or SyncScheduler.
// Local Rust server is the per-device Google transport boundary.

import * as GoogleApi from "./api";
import type { VaultDescriptor } from "./api";

export interface ProviderAccount {
  provider: "google_drive";
  accountId?: string;
  email?: string;
}

export interface RemoteVaultHandle {
  fileId: string;
  remoteRevision: string;
}

export interface VaultProvider {
  authorize(): Promise<ProviderAccount>;
  disconnect(): Promise<void>;
  listVaults(): Promise<VaultDescriptor[]>;
  readVault(remoteRef: { fileId: string } | { vaultId: string }): Promise<{
    packageBytes: Uint8Array;
    remoteRevision: string;
    fileId: string;
  }>;
  createVault(vaultId: string, packageBytes: Uint8Array): Promise<RemoteVaultHandle>;
  replaceVault(
    remoteRef: { fileId: string } | { vaultId: string },
    packageBytes: Uint8Array,
    ifMatchRevision?: string
  ): Promise<{ remoteRevision: string }>;
  deleteVault(
    remoteRef: { fileId: string } | { vaultId: string },
    ifMatchRevision?: string
  ): Promise<void>;
  getStatus(): Promise<{ connected: boolean; email?: string; providerAccountId?: string }>;
}

class GoogleDriveProvider implements VaultProvider {
  async authorize(): Promise<ProviderAccount> {
    const { auth_url } = await GoogleApi.startGoogleAuth();
    GoogleApi.redirectToGoogleAuth(auth_url);
    // This will redirect; caller should handle navigation
    // Return placeholder; actual account info available after callback via getStatus
    return { provider: "google_drive" };
  }

  async disconnect(): Promise<void> {
    await GoogleApi.disconnectGoogle();
  }

  async listVaults(): Promise<VaultDescriptor[]> {
    return GoogleApi.listGoogleVaults();
  }

  async readVault(remoteRef: { fileId: string } | { vaultId: string }): Promise<{
    packageBytes: Uint8Array;
    remoteRevision: string;
    fileId: string;
  }> {
    const data = await GoogleApi.readGoogleVault(
      "fileId" in remoteRef ? { file_id: remoteRef.fileId } : { vault_id: (remoteRef as any).vaultId }
    );
    // Package is base64 – avoid Buffer type dependency for web
    const bytes = (() => {
      const g = globalThis as any;
      if (typeof g.atob === "function") {
        return Uint8Array.from(g.atob(data.package), (c: string) => c.charCodeAt(0));
      }
      if (g.Buffer) return g.Buffer.from(data.package, "base64");
      // Fallback manual
      return Uint8Array.from(atob(data.package), (c) => c.charCodeAt(0));
    })();
    return { packageBytes: bytes, remoteRevision: data.remote_revision, fileId: data.file_id };
  }

  async createVault(vaultId: string, packageBytes: Uint8Array): Promise<RemoteVaultHandle> {
    const b64 = (() => {
      const g = globalThis as any;
      if (typeof g.btoa === "function") {
        // chunk to avoid call-stack limits
        let binary = "";
        for (let i = 0; i < packageBytes.length; i++) binary += String.fromCharCode(packageBytes[i]);
        return g.btoa(binary);
      }
      if (g.Buffer) return g.Buffer.from(packageBytes).toString("base64");
      return btoa(String.fromCharCode(...packageBytes));
    })();
    const res = await GoogleApi.createGoogleVault(vaultId, b64);
    return { fileId: res.file_id, remoteRevision: res.remote_revision };
  }

  async replaceVault(
    remoteRef: { fileId: string } | { vaultId: string },
    packageBytes: Uint8Array,
    ifMatchRevision?: string
  ): Promise<{ remoteRevision: string }> {
    const b64 = (() => {
      const g = globalThis as any;
      if (typeof g.btoa === "function") {
        let binary = "";
        for (let i = 0; i < packageBytes.length; i++) binary += String.fromCharCode(packageBytes[i]);
        return g.btoa(binary);
      }
      if (g.Buffer) return g.Buffer.from(packageBytes).toString("base64");
      return btoa(String.fromCharCode(...packageBytes));
    })();
    const res = await GoogleApi.replaceGoogleVault({
      ...("fileId" in remoteRef ? { file_id: remoteRef.fileId } : { vault_id: (remoteRef as any).vaultId }),
      package: b64,
      if_match_revision: ifMatchRevision,
    } as any);
    return { remoteRevision: res.remote_revision };
  }

  async deleteVault(remoteRef: { fileId: string } | { vaultId: string }): Promise<void> {
    await GoogleApi.deleteGoogleVault(
      "fileId" in remoteRef ? { file_id: remoteRef.fileId } : { vault_id: (remoteRef as any).vaultId }
    );
  }

  async getStatus(): Promise<{ connected: boolean; email?: string; providerAccountId?: string }> {
    const s = await GoogleApi.getGoogleStatus();
    return { connected: s.connected, email: s.email, providerAccountId: s.provider_account_id };
  }
}

export const googleDriveProvider: VaultProvider = new GoogleDriveProvider();

// Generic factory – currently only Google Drive
export function getProvider(kind: "google_drive" = "google_drive"): VaultProvider {
  return googleDriveProvider;
}
