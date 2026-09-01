import { http } from "../queries/http";

// --- Types per provider-neutral interface §4.3 ---

export interface ProviderAccount {
  provider: "google_drive";
  accountId?: string;
  email?: string;
  scope?: string;
}

export interface VaultDescriptor {
  vault_id: string;
  file_id: string;
  name: string;
  modified_time?: string;
  size?: string;
  head_revision_id?: string;
  version?: string;
}

export type ProviderErrorCode =
  | "PROVIDER_AUTH_REQUIRED"
  | "PROVIDER_WRONG_ACCOUNT"
  | "PROVIDER_PERMISSION_DENIED"
  | "REMOTE_CONFLICT"
  | "REMOTE_UNAVAILABLE"
  | "REMOTE_DELETED"
  | "VAULT_NOT_FOUND"
  | "PACKAGE_INVALID"
  | "PROVIDER_RATE_LIMITED"
  | "GOOGLE_NOT_CONFIGURED"
  | "UNKNOWN";

export function isProviderError(error: unknown, code?: ProviderErrorCode): boolean {
  const c = (error as any)?.response?.data?.code as string | undefined;
  if (!c) return false;
  return code ? c === code : true;
}

// --- Google OAuth ---

export async function getGoogleStatus(): Promise<{
  connected: boolean;
  email?: string;
  provider_account_id?: string;
  scope?: string;
}> {
  const res = await http.get<{
    connected: boolean;
    email?: string;
    provider_account_id?: string;
    scope?: string;
  }>("/google/status");
  return res.data;
}

export async function startGoogleAuth(): Promise<{ auth_url: string; state: string }> {
  const res = await http.get<{ auth_url: string; state: string }>("/google/auth/start");
  return res.data;
}

export async function startGoogleAuthPublic(email: string): Promise<{ auth_url: string; state: string }> {
  const res = await http.get<{ auth_url: string; state: string }>("/google/auth/start", {
    params: { email },
  });
  return res.data;
}

export async function listGoogleVaultsPending(state: string): Promise<VaultDescriptor[]> {
  const res = await http.get<{ vaults: VaultDescriptor[] }>("/google/vaults/pending", {
    params: { state },
  });
  return res.data.vaults;
}

export async function readGoogleVaultPending(state: string, fileId: string): Promise<{ package: string; remote_revision: string; file_id: string }> {
  const res = await http.get<{ package: string; remote_revision: string; file_id: string }>(
    "/google/vaults/pending/read",
    { params: { state, file_id: fileId } }
  );
  return res.data;
}

export async function linkPendingGoogleToken(state: string): Promise<{ linked: boolean }> {
  const res = await http.post<{ linked: boolean }>("/google/link-pending", { state });
  return res.data;
}

export async function disconnectGoogle(): Promise<{ disconnected: boolean }> {
  const res = await http.post<{ disconnected: boolean }>("/google/disconnect");
  return res.data;
}

export function redirectToGoogleAuth(authUrl: string) {
  // Browser asks local API to start Google authorization – then redirects
  // Uses same-window navigation to preserve session cookie (local Rust server)
  if (typeof window !== "undefined") {
    window.location.href = authUrl;
  }
}

// --- Drive transport ---

export async function listGoogleVaults(): Promise<VaultDescriptor[]> {
  const res = await http.get<{ vaults: VaultDescriptor[] }>("/google/vaults");
  return res.data.vaults;
}

export async function createGoogleVault(vaultId: string, packageB64: string): Promise<{
  file_id: string;
  remote_revision: string;
  vault_id: string;
}> {
  const res = await http.post<{
    file_id: string;
    remote_revision: string;
    vault_id: string;
  }>("/google/vaults/create", {
    vault_id: vaultId,
    package: packageB64,
  });
  return res.data;
}

export async function readGoogleVault(params: {
  vault_id?: string;
  file_id?: string;
}): Promise<{ package: string; remote_revision: string; file_id: string }> {
  const res = await http.get<{
    package: string;
    remote_revision: string;
    file_id: string;
  }>("/google/vaults/read", { params });
  return res.data;
}

export async function replaceGoogleVault(params: {
  vault_id?: string;
  file_id?: string;
  package: string;
  if_match_revision?: string;
}): Promise<{ remote_revision: string; file_id: string }> {
  const res = await http.post<{
    remote_revision: string;
    file_id: string;
  }>("/google/vaults/replace", params);
  return res.data;
}

export async function deleteGoogleVault(params: {
  vault_id?: string;
  file_id?: string;
}): Promise<{ deleted: boolean; file_id: string }> {
  const res = await http.post<{ deleted: boolean; file_id: string }>(
    "/google/vaults/delete",
    params
  );
  return res.data;
}

export async function getGoogleBinding(vaultId: string): Promise<{
  vault_id: string;
  provider_kind: string;
  provider_account_id?: string;
  drive_file_id?: string;
  remote_revision?: string;
  sync_status: string;
}> {
  const res = await http.get<{
    vault_id: string;
    provider_kind: string;
    provider_account_id?: string;
    drive_file_id?: string;
    remote_revision?: string;
    sync_status: string;
  }>("/google/binding", { params: { vault_id: vaultId } });
  return res.data;
}

export async function listGoogleBindings(): Promise<
  Array<{
    vault_id: string;
    provider_kind: string;
    provider_account_id?: string;
    drive_file_id?: string;
    remote_revision?: string;
    sync_status: string;
  }>
> {
  const res = await http.get<{ bindings: Array<{
    vault_id: string;
    provider_kind: string;
    provider_account_id?: string;
    drive_file_id?: string;
    remote_revision?: string;
    sync_status: string;
  }> }>("/google/bindings");
  return res.data.bindings;
}

// --- Helper to detect if Google is configured ---
export async function isGoogleConfigured(): Promise<boolean> {
  try {
    await startGoogleAuth();
    // If it returns auth_url, it's configured – but we don't want to create state unnecessarily
    // So just check status with special handling: if GOOGLE_NOT_CONFIGURED, it would have 500
    // Instead, we can try getGoogleStatus and see if it ever returns GOOGLE_NOT_CONFIGURED
    return true;
  } catch (e: any) {
    const code = e?.response?.data?.code as string | undefined;
    if (code === "GOOGLE_NOT_CONFIGURED") return false;
    // If we got auth_url even with error, still configured
    // For now, assume configured if start didn't return GOOGLE_NOT_CONFIGURED
    // Fallback: check status
    try {
      await getGoogleStatus();
      return true;
    } catch (e2: any) {
      const c2 = e2?.response?.data?.code as string | undefined;
      if (c2 === "GOOGLE_NOT_CONFIGURED") return false;
      return true;
    }
  }
}
