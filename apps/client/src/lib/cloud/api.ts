import { http } from "../queries/http";

// --- Types per provider-neutral interface §4.3 ---

export interface ProviderAccount {
  provider: string;
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
  | "UNKNOWN";

export function isProviderError(error: unknown, code?: ProviderErrorCode): boolean {
  const c = (error as any)?.response?.data?.code as string | undefined;
  if (!c) return false;
  return code ? c === code : true;
}

// --- Google OAuth ---

export async function getCloudStatus(): Promise<{
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
  }>("/cloud/status");
  return res.data;
}

export async function startCloudAuth(provider: string): Promise<{ auth_url: string; state: string }> {
  const res = await http.get<{ auth_url: string; state: string }>("/cloud/auth/start", { params: { provider } });
  return res.data;
}

export async function listCloudVaultsPending(state: string): Promise<VaultDescriptor[]> {
  const res = await http.get<{ vaults: VaultDescriptor[] }>("/cloud/vaults/pending", {
    params: { state },
  });
  return res.data.vaults;
}

export async function readCloudVaultPending(state: string, fileId: string): Promise<{ package: string; remote_revision: string; file_id: string }> {
  const res = await http.get<{ package: string; remote_revision: string; file_id: string }>(
    "/cloud/vaults/pending/read",
    { params: { state, file_id: fileId } }
  );
  return res.data;
}

export async function linkPendingCloudToken(state: string): Promise<{ linked: boolean }> {
  const res = await http.post<{ linked: boolean }>("/cloud/link-pending", { state });
  return res.data;
}

export async function persistCloudBinding(input: { vault_id: string; remote_file_id?: string; provider: string }): Promise<{
  upserted: boolean; provider_kind: string; remote_file_id: string; remote_revision?: string;
}> {
  const { provider, ...binding } = input;
  const res = await http.post<{ upserted: boolean; provider_kind: string; remote_file_id: string; remote_revision?: string }>("/cloud/binding", binding, { params: { provider } });
  return res.data;
}

export interface CloudCredential { kind: string; display_name: string; email?: string }
export async function listCloudCredentials(): Promise<CloudCredential[]> {
  const res = await http.get<{ credentials: CloudCredential[] }>("/cloud/credentials");
  return res.data.credentials;
}

export async function disconnectCloud(): Promise<{ disconnected: boolean }> {
  const res = await http.post<{ disconnected: boolean }>("/cloud/disconnect");
  return res.data;
}

export function redirectToCloudAuth(authUrl: string) {
  // Browser asks local API to start Google authorization – then redirects
  // Uses same-window navigation to preserve session cookie (local Rust server)
  if (typeof window !== "undefined") {
    window.location.href = authUrl;
  }
}

// --- Drive transport ---

export async function listCloudVaults(): Promise<VaultDescriptor[]> {
  const res = await http.get<{ vaults: VaultDescriptor[] }>("/cloud/vaults");
  return res.data.vaults;
}

export async function createCloudVault(vaultId: string, packageB64: string): Promise<{
  file_id: string;
  remote_revision: string;
  vault_id: string;
}> {
  const res = await http.post<{
    file_id: string;
    remote_revision: string;
    vault_id: string;
  }>("/cloud/vaults/create", {
    vault_id: vaultId,
    package: packageB64,
  });
  return res.data;
}

export async function readCloudVault(params: {
  vault_id?: string;
  file_id?: string;
}): Promise<{ package: string; remote_revision: string; file_id: string }> {
  const res = await http.get<{
    package: string;
    remote_revision: string;
    file_id: string;
  }>("/cloud/vaults/read", { params });
  return res.data;
}

export async function replaceCloudVault(params: {
  vault_id?: string;
  file_id?: string;
  package: string;
  if_match_revision?: string;
}): Promise<{ remote_revision: string; file_id: string }> {
  const res = await http.post<{
    remote_revision: string;
    file_id: string;
  }>("/cloud/vaults/replace", params);
  return res.data;
}

export async function deleteCloudVault(params: {
  vault_id?: string;
  file_id?: string;
}): Promise<{ deleted: boolean; file_id: string }> {
  const res = await http.post<{ deleted: boolean; file_id: string }>(
    "/cloud/vaults/delete",
    params
  );
  return res.data;
}

/**
 * Real backup state for the Drive copy of a vault.
 *
 * `remote_revision` alone cannot answer "is my backup current?" — it is the
 * Drive revision, not the vault version it corresponds to.
 * `mirrored_vault_version` vs `vault_version` can, and `versions_behind` is
 * that gap: the number of committed writes the disaster-recovery copy is
 * missing.
 */
export interface CloudBinding {
  vault_id: string;
  provider_kind: string;
  provider_account_id?: string;
  /** Opaque provider file handle. Renamed from `drive_file_id`: the value is
   * provider-agnostic, though for Drive it is a Drive id. */
  remote_file_id?: string;
  remote_revision?: string;
  /** idle | pending | mirroring | auth_required | unlinked | conflict | error */
  sync_status: string;
  /** Current server vault version (the write authority). */
  vault_version: number;
  /** Vault version held in Drive; undefined = never mirrored. */
  mirrored_vault_version?: number;
  /** Committed writes the Drive copy is missing (0 = backup current). */
  versions_behind: number;
  /** Which incarnation of this binding the values above describe. Bumped by a
   * provider switch, enrollment, import or disconnect, so a response that was in
   * flight across one of those can be recognised as stale and dropped. */
  binding_generation: number;
  last_mirrored_at?: string;
  last_mirror_error?: string;
  created_at: string;
  updated_at: string;
}

/**
 * The vault's backup binding, or `null` when this vault has none.
 *
 * A missing binding is a normal state ("not backed up yet"), not an error, so it
 * is returned as `null` rather than surfacing as a rejected query. Everything
 * else still throws, which is what lets the UI distinguish "nothing configured"
 * from "could not load".
 */
export async function getCloudBinding(vaultId: string): Promise<CloudBinding | null> {
  try {
    const res = await http.get<CloudBinding>("/cloud/binding", { params: { vault_id: vaultId } });
    return res.data;
  } catch (error: any) {
    if (error?.response?.status === 404) return null;
    throw error;
  }
}

export async function listCloudBindings(): Promise<CloudBinding[]> {
  const res = await http.get<{ bindings: CloudBinding[] }>("/cloud/bindings");
  return res.data.bindings;
}

/** Result of an explicit "Back up now". Mirrors the server's discriminated union. */
export type MirrorResult =
  | { result: "mirrored"; vault_version: number }
  | { result: "up_to_date"; vault_version: number }
  | { result: "unlinked" }
  | { result: "auth_required" }
  | { result: "conflict" }
  | { result: "unsupported"; reason: string }
  | { result: "error"; code: string };

/**
 * Triggers a backup now and awaits its outcome.
 *
 * The automatic mirror is detached server-side, so this is the only way for the
 * UI to learn what actually happened. It uses the same revision CAS gate, so a
 * retry after a conflict fails again rather than overwriting a Drive copy that
 * changed — "Back up now" means "try again", never "force overwrite".
 */
export async function mirrorCloudVault(): Promise<{
  mirror: MirrorResult;
  binding?: CloudBinding;
}> {
  const res = await http.post<{ mirror: MirrorResult; binding?: CloudBinding }>(
    "/cloud/vaults/mirror"
  );
  return res.data;
}

export interface CloudProviderInfo { kind: string; display_name: string }
export async function listCloudProviders(): Promise<CloudProviderInfo[]> {
  const res = await http.get<{ providers: CloudProviderInfo[] }>("/cloud/providers");
  return res.data.providers;
}

export function packageBytesFromBase64(encoded: string): Uint8Array {
  const g = globalThis as any;
  if (typeof g.atob === "function") return Uint8Array.from(g.atob(encoded), (c: string) => c.charCodeAt(0));
  if (g.Buffer) return g.Buffer.from(encoded, "base64");
  return Uint8Array.from(atob(encoded), (c) => c.charCodeAt(0));
}
export function packageBytesToBase64(bytes: Uint8Array): string {
  const g = globalThis as any;
  if (typeof g.btoa === "function") {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
    return g.btoa(binary);
  }
  if (g.Buffer) return g.Buffer.from(bytes).toString("base64");
  return btoa(String.fromCharCode(...bytes));
}
