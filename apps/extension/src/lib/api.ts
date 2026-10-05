// Server API client for the extension service worker.
//
// Same endpoints as the web app (`apps/server/src/main.rs` /api scope),
// same zero-knowledge contract: only vault_id + vault_verifier + ciphertext +
// KDF params cross the wire. Requests use `credentials: "include"` so the
// HttpOnly `voult_session` cookie flows; this requires the extension origin in
// the server's CORS allowlist (see plans/chrome-extension-mv3.md §8) plus
// `host_permissions` for the server origin in the manifest.
//
// M0 default is localhost-only. M1 adds a settings-stored server URL with
// http-rejection outside the loopback allowlist.

import type { UpdateVaultRequest, UpdateVaultResponse, VaultResponse } from "@voult/vault-core";

export const DEFAULT_SERVER_URL = "http://localhost:8080";

export function apiBase(serverUrl: string): string {
  return `${serverUrl.replace(/\/+$/, "")}/api`;
}

async function request<T>(path: string, init: RequestInit, serverUrl: string): Promise<T> {
  const res = await fetch(`${apiBase(serverUrl)}${path}`, {
    ...init,
    credentials: "include",
    headers: { "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`API ${path} failed: ${res.status} ${body.slice(0, 200)}`);
  }
  return (await res.json()) as T;
}

export async function fetchCryptoParams(
  vaultId: string,
  serverUrl = DEFAULT_SERVER_URL,
): Promise<{ salt: string; iterations: number }> {
  const res = await fetch(`${apiBase(serverUrl)}/get_crypto_params?vault_id=${encodeURIComponent(vaultId)}`, {
    credentials: "include",
  });
  if (!res.ok) throw new Error(`get_crypto_params failed: ${res.status}`);
  return (await res.json()) as { salt: string; iterations: number };
}

export async function postAuth(
  vaultId: string,
  vaultVerifier: string,
  serverUrl = DEFAULT_SERVER_URL,
): Promise<{ vault_id: string }> {
  return request(
    "/auth",
    { method: "POST", body: JSON.stringify({ vault_id: vaultId, vault_verifier: vaultVerifier }) },
    serverUrl,
  );
}

export async function fetchVault(serverUrl = DEFAULT_SERVER_URL): Promise<VaultResponse> {
  const res = await fetch(`${apiBase(serverUrl)}/get_vault`, { credentials: "include" });
  if (!res.ok) throw new Error(`get_vault failed: ${res.status}`);
  return (await res.json()) as VaultResponse;
}

export async function postUpdateVault(
  payload: UpdateVaultRequest,
  serverUrl = DEFAULT_SERVER_URL,
): Promise<UpdateVaultResponse> {
  return request("/update_vault", { method: "POST", body: JSON.stringify(payload) }, serverUrl);
}

export interface SessionStatus {
  authenticated: boolean;
  vault_id: string;
  crypto_version: number;
  // Global lock signal (POST /api/lock bumps it). Absent on old servers —
  // callers treat undefined as 0.
  lock_epoch?: number;
}

export async function fetchSession(serverUrl = DEFAULT_SERVER_URL): Promise<SessionStatus> {
  const res = await fetch(`${apiBase(serverUrl)}/session`, { credentials: "include" });
  if (!res.ok) throw new Error(`session probe failed: ${res.status}`);
  return (await res.json()) as SessionStatus;
}

export async function postLogout(serverUrl = DEFAULT_SERVER_URL): Promise<void> {
  const res = await fetch(`${apiBase(serverUrl)}/logout`, {
    method: "POST",
    credentials: "include",
  });
  if (!res.ok) throw new Error(`logout failed: ${res.status}`);
}

/**
 * Global lock write-through. Bumps the vault's lock_epoch so the web app
 * observes it on its next check-on-use GET /session and wipes keys.
 * Best-effort: callers still lock locally when offline.
 */
export async function postLock(serverUrl = DEFAULT_SERVER_URL): Promise<{ lock_epoch: number }> {
  return request<{ lock_epoch: number }>("/lock", { method: "POST" }, serverUrl);
}

export function isVersionConflict(error: unknown): boolean {
  return error instanceof Error && error.message.includes(" 409 ");
}

export function isNetworkError(error: unknown): boolean {
  return error instanceof TypeError;
}
