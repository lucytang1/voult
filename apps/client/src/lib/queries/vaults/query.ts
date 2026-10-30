import { http } from "../http";
import { useQuery } from "@tanstack/react-query";

export interface CreateVaultRequest {
  vault_id?: string;
  vault: string;
  vaultiv: string;
  salt: string;
  iterations: number;
  // Required by the server: the only supported crypto version (2). There is no
  // default, because a missing value used to create a v1 row that could never
  // be backed up or recovered.
  crypto_version: number;
  vault_key_wrap: string;
  vault_key_wrap_iv: string;
  vault_verifier: string;
  recovery_verifier: string;
  recovery_salt: string;
  recovery_wrap: string;
  recovery_wrap_iv: string;
}

export interface CreateVaultResponse {
  vault_id: string;
  vault: string;
  vaultiv: string;
  salt: string;
  iterations: number;
  version: number;
  crypto_version: number;
}

export async function createVault(payload: CreateVaultRequest): Promise<CreateVaultResponse> {
  const res = await http.post<CreateVaultResponse>("/vaults", payload);
  return res.data;
}

/** Vault summaries are server state; keep them out of component-owned copies. */
export function useVaultList(enabled: boolean, vaultId?: string) {
  return useQuery({
    queryKey: ["vaults", vaultId ?? "anonymous"],
    queryFn: listVaults,
    enabled,
    staleTime: 30_000,
  });
}

export interface VaultSummary {
  vault_id: string;
  version: number;
  crypto_version: number;
  created_at: string;
}

export async function listVaults(): Promise<VaultSummary[]> {
  const res = await http.get<{ vaults: VaultSummary[] }>("/vaults");
  return res.data.vaults;
}
