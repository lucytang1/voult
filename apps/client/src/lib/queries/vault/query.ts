import { useMutation, useQuery, UseQueryOptions } from "@tanstack/react-query";
import {
  UpdateVaultRequest,
  UpdateVaultResponse,
  VaultResponse,
} from "./api.schema";
import { useEffect } from "react";
import { updateVaultVersion } from "../../state";
import { http } from "../http";

export async function fetchVault() {
  const response = await http.get<VaultResponse>("/get_vault");
  return response.data;
}

export const useGetVault = (
  options?: Omit<UseQueryOptions<VaultResponse, Error>, "queryKey" | "queryFn">,
) => {
  const query = useQuery<VaultResponse, Error>({
    queryKey: ["vault"],
    queryFn: fetchVault,
    ...options,
  });
  const { data } = query;

  // Keep the in-memory version in sync with the latest fetch, but do NOT write
  // client_state.vault_version here — sync() is the sole writer of the persisted
  // base version (see conflict-resolution.md, §4f).
  useEffect(() => {
    if (data) {
      updateVaultVersion(data.vault.version);
    }
  }, [data]);
  return query;
};

export async function updateVault(
  payload: UpdateVaultRequest,
): Promise<UpdateVaultResponse> {
  const response = await http.post<UpdateVaultResponse>("/update_vault", payload);
  return response.data;
}

export const useUpdateVault = () => {
  return useMutation<UpdateVaultResponse, Error, UpdateVaultRequest>({
    mutationFn: updateVault,
  });
};

export async function fetchVaultWithId(vaultId:string){ return fetchVault(); }
