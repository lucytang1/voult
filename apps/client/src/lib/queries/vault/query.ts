import { useMutation, useQuery, UseQueryOptions } from "@tanstack/react-query";
import {
  UpdateVaultRequest,
  UpdateVaultResponse,
  VaultResponse,
} from "./api.schema";
import { useEffect } from "react";
import { captureSelectionEpoch, updateVaultVersion } from "../../state";
import { http } from "../http";

export async function fetchVault() {
  const response = await http.get<VaultResponse>("/get_vault");
  return response.data;
}

export const useGetVault = (
  options?: Omit<UseQueryOptions<VaultResponse, Error>, "queryKey" | "queryFn">,
  vaultId?: string,
) => {
  const query = useQuery<VaultResponse, Error>({
    queryKey: ["vault", vaultId ?? "current"],
    queryFn: fetchVault,
    ...options,
  });
  const { data } = query;

  // Keep the in-memory version in sync with the latest fetch, but do NOT write
  // client_state.vault_version here — sync() is the sole writer of the persisted
  // base version (see conflict-resolution.md, §4f).
  //
  // M3: guarded, because a fetch issued under vault A can resolve after the
  // user has switched to B. Writing A's version into B's state would corrupt
  // B's sync base version. The epoch advances on every selection change, so it
  // also catches an A→B→A switch that an id comparison would miss.
  useEffect(() => {
    if (!data) return;
    const guard = captureSelectionEpoch();
    // Re-check in a microtask: the response may have landed in the same tick
    // the user committed a switch.
    Promise.resolve().then(() => {
      if (!guard.stillCurrent()) return;
      updateVaultVersion(data.vault.version);
    });
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
