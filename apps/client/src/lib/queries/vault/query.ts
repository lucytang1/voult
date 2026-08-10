import { useMutation, useQuery, UseQueryOptions } from "@tanstack/react-query";
import axios from "axios";
import {
  UpdateVaultRequest,
  UpdateVaultResponse,
  VaultRequest,
  VaultResponse,
} from "./api.schema";
import { useEffect } from "react";
import { updateVaultVersion } from "../../state";

export async function fetchVault(request: VaultRequest) {
  const response = await axios.get<VaultResponse>(
    `${process.env.EXPO_PUBLIC_API_URL}/get_vault`,
    {
      params: {
        email: request.email,
        user_key: request.user_key,
      },
    },
  );
  return response.data;
}
export const useGetVault = (
  request: VaultRequest,
  options?: Omit<UseQueryOptions<VaultResponse, Error>, "queryKey" | "queryFn">,
) => {
  const query = useQuery<VaultResponse, Error>({
    queryKey: ["vault", request.email, request.user_key],
    queryFn: () => fetchVault(request),
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
  const response = await axios.post<UpdateVaultResponse>(
    `${process.env.EXPO_PUBLIC_API_URL}/update_vault`,
    payload,
  );
  return response.data;
}

export const useUpdateVault = () => {
  return useMutation<UpdateVaultResponse, Error, UpdateVaultRequest>({
    mutationFn: updateVault,
  });
};
