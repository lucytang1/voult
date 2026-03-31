import { useMutation, useQuery, UseQueryOptions } from "@tanstack/react-query";
import axios from "axios";
import {
  UpdateVaultRequest,
  UpdateVaultResponse,
  VaultRequest,
  VaultResponse,
} from "./api.schema";
import { useEffect } from "react";
import { upsertVaultVersion } from "../../sqlite/web/services/client-state-service";
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

  useEffect(() => {
    const run = async () => {
      if (data) {
        await updateClientSiteVaultVersion(data.vault.version);
      }
    };
    run();
  }, [data]);
  return query;
};

async function updateClientSiteVaultVersion(version: number) {
  const { result } = await upsertVaultVersion(version);
  if (result) {
    updateVaultVersion(version);
    console.log(result);
  }
}

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
