import { useQuery } from "@tanstack/react-query";
import { http } from "../http";
import { SaltResponse } from "./api.schema";


/** Plain fetch used outside React (e.g. the /lock unlock flow). */
export async function fetchCryptoParams(vaultId: string): Promise<SaltResponse> {
  const response = await http.get<SaltResponse>("/get_crypto_params", {
    params: { vault_id: vaultId },
  });
  return response.data;
}

export const useGetCryptoParams = (vaultId: string, enabled: boolean) => {
  return useQuery<SaltResponse, Error>({
    queryKey: ["cryptoParams", vaultId],
    enabled,
    queryFn: async () => {
      const response = await http.get<SaltResponse>("/get_crypto_params", {
        params: { vault_id: vaultId },
      });
      return response.data;
    },
  });
};
