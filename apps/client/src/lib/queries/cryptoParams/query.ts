import { useQuery } from "@tanstack/react-query";
import { http } from "../http";
import { SaltResponse } from "./api.schema";


/** Plain fetch used outside React (e.g. the /lock unlock flow). */
export async function fetchCryptoParams(email: string): Promise<SaltResponse> {
  const response = await http.get<SaltResponse>("/get_crypto_params", {
    params: { email },
  });
  return response.data;
}

export const useGetCryptoParams = (email: string, enabled: boolean) => {
  return useQuery<SaltResponse, Error>({
    queryKey: ["cryptoParams", email],
    enabled,
    queryFn: async () => {
      const response = await http.get<SaltResponse>("/get_crypto_params", {
        params: { email },
      });
      return response.data;
    },
  });
};