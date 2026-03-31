import { useQuery } from "@tanstack/react-query";
import axios from "axios";
import { SaltResponse } from "./api.schema";


export const useGetCryptoParams = (email: string, enabled: boolean) => {
  return useQuery<SaltResponse, Error>({
    queryKey: ["cryptoParams", email],
    enabled,
    queryFn: async () => {
      const response = await axios.get<SaltResponse>(
        `${process.env.EXPO_PUBLIC_API_URL}/get_crypto_params`,
        {
          params: { email },
        }
      );
      return response.data;
    },
  });
};