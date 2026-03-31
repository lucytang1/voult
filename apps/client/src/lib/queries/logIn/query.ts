import { useMutation } from "@tanstack/react-query";
import axios from "axios";
import { LoginRequest, LoginResponse } from "./api.schema";

export const useLogIn = () => {
  return useMutation<LoginResponse, Error, LoginRequest>({
    mutationFn: async (payload) => {
      const response = await axios.post<LoginResponse>(
        `${process.env.EXPO_PUBLIC_API_URL}/auth`,
        payload
      );
      return response.data;
    },

    onSuccess: (data) => {
      globalThis.localStorage.setItem("email", data.user.email);
    }
  });
};
