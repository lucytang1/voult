import { useMutation } from "@tanstack/react-query";
import { http } from "../http";
import { LoginRequest, LoginResponse } from "./api.schema";

export async function login(payload: LoginRequest): Promise<LoginResponse> {
  const response = await http.post<LoginResponse>("/auth", payload);
  return response.data;
}

export const useLogIn = () => {
  return useMutation<LoginResponse, Error, LoginRequest>({
    mutationFn: login,
  });
};
