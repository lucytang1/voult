import { useMutation } from "@tanstack/react-query";
import { RegisterRequest, RegisterResponse } from "./api.schema";
import { http } from "../http";

export async function register(payload: RegisterRequest): Promise<RegisterResponse> {
  const response = await http.post<RegisterResponse>("/register", payload);
  return response.data;
}

export const useSignUp = () => {
    return useMutation<RegisterResponse, Error, RegisterRequest>({
        mutationFn: register,
        onSuccess: (data) => {
            console.log("SignUp success", data);
        },
        onError: (error) => {
            console.error("SignUp error", error);
        },
    });
}
