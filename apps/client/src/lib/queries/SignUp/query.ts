import { useMutation } from "@tanstack/react-query";
import { RegisterRequest, RegisterResponse } from "./api.schema";
import axios from "axios";

export const useSignUp = () => {
    return useMutation<RegisterResponse, Error, RegisterRequest>({
        mutationFn: async (payload) => {
            console.log("SignUp request", payload);
            const response = await axios.post<RegisterResponse>(`${process.env.EXPO_PUBLIC_API_URL}/register`, payload);
            console.log("SignUp response status", response.status);
            return response.data;
        },
        onSuccess: (data) => {
            console.log("SignUp success", data);
        },
        onError: (error) => {
            console.error("SignUp error", error);
        },
    });
}