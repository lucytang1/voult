import { useMutation } from "@tanstack/react-query";
import { http } from "../http";

type LogoutResponse = {
  ok: boolean;
};

export async function logout() {
  const response = await http.post<LogoutResponse>("/logout");
  return response.data;
}

export const useLogout = () => {
  return useMutation<LogoutResponse, Error>({
    mutationFn: logout,
  });
};
