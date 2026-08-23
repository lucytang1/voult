import { useQuery } from "@tanstack/react-query";
import { http } from "../http";
import { SessionResponse } from "./api.schema";

export async function fetchSession() {
  const response = await http.get<SessionResponse>("/session");
  return response.data;
}

export const useGetSession = (enabled = true) => {
  return useQuery<SessionResponse, Error>({
    queryKey: ["session"],
    queryFn: fetchSession,
    enabled,
    retry: false,
  });
};
