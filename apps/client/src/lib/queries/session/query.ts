import { useQuery } from "@tanstack/react-query";
import { http } from "../http";
import { SessionResponse } from "./api.schema";

export async function fetchSession() {
  const response = await http.get<SessionResponse>("/session");
  return response.data;
}

/**
 * Global lock write-through (web ↔ extension consistency). Bumps the vault's
 * `lock_epoch` so peers observe it on their next check-on-use `GET /session`
 * and wipe keys. Best-effort: callers still lock locally when offline and
 * retry the push on the next online trigger.
 */
export async function postLock(): Promise<{ lock_epoch: number }> {
  const response = await http.post<{ lock_epoch: number }>("/lock");
  return response.data;
}

/** Destroys the caller's session cookie. Idempotent (see POST /api/logout). */
export async function postLogout(): Promise<{ ok: boolean }> {
  const response = await http.post<{ ok: boolean }>("/logout");
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
