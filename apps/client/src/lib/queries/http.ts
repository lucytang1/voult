import axios from "axios";
import { teardownVaultSession } from "../auth/teardown";
import { queryClient } from "./client";

/**
 * Shared HTTP client for the vault API. Credentialed requests (session
 * cookie) are enabled via `withCredentials: true`.
 *
 * On a `SESSION_REQUIRED` response the centralized session handler runs: an
 * unlocked vault keeps its key and plaintext (local use continues, sync pauses)
 * and only `serverSession` becomes `missing`; a locked vault stays locked. The
 * vault selection and local device material are never dropped — a dead cookie
 * is an authorization fact, not a change of identity and not a lock. A locked
 * vault's user re-authenticates with the master password (see
 * `reauthenticateAndUnlock`).
 *
 * The query cache is in-memory only; it is cleared for a locked vault so no
 * ciphertext outlives the session, but kept while the vault is open. There is no
 * user-facing logout/deselect action.
 */
export const http = axios.create({
  // Falls back to the same origin's /api root when served by the backend.
  baseURL: process.env.EXPO_PUBLIC_API_URL || "/api",
  withCredentials: true,
});

export function isSessionRequired(error: unknown): boolean {
  return (
    (error as { response?: { status?: number; data?: { code?: string } } })
      ?.response?.status === 401 &&
    (error as { response?: { data?: { code?: string } } })?.response?.data
      ?.code === "SESSION_REQUIRED"
  );
}

/**
 * True when the request never got an HTTP response (server down, DNS failure,
 * CORS/network outage). Offline is a normal state for the intent queue — sync
 * callers use this to back off quietly instead of erroring.
 */
export function isNetworkError(error: unknown): boolean {
  return !(
    error as { response?: unknown }
  )?.response;
}

http.interceptors.response.use(
  (response) => response,
  (error) => {
    if (isSessionRequired(error)) {
      void teardownVaultSession(queryClient);
    }
    return Promise.reject(error);
  },
);
