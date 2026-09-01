import axios from "axios";
import { teardownVaultSession } from "../auth/teardown";

/**
 * Shared HTTP client for the vault API. Credentialed requests (session
 * cookie) are enabled via `withCredentials: true`. On a `SESSION_REQUIRED`
 * response the session is torn down (closes this vault's SQLite DB, deletes
 * this vault's device records, wipes volatile state) so a dead server session
 * can never leak one vault's local data into another's. The query cache is
 * in-memory only here; routing away from authenticated screens drops it.
 * There is no explicit logout — this is the only path back to
 * not_authenticated besides manual cookie removal.
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
      void teardownVaultSession();
    }
    return Promise.reject(error);
  },
);
