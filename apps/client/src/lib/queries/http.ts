import axios from "axios";
import { teardownVaultSession } from "../auth/teardown";
import { queryClient } from "./client";

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

/** Absolute or root-relative URL for a same-origin API path (e.g. the
 * favicon proxy used as an <img> source — plain strings, not axios, so the
 * base must be applied manually). Relative in production (same-origin serve),
 * absolute against EXPO_PUBLIC_API_URL in split-origin dev. */
export function apiUrl(path: string): string {
  const base = (process.env.EXPO_PUBLIC_API_URL || "/api").replace(/\/+$/, "");
  const clean = path.startsWith("/") ? path : `/${path}`;
  return `${base}${clean}`;
}

/** Same-origin URL that proxies a vault icon through the backend (required:
 * the app's COEP `require-corp` header makes the browser refuse cross-origin
 * `<img>` loads, and favicon hosts don't send CORP). Session cookie still
 * applies: same-origin in production; split-origin dev loads fall back to the
 * letter tile (background <img> sends no cookies cross-origin). */
export function proxiedFaviconUrl(iconUrl: string): string {
  return apiUrl(`/favicon?u=${encodeURIComponent(iconUrl)}`);
}

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
