/**
 * API base URL helpers.
 *
 * Deliberately dependency-free: the favicon cache needs the proxy URL but must
 * not pull in the shared axios client (and, through it, the session teardown
 * path) — importing `http.ts` from the icon cache would create an import cycle
 * with `auth/teardown.ts`.
 */

/** Same API root the shared axios client uses: `EXPO_PUBLIC_API_URL`, else the
 * same origin's `/api` (production is served by the backend). */
export function apiUrl(path: string): string {
  const base = (process.env.EXPO_PUBLIC_API_URL || "/api").replace(/\/+$/, "");
  const clean = path.startsWith("/") ? path : `/${path}`;
  return `${base}${clean}`;
}

/**
 * Same-origin URL that proxies a vault icon through the backend (required: the
 * app's COEP `require-corp` header makes the browser refuse cross-origin
 * loads, and favicon hosts don't send CORP). The session cookie still applies:
 * same-origin in production, and the caller must send credentials in
 * split-origin dev, which is why the icon cache fetches this with axios
 * instead of handing it to an `<img>`.
 */
export function proxiedFaviconUrl(iconUrl: string): string {
  return apiUrl(`/favicon?u=${encodeURIComponent(iconUrl)}`);
}
