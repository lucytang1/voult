import { useEffect, useSyncExternalStore } from "react";
import {
  ensureFavicon,
  faviconEntry,
  subscribeFavicons,
  type FaviconEntry,
} from ".";

/**
 * Reads one item's icon from the cache and fetches it on a miss.
 *
 * The read is **synchronous and render-time** (`useSyncExternalStore`), which
 * is the whole point: once `hydrateFavicons` has run, the icon is present in
 * the first paint of the row rather than arriving a frame (or a second) later
 * and replacing the fallback glyph.
 *
 * `undefined` means "nothing known yet" — the caller should show its fallback.
 * A resolved entry with `failed: true` means "tried, there is nothing to show",
 * and no further request is made for it until the negative entry expires.
 */
export function useFavicon(
  vaultId: string | null | undefined,
  url: string | undefined,
): FaviconEntry | undefined {
  const entry = useSyncExternalStore(
    subscribeFavicons,
    () => (vaultId && url ? faviconEntry(vaultId, url) : undefined),
    // No server snapshot: this is a browser-only cache and the app renders its
    // own fallback until the client has an answer.
    () => undefined,
  );

  // `entry` is in the dependency list on purpose: when the fetch lands and the
  // store notifies, this effect re-runs with a resolved entry and stops.
  useEffect(() => {
    if (!vaultId || !url || entry) return;
    void ensureFavicon(vaultId, url).catch(() => undefined);
  }, [vaultId, url, entry]);

  return entry;
}
