/**
 * Site-icon cache for the vault list.
 *
 * Why this module exists: icons used to ride a per-row `useQuery` that fetched
 * through `/api/favicon` on every mount. The query cache is in-memory, the
 * server answers `no-store`, and a reload wipes everything — so every launch
 * re-fetched every icon, and the list painted the fallback glyph first and the
 * real icon seconds later (or never, for URLs that 404).
 *
 * The fix is two layers:
 *
 *  1. **Memory** — a synchronous `Map`, so a warm icon is available during the
 *     very first render of a row (no fallback frame at all).
 *  2. **IndexedDB** — per-vault, 30-day TTL, so a reload/unlock is warm too.
 *     Negative results are cached for 6 hours, so a dead icon costs one request
 *     ever rather than one per render.
 *
 * What is stored is a site icon — effectively a plaintext hint about which
 * sites a vault contains. Accepted deliberately (see
 * `plans/favicon-loading-ux.md`, D1): it is the same class of data as the
 * plaintext vault-name cache, it is namespaced per vault, and it is deleted on
 * sign-out (`deleteVaultFavicons`). It is never uploaded, never logged, and is
 * not a matching signal — `faviconForItem` in `@voult/vault-core` decides the
 * URL, this module only remembers the bytes.
 *
 * Icons are fetched with a **dedicated** axios instance, not the shared
 * credentialed `http` client: that client runs `teardownVaultSession` on any
 * 401, and an icon failing must never be able to mark the server session
 * missing.
 */
import axios from "axios";
import { proxiedFaviconUrl } from "../queries/api-url";
import {
  FAVICON_STORE,
  FAVICON_VAULT_INDEX,
  hasIndexedDb,
  openVaultDb,
} from "../storage/indexed-db";

/** A real icon rarely changes; a month keeps reloads warm without hoarding. */
const TTL_HIT_MS = 30 * 24 * 60 * 60 * 1000;
/** Shorter, so a temporarily broken icon is retried soon but not constantly. */
const TTL_MISS_MS = 6 * 60 * 60 * 1000;
/** Per-vault cap; the oldest entries are dropped during hydration. */
const MAX_ENTRIES_PER_VAULT = 1000;
/** Matches the server's cap — anything larger is not worth storing. */
const MAX_ICON_BYTES = 256 * 1024;
/** Background warm-up: bounded so a 1000-item vault cannot stampede. */
const WARM_LIMIT = 80;
const WARM_CONCURRENCY = 4;
/**
 * A fetch that failed for a reason that says nothing about the icon (offline,
 * expired session) is retried once after this delay. Without it, an app opened
 * offline would keep its fallback glyphs until the screen remounted.
 */
const RETRY_DELAY_MS = 20_000;

interface FaviconRecord {
  vault_id: string;
  url: string;
  /** MIME type of `data`; empty for a negative entry. */
  content_type: string;
  /** Base64 image bytes; empty for a negative entry. */
  data: string;
  fetched_at: number;
  /** 1 = this URL produced no usable image (negative entry). */
  failed: 0 | 1;
}

/** What the UI reads. `src` is a ready-to-render data URL. */
export interface FaviconEntry {
  src?: string;
  failed: boolean;
  fetchedAt: number;
}

const iconHttp = axios.create({ withCredentials: true });

/**
 * Memory cache, keyed `${vaultId}\n${url}`. Holds the same shape the hook
 * renders, so `useSyncExternalStore` can return a stable reference per write.
 */
const memory = new Map<string, FaviconEntry>();
const listeners = new Set<() => void>();
/** In-flight fetches, so two rows (or a row and the warm-up) share one request. */
const inflight = new Map<string, Promise<void>>();
/** Pending retry timers for outcomes that carry no information about the icon. */
const retryTimers = new Map<string, ReturnType<typeof setTimeout>>();

const keyFor = (vaultId: string, url: string) => `${vaultId}\n${url}`;

function notify(): void {
  for (const listener of [...listeners]) listener();
}

/** Subscribe to cache updates (`useSyncExternalStore` contract). */
export function subscribeFavicons(listener: () => void): () => void {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

/**
 * Synchronous lookup used during render. Returns the same object reference
 * until that URL's entry is rewritten, which is what keeps
 * `useSyncExternalStore` from looping.
 */
export function faviconEntry(vaultId: string, url: string): FaviconEntry | undefined {
  return memory.get(keyFor(vaultId, url));
}

function entryFromRecord(record: FaviconRecord): FaviconEntry {
  if (record.failed) {
    return { failed: true, fetchedAt: record.fetched_at };
  }
  return {
    src: `data:${record.content_type || "image/png"};base64,${record.data}`,
    failed: false,
    fetchedAt: record.fetched_at,
  };
}

function isFresh(record: FaviconRecord, now = Date.now()): boolean {
  const ttl = record.failed ? TTL_MISS_MS : TTL_HIT_MS;
  return now - record.fetched_at < ttl;
}

function isRecord(value: unknown): value is FaviconRecord {
  const record = value as FaviconRecord | null;
  return (
    !!record &&
    typeof record.vault_id === "string" &&
    typeof record.url === "string" &&
    typeof record.content_type === "string" &&
    typeof record.data === "string" &&
    typeof record.fetched_at === "number" &&
    (record.failed === 0 || record.failed === 1)
  );
}

// --- IndexedDB plumbing ----------------------------------------------------

function readRecord(key: string): Promise<FaviconRecord | null> {
  if (!hasIndexedDb()) return Promise.resolve(null);
  return openVaultDb()
    .then(
      (db) =>
        new Promise<FaviconRecord | null>((resolve, reject) => {
          const tx = db.transaction(FAVICON_STORE, "readonly");
          const request = tx.objectStore(FAVICON_STORE).get(key);
          request.onsuccess = () => {
            const value = request.result;
            resolve(isRecord(value) ? value : null);
          };
          request.onerror = () => reject(request.error);
        }).finally(() => db.close()),
    )
    .catch(() => null);
}

function writeRecord(key: string, record: FaviconRecord): Promise<void> {
  return openVaultDb().then(
    (db) =>
      new Promise<void>((resolve, reject) => {
        const tx = db.transaction(FAVICON_STORE, "readwrite");
        tx.objectStore(FAVICON_STORE).put(record, key);
        // Resolve on completion, not on the request, so the write is durable
        // before anyone treats the icon as cached.
        tx.oncomplete = () => resolve();
        tx.onerror = () => reject(tx.error);
      }).finally(() => db.close()),
  );
}

function deleteRecords(keys: string[]): Promise<void> {
  if (keys.length === 0 || !hasIndexedDb()) return Promise.resolve();
  return openVaultDb()
    .then(
      (db) =>
        new Promise<void>((resolve, reject) => {
          const tx = db.transaction(FAVICON_STORE, "readwrite");
          const store = tx.objectStore(FAVICON_STORE);
          for (const key of keys) store.delete(key);
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
        }).finally(() => db.close()),
    )
    // Pruning is best-effort: a failed delete must never break hydration.
    .catch(() => {});
}

// --- Hydration -------------------------------------------------------------

/**
 * Loads this vault's cached icons into memory and prunes the store.
 *
 * One cursor pass at home-screen mount: it fills the synchronous map so the
 * list's first paint already has real icons, and it is also the single place
 * that enforces the TTL and the per-vault cap.
 */
export async function hydrateFavicons(vaultId: string): Promise<void> {
  if (!hasIndexedDb()) return;
  const db = await openVaultDb();
  try {
    const records = await new Promise<unknown[]>((resolve, reject) => {
      const tx = db.transaction(FAVICON_STORE, "readonly");
      const index = tx.objectStore(FAVICON_STORE).index(FAVICON_VAULT_INDEX);
      const request = index.getAll(IDBKeyRange.only(vaultId));
      request.onsuccess = () => resolve(request.result as unknown[]);
      request.onerror = () => reject(request.error);
    });

    const now = Date.now();
    const live: FaviconRecord[] = [];
    const stale: string[] = [];
    for (const value of records) {
      if (!isRecord(value) || !isFresh(value, now)) {
        // A malformed record is unreachable through this module, but dropping
        // it beats rendering garbage from a partially-written store.
        if (isRecord(value) && typeof value.url === "string") {
          stale.push(keyFor(vaultId, value.url));
        }
        continue;
      }
      live.push(value);
    }

    // Newest first, then cap: the icons for recently-seen items are the ones
    // the user is most likely to look at again.
    live.sort((a, b) => b.fetched_at - a.fetched_at);
    for (const dropped of live.slice(MAX_ENTRIES_PER_VAULT)) {
      stale.push(keyFor(vaultId, dropped.url));
    }

    for (const record of live.slice(0, MAX_ENTRIES_PER_VAULT)) {
      memory.set(keyFor(vaultId, record.url), entryFromRecord(record));
    }
    if (stale.length > 0) {
      await deleteRecords(stale);
      console.info(`Pruned ${stale.length} stale favicon cache entries`);
    }
    notify();
  } finally {
    db.close();
  }
}

// --- Fetching --------------------------------------------------------------

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  // Chunk to avoid overflowing the JS argument stack on a large icon.
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

type FetchOutcome =
  | { kind: "icon"; contentType: string; data: string }
  | { kind: "dead" }
  /** Not evidence about the icon: keep no record and try again later. */
  | { kind: "retry" };

async function fetchIcon(url: string): Promise<FetchOutcome> {
  try {
    const response = await iconHttp.get<ArrayBuffer>(proxiedFaviconUrl(url), {
      responseType: "arraybuffer",
    });
    const bytes = new Uint8Array(response.data);
    if (bytes.length === 0 || bytes.length > MAX_ICON_BYTES) {
      return { kind: "dead" };
    }
    const rawType = response.headers["content-type"];
    const contentType =
      typeof rawType === "string" && rawType.startsWith("image/")
        ? rawType.split(";")[0].trim()
        : "image/png";
    return { kind: "icon", contentType, data: bytesToBase64(bytes) };
  } catch (error) {
    const status = (error as { response?: { status?: number } })?.response?.status;
    // No status = transport/offline, and 401 = the session cookie is gone, not
    // the icon. Neither says anything about the icon, so cache nothing and
    // retry on the next unlock / reconnect. (The proxy uses the same generic
    // 502 for every "this URL has no icon" outcome.)
    if (status === undefined || status === 401) return { kind: "retry" };
    return { kind: "dead" };
  }
}

/**
 * One bounded retry for an outcome that told us nothing about the icon (offline,
 * or the session cookie is gone). It never loops: the timer fires once, and a
 * cached entry — including a negative one — suppresses the refetch.
 */
function scheduleRetry(vaultId: string, url: string, key: string): void {
  if (retryTimers.has(key)) return;
  const timer = setTimeout(() => {
    retryTimers.delete(key);
    if (!memory.has(key)) {
      void ensureFavicon(vaultId, url).catch(() => undefined);
    }
  }, RETRY_DELAY_MS);
  retryTimers.set(key, timer);
}

/**
 * Makes sure this URL's icon is in the memory cache, fetching it once if not.
 *
 * Safe to call from every row and again from the warm-up: concurrent calls
 * share one request, and a cached (even negative) entry short-circuits.
 */
export function ensureFavicon(vaultId: string, url: string): Promise<void> {
  const key = keyFor(vaultId, url);
  if (memory.has(key)) return Promise.resolve();
  const existing = inflight.get(key);
  if (existing) return existing;

  const task = (async () => {
    try {
      const stored = await readRecord(key);
      if (stored) {
        if (isFresh(stored)) {
          memory.set(key, entryFromRecord(stored));
          notify();
          return;
        }
        // Expired: drop it and refetch below.
        void deleteRecords([key]);
      }

      const outcome = await fetchIcon(url);
      if (outcome.kind === "retry") {
        scheduleRetry(vaultId, url, key);
        return;
      }

      const record: FaviconRecord =
        outcome.kind === "icon"
          ? {
              vault_id: vaultId,
              url,
              content_type: outcome.contentType,
              data: outcome.data,
              fetched_at: Date.now(),
              failed: 0,
            }
          : {
              vault_id: vaultId,
              url,
              content_type: "",
              data: "",
              fetched_at: Date.now(),
              failed: 1,
            };

      // Paint from memory straight away; the disk write is durability only.
      memory.set(key, entryFromRecord(record));
      notify();
      await writeRecord(key, record).catch((e) =>
        console.warn("Favicon cache write failed", e),
      );
    } finally {
      inflight.delete(key);
    }
  })();

  inflight.set(key, task);
  return task;
}

// --- Warm-up ---------------------------------------------------------------

async function runPool<T>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<unknown>,
): Promise<void> {
  let next = 0;
  const runners = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      while (next < items.length) {
        const item = items[next++];
        try {
          await worker(item);
        } catch {
          // A single icon failing is already a cached outcome; never let it
          // abort the pool.
        }
      }
    },
  );
  await Promise.all(runners);
}

/**
 * Prefetches icons for the whole vault in idle time, after the list is up.
 *
 * Without this, scrolling to a row or opening the detail panel starts a cold
 * fetch. It is deliberately post-render and rate-limited so it never competes
 * with the vault/session requests that actually gate the screen.
 */
export function warmFavicons(vaultId: string, urls: Iterable<string>): void {
  if (typeof window === "undefined") return;
  const queue = [...new Set(urls)]
    .filter((url) => !!url && !memory.has(keyFor(vaultId, url)))
    .slice(0, WARM_LIMIT);
  if (queue.length === 0) return;

  const schedule = (callback: () => void) => {
    const ric = (
      window as unknown as {
        requestIdleCallback?: (cb: () => void, opts?: { timeout: number }) => void;
      }
    ).requestIdleCallback;
    if (ric) ric(callback, { timeout: 2000 });
    else window.setTimeout(callback, 250);
  };

  schedule(() => {
    void runPool(queue, WARM_CONCURRENCY, (url) => ensureFavicon(vaultId, url));
  });
}

// --- Purge -----------------------------------------------------------------

/** Drops one vault's icons from memory. The disk records stay namespaced. */
export function forgetVaultFavicons(vaultId: string): void {
  const prefix = `${vaultId}\n`;
  let changed = false;
  for (const key of [...memory.keys()]) {
    if (key.startsWith(prefix)) {
      memory.delete(key);
      changed = true;
    }
  }
  if (changed) notify();
}

/**
 * Deletes one vault's icons from memory **and** disk. Sign-out only: an expired
 * cookie or a lock must not erase display data the user will want again, but a
 * deliberate sign-out removes every vault-derived byte this browser kept.
 */
export async function deleteVaultFavicons(vaultId: string): Promise<void> {
  forgetVaultFavicons(vaultId);
  if (!hasIndexedDb()) return;
  const db = await openVaultDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(FAVICON_STORE, "readwrite");
      const index = tx.objectStore(FAVICON_STORE).index(FAVICON_VAULT_INDEX);
      const request = index.openKeyCursor(IDBKeyRange.only(vaultId));
      request.onsuccess = () => {
        const cursor = request.result;
        if (!cursor) return; // tx.oncomplete resolves
        cursor.delete();
        cursor.continue();
      };
      request.onerror = () => reject(request.error);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } finally {
    db.close();
  }
  console.info("Deleted cached icons for this vault");
}
