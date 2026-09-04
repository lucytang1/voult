// Vault session manager — the worker's source of truth while unlocked.
//
// Mirrors the web app's auth flows (`apps/client/src/lib/auth/flows/*`,
// `architecture.md §Login Flow`) with one structural difference: the vault key
// + decrypted items live in this module's memory (the popup unloads when
// closed; the worker outlives it). Everything persisted is zero-knowledge-safe
// or non-sensitive:
//
//  - memory only (wiped on lock): vaultKey, items, version
//  - chrome.storage.session (cleared on browser close): locked flag, vault id
//  - chrome.storage.local: server URL, lock timeout, active vault id,
//    `never:<origin>` list (M2)
//  - IndexedDB `voult-ext`: device key + device envelope (CryptoKey handles)
//
// Wrong passwords fail at local AES-GCM unwrap — no network call distinguishes
// them, so nothing about the attempt leaves the device.

import {
  CRYPTO_VERSION,
  b64,
  createAuthKey,
  decrypt,
  derivePasswordWrappingKey,
  encrypt,
  getAuthVerifierB64,
  importVaultKey,
  isValidVaultId,
  mergeVault,
  originOfUrl,
  rankOriginMatch,
  unwrapKeyBytes,
  uuid,
  wrapKeyBytes,
  type VaultItem,
} from "@voult/vault-core";
import {
  fetchCryptoParams,
  fetchSession,
  fetchVault,
  isNetworkError,
  isVersionConflict,
  postAuth,
  postLock,
  postLogout,
  postUpdateVault,
  DEFAULT_SERVER_URL,
} from "../lib/api";
import {
  getDeviceEnvelope,
  getDeviceKey,
  getOrCreateDeviceKey,
  saveDeviceEnvelope,
  deleteDeviceRecords,
} from "../lib/deviceKey";
import {
  ACTIVE_VAULT_KEY,
  LOCKED_FLAG_KEY,
  clearVaultRecords,
  getLocalValue,
  recordKey,
  setLocalValue,
  setSessionValue,
} from "../lib/storage";
import type { LoginMatch, PopupState, Rank, SavePrompt } from "../lib/messaging";

const SERVER_URL_KEY = "voult.serverUrl";
const LOCK_TIMEOUT_KEY = "voult.lockTimeoutMinutes";
const NEVER_PREFIX = "never:";
const DEFAULT_LOCK_TIMEOUT_MINUTES = 5;

// --- In-memory unlocked state (never persisted) ----------------------------

let vaultKey: CryptoKey | null = null;
let items: VaultItem[] = [];
let version: number | null = null;
let vaultId: string | null = null;
let lastActivity = 0;

// Last server lock_epoch converged to, per vault (memory cache over
// chrome.storage.local `vault:<id>:lockEpoch`). Survives worker restarts so a
// peer's lock is never missed; survives our own lock (a lock publishes a new
// epoch); cleared only on logout / onboarding switch.
let epochCache: { vaultId: string; epoch: number } | null = null;

const epochKey = (id: string) => recordKey(id, "lockEpoch");

async function getKnownEpoch(id: string): Promise<number | null> {
  if (epochCache && epochCache.vaultId === id) return epochCache.epoch;
  const stored = await getLocalValue<number>(epochKey(id));
  epochCache = stored !== null ? { vaultId: id, epoch: stored } : null;
  return stored;
}

async function setKnownEpoch(id: string, epoch: number): Promise<void> {
  epochCache = { vaultId: id, epoch };
  await setLocalValue(epochKey(id), epoch);
}

export function isUnlocked(): boolean {
  return vaultKey !== null && vaultId !== null;
}

function touch(): void {
  lastActivity = Date.now();
}

/** Seconds since any authenticated activity (message, fill, save). */
export function idleSeconds(): number {
  if (!isUnlocked()) return Number.POSITIVE_INFINITY;
  return (Date.now() - lastActivity) / 1000;
}

// --- Settings --------------------------------------------------------------

export async function getServerUrl(): Promise<string> {
  return (await getLocalValue<string>(SERVER_URL_KEY)) ?? DEFAULT_SERVER_URL;
}

export async function getLockTimeoutMinutes(): Promise<number> {
  return (await getLocalValue<number>(LOCK_TIMEOUT_KEY)) ?? DEFAULT_LOCK_TIMEOUT_MINUTES;
}

/** Rejects non-http(s) URLs and http outside the loopback allowlist. */
export function normalizeServerUrl(input: string): string {
  const trimmed = input.trim().replace(/\/+$/, "");
  const url = new URL(trimmed);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Server URL must be http(s).");
  }
  if (url.protocol === "http:") {
    const host = url.hostname.toLowerCase();
    const loopback =
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".test") ||
      host === "127.0.0.1" ||
      host === "::1";
    if (!loopback) throw new Error("Plain http is allowed only for localhost (production must use https).");
  }
  return trimmed;
}

// --- Onboarding ------------------------------------------------------------

export async function saveOnboarding(vaultIdInput: string, serverUrlInput: string): Promise<void> {
  const id = vaultIdInput.trim();
  if (!isValidVaultId(id)) throw new Error("Vault ID must be a UUID (copy it from the Voult web app).");
  const serverUrl = normalizeServerUrl(serverUrlInput);
  // Single-vault invariant: switching the onboarded vault abandons the old
  // one entirely (keys wiped, per-vault records cleared) so two vaults can
  // never be live side by side. clearVaultRecords also drops the old vault's
  // stored lock epoch (same `vault:<id>:` prefix).
  const previous = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  if (previous && previous !== id) {
    await lock();
    try {
      await deleteDeviceRecords(previous);
      await clearVaultRecords(previous);
    } catch (e) {
      console.error("[voult] failed to clear previous vault records on switch", e);
    }
    if (epochCache && epochCache.vaultId === previous) epochCache = null;
  }
  await setLocalValue(SERVER_URL_KEY, serverUrl);
  await setLocalValue(ACTIVE_VAULT_KEY, id);
  await setSessionValue(LOCKED_FLAG_KEY, 1);
}

// --- Unlock ----------------------------------------------------------------

function parseVaultJson(plain: string, id: string): VaultItem[] {
  const parsed = JSON.parse(plain) as { items?: VaultItem[] };
  return parsed.items ?? [];
}

async function persistDeviceEnvelope(id: string, vaultKeyRaw: Uint8Array): Promise<void> {
  const device = await getOrCreateDeviceKey(id);
  const { cipher, iv } = await wrapKeyBytes(vaultKeyRaw, device.key);
  await saveDeviceEnvelope(id, {
    device_id: device.device_id,
    wrapped_vault_key: b64(cipher),
    wrapped_vault_key_iv: b64(iv),
    crypto_version: CRYPTO_VERSION,
  });
}

async function finishUnlock(
  id: string,
  key: CryptoKey,
  raw: Uint8Array | null,
  serverItems: VaultItem[],
  serverVersion: number,
  lockEpoch: number,
): Promise<void> {
  vaultKey = key;
  vaultId = id;
  items = serverItems;
  version = serverVersion;
  touch();
  // Baseline for peer-lock detection: a later epoch means "locked elsewhere".
  await setKnownEpoch(id, lockEpoch);
  // Enroll/refresh this browser's device envelope so next time can unlock
  // silently while the session lives.
  if (raw) {
    try {
      await persistDeviceEnvelope(id, raw);
    } catch (e) {
      console.warn("[voult] device envelope persist failed (unlock still valid)", e);
    }
  }
  await setLocalValue(ACTIVE_VAULT_KEY, id);
  await chrome.storage.session.remove(LOCKED_FLAG_KEY);
  await scheduleAutoLock();
}

/**
 * Password unlock. Derives locally, authenticates with the static verifier,
 * unwraps the vault key, fetches + decrypts. Throws "Incorrect password." on
 * AES-GCM failure so the popup can show it without leaking error detail.
 */
export async function unlockWithPassword(password: string): Promise<void> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? "";
  if (!isValidVaultId(id)) throw new Error("No vault onboarded — set the vault ID first.");
  const serverUrl = await getServerUrl();
  const params = await fetchCryptoParams(id, serverUrl);
  const authKey = await createAuthKey(password, params.salt, params.iterations);
  const vaultVerifier = await getAuthVerifierB64(authKey);
  await postAuth(id, vaultVerifier, serverUrl);
  const wrappingKey = await derivePasswordWrappingKey(password, params.salt, params.iterations);
  const vaultData = await fetchVault(serverUrl);
  const v = vaultData.vault;
  if (!v.vault_key_wrap || !v.vault_key_wrap_iv) {
    throw new Error("Vault key material unavailable for unlock.");
  }
  let raw: Uint8Array;
  try {
    raw = await unwrapKeyBytes(v.vault_key_wrap, v.vault_key_wrap_iv, wrappingKey);
  } catch {
    throw new Error("Incorrect password.");
  }
  const key = await importVaultKey(raw);
  const plain = await decrypt(v.vault, v.vaultiv, key);
  // Converge to the current server epoch (a peer may have locked since our
  // last sync). Best-effort: unlock stays valid; the next check converges.
  let lockEpoch = 0;
  try {
    const session = await fetchSession(serverUrl);
    if (session.authenticated && session.vault_id === id) {
      lockEpoch = session.lock_epoch ?? 0;
    }
  } catch {
    // Offline/legacy server — unlock still valid.
  }
  await finishUnlock(id, key, raw, parseVaultJson(plain, id), v.version, lockEpoch);
  console.info("[voult] unlocked with password");
}

/**
 * Silent device unlock: session cookie → local device key + envelope →
 * unwrap → fetch + decrypt. Returns false (not throw) when anything is
 * missing — the caller falls back to the password screen.
 */
export async function unlockWithDevice(): Promise<boolean> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? "";
  if (!isValidVaultId(id)) return false;
  const serverUrl = await getServerUrl();
  let session: Awaited<ReturnType<typeof fetchSession>>;
  try {
    session = await fetchSession(serverUrl);
  } catch {
    return false;
  }
  if (!session.authenticated || session.vault_id !== id) return false;
  const device = await getDeviceKey(id);
  if (!device) return false;
  const envelope = await getDeviceEnvelope(id);
  if (!envelope || envelope.device_id !== device.device_id) return false;
  let raw: Uint8Array;
  try {
    raw = await unwrapKeyBytes(envelope.wrapped_vault_key, envelope.wrapped_vault_key_iv, device.key);
  } catch {
    return false;
  }
  const key = await importVaultKey(raw);
  let vaultData: Awaited<ReturnType<typeof fetchVault>>;
  try {
    vaultData = await fetchVault(serverUrl);
  } catch {
    return false;
  }
  const v = vaultData.vault;
  let plain: string;
  try {
    plain = await decrypt(v.vault, v.vaultiv, key);
  } catch {
    return false;
  }
  await finishUnlock(id, key, null, parseVaultJson(plain, id), v.version, session.lock_epoch ?? 0);
  console.info("[voult] unlocked with device key");
  return true;
}

// --- Cross-surface session sync --------------------------------------------
//
// No direct channel exists between web tabs and the extension (different
// origins share no storage or BroadcastChannel), so convergence flows through
// the server lock_epoch counter (see POST /api/lock). This check runs on
// popup open, before any credential release, and on the slow autolock-alarm
// tick — never on a dedicated fast poller (MV3 workers sleep anyway).
//
// Rules mirror the web use-session-sync hook:
// - probe failure (offline) → stay as-is; offline is a normal state.
// - session for a different vault → single-vault invariant: adopt the new
//   vault id locked (last-writer-wins), never auto-unlock it.
// - epoch bump over our known baseline → peer locked → wipe keys now.
// - unknown baseline (null) → adopt without wiping (fresh enrollment).
// Unlock never propagates: each side re-unwraps with its own device key.

export async function syncSession(): Promise<void> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  if (!id || !isValidVaultId(id)) return;
  const serverUrl = await getServerUrl();
  let session: Awaited<ReturnType<typeof fetchSession>>;
  try {
    session = await fetchSession(serverUrl);
  } catch {
    return;
  }
  if (!session.authenticated || session.vault_id !== id) {
    // Logged out elsewhere, or another surface switched vaults: drop keys so
    // this side can never act on a stale vault, then converge the onboarding
    // id to the server truth (locked — the user unlocks explicitly).
    if (isUnlocked()) await lock();
    if (session.authenticated && session.vault_id !== id && isValidVaultId(session.vault_id)) {
      await setLocalValue(ACTIVE_VAULT_KEY, session.vault_id);
      await setSessionValue(LOCKED_FLAG_KEY, 1);
    }
    return;
  }
  const epoch = session.lock_epoch ?? 0;
  const known = await getKnownEpoch(id);
  if (known === null) {
    await setKnownEpoch(id, epoch);
    return;
  }
  if (epoch > known) {
    await lock();
    await setKnownEpoch(id, epoch);
  }
}

// --- Lock / logout -----------------------------------------------------------

/** Wipes keys + plaintext from memory, keeps session + device envelope. */
export async function lock(): Promise<void> {
  vaultKey = null;
  items = [];
  version = null;
  vaultId = null;
  pendingSave = null;
  await setSessionValue(LOCKED_FLAG_KEY, 1);
  await chrome.alarms.clear(AUTOLOCK_ALARM);
  console.info("[voult] locked");
}

/**
 * User-initiated lock (button, idle timeout, screen lock): publish the global
 * lock first so the web app converges, then wipe locally. Best-effort: an
 * offline lock still locks this side and converges later. Never called from
 * syncSession — a peer-observed lock must not re-bump the epoch (that would
 * ping-pong the counter on every tick).
 */
export async function publishLock(): Promise<void> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  if (id && isValidVaultId(id)) {
    try {
      const serverUrl = await getServerUrl();
      const { lock_epoch } = await postLock(serverUrl);
      await setKnownEpoch(id, lock_epoch);
    } catch (e) {
      console.warn("[voult] lock publish failed; locked locally only", e);
    }
  }
  await lock();
}

/** Full logout: server session + this vault's local records + memory. */
export async function logout(): Promise<void> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  const serverUrl = await getServerUrl();
  try {
    await postLogout(serverUrl);
  } catch (e) {
    console.warn("[voult] server logout failed; continuing local teardown", e);
  }
  await lock();
  if (id) {
    try {
      await deleteDeviceRecords(id);
      await clearVaultRecords(id);
    } catch (e) {
      console.error("[voult] failed to delete local vault records on logout", e);
    }
    // clearVaultRecords drops the stored epoch (same prefix); reset memory.
    if (epochCache && epochCache.vaultId === id) epochCache = null;
  }
  await chrome.storage.local.remove(ACTIVE_VAULT_KEY);
  await chrome.storage.session.remove(LOCKED_FLAG_KEY);
}

// --- Matching (origin-bound) -------------------------------------------------

function rankOf(item: VaultItem, pageOrigin: string): Rank | null {
  const r = rankOriginMatch({ origin: item.origin, urls: item.urls }, pageOrigin);
  return r ? r.kind : null;
}

const rankOrder: Record<Rank, number> = { exact: 0, linked: 1, subdomain: 2 };

/** Logins matching a page origin, exact/linked before subdomain fallback. */
export function queryLogins(pageOrigin: string): LoginMatch[] {
  if (!isUnlocked()) return [];
  touch();
  let canonical: string;
  try {
    canonical = originOfUrl(pageOrigin);
  } catch {
    return [];
  }
  return items
    .map((item) => {
      const rank = rankOf(item, canonical);
      if (!rank) return null;
      const m: LoginMatch = {
        id: item.id,
        username: item.username,
        label: item.site || item.origin || canonical,
        origin: item.origin ?? canonical,
        rank,
      };
      return m;
    })
    .filter((m): m is LoginMatch => m !== null)
    .sort((a, b) => rankOrder[a.rank] - rankOrder[b.rank] || a.username.localeCompare(b.username));
}

/** One credential for an explicit fill gesture. Throws when locked/unknown. */
export function credentialForFill(id: string): { username: string; password: string } {
  if (!isUnlocked()) throw new Error("Vault is locked.");
  touch();
  const item = items.find((i) => i.id === id);
  if (!item) throw new Error("Login not found.");
  return { username: item.username, password: item.password };
}

// --- Popup state ---------------------------------------------------------------

export function isInsecureOrigin(tabOrigin: string | undefined): boolean {
  if (!tabOrigin) return false;
  try {
    return new URL(tabOrigin).protocol === "http:";
  } catch {
    return false;
  }
}

export async function getPopupState(tabOrigin?: string): Promise<PopupState> {
  const serverUrl = await getServerUrl();
  const lockTimeoutMinutes = await getLockTimeoutMinutes();
  const activeId = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  if (!activeId) {
    return {
      status: "needs-onboarding",
      vaultId: null,
      serverUrl,
      lockTimeoutMinutes,
      items: null,
      matches: null,
      version: null,
      insecureOrigin: isInsecureOrigin(tabOrigin),
    };
  }
  if (!isUnlocked()) {
    return {
      status: "locked",
      vaultId: activeId,
      serverUrl,
      lockTimeoutMinutes,
      items: null,
      matches: null,
      version: null,
      insecureOrigin: isInsecureOrigin(tabOrigin),
    };
  }
  const ranked = tabOrigin ? queryLogins(tabOrigin) : null;
  const matchedIds = new Set((ranked ?? []).map((m) => m.id));
  const ordered = [...items].sort(
    (a, b) =>
      (matchedIds.has(a.id) ? 0 : 1) - (matchedIds.has(b.id) ? 0 : 1) ||
      a.site.localeCompare(b.site),
  );
  return {
    status: "unlocked",
    vaultId,
    serverUrl,
    lockTimeoutMinutes,
    items: ordered,
    matches: ranked,
    version,
    insecureOrigin: isInsecureOrigin(tabOrigin),
  };
}

// --- Auto-lock -----------------------------------------------------------------

const AUTOLOCK_ALARM = "voult-autolock";

async function scheduleAutoLock(): Promise<void> {
  await chrome.alarms.clear(AUTOLOCK_ALARM);
  // Fires every minute; the handler compares against the configured timeout.
  await chrome.alarms.create(AUTOLOCK_ALARM, { periodInMinutes: 1 });
}

export async function handleAlarm(alarm: chrome.alarms.Alarm): Promise<void> {
  if (alarm.name !== AUTOLOCK_ALARM) return;
  // Slow fallback convergence (no dedicated poller): one cheap GET /session
  // per minute tick so an idle-but-open popup converges to a peer's lock,
  // logout, or vault switch. Offline failures are silent by design.
  const activeId = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  if (!isUnlocked()) {
    if (activeId) {
      try {
        await syncSession();
      } catch {
        // Offline — stay as-is.
      }
    }
    return;
  }
  const timeoutMinutes = await getLockTimeoutMinutes();
  if (idleSeconds() >= timeoutMinutes * 60) {
    console.info("[voult] auto-lock after idle timeout");
    await publishLock();
    return;
  }
  try {
    await syncSession();
  } catch {
    // Offline — stay unlocked; the next tick or pre-fill check converges.
  }
}

// --- M2 save queue (in-memory only — never persist plaintext) -------------------

export interface PendingSave {
  username: string;
  password: string;
  origin: string;
  mode: "save" | "update";
  itemId?: string;
}

let pendingSave: PendingSave | null = null;

export function setPendingSave(save: PendingSave | null): void {
  pendingSave = save;
}

export function getPendingSave(): PendingSave | null {
  return pendingSave;
}

/** Adopt a freshly pushed server snapshot into the in-memory cache. */
export function adoptSnapshot(nextItems: VaultItem[], nextVersion: number): void {
  if (!isUnlocked()) return;
  items = nextItems;
  version = nextVersion;
  touch();
}

export function currentVersion(): number | null {
  return version;
}

export function currentVaultKey(): CryptoKey | null {
  return vaultKey;
}

export function currentVaultId(): string | null {
  return vaultId;
}

export async function isNeverOrigin(origin: string): Promise<boolean> {
  return (await getLocalValue<boolean>(`${NEVER_PREFIX}${origin}`)) === true;
}

export async function markNeverOrigin(origin: string): Promise<void> {
  await setLocalValue(`${NEVER_PREFIX}${origin}`, true);
}

export { NEVER_PREFIX };

// --- M2: offer to save / update ------------------------------------------------
//
// Dedupe runs against the in-memory cache while unlocked; when locked the
// candidate is dropped silently (plaintext is never queued or persisted).
// The write path reuses the shared mergeVault policy by wrapping the single
// op as one encrypted PendingIntent, then pushes with the same bounded CAS
// retry as the web sync loop (<=3 attempts, abort when the session changes).

const MAX_SAVE_RETRIES = 3;

function siteLabelForOrigin(origin: string): string {
  try {
    const host = new URL(origin).hostname;
    return host.replace(/^www\./, "");
  } catch {
    return origin;
  }
}

/** Decides whether a captured login deserves a save/update prompt. */
export async function evaluateCandidate(
  username: string,
  password: string,
  pageOrigin: string,
): Promise<SavePrompt> {
  if (!isUnlocked()) return { prompt: false };
  let canonical: string;
  try {
    canonical = originOfUrl(pageOrigin);
  } catch {
    return { prompt: false };
  }
  if (!username || !password) return { prompt: false };
  if (await isNeverOrigin(canonical)) return { prompt: false };
  touch();
  // Only origin-bound items participate: legacy items without an origin will
  // prompt a fresh save once (healing them into origin-bound entries; the old
  // row can be deleted in the web app). Documented v1 trade-off.
  const exact = items.find((i) => i.origin === canonical && i.username === username);
  if (exact && exact.password === password) return { prompt: false };
  if (exact) return { prompt: true, mode: "update", origin: canonical, username };
  return { prompt: true, mode: "save", origin: canonical, username };
}

export interface SaveResult {
  saved: boolean;
  /** True when the server was unreachable — candidate stays in memory only. */
  offline: boolean;
}

/**
 * Applies one confirmed save/update and pushes via read-modify-CAS-write.
 * Returns offline:true (and stashes the candidate in memory until lock) when
 * the network is down — plaintext is never written to disk.
 */
export async function pushSave(
  username: string,
  password: string,
  origin: string,
  mode: "save" | "update",
): Promise<SaveResult> {
  const key = currentVaultKey();
  const id = currentVaultId();
  if (!key || !id) throw new Error("Vault is locked.");
  const serverUrl = await getServerUrl();
  const pinId = id;
  const sessionChanged = () => currentVaultId() !== pinId || currentVaultKey() !== key;

  const op =
    mode === "save"
      ? {
          operation: "create",
          payload: {
            id: uuid(),
            site: siteLabelForOrigin(origin),
            username,
            password,
            origin,
          },
        }
      : (() => {
          const existing = items.find((i) => i.origin === origin && i.username === username);
          if (!existing) {
            throw new Error("Saved login changed; please capture it again.");
          }
          return { operation: "update", payload: { id: existing.id, fields: { password } } };
        })();

  const enc = await encrypt(JSON.stringify(op.payload), key);
  const intent = {
    id: uuid(),
    operation: op.operation,
    payload: b64(enc.cipher),
    payload_iv: b64(enc.iv),
    created_at: new Date().toISOString(),
  };

  for (let attempt = 1; attempt <= MAX_SAVE_RETRIES; attempt++) {
    if (sessionChanged()) throw new Error("Session changed; save aborted.");
    let serverItems: VaultItem[];
    let serverVersion: number;
    try {
      const vaultData = await fetchVault(serverUrl);
      const plain = await decrypt(vaultData.vault.vault, vaultData.vault.vaultiv, key);
      const parsed = JSON.parse(plain) as { items?: VaultItem[] };
      serverItems = parsed.items ?? [];
      serverVersion = vaultData.vault.version;
    } catch (e) {
      if (isNetworkError(e)) {
        setPendingSave({ username, password, origin, mode });
        return { saved: false, offline: true };
      }
      throw e;
    }

    const merged = await mergeVault(serverItems, [intent], key);
    if (!merged.changed) {
      adoptSnapshot(merged.items, serverVersion);
      setPendingSave(null);
      return { saved: true, offline: false };
    }
    const encrypted = await encrypt(JSON.stringify({ items: merged.items }), key);
    if (sessionChanged()) throw new Error("Session changed; save aborted.");
    try {
      const response = await postUpdateVault(
        { vault: b64(encrypted.cipher), vaultiv: b64(encrypted.iv), version: serverVersion },
        serverUrl,
      );
      const syncedPlain = await decrypt(response.vault, response.vaultiv, key);
      const synced = (JSON.parse(syncedPlain) as { items?: VaultItem[] }).items ?? [];
      adoptSnapshot(synced, response.version);
      setPendingSave(null);
      console.info("[voult] login saved");
      return { saved: true, offline: false };
    } catch (e) {
      if (isNetworkError(e)) {
        setPendingSave({ username, password, origin, mode });
        return { saved: false, offline: true };
      }
      if (isVersionConflict(e)) {
        // Another client pushed between fetch and push — reconcile against
        // the new snapshot on the next iteration.
        console.warn("[voult] save version conflict, retrying", { attempt });
        continue;
      }
      throw e;
    }
  }
  setPendingSave({ username, password, origin, mode });
  return { saved: false, offline: false };
}
