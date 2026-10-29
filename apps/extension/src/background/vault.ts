// Vault session manager — the worker's source of truth while unlocked.
//
// Mirrors the web app's auth flows (`apps/client/src/lib/auth/flows/*`,
// `architecture.md §Login Flow`) with one structural difference: the vault key
// + decrypted items live in this module's memory (the popup unloads when
// closed; the worker outlives it). Everything persisted is zero-knowledge-safe
// or non-sensitive:
//
//  - memory only (wiped on lock): vaultKey, items, version
//  - chrome.storage.session (cleared on browser close): locked flag, vault id,
//    folder filter (opaque id only)
//  - chrome.storage.local: server URL, lock timeout, active vault id,
//    `never:<origin>` list (M2)
//  - IndexedDB `voult-ext`: device key + device envelope (CryptoKey handles)
//
// Wrong passwords fail at local AES-GCM unwrap — no network call distinguishes
// them, so nothing about the attempt leaves the device.

import {
  CRYPTO_VERSION,
  DEFAULT_FOLDER_ID,
  DEFAULT_VAULT_NAME,
  b64,
  createAuthKey,
  decrypt,
  derivePasswordWrappingKey,
  encrypt,
  fallbackFaviconUrl,
  faviconForItem,
  findItemForAccount,
  getAuthVerifierB64,
  hasSsoSignIn,
  importVaultKey,
  isValidVaultId,
  itemsInFolder,
  mergeVault,
  originOfUrl,
  rankOriginMatch,
  sanitizeFaviconUrl,
  unwrapKeyBytes,
  ssoAccountsForProvider,
  upsertSsoSignIn,
  uuid,
  parseVaultDocument,
  wrapKeyBytes,
  type Folder,
  type SsoProvider,
  type SsoSignIn,
  type VaultItem,
} from "@voult/vault-core";
import {
  fetchCryptoParams,
  fetchSession,
  fetchVault,
  isNetworkError,
  isUnauthorized,
  isVersionConflict,
  pairConsume,
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
  getSessionValue,
  recordKey,
  setLocalValue,
  setSessionValue,
} from "../lib/storage";
import type {
  LoginMatch,
  PopupState,
  Rank,
  SaveFolder,
  SavePrompt,
  OAuthSavePrompt,
} from "../lib/messaging";

const SERVER_URL_KEY = "voult.serverUrl";
const LOCK_TIMEOUT_KEY = "voult.lockTimeoutMinutes";
const NEVER_PREFIX = "never:";
const DEFAULT_LOCK_TIMEOUT_MINUTES = 5;

// Durable, non-secret per-vault records. `chrome.storage.session` dies with the
// browser, which would reset the idle window and forget a deliberate lock on
// restart; these live in `chrome.storage.local` under the vault's namespace.
const LAST_ACTIVITY_SUFFIX = "lastActivity";
const LOCK_RECORD_SUFFIX = "lockRecord";

/** Why the vault is locked. Mirrors the web app's LockReason. */
type LockReason = "manual" | "autolock" | "peer";

interface StoredLockRecord {
  reason: LockReason;
  lockedAt: number;
}

const LOCK_REASONS: readonly LockReason[] = ["manual", "autolock", "peer"];

/** How often activity is written to storage; the deadline is minute-scale. */
const ACTIVITY_PERSIST_MS = 10_000;

// --- In-memory unlocked state (never persisted) ----------------------------

let vaultKey: CryptoKey | null = null;
let items: VaultItem[] = [];
// Folders and the vault's display name are part of the decrypted document.
// The popup needs folders for its folder filter; the name is a label only and
// never part of any identity or wire contract.
let folders: Folder[] = [];
let vaultName: string | null = null;
let version: number | null = null;
let vaultId: string | null = null;
let lastActivity = 0;

// True when a session probe definitively failed authentication. Informational
// only: it must never wipe an unlocked vault or be treated as a lock.
let serverSessionMissing = false;

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

// --- Folder filter (unlocked lifetime only) ---------------------------------
//
// The popup's folder filter lives in the worker, not in popup state: it decides
// which logins are suggested on a page (`queryLogins`) and where a save lands
// (`defaultSaveFolderId`). Keeping it here is what makes it survive closing the
// popup, and clearing it on every lock is what makes the next unlock start at
// All folders.
//
// Mirrored into `chrome.storage.session` (in-memory, never written to disk) so
// a worker restart that device-unlocks the same vault can restore the filter.
// The value is an opaque folder id or the Unfiled marker — no folder name, item,
// or secret — and the record dies with the browser.

const SELECTED_FOLDER_SUFFIX = "selectedFolder";
/** Sentinel for the Unfiled bucket (folder ids are UUIDs, so no clash). */
const UNFILED_SELECTION = "unfiled";

let selectedFolderId: string | null = null;

const selectedFolderKey = (id: string) => recordKey(id, SELECTED_FOLDER_SUFFIX);

/**
 * The persisted filter, normalized against the live document. A folder that no
 * longer exists (deleted on another device and adopted by a sync) falls back to
 * All folders, which is also what a missing value means.
 */
function normalizeFolderSelection(value: string | null | undefined): string | null {
  if (value === UNFILED_SELECTION) return UNFILED_SELECTION;
  if (typeof value === "string" && folders.some((f) => f.id === value)) return value;
  return null;
}

async function persistFolderSelection(id: string, value: string | null): Promise<void> {
  if (value === null) await chrome.storage.session.remove(selectedFolderKey(id));
  else await setSessionValue(selectedFolderKey(id), value);
}

/**
 * Popup gesture: switch the folder filter. Persisted for the unlocked lifetime.
 * A locked vault has no folders, so a selection is meaningless there.
 */
export async function setFolderSelection(folderId: string | null): Promise<void> {
  const id = vaultId ?? ((await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null);
  const next = isUnlocked() ? normalizeFolderSelection(folderId) : null;
  selectedFolderId = next;
  if (id && isValidVaultId(id)) await persistFolderSelection(id, next);
}

// --- Durable idle + lock records ---------------------------------------------
//
// The auto-lock timer is a deadline, not a background job: an MV3 worker (or
// the whole browser) can stop before the timeout elapses. Persisting the last
// activity lets the next start compare wall-clock idle time instead of starting
// a fresh window, and persisting the lock reason lets a deliberate lock survive
// a restart even when the timeout is "Never".

const activityKey = (id: string) => recordKey(id, LAST_ACTIVITY_SUFFIX);
const lockRecordKey = (id: string) => recordKey(id, LOCK_RECORD_SUFFIX);

async function getLastActivity(id: string): Promise<number | null> {
  const stored = await getLocalValue<number>(activityKey(id));
  if (typeof stored !== "number" || !Number.isFinite(stored) || stored <= 0) return null;
  // A far-future timestamp would make idle time negative and keep the vault
  // open forever; treat it as corrupt.
  if (stored > Date.now() + 60_000) return null;
  return stored;
}

async function setLastActivity(id: string, at: number): Promise<void> {
  await setLocalValue(activityKey(id), at);
}

async function getLockRecord(id: string): Promise<StoredLockRecord | null> {
  const stored = await getLocalValue<StoredLockRecord>(lockRecordKey(id));
  if (
    !stored ||
    !LOCK_REASONS.includes(stored.reason) ||
    typeof stored.lockedAt !== "number" ||
    !Number.isFinite(stored.lockedAt)
  ) {
    return null;
  }
  return stored;
}

async function setLockRecord(id: string, record: StoredLockRecord): Promise<void> {
  await setLocalValue(lockRecordKey(id), record);
}

async function clearLockRecord(id: string): Promise<void> {
  await chrome.storage.local.remove(lockRecordKey(id));
}

let lastActivityPersistedAt = 0;

function touch(): void {
  const now = Date.now();
  lastActivity = now;
  const id = vaultId;
  if (!id) return;
  // Throttle: pointer/fill traffic can call this constantly, and the timer
  // only needs minute-scale precision.
  if (now - lastActivityPersistedAt < ACTIVITY_PERSIST_MS) return;
  lastActivityPersistedAt = now;
  void setLastActivity(id, now).catch((e) => {
    console.warn("[voult] failed to persist activity", e);
  });
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

// --- Onboarding (password-only: vault id is never typed) --------------------
// The vault id is adopted either from the existing session cookie
// (auto-discovery when the web app signed in first) or from a one-time
// pairing code shown in the web app. Both paths converge on the same
// single-vault invariant as the legacy manual onboarding below.

/** Shared tail: abandon any previous vault, pin the new id locked. */
async function pinVaultLocked(id: string, serverUrl: string): Promise<void> {
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

/**
 * Auto-discovery (M0): when the web app already holds a session cookie in
 * this browser profile, adopt its vault id without asking the user to type
 * anything. Returns the adopted id, or null when no session exists (caller
 * falls back to the pairing-code form). Never unlocks — just onboards locked.
 */
export async function adoptSessionProbe(): Promise<string | null> {
  const serverUrl = await getServerUrl();
  let session: Awaited<ReturnType<typeof fetchSession>>;
  try {
    session = await fetchSession(serverUrl);
  } catch {
    return null;
  }
  if (!session.authenticated || !isValidVaultId(session.vault_id)) return null;
  await pinVaultLocked(session.vault_id, serverUrl);
  await setKnownEpoch(session.vault_id, session.lock_epoch ?? 0);
  return session.vault_id;
}

/**
 * Pairing-code redeem (M1): exchange the 6-character code shown in the web
 * app for the vault identity, then pin it locked. The master password is
 * still required on the next unlock — the code is not an auth credential.
 */
export async function pairWithCode(rawCode: string, serverUrlInput?: string): Promise<string> {
  const code = rawCode.trim();
  if (!code) throw new Error("Enter the pairing code from the web app.");
  const serverUrl = serverUrlInput?.trim()
    ? normalizeServerUrl(serverUrlInput)
    : await getServerUrl();
  let vaultId: string;
  try {
    ({ vault_id: vaultId } = await pairConsume(code, serverUrl));
  } catch (e) {
    // Offline is a normal state — don't blame the code when the network is down.
    if (isNetworkError(e)) throw new Error("Server unreachable — check the server URL and try again.");
    throw new Error("Invalid or expired code — generate a fresh one in the web app.");
  }
  if (!isValidVaultId(vaultId)) throw new Error("Pairing failed — try again.");
  await pinVaultLocked(vaultId, serverUrl);
  try {
    const session = await fetchSession(serverUrl);
    if (session.authenticated && session.vault_id === vaultId) {
      await setKnownEpoch(vaultId, session.lock_epoch ?? 0);
    }
  } catch {
    // Offline/cookie-blocked after pairing — unlock via password still works;
    // the next online check converges the epoch baseline.
  }
  return vaultId;
}

/** Forget the onboarded vault and return to the Connect screen. */
export async function resetOnboarding(): Promise<void> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  await lock();
  if (id) {
    try {
      await deleteDeviceRecords(id);
      await clearVaultRecords(id);
    } catch (e) {
      console.error("[voult] failed to clear vault records on reset", e);
    }
    if (epochCache && epochCache.vaultId === id) epochCache = null;
    await chrome.storage.local.remove(ACTIVE_VAULT_KEY);
  }
  await setSessionValue(LOCKED_FLAG_KEY, 1);
}

export async function saveOnboarding(vaultIdInput: string, serverUrlInput: string): Promise<void> {
  // Legacy manual path (kept for already-onboarded profiles and tests).
  // The popup no longer offers a UUID field — new users pair via code or
  // session auto-discovery. Shares the single-vault pin tail above.
  const id = vaultIdInput.trim();
  if (!isValidVaultId(id)) throw new Error("Vault ID must be a UUID (copy it from the Voult web app).");
  const serverUrl = normalizeServerUrl(serverUrlInput);
  await pinVaultLocked(id, serverUrl);
}

// --- Unlock ----------------------------------------------------------------

function parseVaultState(plain: string): { name: string; folders: Folder[]; items: VaultItem[] } {
  const doc = parseVaultDocument(plain);
  return { name: doc.name, folders: doc.folders, items: doc.items };
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
  serverDoc: { name: string; folders: Folder[]; items: VaultItem[] },
  serverVersion: number,
  lockEpoch: number,
): Promise<void> {
  vaultKey = key;
  vaultId = id;
  vaultName = serverDoc.name;
  folders = serverDoc.folders;
  items = serverDoc.items;
  // The filter belongs to the currently-unlocked session. A set `voult.locked`
  // flag means this unlock comes from the lock screen (or a startup restore that
  // declined to restore), so start at All folders and drop any leftover record.
  // No flag means the vault was never locked — a worker restart or a popup close
  // — and the filter carries over. A folder id the new document no longer has
  // normalizes back to All folders either way.
  const cameFromLock = (await getSessionValue<number>(LOCKED_FLAG_KEY)) !== null;
  selectedFolderId = normalizeFolderSelection(
    cameFromLock ? null : await getSessionValue<string>(selectedFolderKey(id)),
  );
  if (cameFromLock) {
    try {
      await chrome.storage.session.remove(selectedFolderKey(id));
    } catch (e) {
      console.warn("[voult] failed to clear stale folder filter", e);
    }
  }
  version = serverVersion;
  lastActivity = Date.now();
  lastActivityPersistedAt = lastActivity;
  touch();
  serverSessionMissing = false;
  // An unlock ends any persisted lock decision.
  await clearLockRecord(id);
  await setLastActivity(id, lastActivity);
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
 * Vault fetch immediately after a successful POST /auth. Retries once on
 * 401: POST /auth already verified the password, so the first 401 means
 * the fresh session cookie lost a commit race (not a bad credential), and
 * the retry — after the cookie store settles — succeeds. A second 401 is
 * real (e.g. server restarted with a new cookie key) and is rethrown.
 */
async function fetchVaultAfterAuth(
  serverUrl: string,
): Promise<Awaited<ReturnType<typeof fetchVault>>> {
  try {
    return await fetchVault(serverUrl);
  } catch (e) {
    if (!isUnauthorized(e)) throw e;
    console.warn("[voult] vault fetch raced the fresh session cookie; retrying once");
    await new Promise((r) => setTimeout(r, 500));
    return await fetchVault(serverUrl);
  }
}

/**
 * Password unlock. Derives locally, authenticates with the static verifier,
 * unwraps the vault key, fetches + decrypts. Throws "Incorrect password." on
 * AES-GCM failure so the popup can show it without leaking error detail.
 *
 * A successful POST /auth proves the password was correct, so a 401 on the
 * vault fetch immediately after is never "wrong password" — it is the
 * session cookie losing a commit race in the extension network stack (the
 * follow-up request arrives cookieless; a later attempt then succeeds).
 * Retry that fetch once after a short delay instead of failing the login.
 */
export async function unlockWithPassword(password: string): Promise<void> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? "";
  if (!isValidVaultId(id)) throw new Error("No vault onboarded — connect the extension first.");
  const serverUrl = await getServerUrl();
  const params = await fetchCryptoParams(id, serverUrl);
  const authKey = await createAuthKey(password, params.salt, params.iterations);
  const vaultVerifier = await getAuthVerifierB64(authKey);
  await postAuth(id, vaultVerifier, serverUrl);
  const wrappingKey = await derivePasswordWrappingKey(password, params.salt, params.iterations);
  const vaultData = await fetchVaultAfterAuth(serverUrl);
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
  await finishUnlock(id, key, raw, parseVaultState(plain), v.version, lockEpoch);
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
  await finishUnlock(id, key, null, parseVaultState(plain), v.version, session.lock_epoch ?? 0);
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
    // Offline is a normal state; it says nothing about the cookie or the lock.
    return;
  }
  if (!session.authenticated) {
    // Authorization lost, not a lock decision. Keep an unlocked vault usable
    // locally; server-dependent work (sync/update) surfaces the 401 on its own
    // request. Wiping here would contradict "Auto-lock: Never".
    serverSessionMissing = true;
    return;
  }
  serverSessionMissing = false;
  if (session.vault_id !== id) {
    // Another surface switched vaults: single-vault invariant. Drop this
    // vault's keys (identity changed) and adopt the server's id locked.
    if (isUnlocked()) await lock("peer");
    if (isValidVaultId(session.vault_id)) {
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
    await lock("peer");
    await setKnownEpoch(id, epoch);
  }
}

// --- Lock / logout -----------------------------------------------------------

/**
 * Wipes keys + plaintext from memory, records why, and keeps the session and
 * device envelope. Local-only: callers that want peers to converge must use
 * `publishLock` (or add the peer notification themselves, as `syncSession`
 * deliberately does not — re-publishing an observed epoch would ping-pong).
 */
export async function lock(reason: LockReason = "manual"): Promise<void> {
  const id = vaultId ?? ((await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null);
  const wasUnlocked = isUnlocked();
  vaultKey = null;
  items = [];
  folders = [];
  vaultName = null;
  version = null;
  vaultId = null;
  // A lock ends the folder filter: the next unlock starts at All folders.
  selectedFolderId = null;
  pendingSave = null;
  pendingOAuth = null;
  pendingPrompt = null;
  if (id && isValidVaultId(id)) {
    try {
      await chrome.storage.session.remove(selectedFolderKey(id));
    } catch (e) {
      // A stale session value is harmless (unlock re-reads it, and a lock path
      // always resets memory to All folders); never let cleanup block the lock.
      console.warn("[voult] failed to clear folder filter", e);
    }
  }
  if (wasUnlocked && id && isValidVaultId(id)) {
    // Durable: chrome.storage.session dies with the browser, so a manual lock
    // (or a timer result) must be recorded locally to survive a restart.
    try {
      await setLockRecord(id, { reason, lockedAt: Date.now() });
    } catch (e) {
      console.warn("[voult] failed to persist lock record", e);
    }
  }
  await setSessionValue(LOCKED_FLAG_KEY, 1);
  await chrome.alarms.clear(AUTOLOCK_ALARM);
  console.info(`[voult] locked (${reason})`);
}

/**
 * Lock this surface, and publish the global lock only when the lock was
 * **manual** (button, explicit action). An idle/timer lock is local to this
 * surface: web and extension have separate timeouts, so a timer firing here
 * must not force the other surface to lock — and must not bump `lock_epoch`,
 * which peers would record as a durable `peer` lock.
 *
 * Local locking happens first and never waits on the network. Peers converge on
 * their next successful check if the request made it through.
 */
export async function publishLock(reason: "manual" | "autolock" = "manual"): Promise<void> {
  const id = (await getLocalValue<string>(ACTIVE_VAULT_KEY)) ?? null;
  await lock(reason);
  if (reason !== "manual") return;
  if (id && isValidVaultId(id)) {
    try {
      const serverUrl = await getServerUrl();
      const { lock_epoch } = await postLock(serverUrl);
      await setKnownEpoch(id, lock_epoch);
    } catch (e) {
      console.warn("[voult] lock publish failed; locked locally only", e);
    }
  }
}

/**
 * Startup restore decision, mirroring the web app's `decideRestore()`.
 *
 * The browser may have been closed past the idle deadline, so a fresh in-memory
 * timer cannot be trusted. Reads the durable lock record and last-activity
 * timestamp first:
 *
 *  - manual/peer lock -> stay locked until an explicit unlock.
 *  - autolock within its window -> stay locked.
 *  - finite timer and the persisted idle time is past the deadline -> stay
 *    locked (no timestamp also fails safe).
 *  - Never, or no record and still within the window -> try device unlock.
 *
 * Returns whether the vault was unlocked.
 */
export async function restoreOnStartup(): Promise<boolean> {
  const id = await getLocalValue<string>(ACTIVE_VAULT_KEY);
  if (!id || !isValidVaultId(id)) return false;

  const record = await getLockRecord(id);
  const timeout = await getLockTimeoutMinutes();
  const now = Date.now();

  if (record?.reason === "manual" || record?.reason === "peer") {
    console.info(`[voult] staying locked on startup (${record.reason})`);
    return false;
  }
  if (record?.reason === "autolock" && timeout > 0) {
    if (now - record.lockedAt < timeout * 60_000) {
      console.info("[voult] staying locked: autolock window still open");
      return false;
    }
  }
  if (timeout > 0) {
    const last = await getLastActivity(id);
    if (last === null || now - last >= timeout * 60_000) {
      console.info("[voult] staying locked: idle deadline elapsed");
      return false;
    }
  }
  return await unlockWithDevice();
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

const rankOrder: Record<Rank, number> = { exact: 0, linked: 1 };

/** Items visible under the popup's current folder filter (null = whole vault). */
function itemsInSelectedFolder(): VaultItem[] {
  const selection = normalizeFolderSelection(selectedFolderId);
  if (selection === null) return items;
  return itemsInFolder(
    items,
    folders,
    selection === UNFILED_SELECTION ? null : selection,
  );
}

/**
 * Logins matching a page origin, exact before explicitly linked. There is no
 * subdomain/suffix fallback: a different host — including a parent or child —
 * gets nothing unless the item links that origin explicitly.
 *
 * Suggestions follow the popup's folder filter: a login filed in another folder
 * is never offered for this page, and with no match left in view the content
 * script shows no dropdown at all. "All folders" keeps the whole vault eligible.
 */
export function queryLogins(pageOrigin: string): LoginMatch[] {
  if (!isUnlocked()) return [];
  touch();
  let canonical: string;
  try {
    canonical = originOfUrl(pageOrigin);
  } catch {
    return [];
  }
  return itemsInSelectedFolder()
    .map((item) => {
      const rank = rankOf(item, canonical);
      if (!rank) return null;
      const m: LoginMatch = {
        id: item.id,
        username: item.username ?? "",
        label: item.site || item.origin || canonical,
        origin: item.origin ?? canonical,
        rank,
        // One item carries every sign-in option: password fill and/or SSO.
        hasPassword: !!item.password,
        sso: item.sso ?? [],
        // Display-only icon (stored favicon, else `<origin>/favicon.ico`).
        faviconUrl: faviconForItem(item),
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
  // SSO-only items hold no secret — they inform, never fill. Items carrying
  // both a password and SSO methods fill the password; the content script
  // shows the SSO rows alongside and never calls fill for
  // passwordless picks. This is the worker-side backstop (also blocks a
  // compromised renderer asking for a passwordless id directly).
  if (!item.password) {
    throw new Error("This login uses Continue-with-SSO — no password to fill.");
  }
  return { username: item.username ?? "", password: item.password };
}

/**
 * Sign-in methods when an id names a passwordless login, else null. Lets the
 * worker answer FILL_CREDENTIAL with a highlight directive instead of a
 * secret — the content script scrolls to the site's own SSO button. Items
 * that also store a password fill normally, so this returns null for them.
 * Returns the full methods (provider + account) so the UI can name which
 * account the tap will sign into.
 */
export function oauthSignInsForFill(id: string): SsoSignIn[] | null {
  if (!isUnlocked()) return null;
  const item = items.find((i) => i.id === id);
  if (!item || item.password) return null;
  const methods = item.sso ?? [];
  return methods.length > 0 ? methods : null;
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
      vaultName: null,
      serverUrl,
      lockTimeoutMinutes,
      serverSessionMissing,
      folders: [],
      selectedFolderId: null,
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
      vaultName: null,
      serverUrl,
      lockTimeoutMinutes,
      serverSessionMissing,
      folders: [],
      selectedFolderId: null,
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
    vaultName,
    serverUrl,
    lockTimeoutMinutes,
    serverSessionMissing,
    folders,
    selectedFolderId: normalizeFolderSelection(selectedFolderId),
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
  if (timeoutMinutes > 0 && idleSeconds() >= timeoutMinutes * 60) {
    console.info("[voult] auto-lock after idle timeout");
    await publishLock("autolock");
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
  /** Destination chosen in the save card (null = Unfiled); omitted = no choice. */
  folderId?: string | null;
  /** Page's declared icon at capture time (re-validated before any write). */
  faviconUrl?: string | null;
}

let pendingSave: PendingSave | null = null;

export function setPendingSave(save: PendingSave | null): void {
  pendingSave = save;
}

export function getPendingSave(): PendingSave | null {
  return pendingSave;
}

// --- Redirect-surviving save prompt (memory only — never persisted) ---------
//
// The save banner is page-anchored, so a sign-in redirect destroys it before
// the user can act. The worker therefore retains the last prompted capture;
// each freshly loaded page on the same origin re-asks via
// getPendingPrompt() and re-shows the banner. Confirm uses the retained
// secret (the new page has no password field); explicit dismiss / never /
// lock / successful save clears it.

export interface PendingPrompt {
  username: string;
  password: string;
  origin: string;
  mode: "save" | "update";
  faviconUrl?: string | null;
  /** Wall-clock of the capture; compared against PENDING_PROMPT_TTL_MS. */
  at: number;
}

let pendingPrompt: PendingPrompt | null = null;

/** Prompt survives long enough for any IdP/login redirect dance, no longer. */
const PENDING_PROMPT_TTL_MS = 5 * 60 * 1000;

export function setPendingPrompt(p: PendingPrompt | null): void {
  pendingPrompt = p;
}

export function clearPendingPrompt(): void {
  pendingPrompt = null;
}

/**
 * Returns the retained prompt for `pageOrigin` when it is still actionable:
 * unlocked, fresh, same origin, not never-listed, and not already saved.
 * Stale entries are cleared so one capture prompts at most until resolved.
 */
export async function getPendingPrompt(pageOrigin: string): Promise<SavePrompt> {
  if (!isUnlocked() || !pendingPrompt) return { prompt: false };
  let canonical: string;
  try {
    canonical = originOfUrl(pageOrigin);
  } catch {
    return { prompt: false };
  }
  const p = pendingPrompt;
  if (p.origin !== canonical) return { prompt: false };
  if (Date.now() - p.at > PENDING_PROMPT_TTL_MS) {
    pendingPrompt = null;
    return { prompt: false };
  }
  if (await isNeverOrigin(canonical)) {
    pendingPrompt = null;
    return { prompt: false };
  }
  touch();
  // Resolved meanwhile (saved elsewhere / duplicate tab confirmed) → drop.
  const exact = items.find((i) => i.origin === canonical && i.username === p.username);
  if (exact && exact.password === p.password) {
    pendingPrompt = null;
    return { prompt: false };
  }
  const dest = saveDestinations();
  return {
    prompt: true,
    mode: p.mode,
    origin: canonical,
    username: p.username,
    ...dest,
    // An update never moves the entry: it stays in the folder it already has.
    folderId: p.mode === "update" ? (exact?.folderId ?? null) : dest.folderId,
    faviconUrl: sanitizeFaviconUrl(p.faviconUrl) ?? fallbackFaviconUrl(canonical) ?? null,
  };
}

/**
 * Confirms the retained prompt using the stored secret. The caller may pass
 * the new page's icon (preferred) and the destination picked in the card;
 * otherwise the capture-time icon is used and the first folder is the default.
 * Keeps the prompt when offline so a later page can retry; clears on save.
 */
export async function confirmPendingPrompt(
  pageOrigin: string,
  faviconUrl?: string | null,
  folderId?: string | null,
): Promise<SaveResult> {
  if (!isUnlocked() || !pendingPrompt) throw new Error("Nothing to save.");
  let canonical: string;
  try {
    canonical = originOfUrl(pageOrigin);
  } catch {
    throw new Error("Unknown site origin.");
  }
  const p = pendingPrompt;
  if (p.origin !== canonical) throw new Error("Saved login changed; please capture it again.");
  if (Date.now() - p.at > PENDING_PROMPT_TTL_MS) {
    pendingPrompt = null;
    throw new Error("Saved login expired; please capture it again.");
  }
  const icon = sanitizeFaviconUrl(faviconUrl) ?? sanitizeFaviconUrl(p.faviconUrl) ?? null;
  const result = await pushSave(p.username, p.password, canonical, p.mode, icon, folderId);
  if (result.saved) pendingPrompt = null;
  return result;
}

/** Adopt a freshly pushed server snapshot into the in-memory cache. */
export function adoptSnapshot(
  nextDoc: { name: string; folders: Folder[]; items: VaultItem[] },
  nextVersion: number,
): void {
  if (!isUnlocked()) return;
  vaultName = nextDoc.name;
  folders = nextDoc.folders;
  items = nextDoc.items;
  version = nextVersion;
  // A folder deleted elsewhere can invalidate the filter; fall back to All
  // folders (and mirror the correction) instead of scoping to a ghost folder.
  const selection = normalizeFolderSelection(selectedFolderId);
  if (selection !== selectedFolderId) {
    selectedFolderId = selection;
    const id = vaultId;
    if (id) {
      void persistFolderSelection(id, selection).catch((e) => {
        console.warn("[voult] failed to correct folder filter", e);
      });
    }
  }
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

/**
 * Where a save lands when the card's picker was never touched:
 *
 *  - the folder the user is currently viewing, so the save follows the filter;
 *  - "Unfiled" when that is the bucket in view (an explicit empty destination);
 *  - otherwise the vault's default folder — `DEFAULT_FOLDER_ID`, i.e. the folder
 *    every vault is born with ("Personal", even if it was renamed since);
 *  - the first folder, or Unfiled, when that folder was deleted.
 *
 * A dangling filter id normalizes to All folders first, so this can never return
 * a folder that is not in the current document.
 */
function defaultSaveFolderId(): string | null {
  const selection = normalizeFolderSelection(selectedFolderId);
  if (selection === UNFILED_SELECTION) return null;
  if (selection) return selection;
  if (folders.some((f) => f.id === DEFAULT_FOLDER_ID)) return DEFAULT_FOLDER_ID;
  return folders[0]?.id ?? null;
}

/**
 * Destination choices for the save card: the vault label (display only), the
 * folder list in document order, and the preselected destination (see
 * `defaultSaveFolderId`). Read straight from the unlocked cache, so rendering
 * the card never costs a network hop.
 */
function saveDestinations(): {
  vaultName: string | null;
  folders: SaveFolder[];
  folderId: string | null;
} {
  return {
    vaultName,
    folders: folders.map((f) => ({ id: f.id, name: f.name })),
    folderId: defaultSaveFolderId(),
  };
}

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

/**
 * Decides whether a captured login deserves a save/update prompt. `faviconUrl`
 * is the page's icon hint, used for the card's tile only (never stored here —
 * the write path re-sanitizes whatever it finally keeps).
 */
export async function evaluateCandidate(
  username: string,
  password: string,
  pageOrigin: string,
  faviconUrl?: string | null,
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
  const dest = saveDestinations();
  const icon = sanitizeFaviconUrl(faviconUrl) ?? fallbackFaviconUrl(canonical) ?? null;
  // Only origin-bound items participate: legacy items without an origin will
  // prompt a fresh save once (healing them into origin-bound entries; the old
  // row can be deleted in the web app). Documented v1 trade-off.
  const exact = items.find((i) => i.origin === canonical && i.username === username);
  if (exact && exact.password === password) return { prompt: false };
  if (exact) {
    return {
      prompt: true,
      mode: "update",
      origin: canonical,
      username,
      ...dest,
      // An update keeps the entry in the folder it already lives in.
      folderId: exact.folderId ?? null,
      faviconUrl: icon,
    };
  }
  return { prompt: true, mode: "save", origin: canonical, username, ...dest, faviconUrl: icon };
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
 *
 * `faviconUrl` is the page's declared icon (untrusted content-script hint):
 * sanitized here (http(s) only, length-capped) and never allowed to block or
 * fail the save. Fresh saves store it (falling back to `<origin>/favicon.ico`
 * when the page declares none); updates heal a missing/stale icon alongside
 * the password change via the same per-field LWW path.
 *
 * `folderId` is the destination picked in the save card: a folder id, or null
 * for the Unfiled bucket. Omitted (an older content script) falls back to the
 * selected folder / the vault's default folder — see `defaultSaveFolderId`.
 * Updates ignore it — they never move an entry.
 */
export async function pushSave(
  username: string,
  password: string,
  origin: string,
  mode: "save" | "update",
  faviconUrl?: string | null,
  folderId?: string | null,
): Promise<SaveResult> {
  if (!isUnlocked()) throw new Error("Vault is locked.");

  // Resolve the destination once, outside the CAS retry: the collection point
  // must not change between attempts.
  const destination = folderId === undefined ? defaultSaveFolderId() : folderId;

  // Icon resolution happens against the in-memory cache while unlocked so an
  // update can heal a missing icon. The op is fixed across CAS retries (creates
  // are idempotent by id; updates replay per-field LWW onto each snapshot).
  const resolveIcon = (existing?: VaultItem): string | undefined =>
    sanitizeFaviconUrl(faviconUrl) ?? fallbackFaviconUrl(origin) ?? existing?.faviconUrl;

  const op =
    mode === "save"
      ? (() => {
          const icon = resolveIcon();
          return {
            operation: "create",
            payload: {
              id: uuid(),
              site: siteLabelForOrigin(origin),
              username,
              password,
              sso: [],
              origin,
              // Omitted rather than null: the document schema treats a missing
              // folderId as the Unfiled bucket, and does not accept null.
              ...(destination ? { folderId: destination } : {}),
              ...(icon ? { faviconUrl: icon } : {}),
            },
          };
        })()
      : (() => {
          const existing = items.find((i) => i.origin === origin && i.username === username);
          if (!existing) {
            throw new Error("Saved login changed; please capture it again.");
          }
          const icon = resolveIcon(existing);
          return {
            operation: "update",
            payload: {
              id: existing.id,
              fields: {
                password,
                // Heal a missing icon or refresh a changed one; identical
                // values are a no-op downstream (changed stays false).
                ...(icon && icon !== existing.faviconUrl ? { faviconUrl: icon } : {}),
              },
            },
          };
        })();

  return pushSingleIntent(op, () =>
    setPendingSave({
      username,
      password,
      origin,
      mode,
      folderId: destination,
      faviconUrl: sanitizeFaviconUrl(faviconUrl) ?? null,
    }),
  );
}

/**
 * Shared read-modify-CAS-write for one confirmed intent (password or OAuth).
 * `onOffline` stashes the in-memory retry candidate when the network is down
 * (plaintext never touches disk); callers clear their pending state on success
 * via the returned `saved` flag. Bounded retries; aborts on session change.
 */
async function pushSingleIntent(
  op: { operation: string; payload: unknown },
  onOffline: () => void,
): Promise<SaveResult> {
  const key = currentVaultKey();
  const id = currentVaultId();
  if (!key || !id) throw new Error("Vault is locked.");
  const serverUrl = await getServerUrl();
  const pinId = id;
  const sessionChanged = () => currentVaultId() !== pinId || currentVaultKey() !== key;

  // The destination is decided by the caller (pushSave / pushSaveOAuth) before
  // the first attempt, so a create never silently lands somewhere else after a
  // retry. A missing folderId is the Unfiled bucket.
  const payload = { ...(op.payload as Record<string, unknown>) };
  const enc = await encrypt(JSON.stringify(payload), key);
  const intent = {
    id: uuid(),
    operation: op.operation,
    payload: b64(enc.cipher),
    payload_iv: b64(enc.iv),
    created_at: new Date().toISOString(),
  };

  for (let attempt = 1; attempt <= MAX_SAVE_RETRIES; attempt++) {
    if (sessionChanged()) throw new Error("Session changed; save aborted.");
    let serverDoc: { name: string; folders?: Folder[]; items: VaultItem[] };
    let serverVersion: number;
    try {
      const vaultData = await fetchVault(serverUrl);
      const plain = await decrypt(vaultData.vault.vault, vaultData.vault.vaultiv, key);
      // Preserve the whole document: name, folders and items. The extension must
      // never strip a field it does not render, or a web-app rename/folder
      // change would be lost on the next save from here.
      const parsed = parseVaultDocument(plain);
      serverDoc = {
        name: parsed.name,
        folders: parsed.folders,
        items: parsed.items,
      };
      serverVersion = vaultData.vault.version;
    } catch (e) {
      if (isNetworkError(e)) {
        onOffline();
        return { saved: false, offline: true };
      }
      throw e;
    }

    const merged = await mergeVault(serverDoc, [intent], key);
    if (!merged.changed) {
      adoptSnapshot(merged, serverVersion);
      setPendingSave(null);
      return { saved: true, offline: false };
    }
    const encrypted = await encrypt(JSON.stringify({ name: merged.name, folders: merged.folders, items: merged.items }), key);
    if (sessionChanged()) throw new Error("Session changed; save aborted.");
    try {
      const response = await postUpdateVault(
        { vault: b64(encrypted.cipher), vaultiv: b64(encrypted.iv), version: serverVersion },
        serverUrl,
      );
      const syncedPlain = await decrypt(response.vault, response.vaultiv, key);
      // Adopt the whole document, not just items: a folder create/rename that
      // the server applied must be visible to the popup's folder filter.
      adoptSnapshot(parseVaultState(syncedPlain), response.version);
      setPendingSave(null);
      console.info("[voult] login saved");
      return { saved: true, offline: false };
    } catch (e) {
      if (isNetworkError(e)) {
        onOffline();
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
  onOffline();
  return { saved: false, offline: false };
}

// --- OAuth sign-in memory ------------------------------------------------------
//
// Tracks one in-flight "Continue with X" click (memory only, never persisted)
// and decides whether a later page state on the same origin looks like the
// user came back from the IdP. A prompt is only ever a suggestion — the save
// happens on explicit banner confirm via pushSaveOAuth(), reusing the same
// CAS path as password saves. No OAuth secret ever exists to store; the
// provider is linked onto the site's login alongside any password.
//
// We cannot observe WHICH IdP account was used, so the prompt never asserts
// one: it carries the vault's known accounts for that provider and lets the
// user pick. With no known account the method is stored provider-only.

export interface PendingOAuth {
  provider: SsoProvider;
  sourceOrigin: string;
  tabId?: number;
  /** Wall-clock of the click; compared against OAUTH_WINDOW_MS. */
  at: number;
}

/** Click→return window. Longer than any real IdP dance; short enough that a
 *  stale click can't nag across sessions (lock() also clears it). */
const OAUTH_WINDOW_MS = 10 * 60 * 1000;

/** Cap on vault accounts offered in the SSO banner — a picker, not a roster. */
const ACCOUNT_CHOICE_LIMIT = 8;

let pendingOAuth: PendingOAuth | null = null;

/** Record a click on an SSO button. New clicks overwrite (single slot). */
export function recordOAuthClick(provider: SsoProvider, sourceOrigin: string, tabId?: number): void {
  try {
    sourceOrigin = originOfUrl(sourceOrigin);
  } catch {
    return;
  }
  pendingOAuth = { provider, sourceOrigin, tabId, at: Date.now() };
  touch();
}

export function clearPendingOAuth(): void {
  pendingOAuth = null;
}

/** Drop a stale click for one origin (e.g. the user typed a password instead). */
export function clearPendingOAuthFor(origin: string): void {
  if (pendingOAuth && pendingOAuth.sourceOrigin === origin) pendingOAuth = null;
}

/** Paths that still look like "choosing how to sign in". */
const LOGIN_PATH_RE = /\/(login|signin|sign-in|auth|oauth|authorize)/i;

/**
 * Decides whether a page state (reported by the content script on SSO pages)
 * deserves a "Signed in with X?" prompt. Returns prompt:false while the user
 * still looks mid-choice (login form present on a login-ish path) so we never
 * nag before the dance finishes. Clears the pending click once it resolves
 * (saved-elsewhere, never-listed, expired) so one click prompts at most once.
 */
export async function evaluateOAuthPageState(
  offers: SsoProvider[],
  hasLoginForm: boolean,
  path: string,
  pageOrigin: string,
  faviconUrl?: string | null,
): Promise<OAuthSavePrompt> {
  void offers;
  if (!isUnlocked() || !pendingOAuth) return { prompt: false };
  let canonical: string;
  try {
    canonical = originOfUrl(pageOrigin);
  } catch {
    return { prompt: false };
  }
  const pending = pendingOAuth;
  if (pending.sourceOrigin !== canonical) return { prompt: false };
  if (Date.now() - pending.at > OAUTH_WINDOW_MS) {
    pendingOAuth = null;
    return { prompt: false };
  }
  if (await isNeverOrigin(canonical)) {
    pendingOAuth = null;
    return { prompt: false };
  }
  touch();
  // Still choosing (form + login path both present) → wait, keep pending.
  if (hasLoginForm && LOGIN_PATH_RE.test(path)) return { prompt: false };
  // Already remembered → no prompt. The prompt carries no account of its own
  // (we cannot know which one was used), so this suppresses re-prompting for
  // a provider the user already saved *at some account* on this site. A second,
  // different account at the same provider is therefore not offered a second
  // prompt — it must be added manually. That is deliberate: nagging on every
  // sign-in with an account we cannot verify is worse than a missed suggestion.
  if (
    items.some(
      (i) => i.origin === canonical && (i.sso ?? []).some((s) => s.provider === pending.provider),
    )
  ) {
    pendingOAuth = null;
    return { prompt: false };
  }
  pendingOAuth = null;
  // Offer what the vault already knows about this provider. Bounded so a large
  // vault cannot turn the card into an unreadable list of accounts.
  const accounts = ssoAccountsForProvider(items, pending.provider).slice(0, ACCOUNT_CHOICE_LIMIT);
  return {
    prompt: true,
    provider: pending.provider,
    origin: canonical,
    accounts,
    ...saveDestinations(),
    faviconUrl: sanitizeFaviconUrl(faviconUrl) ?? fallbackFaviconUrl(canonical) ?? null,
  };
}

/**
 * Saves a confirmed SSO sign-in (no secret — a provider+account method linked
 * onto the site's login) via the shared CAS push.
 *
 * `account` may be empty: that is the honest answer when the vault holds no
 * account for this provider, and it stores a provider-only method ("Sign in
 * with GitHub") on an item with no `username`. A non-empty account means the
 * user picked one of the vault's known accounts for that provider in the
 * banner, and it is stored exactly as if they had typed it.
 *
 * One item = one account. A named sign-in joins the same-origin item that
 * already represents `account` — which is what keeps case B (site username +
 * password + "Continue with Google" on the same account) a single row, and case
 * F (personal and work Google on one site) two rows. A named method is only
 * ever attached to an item whose identity matches, so the sso/account pair can
 * never contradict `username`. A provider-only method has no identity to match,
 * so it never joins an existing item: it becomes its own row, and a repeat
 * capture of the same method is a silent no-op rather than a duplicate.
 *
 * Throws when locked or on an unparseable origin.
 */
export async function pushSaveOAuth(
  provider: SsoProvider,
  account: string,
  origin: string,
  faviconUrl?: string | null,
  folderId?: string | null,
): Promise<SaveResult> {
  if (!isUnlocked()) throw new Error("Vault is locked.");
  const trimmed = account.trim();
  let canonical: string;
  try {
    canonical = originOfUrl(origin);
  } catch {
    throw new Error("Unknown site origin.");
  }
  // Same destination rule as password saves: an explicit card choice wins,
  // null means Unfiled, and "no choice" files into the selected folder (or the
  // vault's default folder when the view is All folders).
  const destination = folderId === undefined ? defaultSaveFolderId() : folderId;
  // Already stored on this origin — nothing to write. Reachable because the
  // banner offers vault-wide accounts: picking an account this site already
  // signs in with is a legitimate choice that simply needs no change.
  if (items.some((i) => i.origin === canonical && hasSsoSignIn(i, provider, trimmed))) {
    console.info("[voult] oauth login already saved for this origin");
    return { saved: false, offline: false };
  }
  // Only a NAMED account can join an existing item — findItemForAccount matches
  // on `username`, which a provider-only item deliberately has no value for.
  const existing = trimmed ? findItemForAccount(items, canonical, trimmed) : undefined;
  const icon = sanitizeFaviconUrl(faviconUrl) ?? fallbackFaviconUrl(canonical);
  const op = existing
    ? {
        operation: "update",
        payload: {
          id: existing.id,
          fields: {
            sso: upsertSsoSignIn(existing.sso ?? [], { provider, account: trimmed }),
            ...(icon && icon !== existing.faviconUrl ? { faviconUrl: icon } : {}),
          },
        },
      }
    : {
        operation: "create",
        payload: {
          id: uuid(),
          site: siteLabelForOrigin(canonical),
          // The IdP account IS this account's identity — there is no
          // site-local username for an SSO-only login. Provider-only sign-ins
          // store none: an unknown identity stays unknown rather than becoming
          // an empty `username` every surface would have to special-case.
          ...(trimmed ? { username: trimmed } : {}),
          sso: [{ provider, account: trimmed }],
          origin: canonical,
          // Missing (not null) = Unfiled, per the document schema.
          ...(destination ? { folderId: destination } : {}),
          ...(icon ? { faviconUrl: icon } : {}),
        },
      };
  const res = await pushSingleIntent(op, () => undefined);
  if (res.saved) console.info("[voult] oauth login saved");
  return res;
}
