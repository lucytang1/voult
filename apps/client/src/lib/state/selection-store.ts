/**
 * Durable, vault-scoped metadata for the selected vault and its lock record.
 *
 * M2 replaces the previous `sessionStorage["voult.lockedAt"]` timestamp with
 * this module. Three changes, all required by the plan's restart semantics:
 *
 *  1. `localStorage` instead of `sessionStorage`. `sessionStorage` is scoped to
 *     one tab, so a lock record could never survive a browser, app, or device
 *     restart — which is exactly what the model must support. Persistence here
 *     means surviving restarts on the same installation / browser profile where
 *     this storage and the device key remain. It does NOT mean syncing unlock
 *     keys across devices, and it does not survive cleared app data.
 *
 *  2. The lock record names its vault and its reason. A bare timestamp cannot
 *     tell a lock the user just performed from a timer that fired seconds ago,
 *     and `AUTOLOCK_NEVER` is a different promise than "15 minutes". With the
 *     reason recorded, `decideRestore()` is a pure function of stored data.
 *
 *  3. The selected vault id is persisted too, so the app can restore a
 *     selection even when the session cookie is gone — the core M2 rule that a
 *     dead cookie must not erase the user's identity.
 *
 * Nothing here is secret: a UUID, an enum, and two timestamps. Keys, passwords,
 * envelopes, and vault contents are never written here.
 */

const SELECTION_KEY = "voult.selectedVault";
const LOCK_RECORD_KEY = "voult.lockRecord";

/** localStorage is absent during SSR/prerender and can throw when disabled. */
function storage(): Storage | null {
  try {
    if (typeof localStorage === "undefined") return null;
    return localStorage;
  } catch {
    // Access itself can throw when the browser blocks storage entirely.
    return null;
  }
}

function readRaw(key: string): string | null {
  try {
    return storage()?.getItem(key) ?? null;
  } catch (e) {
    console.warn(`Failed to read ${key}`, e);
    return null;
  }
}

function writeRaw(key: string, value: string): void {
  try {
    storage()?.setItem(key, value);
  } catch (e) {
    // Quota or private-mode failure. Non-fatal: the app still works in-memory
    // for this tab, it just cannot restore across a restart.
    console.warn(`Failed to persist ${key}`, e);
  }
}

function removeRaw(key: string): void {
  try {
    storage()?.removeItem(key);
  } catch (e) {
    console.warn(`Failed to remove ${key}`, e);
  }
}

// --- Selected vault ------------------------------------------------------

/** The persisted vault id, or null when nothing has been selected yet. */
export function readSelectedVaultId(): string | null {
  const raw = readRaw(SELECTION_KEY);
  if (raw === null || raw === "") return null;
  return raw;
}

export function persistSelectedVaultId(vaultId: string): void {
  writeRaw(SELECTION_KEY, vaultId);
}

export function clearSelectedVaultId(): void {
  removeRaw(SELECTION_KEY);
}

// --- Lock record ---------------------------------------------------------

/**
 * Mirrors `LockReason` from state/vault-state.ts. Re-declared structurally
 * rather than imported so that a malformed stored value is caught by the
 * validator below instead of being trusted as a typed enum.
 */
const LOCK_REASONS = ["manual", "autolock", "peer"] as const;
export type StoredLockReason = (typeof LOCK_REASONS)[number];

export interface StoredLockRecord {
  vaultId: string;
  reason: StoredLockReason;
  lockedAt: number;
}

function isLockReason(value: unknown): value is StoredLockReason {
  return typeof value === "string" && (LOCK_REASONS as readonly string[]).includes(value);
}

/**
 * Reads the persisted lock record.
 *
 * Validates shape on the way out. This is user-writable storage that survives
 * upgrades and can be hand-edited, so a corrupt or partial record is discarded
 * rather than fed into the restore decision — a bogus `lockedAt` could
 * otherwise keep a vault permanently locked, or (with a far-future timestamp)
 * force an unlock the user did not ask for.
 */
export function readLockRecord(): StoredLockRecord | null {
  const raw = readRaw(LOCK_RECORD_KEY);
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    console.warn("Discarding unparseable lock record");
    return null;
  }
  const r = parsed as Partial<StoredLockRecord>;
  if (
    typeof r?.vaultId !== "string" ||
    r.vaultId === "" ||
    !isLockReason(r?.reason) ||
    typeof r?.lockedAt !== "number" ||
    !Number.isFinite(r.lockedAt)
  ) {
    console.warn("Discarding invalid lock record", parsed);
    return null;
  }
  return { vaultId: r.vaultId, reason: r.reason, lockedAt: r.lockedAt };
}

export function persistLockRecord(record: StoredLockRecord): void {
  writeRaw(LOCK_RECORD_KEY, JSON.stringify(record));
}

export function clearLockRecord(): void {
  removeRaw(LOCK_RECORD_KEY);
}

// --- Idle activity -------------------------------------------------------

/**
 * Last recorded activity while a vault was unlocked, per vault.
 *
 * The auto-lock timer is a *deadline*, not a background job: a closed tab or
 * browser cannot run code at the five-minute mark. Persisting the timestamp
 * lets the next start compare wall-clock idle time before it restores a key or
 * renders a vault, so closing the app early does not reset the window.
 *
 * Not secret: a number. Never key material, a password, or vault contents.
 */
const ACTIVITY_PREFIX = "voult.lastActivity.";

const activityKey = (vaultId: string) => `${ACTIVITY_PREFIX}${vaultId}`;

/** Epoch ms of the last activity, or null when none has been recorded. */
export function readLastActivity(vaultId: string): number | null {
  const raw = readRaw(activityKey(vaultId));
  if (raw === null) return null;
  const parsed = Number(raw);
  // A corrupt/far-future value could keep a vault open forever (negative idle
  // time), so only accept a finite past-ish timestamp.
  if (!Number.isFinite(parsed) || parsed <= 0 || parsed > Date.now() + 60_000) {
    console.warn("Discarding invalid last-activity timestamp", raw);
    return null;
  }
  return parsed;
}

export function persistLastActivity(vaultId: string, at: number = Date.now()): void {
  writeRaw(activityKey(vaultId), String(at));
}

export function clearLastActivity(vaultId: string): void {
  removeRaw(activityKey(vaultId));
}

// --- One-time lock-policy migration -------------------------------------

const POLICY_VERSION_KEY = "voult.lockPolicyVersion";
/** Bump when the meaning of a stored lock reason changes. */
const POLICY_VERSION = 2;

/**
 * Heal lock records written by the earlier build that published *timer* locks
 * through `POST /lock`. Those bumps were recorded by peers as `peer` — a
 * "someone deliberately locked this" decision — so the vault kept reopening
 * locked even when the local timer permitted a restore.
 *
 * From POLICY_VERSION 2 only a manual lock can produce a peer record, so a
 * pre-existing `peer` record is ambiguous. Discarding it once is the safe
 * trade: the user simply unlocks (or stays unlocked) and a future deliberate
 * lock is recorded normally. This runs once per browser profile.
 */
export function migrateLockPolicy(): void {
  const current = readRaw(POLICY_VERSION_KEY);
  if (current === String(POLICY_VERSION)) return;
  const record = readLockRecord();
  if (record?.reason === "peer") {
    console.info("Discarding a legacy peer lock record (timer-lock propagation fix)");
    clearLockRecord();
  }
  writeRaw(POLICY_VERSION_KEY, String(POLICY_VERSION));
}