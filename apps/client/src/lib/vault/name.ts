/**
 * Vault display names.
 *
 * A vault's *identity* is still its UUID: storage is namespaced by it, the
 * session cookie carries it, and every cross-vault guard compares it. What
 * this module adds is the human label — a name the user picks at onboarding and
 * can change later.
 *
 * The canonical name lives inside the encrypted vault document (so the server
 * never learns it and it travels with the vault across devices and cloud
 * backups). That document is only readable while unlocked, but the lock screen
 * and vault chooser must render a name *before* the key is in memory, so the
 * last known name is cached per vault in localStorage.
 *
 * The cache is a label, not a secret: same class of data as
 * `voult.selectedVault` in `selection-store.ts`. Key material, passwords and
 * vault contents are never written here.
 */

import {
  DEFAULT_VAULT_NAME,
  MAX_VAULT_NAME_LENGTH,
} from "@voult/vault-core";

export { DEFAULT_VAULT_NAME, MAX_VAULT_NAME_LENGTH };

const CACHE_PREFIX = "voult.vaultName.";
/** An optimistic rename that has not reached the server document yet. */
const PENDING_PREFIX = "voult.pendingVaultName.";

/**
 * Canonical form of a user-entered name, or `null` when it is unusable.
 *
 * Collapses internal whitespace and strips control characters so a pasted name
 * cannot smuggle newlines into the UI, and bounds the length so the encrypted
 * document (and the recovery PDF line) stays a sane size. There is no
 * uniqueness rule: two vaults may share a name, because `vaultId` is what
 * identifies them.
 */
export function normalizeVaultName(input: string): string | null {
  if (typeof input !== "string") return null;
  const cleaned = input
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned || cleaned.length > MAX_VAULT_NAME_LENGTH) return null;
  return cleaned;
}

/** localStorage is absent during SSR/prerender and can throw when disabled. */
function storage(): Storage | null {
  try {
    if (typeof localStorage === "undefined") return null;
    return localStorage;
  } catch {
    return null;
  }
}

function readRaw(key: string): string | null {
  try {
    return storage()?.getItem(key) ?? null;
  } catch (e) {
    console.warn("Failed to read cached vault name", e);
    return null;
  }
}

function writeRaw(key: string, value: string): void {
  try {
    storage()?.setItem(key, value);
  } catch (e) {
    // Private mode / quota. Non-fatal: the document still carries the name.
    console.warn("Failed to persist vault name", e);
  }
}

function removeRaw(key: string): void {
  try {
    storage()?.removeItem(key);
  } catch (e) {
    console.warn("Failed to remove cached vault name", e);
  }
}

/** Last name confirmed by a vault document, without considering renames in flight. */
export function readCachedVaultName(vaultId: string): string | null {
  return normalizeVaultName(readRaw(`${CACHE_PREFIX}${vaultId}`) ?? "");
}

/** Record the name carried by a decrypted document. */
export function cacheVaultName(vaultId: string, name: string): void {
  const normalized = normalizeVaultName(name);
  if (!normalized) return;
  writeRaw(`${CACHE_PREFIX}${vaultId}`, normalized);
}

/**
 * Mark a rename as locally applied but not yet confirmed by the server.
 *
 * While set, this value outranks the document's name for display. Without it a
 * lock/unlock (which re-reads the server document) could visually revert a
 * rename that is still queued, before sync has a chance to run.
 */
export function setPendingVaultName(vaultId: string, name: string): void {
  const normalized = normalizeVaultName(name);
  if (normalized) writeRaw(`${PENDING_PREFIX}${vaultId}`, normalized);
}

export function readPendingVaultName(vaultId: string): string | null {
  return normalizeVaultName(readRaw(`${PENDING_PREFIX}${vaultId}`) ?? "");
}

export function clearPendingVaultName(vaultId: string): void {
  removeRaw(`${PENDING_PREFIX}${vaultId}`);
}

/**
 * The name to render for a vault: a pending rename, else the document's name,
 * else the cached copy, else a short id.
 *
 * Callers pass `docName` when they hold a decrypted document (the normal
 * unlocked case). The short id is a last-resort fallback for a vault this
 * device has never opened — never the primary label.
 */
export function displayVaultName(
  vaultId: string | null | undefined,
  docName?: string | null,
): string {
  if (!vaultId) return "Vault";
  return (
    readPendingVaultName(vaultId) ??
    (docName && docName.trim() ? docName : null) ??
    readCachedVaultName(vaultId) ??
    `Vault ${vaultId.slice(0, 8)}…`
  );
}

/** True when this device has a name for the vault (used to hide redundant ids). */
export function hasKnownVaultName(vaultId: string | null | undefined): boolean {
  if (!vaultId) return false;
  return Boolean(readPendingVaultName(vaultId) ?? readCachedVaultName(vaultId));
}
