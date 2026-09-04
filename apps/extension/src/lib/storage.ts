// chrome.storage accessors with per-vault namespacing.
//
// Mirrors the web app's per-vault isolation (one OPFS file + one IndexedDB
// record per vault): every key is prefixed `vault:<vaultId>:...` so two
// vaults onboarded in one browser profile can never see each other's data.
// `chrome.storage.session` holds only non-sensitive flags (locked, vaultId) —
// never keys, verifier, or plaintext. The wrapped device envelope stored here
// is zero-knowledge-safe (the server already knows it).

const recordKey = (vaultId: string, suffix: string) => `vault:${vaultId}:${suffix}`;

export const LOCKED_FLAG_KEY = "voult.locked";
export const ACTIVE_VAULT_KEY = "voult.activeVaultId";

export async function getSessionValue<T>(key: string): Promise<T | null> {
  const got = await chrome.storage.session.get(key);
  return (got[key] as T | undefined) ?? null;
}

export async function setSessionValue(key: string, value: unknown): Promise<void> {
  await chrome.storage.session.set({ [key]: value });
}

export async function getLocalValue<T>(key: string): Promise<T | null> {
  const got = await chrome.storage.local.get(key);
  return (got[key] as T | undefined) ?? null;
}

export async function setLocalValue(key: string, value: unknown): Promise<void> {
  await chrome.storage.local.set({ [key]: value });
}

export async function removeLocalValues(keys: string[]): Promise<void> {
  if (keys.length) await chrome.storage.local.remove(keys);
}

/** All local keys belonging to one vault (for scoped logout/teardown). */
export async function listVaultKeys(vaultId: string): Promise<string[]> {
  const all = await chrome.storage.local.get(null);
  const prefix = `vault:${vaultId}:`;
  return Object.keys(all).filter((k) => k.startsWith(prefix));
}

/** Deletes only this vault's local records; other vaults are untouched. */
export async function clearVaultRecords(vaultId: string): Promise<void> {
  await removeLocalValues(await listVaultKeys(vaultId));
}

export { recordKey };
