import { create } from "zustand";
import { AppState, AuthState, DecryptedVault, LockMetadata, SessionState, VaultItem } from "./type";
import { UpdateVaultItem, CreateVaultItem, DeleteVaultItem } from "../sync/type";
import { getWebAutolockMinutes } from "../settings";

const useAppStore = create<AppState>()((set) => ({
  vaultKey: null,
  authKey: null,
  session: null,
  decryptedVault: null,
  vaultVersion: null,
  lockEpoch: null,
  isLocked: true,
  isSyncing: false,
  lockMetadata: null,
}));

const setVaultKey = (vaultKey: CryptoKey) => {
  // Any path that installs a key (login, signup, password unlock) ends the
  // locked state, including its persisted record.
  clearLockRecord();
  useAppStore.setState({ vaultKey, isLocked: false });
};
const setAuthKey = (authKey: CryptoKey) => useAppStore.setState({ authKey });
const setSession = (session: SessionState) =>
  useAppStore.setState({ session });
const updateVaultVersion = (vaultVersion: number) =>
  useAppStore.setState({ vaultVersion });
const setSyncStatus = (isSyncing: boolean) =>
  useAppStore.setState({ isSyncing });
/**
 * Last server `lock_epoch` this client has converged to. Set on unlock (from
 * the pre-unlock GET /session) and on every observed session; advanced by the
 * POST /lock response on our own lock. Deliberately NOT cleared by
 * lockVaultStorage — a lock must remember the epoch it just published so a
 * stale poll can't resurrect keys. Cleared only with the session itself.
 */
const updateLockEpoch = (lockEpoch: number) =>
  useAppStore.setState({ lockEpoch });

// --- Auth state machine --------------------------------------------------
//
// The app has two top-level states:
//   not_authenticated — no session cookie / session cleared
//   authenticated     — session alive, subdivided into locked / unlocked
// Derived as three values for routing: not_authenticated | locked | unlocked.
export const getAuthState = (): AuthState => {
  const { session, isLocked } = useAppStore.getState();
  if (!session) return "not_authenticated";
  return isLocked ? "locked" : "unlocked";
};

const updateDecryptedVault = (decryptedVault: DecryptedVault) =>
  useAppStore.setState({ decryptedVault });

const addVaultItem = (item: CreateVaultItem) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: state.decryptedVault?.vaultId ?? state.session?.vaultId ?? "",
      items: state.decryptedVault
        ? [...state.decryptedVault.items, item]
        : [item],
    },
  }));

const updateVaultItem = (
  updateditem: UpdateVaultItem,
) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: state.decryptedVault?.vaultId ?? state.session?.vaultId ?? "",
      items:
        state.decryptedVault?.items.map((item) =>
          item.id === updateditem.id ? { ...item, ...updateditem.fields} : item,
        ) ?? [],
    },
  }));

const deleteVaultItem = (deleteitem: DeleteVaultItem) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: state.decryptedVault?.vaultId ?? state.session?.vaultId ?? "",
      items:
        state.decryptedVault?.items.filter(
          (item) => !(item.id === deleteitem.id),
        ) ?? [],
    },
  }));

// --- Lifecycle helpers (vault-native names) ------------------------------

/**
 * A lock survives a reload only until the web autolock timeout lapses.
 *
 * In-memory state is lost on refresh, so without a record a reload would
 * silently re-unlock via the device key — correct for an *expired* lock, but
 * not for a lock the user just performed or an autolock that fired seconds ago.
 * We therefore store the wall-clock time of the last lock instead of a boolean,
 * and treat the lock as live only until the web autolock timeout has elapsed.
 * "Never" (0) means the lock holds until an explicit unlock, which is the
 * old behaviour for users who opt out of autolock.
 *
 * sessionStorage (not localStorage) keeps this scoped to the browser session:
 * a fresh tab/window is a fresh storage area and gets a clean auto-unlock.
 */
const LOCKED_AT_KEY = "voult.lockedAt";

/** Records the moment of a lock and returns it. */
export function persistLockRecord(): number {
  const lockedAt = Date.now();
  try {
    sessionStorage.setItem(LOCKED_AT_KEY, String(lockedAt));
  } catch (e) {
    console.warn("Failed to persist lock record", e);
  }
  return lockedAt;
}

export function clearLockRecord() {
  try {
    sessionStorage.removeItem(LOCKED_AT_KEY);
  } catch {
    // ignore
  }
}

function readLockRecord(): number | null {
  try {
    const raw = sessionStorage.getItem(LOCKED_AT_KEY);
    if (raw === null) return null;
    const parsed = Number(raw);
    if (!Number.isFinite(parsed)) {
      console.warn("Discarding invalid lock record", raw);
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

/**
 * True while the most recent lock is still inside its autolock window, i.e.
 * this reload must stay on /lock. Once the window lapses the record is dropped
 * and the caller may attempt a silent device-key unlock.
 */
export function isLockStillActive(): boolean {
  const lockedAt = readLockRecord();
  if (lockedAt === null) return false;
  const minutes = getWebAutolockMinutes();
  if (minutes <= 0) return true; // autolock disabled: hold until explicit unlock
  if (Date.now() - lockedAt < minutes * 60_000) return true;
  clearLockRecord();
  return false;
}

/**
 * Locking clears the vault key, auth key, decrypted vault, and cached unlock
 * metadata while retaining the session cookie, vault version (so pending sync
 * intents keep a valid base_version), device key, and envelope. The metadata
 * captured here lets unlock re-derive the vault key from the master password
 * entirely client-side.
 *
 * Note: clearing TanStack Query's ["vault"] cache (ciphertext) is done by the
 * caller where the query client is available.
 */
const lockVaultStorage = (metadata: LockMetadata | null = null) => {
  persistLockRecord();
  useAppStore.setState({
    vaultKey: null,
    authKey: null,
    decryptedVault: null,
    isLocked: true,
    lockMetadata: metadata,
  });
};

/**
 * Clears volatile keys and session metadata when the session expires or is
 * otherwise invalidated (401 SESSION_REQUIRED). The device key and envelope
 * deletion is handled by the caller (teardown path).
 */
const clearSessionState = () => {
  clearLockRecord();
  useAppStore.setState({
    vaultKey: null,
    authKey: null,
    session: null,
    decryptedVault: null,
    vaultVersion: null,
    lockEpoch: null,
    isLocked: true,
    lockMetadata: null,
  });
};

export {
  useAppStore,
  setVaultKey,
  setAuthKey,
  setSession,
  updateDecryptedVault,
  updateVaultVersion,
  setSyncStatus,
  updateLockEpoch,
  lockVaultStorage,
  clearSessionState,
  addVaultItem,
  updateVaultItem,
  deleteVaultItem,
};
