import { create } from "zustand";
import { AppState, AuthState, DecryptedVault, LockMetadata, SessionState, VaultItem } from "./type";
import { UpdateVaultItem, CreateVaultItem, DeleteVaultItem } from "../sync/type";

const useAppStore = create<AppState>()((set) => ({
  vaultKey: null,
  authKey: null,
  session: null,
  decryptedVault: null,
  vaultVersion: null,
  isLocked: true,
  isSyncing: false,
  lockMetadata: null,
}));

const setVaultKey = (vaultKey: CryptoKey) => {
  // Any path that installs a key (login, signup, password unlock) ends the
  // locked state, including its persisted flag.
  clearLockedFlag();
  useAppStore.setState({ vaultKey, isLocked: false });
};
const setAuthKey = (authKey: CryptoKey) => useAppStore.setState({ authKey });
const setSession = (session: SessionState) =>
  useAppStore.setState({ session });
const updateVaultVersion = (vaultVersion: number) =>
  useAppStore.setState({ vaultVersion });
const setSyncStatus = (isSyncing: boolean) =>
  useAppStore.setState({ isSyncing });

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
 * Lock must survive page reloads: in-memory state is lost on refresh, and
 * unlockWithDevice() would otherwise silently re-unlock the vault. A
 * sessionStorage flag marks the session as user-locked so the bootstrap
 * skips device-key auto-unlock. sessionStorage (not localStorage) means a
 * fresh browser session still requires login.
 */
const LOCKED_FLAG_KEY = "voult.locked";
export function persistLockedFlag() {
  try {
    sessionStorage.setItem(LOCKED_FLAG_KEY, "1");
  } catch (e) {
    console.warn("Failed to persist locked flag", e);
  }
}
export function clearLockedFlag() {
  try {
    sessionStorage.removeItem(LOCKED_FLAG_KEY);
  } catch {
    // ignore
  }
}
export function isLockedFlagSet(): boolean {
  try {
    return sessionStorage.getItem(LOCKED_FLAG_KEY) === "1";
  } catch {
    return false;
  }
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
  persistLockedFlag();
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
  clearLockedFlag();
  useAppStore.setState({
    vaultKey: null,
    authKey: null,
    session: null,
    decryptedVault: null,
    vaultVersion: null,
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
  lockVaultStorage,
  clearSessionState,
  addVaultItem,
  updateVaultItem,
  deleteVaultItem,
};
export const setVaultState = (s: any) => useAppStore.setState({ vaultState: s } as any);
export const setVaultMode = (m: any) => useAppStore.setState({ vaultMode: m } as any);
