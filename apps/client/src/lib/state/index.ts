import { create } from "zustand";
import { AppState, DecryptedVault, Folder, LockMetadata, SessionState, VaultItem } from "./type";
import { UpdateVaultItem, CreateVaultItem, DeleteVaultItem } from "../sync/type";
import { getWebAutolockMinutes } from "../settings";
import {
  buildLockRecord,
  commitUnlock,
  decideRestore,
  INITIAL_MODEL,
  lockVault,
  onServerSessionActive,
  onServerSessionMissing,
  onServerSessionUnreachable,
  onVaultUnavailable,
  selectVault,
  selectedVaultId,
  VaultTransitionError,
  type LockReason,
  type ServerSessionStatus,
  type VaultState,
} from "./vault-state";
import {
  clearLockRecord as clearStoredLockRecord,
  clearLastActivity,
  clearSelectedVaultId,
  persistLastActivity,
  persistLockRecord as persistStoredLockRecord,
  readLastActivity,
  readLockRecord as readStoredLockRecord,
  persistSelectedVaultId,
  type StoredLockRecord,
} from "./selection-store";
import { cacheVaultName, DEFAULT_VAULT_NAME } from "../vault/name";

const useAppStore = create<AppState>()((set) => ({
  vault: INITIAL_MODEL.vault,
  selectionEpoch: 0,
  serverSession: INITIAL_MODEL.serverSession,
  availability: INITIAL_MODEL.availability,
  authKey: null,
  session: null,
  decryptedVault: null,
  vaultVersion: null,
  lockEpoch: null,
  isSyncing: false,
  lockMetadata: null,
}));

/**
 * Select a vault *and* adopt its server session, in one state write.
 *
 * This is the only supported way to establish a selection. It exists as one
 * function because the two facts are written together on every path that
 * selects a vault (bootstrap, open, switch, create), and splitting them would
 * let a caller leave the app claiming a selection it has no session for — the
 * exact disagreement this model is meant to make unrepresentable.
 *
 * Selection always lands `locked`: picking a vault never yields plaintext.
 * Callers that have a key commit it afterwards via `commitVaultUnlock`.
 *
 * `options.serverSession` exists because a selection can be restored from local
 * storage while the cookie is known to be missing. "Selected this vault" and
 * "authorized to call the server for it" are orthogonal, and defaulting the
 * latter to `active` here would make a bootstrap without a cookie lie.
 */
const selectVaultSession = (
  session: SessionState,
  options: { serverSession?: ServerSessionStatus } = {},
) => {
  // Durable before in-memory: if the tab dies between these two writes the
  // app must still come back pointed at this vault rather than at first-run.
  persistSelectedVaultId(session.vaultId);
  useAppStore.setState((state) => ({
    session,
    vault: selectVault(session.vaultId),
    // Any selection change invalidates every in-flight async operation, so
    // bump the epoch in the same write. Re-selecting the *same* vault (a
    // routine re-auth, a bootstrap restore) must NOT bump it: no cross-vault
    // contamination is possible when the identity is unchanged, and bumping
    // would needlessly abort a legitimate in-flight sync.
    selectionEpoch:
      state.vault.status !== "no_vault" && state.vault.vaultId === session.vaultId
        ? state.selectionEpoch
        : state.selectionEpoch + 1,
    // An authenticated session is active unless the caller already knows the
    // cookie is missing (bootstrap with a definitive 401).
    serverSession: options.serverSession ?? "active",
    availability: "available",
  }));
};

/**
 * Snapshot the current selection epoch for an async operation that must not
 * commit into a different vault.
 *
 * Usage:
 * ```ts
 * const guard = captureSelectionEpoch();
 * const data = await fetchSomething();
 * if (!guard.stillCurrent()) return; // a switch happened; drop the result
 * commit(data);
 * ```
 *
 * Comparing vault ids instead would fail on A→B→A, where the id is unchanged
 * but the operation is still stale. The epoch counts every transition, so it
 * catches that case too.
 */
export function captureSelectionEpoch(): { stillCurrent: () => boolean } {
  const epoch = useAppStore.getState().selectionEpoch;
  return { stillCurrent: () => useAppStore.getState().selectionEpoch === epoch };
}

/**
 * Install a vault key for the currently selected vault, moving to `unlocked`.
 *
 * Any path that installs a key (login, signup, password unlock) ends the locked
 * state, including its persisted lock record.
 *
 * The selection is re-verified against the session here rather than trusted from
 * the caller: `commitUnlock` rejects a mismatch, so a server that answers for a
 * different vault can never have its key installed under this selection. Note
 * that on the M1 path `requestedVaultId` and `sessionVaultId` are both derived
 * from the same session, so this guards against a *stale* session rather than a
 * mismatched response — M3 passes the requested id explicitly for the switch
 * path, where a genuine mismatch is possible.
 *
 * @throws VaultTransitionError when no vault is selected, which would mean the
 *   caller unlocked a vault the app does not know about.
 */
const commitVaultUnlock = (vaultKey: CryptoKey) => {
  const { session } = useAppStore.getState();
  if (!session) {
    throw new VaultTransitionError(
      "Cannot unlock: no vault is selected. Call selectVaultSession() first.",
    );
  }
  clearLockRecord();
  useAppStore.setState({
    vault: commitUnlock({
      requestedVaultId: session.vaultId,
      sessionVaultId: session.vaultId,
      vaultKey,
    }),
  });
  // A fresh unlock is activity: start the idle deadline from now, not from
  // whatever timestamp was persisted before the vault was last closed.
  persistLastActivity(session.vaultId, Date.now());
};

const setAuthKey = (authKey: CryptoKey) => useAppStore.setState({ authKey });
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

/**
 * Cache the password-wrapped envelope the lock screen uses to unlock locally.
 * Captured *after* the local wipe (see `lockVaultNow`): it is an optimization
 * for the next unlock, never a prerequisite for locking.
 */
const setLockMetadata = (lockMetadata: LockMetadata | null) =>
  useAppStore.setState({ lockMetadata });

// --- Vault state machine -------------------------------------------------
//
// The app has one primary state — which vault is selected and whether its key
// is in memory — held as the `VaultState` union. Routing reads `vault.status`
// directly rather than a separately derived label, so the thing routes on and
// the thing that holds the key cannot disagree.
//
//   no_vault — nothing selected (first run, or app data removed)
//   locked   — a vault is selected, keys absent
//   unlocked — a vault is selected, key in memory
//
// Note `locked` is a statement about local key material, not about the server
// cookie: a selected vault can be locked while its session is missing. M2
// makes that reachable on 401; until then the two still agree.
export const getVaultState = (): VaultState => useAppStore.getState().vault;

const updateDecryptedVault = (decryptedVault: DecryptedVault) => {
  // Every install path (login, unlock, import, sync, switch) funnels through
  // here, so this is the one place that keeps the pre-unlock display cache in
  // step with the document that holds the canonical name.
  cacheVaultName(decryptedVault.vaultId, decryptedVault.name);
  useAppStore.setState({ decryptedVault });
};

/**
 * The vault id to stamp onto a mutated document.
 *
 * Prefers the decrypted document's own id, falling back to the selected vault
 * so a mutation issued before the first fetch still lands with a correct id.
 * Reading the selection (rather than the session) keeps one source of truth:
 * when the two could differ, the selection is what the UI is actually showing.
 */
const documentVaultId = (state: AppState): string =>
  state.decryptedVault?.vaultId ?? selectedVaultId(state.vault) ?? "";

const addVaultItem = (item: CreateVaultItem) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: documentVaultId(state),
      name: state.decryptedVault?.name ?? DEFAULT_VAULT_NAME,
      folders: state.decryptedVault?.folders ?? [],
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
      vaultId: documentVaultId(state),
      name: state.decryptedVault?.name ?? DEFAULT_VAULT_NAME,
      folders: state.decryptedVault?.folders ?? [],
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
      vaultId: documentVaultId(state),
      name: state.decryptedVault?.name ?? DEFAULT_VAULT_NAME,
      folders: state.decryptedVault?.folders ?? [],
      items:
        state.decryptedVault?.items.filter(
          (item) => !(item.id === deleteitem.id),
        ) ?? [],
    },
  }));

/**
 * Optimistically apply a rename to the in-memory document and its display
 * cache. `lib/vault/rename.ts` owns the durable half (pending marker + intent);
 * this exists so the store stays the single writer of `decryptedVault`.
 */
const updateVaultName = (name: string) =>
  useAppStore.setState((state) => {
    const vaultId = documentVaultId(state);
    if (!vaultId) return state;
    cacheVaultName(vaultId, name);
    return {
      decryptedVault: {
        formatVersion: state.decryptedVault?.formatVersion ?? 1,
        vaultId,
        name,
        folders: state.decryptedVault?.folders ?? [],
        items: state.decryptedVault?.items ?? [],
      },
    };
  });

const addVaultFolder = (folder: Folder) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: documentVaultId(state),
      name: state.decryptedVault?.name ?? DEFAULT_VAULT_NAME,
      folders: [...(state.decryptedVault?.folders ?? []), folder],
      items: state.decryptedVault?.items ?? [],
    },
  }));

const updateVaultFolderName = (folderId: string, name: string) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: documentVaultId(state),
      name: state.decryptedVault?.name ?? DEFAULT_VAULT_NAME,
      folders: (state.decryptedVault?.folders ?? []).map((f) =>
        f.id === folderId ? { ...f, name } : f,
      ),
      items: state.decryptedVault?.items ?? [],
    },
  }));

const removeVaultFolder = (folderId: string) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: documentVaultId(state),
      name: state.decryptedVault?.name ?? DEFAULT_VAULT_NAME,
      folders: (state.decryptedVault?.folders ?? []).filter((f) => f.id !== folderId),
      items: (state.decryptedVault?.items ?? []).filter((it) => it.folderId !== folderId),
    },
  }));

const moveVaultItemToFolder = (itemId: string, folderId: string | null) =>
  useAppStore.setState((state) => ({
    decryptedVault: {
      formatVersion: state.decryptedVault?.formatVersion ?? 1,
      vaultId: documentVaultId(state),
      name: state.decryptedVault?.name ?? DEFAULT_VAULT_NAME,
      folders: state.decryptedVault?.folders ?? [],
      items: (state.decryptedVault?.items ?? []).map((it) =>
        it.id === itemId ? { ...it, folderId: folderId ?? undefined } : it,
      ),
    },
  }));

// --- Lifecycle helpers (vault-native names) ------------------------------

/**
 * Records a lock, durably and scoped to the selected vault.
 *
 * M2 replaces the previous `sessionStorage["voult.lockedAt"]` (a tab-scoped
 * bare timestamp) with `selection-store.ts`: `localStorage` so a lock survives a
 * browser/app/device restart, and a record carrying the vault id and the reason
 * so the restore decision can tell "the user locked this" from "a timer fired".
 *
 * `reason` is not cosmetic. `manual` and `peer` must hold until an explicit
 * unlock; `autolock` is allowed to lapse once the window elapses. A single
 * timestamp cannot express that distinction.
 *
 * Returns the stored record so callers can log or branch on it.
 */
export function persistLockRecord(
  reason: LockReason,
  state: AppState = useAppStore.getState(),
): StoredLockRecord | null {
  if (state.vault.status === "no_vault") return null;
  const record = buildLockRecord(state.vault, reason);
  persistStoredLockRecord(record);
  return record;
}

export function clearLockRecord() {
  clearStoredLockRecord();
}

/**
 * Reads the durable activity timestamp for the currently selected vault.
 *
 * Scoped to the selection so one vault's idle time can never govern another's
 * restore decision.
 */
export function readLastActivityForSelection(): number | null {
  const selected = selectedVaultId(useAppStore.getState().vault);
  return selected ? readLastActivity(selected) : null;
}

/**
 * Reads the durable lock record for the currently selected vault, discarding a
 * record that names a different vault (a stale record left by a switch).
 *
 * `expectedVaultId` exists for the bootstrap, which reads the record before it
 * has committed the selection: without it, a stale record from another vault
 * could decide this vault's restore policy.
 */
export function readLockRecordForSelection(
  expectedVaultId?: string,
): StoredLockRecord | null {
  const selected = expectedVaultId ?? selectedVaultId(useAppStore.getState().vault);
  const record = readStoredLockRecord();
  if (!record) return null;
  if (selected && record.vaultId !== selected) {
    console.info("Discarding lock record from a different vault");
    clearStoredLockRecord();
    return null;
  }
  return record;
}

/**
 * True while the most recent lock still holds, i.e. this reload must stay on
 * /lock. Delegates to `decideRestore()` so the policy lives in one place.
 *
 * Note this is now a *decision*, not a storage lookup: whether a lapsed
 * autolock permits a silent device unlock depends on the recorded reason and the
 * current autolock setting together, which a single comparison cannot express.
 * Callers that need to distinguish "lapsed, go ahead and unlock" from "no lock
 * ever happened" should call `decideRestore()` directly instead.
 */
export function isLockStillActive(hasDeviceMaterial = false): boolean {
  const state = useAppStore.getState();
  const decision = decideRestore({
    selectedVaultId: selectedVaultId(state.vault),
    record: readLockRecordForSelection(),
    autolockMinutes: getWebAutolockMinutes(),
    hasDeviceMaterial,
    lastActivityAt: readLastActivityForSelection(),
  });
  // A `no_selection` decision cannot happen here (we just read a selection or
  // not), but treat anything that isn't an explicit unlock as "stay locked".
  return decision.kind === "stay_locked";
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
const lockVaultStorage = (
  metadata: LockMetadata | null = null,
  reason: LockReason = "manual",
) => {
  const state = useAppStore.getState();
  const { vault } = state;
  // Only stamp the lock record on the transition into `locked`. Re-locking an
  // already-locked vault must not push `lockedAt` forward: that would restart
  // the autolock window on every peer lock event and on every redundant call,
  // so a vault locked once could never lapse back to device-unlock.
  const alreadyLocked = vault.status === "locked";
  if (!alreadyLocked) persistLockRecord(reason, state);

  useAppStore.setState({
    authKey: null,
    decryptedVault: null,
    vault: lockVault(vault, { reason }),
    lockMetadata: metadata,
  });

  if (alreadyLocked) {
    console.debug("Lock applied to an already-locked vault; autolock window unchanged");
  }
};

/**
 * The server definitively rejected our cookie (`SESSION_REQUIRED`).
 *
 * This is an authorization fact, not a lock decision, so it no longer records a
 * lock nor wipes local vault state:
 *
 *  - **Already unlocked** — keep the key, plaintext, version, epoch, and the
 *    selection. The vault remains usable locally; sync/cloud calls pause until
 *    the user reauthenticates. Wiping here is what made an expired cookie look
 *    like a user lock and contradicted "Auto-lock: Never".
 *  - **Locked** — keep the selection and device material. There is nothing
 *    secret in memory to wipe; the lock record (if any) keeps its real reason.
 *  - `session` is kept only while unlocked, where it is read as identity
 *    (`vaultId`) by local code; `serverSession: "missing"` is the authoritative
 *    signal that protected calls must not run.
 */
const loseServerSession = () => {
  const state = useAppStore.getState();
  const model = onServerSessionMissing({
    vault: state.vault,
    serverSession: state.serverSession,
    availability: state.availability,
  });
  const stillUnlocked = state.vault.status === "unlocked";

  useAppStore.setState({
    vault: model.vault,
    serverSession: model.serverSession,
    // The key and plaintext are local secrets, not server state. Only drop the
    // transient auth key (never needed after authentication).
    authKey: null,
    // A locked vault has no key to keep a session object for; the lock screen
    // uses `reauthenticateAndUnlock`. An unlocked vault keeps its identity.
    session: stillUnlocked ? state.session : null,
    decryptedVault: stillUnlocked ? state.decryptedVault : null,
    vaultVersion: stillUnlocked ? state.vaultVersion : null,
    // Preserve the epoch: it is non-sensitive, and clearing it would make the
    // next successful check re-adopt an older epoch as if it were unknown.
    lockMetadata: stillUnlocked ? state.lockMetadata : null,
  });
};

/**
 * Mark the selected vault as no longer present on the server. Keeps the
 * selection locked; the lock screen offers switch/create recovery.
 */
const markVaultUnavailable = () => {
  const state = useAppStore.getState();
  const model = onVaultUnavailable({
    vault: state.vault,
    serverSession: state.serverSession,
    availability: state.availability,
  });
  useAppStore.setState({ vault: model.vault, availability: model.availability });
  console.warn("Selected vault is unavailable on the server; staying locked");
};

/** A definitive successful `GET /session`. */
const markServerSessionActive = () => {
  const state = useAppStore.getState();
  useAppStore.setState({
    serverSession: onServerSessionActive({
      vault: state.vault,
      serverSession: state.serverSession,
      availability: state.availability,
    }).serverSession,
    availability: "available",
  });
};

/**
 * A `GET /session` that never got an HTTP response. Deliberately changes
 * nothing: a network outage is not evidence about the cookie.
 */
const markServerSessionUnknown = () => {
  const state = useAppStore.getState();
  useAppStore.setState({
    serverSession: onServerSessionUnreachable({
      vault: state.vault,
      serverSession: state.serverSession,
      availability: state.availability,
    }).serverSession,
  });
};

/**
 * Clears volatile keys and session metadata for a full sign-out (vault
 * deselected). Distinct from `loseServerSession`, which retains the selection —
 * this one is for when the app genuinely has no vault left, e.g. cleared app
 * data. The device key and envelope deletion is handled by the caller.
 */
const clearSessionState = () => {
  const selected = selectedVaultId(useAppStore.getState().vault);
  if (selected) clearLastActivity(selected);
  clearLockRecord();
  clearSelectedVaultId();
  useAppStore.setState({
    authKey: null,
    session: null,
    decryptedVault: null,
    vaultVersion: null,
    lockEpoch: null,
    vault: INITIAL_MODEL.vault,
    serverSession: INITIAL_MODEL.serverSession,
    availability: INITIAL_MODEL.availability,
    lockMetadata: null,
  });
};

/**
 * Atomically switch the selected vault and open it, as ONE state write.
 *
 * M3. The previous switch path called `selectVaultSession`, `commitVaultUnlock`,
 * `updateLockEpoch`, `updateDecryptedVault`, and `updateVaultVersion`
 * separately. Each is a distinct store update, so React could render an
 * intermediate combination — briefly "unlocked with no data", or worse, a
 * selection for B carrying A's last decrypted document. A switch must not be
 * observable in those states at all.
 *
 * This commits selection + session + key + document + version + epoch
 * together, and only after verifying the server answered for the vault we
 * asked about. If validation fails the caller gets a rejection and the store is
 * untouched — the old vault keeps its state, so a failed switch leaves a
 * coherent locked-or-unlocked state rather than a half-switched one.
 */
const switchVaultOpen = (args: {
  /** The vault the user asked to open. */
  requestedVaultId: string;
  session: SessionState;
  vaultKey: CryptoKey;
  decryptedVault: DecryptedVault;
  version: number;
  lockEpoch: number;
}): void => {
  const { requestedVaultId, session, vaultKey, decryptedVault, version, lockEpoch } = args;

  // Identity checks BEFORE anything is written. A server (or a stale cookie)
  // answering for a different vault must never have its key installed under
  // our selection — that is the one failure that could render the wrong
  // vault's plaintext.
  if (session.vaultId !== requestedVaultId) {
    throw new VaultTransitionError(
      `Refusing to switch to ${requestedVaultId}: server authenticated ${session.vaultId}`,
    );
  }
  if (decryptedVault.vaultId !== requestedVaultId) {
    throw new VaultTransitionError(
      `Refusing to install a document for ${decryptedVault.vaultId} under ${requestedVaultId}`,
    );
  }

  const previousVaultId = selectedVaultId(useAppStore.getState().vault);

  // Durable write first: if the tab dies mid-switch, the persisted selection
  // must match what we are about to commit, not the vault we are leaving.
  persistSelectedVaultId(session.vaultId);
  // Keep the pre-unlock label in step with the document we are installing.
  cacheVaultName(decryptedVault.vaultId, decryptedVault.name);
  // Opening a vault is activity; the idle deadline starts here.
  persistLastActivity(session.vaultId, Date.now());

  useAppStore.setState((state) => ({
    vault: commitUnlock({
      requestedVaultId,
      sessionVaultId: session.vaultId,
      vaultKey,
    }),
    session,
    decryptedVault,
    vaultVersion: version,
    lockEpoch,
    serverSession: "active",
    availability: "available",
    lockMetadata: null,
    // Only a genuine identity change invalidates in-flight work.
    selectionEpoch:
      previousVaultId && previousVaultId !== session.vaultId
        ? state.selectionEpoch + 1
        : state.selectionEpoch,
  }));

  // Any persisted lock record belongs to the vault we left.
  clearLockRecord();
};

export {
  useAppStore,
  selectVaultSession,
  commitVaultUnlock,
  switchVaultOpen,
  loseServerSession,
  markVaultUnavailable,
  markServerSessionActive,
  markServerSessionUnknown,
  setAuthKey,
  updateDecryptedVault,
  updateVaultVersion,
  setSyncStatus,
  updateLockEpoch,
  lockVaultStorage,
  setLockMetadata,
  clearSessionState,
  addVaultItem,
  updateVaultItem,
  deleteVaultItem,
  updateVaultName,
  addVaultFolder,
  updateVaultFolderName,
  removeVaultFolder,
  moveVaultItemToFolder,
};
