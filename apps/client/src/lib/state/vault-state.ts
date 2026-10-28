/**
 * M0 — the vault selection state contract.
 *
 * This module defines the app's primary state model and transition helpers.
 * M1 wires the discriminated vault state into the client store and routing;
 * later milestones migrate server-session lifecycle and restart behavior.
 *
 * # The model
 *
 * The *selected vault* is the app's identity. There is no user, no email, no
 * account: `vault.id` is a client-generated UUID and the only thing that
 * distinguishes "inside voult" from "outside voult".
 *
 * ```ts
 * type VaultState =
 *   | { status: "no_vault" }
 *   | { status: "locked"; vaultId: string }
 *   | { status: "unlocked"; vaultId: string; vaultKey: CryptoKey };
 * ```
 *
 * Three states, each one canonical shape:
 *
 *  - `no_vault`    — first run, or local app data was removed. Carries no id,
 *                    because there is nothing selected. This is NOT a routine
 *                    destination: there is no user-facing logout/deselect
 *                    action. Switching and creating vaults are the supported
 *                    ways to change the selection.
 *  - `locked`      — a vault is selected and its keys are absent. Note this
 *                    means "the client has selected this vault", *not* "the
 *                    server cookie is valid". Those are orthogonal facts (see
 *                    `ServerSessionStatus` below) and the whole reason this
 *                    model replaces `not_authenticated`: a dead cookie must not
 *                    be able to erase the user's selection.
 *  - `unlocked`    — a vault is selected and its key is in memory. `vaultKey`
 *                    lives in the union rather than beside it so that
 *                    "unlocked without a key" is unrepresentable.
 *
 * # Why the union instead of extra booleans
 *
 * Adding `selectedVaultId` alongside an independent `isLocked` would
 * be a smaller diff, but it creates three independently writable fields
 * describing one fact. They can disagree, and every disagreement is a bug that
 * only shows up as a wrong screen: unlocked state with a null key, a
 * session for vault B while the UI renders vault A's items, a lock record for a
 * vault that is no longer selected. A discriminated union makes the invalid
 * combinations impossible to construct, and the transitions below reject the
 * rest rather than letting it become runtime state.
 */

// --- Core state ----------------------------------------------------------

/**
 * The app's primary state: which vault is selected, and whether its key is in
 * memory. Exactly one representation per reachable situation.
 *
 * `vaultKey` is a non-extractable `CryptoKey` and must never be persisted,
 * logged, or sent anywhere. It appears here because a union cannot express
 * "unlocked" without it — that is the whole point of carrying it inline.
 */
export type VaultState =
  | { status: "no_vault" }
  | { status: "locked"; vaultId: string }
  | { status: "unlocked"; vaultId: string; vaultKey: CryptoKey };

/**
 * Whether the HttpOnly `voult_session` cookie currently authorizes API calls.
 *
 * Deliberately orthogonal to `VaultState`: the cookie is a *transport and
 * authorization* fact, not an identity fact. A vault can be selected and
 * locked while the cookie is missing (it expired, another surface cleared it),
 * and the correct response is to stay on that vault's lock screen — not to drop
 * the selection and send the user back to first-run.
 *
 *  - `unknown` — not yet probed, or the last probe failed at the transport
 *                level. Offline/server-down must land here and never on
 *                `missing`: a network outage is not proof the cookie is
 *                invalid, and treating it as proof would wipe the selection
 *                every time the user works on a plane.
 *  - `active`  — a definitive `GET /session` succeeded. The cookie names a
 *                vault that exists and protected endpoints may be called.
 *  - `missing` — a definitive `SESSION_REQUIRED` (HTTP 401 with that code).
 *                This is an authorization fact, not a lock: an unlocked vault
 *                stays unlocked and usable locally while sync pauses. The
 *                selection and local device material are retained; the master
 *                password re-establishes the session via the existing verifier
 *                flow, then any locked vault unwraps the key locally.
 */
export type ServerSessionStatus = "unknown" | "active" | "missing";

/**
 * Whether the selected vault still exists on the server. Also orthogonal: an
 * unavailable vault keeps its selection and stays `locked`, and surfaces a
 * recoverable error with switch/create actions. It is emphatically *not* a
 * fourth vault state.
 */
export type VaultAvailability = "unknown" | "available" | "unavailable";

/**
 * The complete state model: one vault fact plus three orthogonal facts that
 * must never be inferred from it.
 *
 * Grouping them in one object makes the independence explicit — the bug this
 * model exists to prevent is reading "no cookie" as "no vault".
 */
export interface AppVaultModel {
  vault: VaultState;
  serverSession: ServerSessionStatus;
  availability: VaultAvailability;
}

/** The initial model, before any bootstrap probe has run. */
export const INITIAL_MODEL: AppVaultModel = {
  vault: { status: "no_vault" },
  // "unknown", not "missing": we genuinely do not know yet.
  serverSession: "unknown",
  availability: "unknown",
};

// --- Lock records --------------------------------------------------------

/**
 * Why a vault is locked. Persisted alongside the selected vault so a restart
 * can decide whether the user has to re-enter their password.
 *
 * The distinction that matters is `manual`/`peer` versus `autolock`: the first
 * two are decisions by a person (or by another surface acting for one) and hold
 * until an explicit unlock; the last is a timer that was only ever a
 * convenience and is allowed to lapse on its own.
 *
 * A server session that has expired is deliberately NOT a lock reason. The
 * cookie authorizes API calls; it does not own the user's lock decision. Losing
 * it must never be recorded as "this vault was locked", or a restart would
 * treat an authorization problem as a user intent.
 */
export type LockReason = "manual" | "autolock" | "peer";

/**
 * The durable, vault-scoped record of the most recent lock.
 *
 * Two deliberate changes from the current implementation (`state/index.ts`,
 * `sessionStorage["voult.lockedAt"]`):
 *
 *  1. `sessionStorage` is tab-scoped, so it cannot survive a browser or device
 *     restart at all. Persistence here means surviving restarts on the same
 *     installation / browser profile where local storage and the device key
 *     remain available. It does NOT imply syncing unlock keys across devices,
 *     and it does not survive cleared app data or device-key loss — with no
 *     device key there is nothing to silently unlock *with* anyway.
 *  2. A bare timestamp cannot distinguish a lock the user just performed from a
 *     timer that fired seconds ago, and `AUTOLOCK_NEVER` is a different
 *     promise than "15 minutes". Carrying the reason makes the restart
 *     decision a pure function of data rather than of the current settings
 *     value, which is what makes `decideRestore` below testable.
 *
 * This record contains no secrets: an id, an enum, and a wall-clock time.
 */
export interface LockRecord {
  vaultId: string;
  reason: LockReason;
  /** Epoch milliseconds of the lock. */
  lockedAt: number;
}

// --- Errors --------------------------------------------------------------

/**
 * Thrown when code attempts a transition the model forbids — e.g. installing a
 * key for a vault that is not the one being unlocked. These are programmer
 * errors, not user-recoverable conditions, so they throw rather than returning
 * a degraded state that would silently render the wrong vault.
 *
 * The plan's rule: on every auth/open/switch result, compare the authenticated
 * or returned vault id against the requested selection *before* committing
 * state. `commitUnlock` is where that comparison happens, so it cannot be
 * forgotten at an individual call site.
 */
export class VaultTransitionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VaultTransitionError";
  }
}

/** Compile-time exhaustiveness guard for `switch` over a union. */
export function assertNever(value: never): never {
  throw new VaultTransitionError(`Unreachable vault state: ${JSON.stringify(value)}`);
}

/**
 * A selected vault id must be a non-empty string. This is the cheap check, not
 * the authoritative one — `initSQLite()` validates UUID shape before opening an
 * OPFS file, and that stays the stricter gate. This exists so a malformed id
 * cannot be committed into state and then propagate into a DB path.
 */
function assertVaultId(vaultId: string, context: string): void {
  if (typeof vaultId !== "string" || vaultId.trim() === "") {
    throw new VaultTransitionError(`${context}: vaultId must be a non-empty string`);
  }
}

// --- Transitions ---------------------------------------------------------

/**
 * Select a vault. The target is always `locked` first: selection alone never
 * yields plaintext, and an unlock is a separate, verified transition.
 *
 * This is the only transition into `no_vault`'s opposite — the one the plan
 * calls "switch vault". The caller is responsible for stopping old-vault work
 * (closing SQLite, dropping caches) before calling; see M3, which makes that
 * ordering atomic around this id.
 */
export function selectVault(vaultId: string): VaultState {
  assertVaultId(vaultId, "selectVault");
  return { status: "locked", vaultId };
}

/**
 * Install an unlocked vault — the single commit point for "this vault is open".
 *
 * Every path that produces a vault key (password login, vault open/switch,
 * silent device unlock) funnels through here, which is what makes the
 * identity check below unavoidable rather than per-call-site diligence.
 *
 * `requestedVaultId` is the vault the user asked for; `sessionVaultId` is what
 * the server actually authenticated. They are distinct parameters on purpose:
 * a caller that passed the same variable twice would be unable to detect the
 * mismatch this exists to catch.
 *
 * @throws VaultTransitionError if the two ids differ.
 */
export function commitUnlock(args: {
  requestedVaultId: string;
  sessionVaultId: string;
  vaultKey: CryptoKey;
}): VaultState {
  const { requestedVaultId, sessionVaultId, vaultKey } = args;
  assertVaultId(requestedVaultId, "commitUnlock");
  assertVaultId(sessionVaultId, "commitUnlock");
  if (requestedVaultId !== sessionVaultId) {
    // Never install vault A's key under vault B's identity: that is the one
    // failure that could render the wrong vault's plaintext.
    throw new VaultTransitionError(
      `Refusing to install vault ${sessionVaultId} under selection ${requestedVaultId}`,
    );
  }
  if (!vaultKey) {
    throw new VaultTransitionError("Refusing to install an empty vault key");
  }
  return { status: "unlocked", vaultId: sessionVaultId, vaultKey };
}

/**
 * Lock the selected vault, recording why.
 *
 * Idempotent on an already-locked vault: re-locking holds no new information
 * and would push `lockedAt` forward, which would quietly restart the autolock
 * window. (The current `lockVaultNow` short-circuits for the same reason.)
 *
 * `no_vault` rejects: there is nothing to lock, and "no vault is locked" would
 * be a confusing way to express "no vault is selected".
 *
 * Returns the new `VaultState`; the caller persists the `LockRecord` and wipes
 * keys/plaintext/SQLite — see M2 for the single shared lock path.
 */
export function lockVault(
  state: VaultState,
  args: { reason: LockReason },
): VaultState {
  if (state.status === "no_vault") {
    throw new VaultTransitionError("Cannot lock: no vault is selected");
  }
  if (state.status === "locked") return state;
  // `reason` is not carried into the state: it belongs to the durable record,
  // not to what is in memory. Use buildLockRecord() alongside this.
  void args.reason;
  return { status: "locked", vaultId: state.vaultId };
}

/**
 * Build the record to persist alongside a lock. Separate from `lockVault` so
 * the durable write can happen on a path that also needs to survive a reload
 * (and so the timestamp is captured once, at the real lock moment).
 */
export function buildLockRecord(
  state: VaultState,
  reason: LockReason,
  lockedAt: number = Date.now(),
): LockRecord {
  if (state.status === "no_vault") {
    throw new VaultTransitionError("Cannot build a lock record: no vault is selected");
  }
  return { vaultId: state.vaultId, reason, lockedAt };
}

/**
 * A definitive server rejection of the cookie.
 *
 * The core rule in one function: this is an **authorization** fact, not a lock
 * decision. An already-unlocked vault stays unlocked — its key and plaintext
 * live only in this device's memory, and a cookie that no longer authorizes API
 * calls cannot make local data disappear. Server-dependent work (sync, cloud)
 * pauses instead.
 *
 * A locked vault stays locked, with the selection retained. Neither case writes
 * a lock record: the user did not lock anything.
 *
 * The device key and envelope stay too — deleting them on cookie expiry means
 * the next unlock can only ever be a password unlock, even for a user who never
 * left the device. Note this must not auto-unlock behind the user's back: a
 * locally available key does not imply protected API access exists.
 */
export function onServerSessionMissing(model: AppVaultModel): AppVaultModel {
  return {
    // Selection and lock state are untouched. `no_vault` stays `no_vault`.
    vault: model.vault,
    serverSession: "missing",
    // An invalid cookie says nothing about whether the vault exists.
    availability: model.availability,
  };
}

/**
 * A `GET /session` that never got an HTTP response (offline, DNS, server down).
 *
 * Deliberately changes nothing — not even `serverSession`. This is the
 * distinction the plan calls out: a transport error is not a revoked session,
 * and it is not evidence about the cookie in either direction.
 *
 * In particular an already-`active` session stays `active`. Downgrading it to
 * `unknown` would look more cautious but would be wrong: the cookie was proven
 * good by an earlier successful probe, and a blip cannot un-prove that. It would
 * also flip `canCallProtectedEndpoints` false, silently stalling sync until some
 * later probe happened to succeed — a network outage turning into a stuck app.
 * The staleness is self-correcting: the next successful probe re-affirms it, and
 * the first real `SESSION_REQUIRED` converges to `missing`.
 *
 * Kept as a named function rather than left implicit so that a three-way probe
 * has an explicit third branch, and a future caller cannot reach for
 * `onServerSessionMissing` in an `else` clause by accident.
 */
export function onServerSessionUnreachable(model: AppVaultModel): AppVaultModel {
  return model;
}

/** A successful `GET /session`. Does not by itself unlock anything. */
export function onServerSessionActive(model: AppVaultModel): AppVaultModel {
  return { ...model, serverSession: "active" };
}

/**
 * The selected vault no longer exists on the server (deleted here or in
 * another surface).
 *
 * Keeps the selection and stays locked — silently clearing it would strand the
 * user with no explanation, and "unavailable" is a recoverable condition, not a
 * different kind of vault. The lock screen renders the error alongside
 * switch/create actions.
 */
export function onVaultUnavailable(model: AppVaultModel): AppVaultModel {
  return {
    ...model,
    vault: model.vault.status === "no_vault" ? model.vault : lockedSame(model.vault.vaultId),
    availability: "unavailable",
  };
}

// --- Restart restore -----------------------------------------------------

/** What startup should do with a persisted selection. */
export type RestoreDecision =
  | { kind: "no_selection" }
  | {
      kind: "stay_locked";
      /**
       * A recorded user/timer lock, or `no_device_material` — nothing to
       * unwrap with, so no silent restore is possible even under "Never".
       */
      reason: LockReason | "no_device_material";
    }
  | { kind: "device_unlock"; because: "never_locked" | "autolock_window_lapsed" };

/**
 * Decide what a restart should restore, from persisted data only.
 *
 * Pure so the policy is reviewable in one place and so the awkward cases are
 * legible rather than buried in `_layout.tsx`. It reads `autolockMinutes` as an
 * argument instead of calling `getWebAutolockMinutes()` so the decision is
 * reproducible — settings change independently of the record, and reading the
 * live value here would make the same record mean different things over time.
 *
 * The cases, in order:
 *
 *  - Nothing persisted            -> `no_selection` (landing).
 *  - `manual` / `peer`            -> stay locked until an explicit unlock. A
 *    person decided this, so a restart does not undo the decision.
 *  - `autolock`, window still open-> stay locked. A refresh seconds after the
 *    timer fired must not look like a fresh start.
 *  - `autolock`, window lapsed    -> device unlock.
 *  - No record at all             -> this is an ordinary restart of a vault the
 *    timer never got to lock. That does NOT mean "unlock unconditionally": the
 *    idle deadline still applies, because while the app was closed no activity
 *    was recorded. `lastActivityAt` is the persisted timestamp of the last
 *    activity while unlocked, so `now - lastActivityAt` is the true idle time.
 *    Within the window (or with `AUTOLOCK_NEVER`) -> device unlock; past it ->
 *    stay locked. With `AUTOLOCK_NEVER` an ordinary restart restores
 *    *unlocked*, which is the point of opting out of timer locking; it does not
 *    make a deliberate manual lock disappear.
 *  - A finite timer but no usable `lastActivityAt` (upgrade, cleared storage)
 *    -> stay locked. Guessing "recently used" would silently defeat the timer,
 *    which is the unsafe direction for a credential store.
 *  - No device key *or* no device envelope -> stay locked, whatever the timer
 *    says. There is nothing on this browser to unwrap, so "Never" cannot
 *    silently reopen the vault; only the master password can.
 *
 * A record naming a different vault than the selection is stale and discarded
 * rather than applied — switching vaults must not inherit the previous vault's
 * lock.
 *
 * Session expiry is not an input here. Whether a cookie exists is orthogonal:
 * it decides if a device unlock can fetch the vault, not whether the user's
 * lock policy permits trying.
 */
export function decideRestore(args: {
  selectedVaultId: string | null;
  record: LockRecord | null;
  autolockMinutes: number;
  /**
   * True only when this browser holds *both* the device key and its
   * device-wrapped vault-key envelope for this vault.
   *
   * The pair is required, not just the key: a device key with no envelope has
   * nothing to unwrap, so `unlockWithDevice()` can only fail. Treating that as
   * usable is what made reloads land on the lock screen while the policy said
   * "restore" — the decision promised a silent unlock that could never happen.
   */
  hasDeviceMaterial: boolean;
  /**
   * Epoch ms of the last recorded activity while this vault was unlocked, or
   * null when never recorded (fresh install, cleared storage, or an old
   * version of the app).
   */
  lastActivityAt: number | null;
  now?: number;
}): RestoreDecision {
  const { selectedVaultId, record, autolockMinutes, hasDeviceMaterial, lastActivityAt } = args;
  const now = args.now ?? Date.now();

  if (!selectedVaultId) return { kind: "no_selection" };

  const expiredByActivity =
    autolockMinutes > 0 &&
    (lastActivityAt === null || now - lastActivityAt >= autolockMinutes * 60_000);

  if (!record || record.vaultId !== selectedVaultId) {
    if (!hasDeviceMaterial) return { kind: "stay_locked", reason: "no_device_material" };
    // Never locking: no timer can hold the vault closed across a restart.
    if (autolockMinutes <= 0) {
      return { kind: "device_unlock", because: "never_locked" };
    }
    return expiredByActivity
      ? { kind: "stay_locked", reason: "autolock" }
      : { kind: "device_unlock", because: "never_locked" };
  }
  if (!hasDeviceMaterial) {
    // The recorded reason still describes the last lock; there is simply no
    // envelope to restore with. Surface that honestly rather than pretending a
    // manual lock is what is holding the vault closed.
    return { kind: "stay_locked", reason: "no_device_material" };
  }

  if (record.reason === "manual" || record.reason === "peer") {
    return { kind: "stay_locked", reason: record.reason };
  }
  // autolock, and a device key is present: only the elapsed window matters.
  if (autolockMinutes <= 0) {
    return { kind: "device_unlock", because: "autolock_window_lapsed" };
  }
  if (now - record.lockedAt < autolockMinutes * 60_000) {
    return { kind: "stay_locked", reason: "autolock" };
  }
  return { kind: "device_unlock", because: "autolock_window_lapsed" };
}

// --- Selectors -----------------------------------------------------------

/** The canonical screen for a vault state. Chooser/OAuth stay workflow routes. */
export function routeFor(state: VaultState): "/" | "/lock" | "/home" {
  switch (state.status) {
    case "no_vault":
      return "/";
    case "locked":
      return "/lock";
    case "unlocked":
      return "/home";
    default:
      return assertNever(state);
  }
}

/** The selected vault id, or null when nothing is selected. */
export function selectedVaultId(state: VaultState): string | null {
  return state.status === "no_vault" ? null : state.vaultId;
}

/** True only with a key actually in memory — never derivable from a session. */
export function hasVaultKey(state: VaultState): boolean {
  return state.status === "unlocked";
}

/**
 * Whether protected endpoints may be called right now.
 *
 * Requires *both* an in-memory key and an active server session. This is the
 * predicate the plan asks for: local key availability and permission to call the
 * API are separate facts, and a locked vault whose cookie is still valid can
 * still make authorized (if useless) calls, while an unlocked vault with a dead
 * cookie can make none.
 */
export function canCallProtectedEndpoints(model: AppVaultModel): boolean {
  return model.serverSession === "active" && hasVaultKey(model.vault);
}

// --- Internal ------------------------------------------------------------

/**
 * Drop to `locked` for a given vault, discarding any key. Written as a
 * narrowing helper because `lockedSame` is only ever reached from a branch
 * that has already excluded `no_vault`, and re-narrowing inline would need a
 * cast at each of those sites.
 */
function lockedSame(vaultId: string): VaultState {
  return { status: "locked", vaultId };
}
