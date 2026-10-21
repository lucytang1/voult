// Re-exported from @voult/vault-core (single source of truth shared with the
// MV3 extension). Import sites across the app are unchanged; the canonical
// definitions (VaultItem + origin, sync op schemas, session/lock types) live
// in packages/vault-core/src/schema.ts.
import type {
  SessionState,
  DecryptedVault,
  LockMetadata,
} from "@voult/vault-core";
import type { VaultState, ServerSessionStatus, VaultAvailability } from "./vault-state";
export {
  VaultItemSchema,
  UpdateVaultItemSchema,
  DeleteVaultItemSchema,
  CreateVaultItemSchema,
  SsoProviderSchema,
  VAULT_DOCUMENT_FORMAT_VERSION,
  normalizeAccount,
  itemHasAccount,
  hasSsoSignIn,
  upsertSsoSignIn,
  ssoProvidersOf,
  findItemForAccount,
} from "@voult/vault-core";
export type {
  VaultItem,
  CreateVaultItem,
  UpdateVaultItem,
  DeleteVaultItem,
  SsoProvider,
  SsoSignIn,
  DecryptedVault,
  SessionState,
  LockMetadata,
} from "@voult/vault-core";

// VoultPackage is web-app-local (cloud-package modeling); it stays here until
// a second consumer needs it.
//
// The package is the vault's portable form. It carries the recovery envelope as
// well as the password envelope, so restoring it on another server reproduces
// the vault's recovery key rather than minting a new one — one vault id, one
// recovery file, wherever it is restored.
export interface VoultPackage {
  packageFormatVersion: number;
  vaultId: string;
  logicalRevision: number;
  cryptoVersion: number;
  cryptoParameters: { salt: string; iterations: number };
  snapshot: { ciphertext: string; iv: string };
  passwordKeyEnvelope: { wrappedVaultKey: string; iv: string };
  recoveryEnvelope: {
    /** HKDF salt for K_rec, base64. */
    salt: string;
    /** HMAC-SHA256(K_rec, "recovery-verify-v1"), base64. */
    verifier: string;
    /** AES-GCM envelope of the raw vault key under K_rec, base64. */
    wrappedVaultKey: string;
    iv: string;
  };
}

/** Zustand store shape (web-app-local; the extension mirrors a subset). */
export interface AppState {
  /**
   * The app's primary state: which vault is selected and whether its key is in
   * memory. This is the single source of truth for lock/unlock — there is
   * deliberately no `isLocked` or `vaultKey` field alongside it, because two
   * writable representations of one fact can disagree, and a disagreement here
   * renders the wrong vault.
   *
   * Carries `vaultKey` inline when unlocked, so "unlocked without a key"
   * cannot be constructed. Read it with `hasVaultKey()` / the `status` field,
   * never by destructuring a parallel field.
   */
  vault: VaultState;
  /**
   * Whether the HttpOnly cookie currently authorizes API calls. Orthogonal to
   * `vault`: the cookie is a transport/authorization fact, not an identity
   * fact, and a dead cookie must not erase the selection. `unknown` until a
   * definitive probe — a network failure never becomes `missing`.
   */
  serverSession: ServerSessionStatus;
  /** Whether the selected vault still exists server-side. Recoverable, not a fourth state. */
  availability: VaultAvailability;
  /**
   * Monotonic counter bumped on every selection change.
   *
   * M3's guard against cross-vault contamination. An async operation that
   * started under vault A cannot know that a switch to B happened while it was
   * awaiting the network; comparing vault ids is not enough, because a switch
   * A→B→A would look unchanged to a naive check. Anything async captures the
   * epoch when it starts and re-reads it before committing — see
   * `captureSelectionEpoch()`.
   */
  selectionEpoch: number;
  /**
   * The server session (cookie-scoped vault + crypto version). Null once the
   * cookie is known to be missing, in which case `vault` still holds the
   * selection and `serverSession` is `missing`.
   */
  session: SessionState | null;
  authKey: CryptoKey | null;
  decryptedVault: DecryptedVault | null;
  vaultVersion: number | null;
  // Last server lock_epoch converged to (null = unknown / no session).
  // Survives lock (a lock publishes a new epoch); cleared with the session.
  lockEpoch: number | null;
  isSyncing: boolean;
  lockMetadata: LockMetadata | null;
}