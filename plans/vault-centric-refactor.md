# Vault-centric Voult refactor

## Objective

Make the vault the only local identity and authorization boundary for the
password-manager data path. A session, password verifier, device envelope,
browser database, sync log, and Google OAuth integration must resolve to one
`vault_id`; no account/user identifier may be used for those concerns.

The server continues to store and transport ciphertext and public KDF metadata
only. The master password, plaintext vault, vault key, and all derived keys
remain client-side.

This is a clean-start schema change. The existing migration history and old
database shape do not need to be preserved: replace the migration set with a
new initial migration and document that existing development databases must be
deleted/recreated. No password recovery or Google Drive sync behavior redesign
is included.

## Target model and decisions

- `vault` is the primary identity. Its UUID is client-generated, stable, and
  embedded in the versioned encrypted vault document.
- Remove `user` and `user_vault` from the core model. There is no ownership join
  and no account login/signup lifecycle.
- Replace the old `user_key` vocabulary with a vault-scoped verifier field,
  e.g. `vault_verifier`. It is still derived from the master password in the
  browser and is only a verifier/authentication credential; it is not the
  password, wrapping key, or vault key. If the desired protocol is not a
  verifier-based login, explicitly choose and implement the replacement before
  removing the field—`vault_id` alone must not become an authorization bearer
  credential.
- Password login uses `{ vault_id, vault_verifier }`. It returns vault metadata
  needed for local unwrap: salt, iterations, crypto version, and the encrypted
  vault-key envelope. It does not accept or return a `user` object.
- Registration creates one vault and establishes a session for that vault.
  Creation accepts the client-generated vault ID, encrypted snapshot, salt,
  iterations, verifier, and password-wrapped vault key.
- The session cookie contains only the authenticated `vault_id` plus the
  framework-managed session state. It never contains password material, keys,
  envelopes, or vault plaintext.
- Google OAuth is vault-scoped: OAuth state, token storage, bindings, and all
  callback validation use `vault_id`. Provider email/account identifiers may be
  retained as Google metadata, but they are not Voult user identities.

## Work plan

### 1. Inventory and API contract freeze

Before editing, make a complete reference list for `user_id`, `userId`,
`user_key`, `session_user_id`, `UserVault`, and account-scoped storage. Use it
as a checklist across Rust, TypeScript, docs, tests, and launcher assumptions.

Define the new request/response contracts in one place:

- `POST /register`: vault identity, verifier, KDF metadata, encrypted vault,
  and password/device wrapping fields.
- `POST /auth`: `vault_id` plus vault verifier; no email or user ID.
- `GET /session`: `{ authenticated, vault_id, crypto_version }`.
- `GET /get_vault`, `POST /update_vault`, `POST /vaults`, and `GET /vaults`:
  derive the vault from the session. Keep an explicit `vault_id` only where a
  vault chooser is genuinely required, and reject a requested ID that differs
  from the session rather than using it as an ownership lookup.
- Logout and all Google endpoints: operate on the session vault.

Update `apps/client/architecture.md` and the root session/security notes after
the contract is settled so they describe the implemented model rather than the
old account model.

### 2. Replace the server schema and entities

Create a new initial migration (and remove the old migration modules from the
migrator) with a clean schema:

- `vault`: `id` primary key, encrypted `vault`, `vaultiv`, `salt`,
  `iterations`, `vault_verifier`, `created_at`, `version`, `crypto_version`,
  optional `vault_key_wrap`, and optional `vault_key_wrap_iv`.
- `session`: `session_id` primary key, `vault_id` foreign key to `vault`,
  `created_at`, and `expires_at`.
- `google_token`: vault-scoped primary key/foreign key and the existing token
  fields needed by Drive. If one vault can have multiple provider accounts,
  use an explicit provider/account key while keeping every row linked to the
  vault.
- `cloud_binding`: `vault_id` plus the existing provider/file/revision/status
  fields; remove the user component from its key.
- `oauth_state`: `vault_id` nullable only for the existing pre-session Google
  entry flow, with the same expiry/nonce fields. Pending Google tables retain
  their current purpose but link the eventual state/token to a vault rather
  than a user.

Remove `apps/server/src/entity/user.rs` and `user_vault.rs` from the active
model, remove their prelude exports, and update relations in vault/session,
Google token, cloud binding, and OAuth entities. Do not leave unused user
foreign keys or compatibility columns in the new schema.

Update `apps/server/src/db.rs`, migration registration, and migration README
instructions to describe the clean-start database. Add a development note that
the old `voult.db` is intentionally incompatible and must be recreated.

### 3. Make session authentication vault-scoped

Refactor `apps/server/src/session_auth.rs`:

- rename the session key to `vault_id`;
- expose `session_vault_id` and `establish_vault_session`;
- rotate/purge an existing session before inserting the new vault ID;
- validate UUID/database encoding consistently.

Update `session_status.rs`, `logout.rs`, and every protected handler to use the
session vault directly. A missing vault row, malformed ID, expired session, or
session/vault mismatch must fail closed with the existing error conventions.

### 4. Rewrite registration, authentication, and vault handlers

In `register.rs` and `auth.rs`:

- remove account/email/user-key structs, lookups, and responses;
- validate the vault ID and verifier payloads;
- insert or fetch exactly one vault;
- establish a vault session after successful registration/authentication;
- return only vault identity and the ciphertext/KDF/envelope metadata needed by
  the client.

In `get_vault.rs`, `update_vault.rs`, and `vaults.rs`:

- remove user and join-table queries;
- select by the authenticated session `vault_id`;
- keep the existing ciphertext-only CAS update and version conflict behavior;
- make create/list semantics explicit for the new model (a session can access
  only its vault; a chooser/list endpoint should not imply account ownership).

Rename `update_user_password.rs` to a vault password/envelope operation only if
it is in scope for existing functionality; otherwise remove or disable the
account-specific endpoint and leave password rotation for a separate feature.
Do not add recovery or server-side password reset.

### 5. Re-scope Google OAuth without changing Drive sync semantics

Update `apps/server/src/google/oauth.rs`, `token_store.rs`, and
`endpoints/google.rs`:

- replace `user_id` parameters, filters, logs, and structs with `vault_id`;
- validate OAuth state against the vault that initiated it;
- store and refresh Google tokens by vault;
- make connect/disconnect/status/list-binding and Drive read/write/delete
  handlers authorize only the session vault;
- preserve file IDs, ciphertext transport, remote revisions, conflict policy,
  and pending-link flow behavior.

For the public/pre-session Google flow, keep only the minimum pending state
needed to finish vault creation/linking. Once the local vault is created, bind
the pending provider data to that vault. Never use Google email as a vault
authorization key and never log tokens or ciphertext.

### 6. Refactor client auth and crypto flows

Update query schemas and flows in:
`apps/client/src/lib/queries/{SignUp,logIn,session,vault,vaults}` and
`apps/client/src/lib/auth/flows/{signup,login}.ts`.

- Generate `vaultId`, salt, random vault key, encrypted document, password
  wrapping envelope, and vault-scoped verifier locally.
- Send only the new vault registration/auth payloads.
- Derive the wrapping key from the vault's returned salt/iterations during
  password unlock; never send the master password or derived keys.
- Build `UnlockedSession` around `vaultId` and vault metadata, with no required
  user object.
- Remove account-only signup and user-email login branches. If an email is
  still useful for Google/provider display, keep it as non-authoritative
  metadata rather than an auth identity.
- Update reload/device unlock to obtain and validate the vault ID from the
  session and vault envelope, including versioned document vault-ID binding.

Use neutral names (`vaultVerifier`, `vaultId`, `vaultSession`) throughout
client code and comments. Keep `authKey` transient and clear it after
authentication as today; it must never enter SQLite, IndexedDB, Zustand
persisted state, logs, URLs, or query caches.

### 7. Make Zustand state vault-native

Update `apps/client/src/lib/state/type.ts` and `index.ts`:

- replace `SessionState.user` with required `vaultId` and any non-authoritative
  display metadata that the UI truly needs;
- remove `selectedVaultId` duplication where the active session already names
  the vault, or make it a separate chooser-only value with strict equality
  checks;
- rename account-oriented lock/teardown helpers (`lockAccountStorage`,
  `teardownAccountSession`) to vault-oriented names;
- ensure lock clears vault key, auth key, decrypted data, transient password
  input, and vault-scoped query data while keeping only the session and durable
  non-secret sync metadata needed for unlock.

Update route guards and bootstrap so a valid session restores `vault_id`, opens
only that vault's local store, and routes to unlock/chooser based on vault
state—not on the presence of an account object.

Delete the "enter email to start" screen entirely. No email field is shown at
any point. `vault_id` is never typed by the user in the normal flow — it is
auto-detected.

**Flow A — session present** (`GET /session` → `{ authenticated: true, vault_id }`):
1. Bootstrap calls `GET /session`; on success restore `vaultId` into Zustand.
2. Open only that vault's local store (`voult-<vaultId>.db`, IndexedDB
   `vault:<vaultId>` envelope). If device key exists, offer biometric/device
   unlock; otherwise show a single master-password field for that `vaultId`.
3. Password unlock derives `vault_verifier` locally and calls
   `POST /auth { vault_id, vault_verifier }` to re-establish/rotate the
   session, then unwraps the vault key and opens the vault. No chooser is shown
   — the session is the chooser.

**Flow B — no session, vault(s) known locally** (IndexedDB `vault:<vaultId>`
records and/or OPFS `voult-<vaultId>.db` files exist):
1. Enumerate *locally-known* vaults only — never `GET /vaults` as an
   unauthenticated global directory (that would enumerate all server vaults and
   leak existence for brute-force). Optionally filter the local list by a
   lightweight authenticated existence check after a vault is selected, but do
   not expose a public server-wide listing.
2. If exactly one local vault exists, skip the picker and show the single
   master-password field for that vault (same `POST /auth` as above).
3. If multiple local vaults exist, show a local vault picker (display name /
   last-unlocked / created_at, not raw UUID) → user picks one → master-password
   field for the chosen `vaultId`.

**Flow C — no session, no locally-known vault** (first run or new device /
cleared storage):
1. Show "Create new vault" (generates `vaultId` locally, `POST /register` with
   verifier/KDF/envelope/ciphertext) and "Restore existing vault".
2. Restore accepts a pasted/imported `vaultId` (or a Google Drive binding via
   the pending OAuth link flow in `§5`) and then prompts for the master password
   to `POST /auth`. No email is requested; no server-wide vault list is shown.

`GET /vaults` (if retained) is authenticated and vault-scoped — it may list
only vaults the session is authorized for (e.g. Drive-linked companions), not
all vaults on the server. Rejected/missing vaults fail closed.

### 8. Re-key browser storage and local SQLite by vault ID

Update `apps/client/src/lib/sqlite/web/{init-db,db,migrations}.ts` and service
files:

- change the OPFS filename to `file:voult-<vaultId>.db?vfs=opfs`;
- remove `userId` from `initSQLite`, `setDb`, current-handle checks, comments,
  and error messages;
- retain `vault_id`, revision, device ID, and sync metadata in the vault-local
  `client_state` table;
- preserve intent durability, encrypted payloads, base-version/CAS behavior,
  and fail-closed writes when no vault database is open;
- decide whether a database format bump is needed for the clean-start local
  schema and make the migration idempotent.

Update `apps/client/src/lib/crypto/device-key.ts` and `auth/utils.ts`:

- key IndexedDB records by `vault:<vaultId>` (or an equivalent unambiguous
  vault-only key), not `user:<userId>:vault:<vaultId>`;
- remove legacy user/current record readers and migration branches;
- make device key, wrapped vault-key envelope, save/load/delete, and “delete
  all” APIs vault-only;
- ensure logout deletes only the active vault's records and cannot delete a
  different vault's data accidentally.

### 9. Teardown, cache, and lifecycle correctness

Refactor `apps/client/src/lib/auth/teardown.ts` and all callers:

- capture `vaultId` before clearing state;
- close the active vault SQLite handle before any state/cache teardown;
- delete only the active vault's device key/envelope on full logout;
- clear vault-scoped TanStack Query caches and volatile Zustand state;
- on lock, close the handle and clear plaintext/key material but retain the
  session, vault ID, durable encrypted intents, and unlock metadata required by
  the existing lock flow;
- make server-forced 401 and explicit logout follow the same vault teardown
  path.

Audit logs for this change to ensure they do not print verifier values,
ciphertext, wrapped keys, decrypted vaults, passwords, or full provider tokens.

### 10. Tests and verification

Add or update server tests for:

- clean migration/schema creation and foreign-key constraints;
- registration/authentication with vault ID and vault verifier;
- session rotation, missing/expired/malformed vault sessions, and logout;
- vault-only authorization and CAS conflicts;
- Google OAuth state, token refresh, binding, and Drive endpoint isolation by
  vault;
- rejection of old user/email/user-key payloads if strict API removal is
  desired.

Add or update client tests/checks for:

- local derivation and wrong-password/tamper failures;
- signup, password login, reload/device unlock, lock, logout, and 401 teardown;
- two vaults in one browser profile using distinct OPFS files and IndexedDB
  records;
- no cross-vault intent/device-envelope access;
- vault document ID validation and sync version/conflict behavior;
- absence of password, raw keys, derived keys, and plaintext vault data from
  network payloads, SQLite, IndexedDB, local/session storage, and logs.

Run the documented checks from the repository root in dependency order:

1. recreate the server database and run migrations;
2. run `npx tsc --noEmit` in `apps/client`;
3. run the Rust formatter/checks/tests in `apps/server`;
4. run `npm run sync:sqlite-web` and `npm run build:web`;
5. start the server against the exported client and manually exercise signup,
   password unlock, lock/logout, two-vault isolation, and Google connect/sync.

## Completion criteria

The refactor is complete when no core auth, session, vault authorization,
device storage, SQLite filename, sync intent, or Google OAuth/token/binding
path requires `user_id`, `userId`, `user_key`, or a `user_vault` lookup; all
protected operations derive authorization from `vault_id`; the new database
boots from an empty install; and the zero-knowledge properties remain true.
