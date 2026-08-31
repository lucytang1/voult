# Optional Google Drive sync and cross-device vault flows

## 1. Scope and decisions

This plan adds optional Google Drive storage and cross-device vault flows to the existing Voult codebase.

The following constraints are non-negotiable:

- Voult remains local-first. A user can create and use a vault without Google Drive or any network connection.
- There is no centralized Voult service. Every device continues to run its own local Actix-Web/Rust server and browser SQLite/OPFS database.
- Google Drive stores and transports encrypted Voult data. It does not authenticate users, decrypt vaults, merge records, or act as a Voult application server.
- The existing random vault-key/password-wrapping model, encrypted intent queue, client-side merge engine, and per-account local storage isolation remain the foundation.
- `user_id` identifies a local account/profile on one device. A new portable `vault_id` identifies the vault across devices and providers.
- Email is account metadata only. It is never used to find, deduplicate, select, or merge a vault.

The recommended first version stores one complete encrypted snapshot package per vault in Google Drive and uses the existing encrypted intent queue for offline writes and client-side conflict replay. Encrypted operation-log or CRDT storage is deferred unless later requirements justify its complexity.

## 2. Current repository architecture

The plan is based on the current implementation:

- `apps/client/src/lib/crypto/index.web.ts` performs PBKDF2/HKDF derivation, AES-GCM encryption, random vault-key generation, and password/device key wrapping. `CRYPTO_VERSION` is currently `2` and PBKDF2 is currently `60000` iterations.
- `apps/client/src/lib/crypto/device-key.ts` stores a non-exportable device key and device-wrapped vault-key envelope in IndexedDB. It currently namespaces records by server-issued `user_id`.
- `apps/client/src/lib/auth/flows/signup.ts` currently generates the vault, sends the encrypted snapshot and password envelope to `/register`, then stores the device envelope.
- `apps/client/src/lib/auth/flows/login.ts` currently authenticates against the local server, fetches the encrypted vault, unwraps the vault key locally, and hydrates Zustand.
- Browser SQLite/OPFS (`apps/client/src/lib/sqlite/web`) currently stores a durable encrypted `intent` table and key/value `client_state`. `init-db.ts` opens one database named from the server `user_id` at a time.
- `apps/client/src/lib/sync/index.ts` fetches a whole encrypted snapshot, decrypts it locally, replays pending intents, encrypts the result, and uses the local server’s integer vault-version CAS.
- `apps/client/src/lib/sync/merge.ts` already supports stable item IDs, idempotent create/update/delete replay, changed-field updates, deterministic ordering, and intent quarantine.
- `SyncScheduler` is a single-flight/coalescing wrapper triggered by focus, reconnect, forced sync, and intent creation.
- The local Rust server persists `user`, `vault`, and session data in SeaORM/SQLite. The current schema makes `user.vault_id` unique and treats one local server vault as authoritative. The server never sees plaintext.
- The local Rust server also serves the exported client and must continue returning COOP/COEP headers for SQLite WASM/OPFS.

The largest required structural change is to stop using the local server-issued `user_id` as the portable vault identity. Existing local storage must remain isolated by local account while the cloud package and cross-device flows use `vault_id`.

## 3. Target identity and storage model

### 3.1 IDs and ownership

Generate `vault_id` in the client with a cryptographically secure random UUID when a new vault is created. It must not be derived from:

- email;
- account password or master password;
- Google account ID;
- Google Drive file ID;
- device ID;
- vault ciphertext.

Use these concepts separately:

| Concept | Scope | Purpose |
|---|---|---|
| `user_id` | One local Rust server/database | Local account/session and local storage isolation |
| `vault_id` | Portable across devices/providers | Identity of the encrypted vault |
| `device_id` | One browser/device and vault | Device envelope and sync attribution |
| Google file ID | One Google Drive account | Provider-specific remote reference |
| remote revision/ETag | One Google Drive file version | Conditional concurrency control |

One local `user_id` may have multiple vault bindings over time. Two different local users may intentionally open the same `vault_id` if they possess the provider access and vault secret. Two independent vaults may have the same email and different master passwords because their `vault_id`s differ.

### 3.2 Local database isolation

Keep local account isolation, but make it explicit that account isolation and vault identity are different:

- Keep a local profile/account record keyed by `user_id`.
- Add a local vault record keyed by `vault_id`, with a relationship from the profile to the selected/opened vault.
- Move the OPFS filename from `file:voult-<userId>.db?vfs=opfs` to a validated composite form such as `file:voult-<userId>-<vaultId>.db?vfs=opfs`. The portable identity is `vault_id`, but the local filename remains account-scoped so separate local accounts cannot access each other’s SQLite data accidentally.
- If one profile can work with multiple vaults, close the current OPFS handle before switching and open the selected vault’s database.
- This implementation intentionally starts from a clean database. Do not add compatibility code for old `user_id`-named databases or old client-state rows.

IndexedDB device-key and device-envelope records should be keyed by `user_id` plus `vault_id` plus `device_id`. This preserves per-account isolation while preventing a device key for one vault from unlocking another vault owned by the same local account. The cloud package carries only the portable `vault_id`; local account IDs never travel to Google Drive.

### 3.3 Versioned encrypted vault package

Introduce a versioned package format separate from the current implicit `{items}` JSON. Conceptually:

```text
VoultPackage {
  package_format_version,
  vault_id,
  logical_revision,
  crypto_version,
  crypto_parameters: { salt, iterations },
  snapshot: { ciphertext, iv },
  password_key_envelope: { wrapped_vault_key, iv },
  package_integrity_metadata
}
```

The `snapshot` plaintext contains a versioned vault document such as `{ formatVersion, vaultId, items }`. The vault ID must be authenticated as part of the encrypted document and/or AES-GCM additional authenticated data so a package cannot be copied between vault identities accidentally.

The password envelope is required for a new device to recover the stable vault key. The device envelope is never uploaded; every device generates its own device key and local envelope after successful unlock.

### 3.4 Clean-start database policy

This feature can land with a complete database reset. The implementation should:

- replace the current SeaORM migration history with a new initial schema migration;
- replace generated SeaORM entities to match the new schema;
- remove obsolete migration modules from `apps/server/migration/src/lib.rs` and delete the old migration files if they are no longer needed;
- use a fresh `voult.db` during development and testing rather than attempting to transform an old database;
- replace the browser OPFS schema with a new initial schema and clear/recreate the local browser database during development;
- remove compatibility branches for old `vault_version`, old user-keyed filenames, legacy device records, and old vault JSON.

This is a product/development reset, not a user-data migration. Before deleting any local database in a real environment, provide an explicit backup/export procedure or confirm that no production data exists.

For the clean SeaORM setup, either hand-write a new schema-first initial migration or use SeaORM CLI to generate a migration, include it in `MigratorTrait::migrations()` in chronological order, run it against a fresh SQLite database, and regenerate entities from the resulting schema. The official workflow is documented in [SeaORM setting up migrations](https://www.sea-ql.org/SeaORM/docs/migration/setting-up-migration/) and [SeaORM writing migrations](https://www.sea-ql.org/SeaORM/docs/migration/writing-migration/). The implementation checklist should include:

```text
cargo install sea-orm-cli
sea-orm-cli migrate init -d apps/server/migration
sea-orm-cli migrate generate create_voult_schema -d apps/server/migration
sea-orm-cli generate entity -u sqlite://apps/server/voult.db -o apps/server/src/entity
```

Use the repository’s actual CLI/version/options after checking `sea-orm-cli --help`; the commands above are planning examples, not commands to run blindly. Since the application runs migrations at startup, the final migration crate must be compiled into the server and its initial migration must be registered by the migration crate.

Google Drive may see a file name, file ID, app properties, package size, and timestamps. Do not place email, usernames, passwords, plaintext item metadata, the master password, or an unwrapped key in Drive metadata.

## 4. Google Drive provider design

### 4.1 Where the integration lives

Google Drive must be implemented behind a provider adapter, not inside merge logic or `SyncScheduler`.

Because this product has a local Rust server on every device, use that local server as the per-device Google transport/OAuth boundary:

- the browser asks the local API to start/complete Google authorization;
- the local Rust server stores provider tokens locally, preferably in the OS keychain and otherwise in an encrypted local store protected by the local installation;
- the local server makes Drive API requests and returns only provider descriptors, encrypted package bytes, revisions, and typed errors;
- the browser retains all vault keys and performs all encryption, decryption, intent replay, and merge operations.

This is not a centralized service: the local server is installed on the user’s device, has no shared Voult database, and cannot interpret the vault contents. A direct browser adapter may be considered later, but it should not be required for the first implementation because refresh-token storage and OAuth callback handling are cleaner in the local server.

### 4.2 Google Drive layout

Use Google Drive’s application-owned hidden storage (`appDataFolder`) for the initial implementation where possible. It avoids polluting the user’s normal Drive files and allows the app to list only its own files.

Store one file per vault, for example:

```text
appDataFolder/
  voult-vault-<vault_id>.json
```

The file body is the serialized `VoultPackage`. The provider adapter may also use Drive app properties such as `voultSchema`, `vaultId`, and `packageKind` for listing/filtering, but the encrypted package remains the integrity authority. A random `vault_id` is an identifier, not a secret; do not pretend a Drive filename hides it.

Support multiple vaults by listing all valid Voult files in the connected Google account and presenting each as a selectable `VaultDescriptor` with non-sensitive label, creation/update time, truncated vault ID, and package status.

### 4.3 Provider-neutral interface

Define a conceptual interface such as:

```text
authorize() -> ProviderAccount
disconnect() -> result
listVaults() -> VaultDescriptor[]
readVault(remoteRef) -> { packageBytes, remoteRevision }
createVault(vaultId, packageBytes) -> { remoteRef, remoteRevision }
replaceVault(remoteRef, packageBytes, ifMatchRevision) -> { remoteRevision }
deleteVault(remoteRef, ifMatchRevision) -> result
```

The adapter also maps Google errors into provider-neutral categories:

- `PROVIDER_AUTH_REQUIRED`;
- `PROVIDER_WRONG_ACCOUNT` or `VAULT_NOT_FOUND`;
- `PROVIDER_PERMISSION_DENIED`;
- `REMOTE_CONFLICT`;
- `REMOTE_UNAVAILABLE`;
- `REMOTE_DELETED`;
- `PACKAGE_INVALID`/`VAULT_INTEGRITY_ERROR`;
- `PROVIDER_RATE_LIMITED`.

Google-specific OAuth scopes, file queries, pagination, upload details, and revision/ETag handling remain inside the Google adapter and local-server Drive module.

### 4.4 Manual Google setup required before implementation/testing

No Google Workspace organization is required for a normal personal-account integration. A developer does need a Google account and a Google Cloud project. A Workspace account/domain is only needed if the app is being tested under an organization’s admin policies or distributed through a Workspace Marketplace/domain-controlled environment.

#### One-time developer setup

1. Create or select a project in the [Google Cloud Console](https://console.cloud.google.com/).
2. Enable the [Google Drive API](https://console.cloud.google.com/apis/library/drive.googleapis.com) for that project. Google’s OAuth documentation lists enabling the API as a prerequisite for applications that call Google APIs. [Official setup guidance](https://developers.google.com/identity/protocols/oauth2/web-server).
3. Configure the OAuth consent screen/Google Auth Platform branding:
   - application name and support/developer contact details;
   - authorized domain(s) for non-local deployments;
   - test users while the app is in testing mode;
   - the narrowest Drive scope required by the implementation.
4. Request the `https://www.googleapis.com/auth/drive.appdata` scope if using Drive’s hidden application-data space. Google documents this as the app’s own configuration-data scope; `appDataFolder` files are not visible in the normal Drive UI and cannot be shared like normal Drive files. [Drive scope guidance](https://developers.google.com/workspace/drive/api/guides/api-specific-auth) and [appDataFolder guidance](https://developers.google.com/workspace/drive/api/guides/appdata).
5. Create an OAuth 2.0 client credential of type **Web application**. Register the exact local callback URI used by the local Rust server, for example `http://localhost:8080/api/google/oauth/callback`, plus the production callback URI when one exists. Google’s web-server OAuth flow requires registered redirect URIs and supports localhost during development. [Official web-server OAuth guidance](https://developers.google.com/identity/protocols/oauth2/web-server).
6. Download the OAuth client configuration and store it outside the repository. Do not commit the client secret to Git, the Expo bundle, `public/`, or a cloud package.
7. Add local `.env` configuration for the Rust server, conceptually:

   ```text
   GOOGLE_CLIENT_ID=...
   GOOGLE_CLIENT_SECRET=...
   GOOGLE_OAUTH_REDIRECT_URI=http://localhost:8080/api/google/oauth/callback
   GOOGLE_DRIVE_SCOPE=https://www.googleapis.com/auth/drive.appdata
   ```

8. Decide whether the consent screen remains in testing mode or is published. Testing-mode users must be added as test users, and Google may show an unverified-app warning. Public distribution may require Google verification depending on the scopes and application configuration; do not assume a local test credential is suitable for production.
9. Confirm the same OAuth client/project is used on all devices that should see the same `appDataFolder` namespace. A different Google Cloud project/client may represent a different application-data space, so treat changing the OAuth client as a storage-migration event.

#### Per-user setup

For each device/user:

1. Sign in to the intended Google account in the browser during OAuth.
2. Grant the requested Drive permission.
3. Confirm that the account shown after authorization is the account the user intended.
4. If testing multiple accounts, use separate browser profiles or explicitly revoke/switch the Google grant between tests.

Do not create Google service-account credentials for this design. Service accounts are intended for application-owned data or administrator-delegated Workspace access, not for silently accessing each user’s personal Drive. User authorization is the correct model for this per-user vault storage.

#### Optional production setup

Before public release, complete the Google OAuth consent-screen publication, branding, authorized-domain verification, privacy-policy/support URLs, scope review, and any required verification. If the product later supports normal user-visible Drive files or sharing, separately evaluate `drive.file`, Google Picker, file-sharing permissions, and the implications of leaving `appDataFolder`; the initial private multi-device design should not add those capabilities unnecessarily.

## 5. Account/auth flow and vault chooser

Keep the familiar email/password signup/sign-in flow, but change registration semantics:

1. Email/password establishes or unlocks the local account/profile represented by `user_id`.
2. Registration must not silently create a vault or upload anything to Google Drive.
3. After successful account authentication, show a vault chooser with:
   - **Create new vault**;
   - **Start from Google Drive**;
   - existing local vaults/bindings, when present.
4. The currently selected vault is explicit state, not inferred from email.

The first implementation may use the account password as the vault’s master password for a familiar UX, but the code should model account authentication and vault unlocking separately. This is essential for allowing two devices to create independent local vaults using the same email and different master passwords when cloud sync is not enabled.

Recommended state additions:

```text
account_state: signed_out | signed_in
vault_state: no_vault_selected | choosing | creating | importing | locked | unlocked
vault_mode: local_only | google_drive
google_state: disconnected | authorizing | connected | unavailable | wrong_account
sync_state: idle | queued | syncing | offline | conflict | remote_missing | error
```

Do not overload the existing three-state `(session, isLocked)` auth model. Keep it for route protection, but add explicit vault/provider state for the chooser and cloud lifecycle.

## 6. User flows and repository changes

### 6.1 Create a new local vault without cloud sync

#### UI/state transition

```text
signed in
  -> Create new vault
  -> enter/confirm master password
  -> creating
  -> unlocked, vault_mode=local_only
```

The UI must state that the vault exists only on this device until Google Drive is enabled. It must not show a cloud-connected state or request Google authorization.

#### Implementation

1. Generate `vault_id`, salt, PBKDF2 parameters, random vault key, and initial versioned vault document.
2. Derive the password wrapping key and create the password-wrapped vault-key envelope using the existing crypto primitives.
3. Generate the device key and device envelope locally.
4. Initialize the vault-scoped local Rust server record and OPFS SQLite database.
5. Store the encrypted snapshot in the local server’s vault row/cache. Store encrypted intents and sync metadata in OPFS.
6. Hydrate Zustand only after the vault ID, key, local DB, and snapshot are all consistent.
7. Do not call Google APIs and do not create a remote binding.

Repository changes:

- split the current `signupFlow` into account signup and `createLocalVaultFlow`;
- stop `/register` from requiring vault ciphertext, or add a separate local profile registration path and a vault creation endpoint;
- add `vault_id` and format version to crypto/package types;
- update device-key storage and `initSQLite` to use `vault_id`;
- replace test signup data with production empty-vault initialization when the product is ready.

### 6.2 Create a vault and immediately connect Google Drive

#### UI/state transition

```text
signed in
  -> Create new vault
  -> choose “Connect Google Drive now”
  -> creating local vault
  -> Google authorization
  -> creating remote vault
  -> verify remote read-back
  -> unlocked, vault_mode=google_drive, sync_state=idle
```

The local vault must become usable before or during authorization. If Google authorization or remote creation fails, keep the local vault intact and offer retry or “Continue local-only.”

#### Implementation

1. Complete local vault creation exactly as in 6.1.
2. Authorize Google Drive through the local Rust server and record the provider account reference.
3. Serialize the initial encrypted package.
4. Create the Drive file with create-if-absent semantics and `vault_id` metadata.
5. Read the file back, validate its package identity and ciphertext, and only then persist the local remote reference/revision.
6. Mark the binding active and schedule normal sync.

Never mark the vault cloud-backed before remote read-back succeeds. A lost response must be recoverable by searching for the same `vault_id` and verifying the package rather than creating a second file.

### 6.3 Enable Google Drive later after adding logins

#### UI/state transition

```text
unlocked, vault_mode=local_only
  -> Settings > Enable Google Drive sync
  -> confirm backup/remote-storage warning
  -> Google authorization
  -> upload current encrypted snapshot
  -> verify read-back
  -> vault_mode=google_drive
```

The user’s existing logins are included only inside the encrypted snapshot. The provider never receives plaintext entries.

#### Implementation

1. Require the vault to be unlocked and the local snapshot/intent queue to be in a known state.
2. Merge or flush local intents into the local snapshot before enrollment; preserve unresolved intents if a local error occurs.
3. Build a package containing the stable `vault_id`, current encrypted snapshot, password envelope, crypto metadata, and logical revision.
4. Create the remote file idempotently.
5. Verify the remote package by reading it back and validating `vault_id` and authenticated ciphertext.
6. Persist the Google file ID, provider account ID, and remote revision locally.
7. Enable scheduler triggers only after the binding is committed.

If the user has already started enrollment and retries, find the existing file by `vault_id` and verify it. Never create a new vault because an earlier Drive response was lost.

### 6.4 Open an existing Google Drive vault on a completely new device

#### UI/state transition

```text
account signed in or local profile created
  -> Start from Google Drive
  -> authorize Google
  -> listing_vaults
  -> user selects vault
  -> downloading
  -> enter master password
  -> decrypting/unlocking
  -> enroll device and initialize local storage
  -> unlocked, vault_mode=google_drive
```

#### Implementation

1. Complete the normal account signup/sign-in shell, but do not create a default local vault.
2. Authorize the intended Google account with the minimum Drive scope.
3. List and validate Voult package descriptors. Multiple files must be shown as multiple vault choices.
4. Download the selected package and validate package format, `vault_id`, and integrity metadata before writing local state.
5. Ask for the vault master password. Derive the wrapping key using the package’s salt/iterations and unwrap the vault key locally.
6. A wrong password must fail closed without replacing any existing local vault. Do not report “no vault found” for a decryption failure.
7. Generate a new `device_id` and device key; create a new local device envelope around the recovered vault key.
8. Create the local Rust vault row/cache and open a new OPFS database keyed by the local `user_id` plus downloaded `vault_id`.
9. Initialize `client_state` with `vault_id`, `base_revision`, Google file ID, provider account ID, and remote revision.
10. Decrypt and hydrate the vault, then perform a read/reconcile pass before enabling edits and background sync.

The original device key is not required and is never downloaded. The portable recovery secret is the master password or a future explicit recovery-key envelope.

### 6.5 Independent local vaults on multiple devices with the same email

#### Expected behavior

Each device may have a local account row with the same email because the devices have separate local Rust databases. If the user selects Create new vault and uses a different master password, each device generates a different `vault_id`, salt, vault key, and local snapshot.

Those vaults remain independent because:

- no Google Drive binding exists;
- local storage is keyed by local `user_id`/vault binding, not email;
- no account lookup is used to find a vault;
- no cloud file is created automatically.

Add tests proving that same-email signup on separate local servers cannot cause a vault import or merge.

### 6.6 Device already has a different local vault

#### UI/state transition

```text
unlocked local vault A
  -> Start from Google Drive
  -> warning: vault B will be opened separately
  -> select Open alongside / Switch / Cancel
  -> download and unlock vault B
```

Never silently overwrite vault A, replace its OPFS database, or merge vault A into vault B.

The UI must offer an explicit choice:

- **Open alongside** if multiple local vault profiles/bindings are supported;
- **Switch vault** after locking/closing A;
- **Cancel** and leave A unchanged.

If the first release supports only one active vault at a time, preserve A’s local DB and device secrets, close its handle, then open B. Store a vault list/binding index outside the active vault DB so B can be selected later without using email as a key.

Before any destructive local replacement, require confirmation and verify that A has no unresolved local-only changes unless the user explicitly exports/copies them.

### 6.7 Multiple vaults in one Google Drive account

`listVaults()` must return all valid Voult files for the connected Google account. Do not assume one Drive account maps to one vault.

The chooser should show a non-sensitive label, last-modified time, truncated `vault_id`, package version, and whether the package is readable only after password entry. Selecting one creates or activates a binding for that `vault_id`; it does not change or delete other bindings.

Remote references are stored per `(local_user_id, vault_id, provider_account_id)`. A provider file ID must never be used as the portable identity because copying a file to a new Drive account changes the file ID.

### 6.8 Wrong Google account or no vault found

After OAuth, show the connected Google account identity returned by Google and let the user confirm it. If no Voult files are listed:

- explain that this account has no discoverable Voult vaults;
- offer switch account, retry authorization, Create new vault, or Continue local-only;
- do not create a remote vault implicitly.

If the user expected a vault but it is absent, distinguish wrong account, insufficient permission, hidden/app-data access issue, and deleted file. Do not use email matching to guess another account or vault.

If a package is listed but fails package validation, stop and show a corrupted/unsupported vault error. Preserve any existing local vault and downloaded bytes for recovery diagnostics without exposing secrets.

### 6.9 Offline use and reconnect

#### Offline edits

Apply edits to Zustand, encrypt the intent payload with the vault key, and insert it into the vault-scoped SQLite `intent` table before reporting success. Set `sync_state=offline` or `queued`; leave the remote revision unchanged.

#### Reconnect

On network regain, focus, app startup after unlock, or an explicit retry:

1. Read the remote package and current revision.
2. If there are no pending intents, adopt a newer remote snapshot locally.
3. If pending intents exist, decrypt the remote snapshot, replay local intents, encrypt the merged snapshot, and conditionally replace the Drive file.
4. On success, update the local package/cache and remote revision, then mark only confirmed intents synced.

The scheduler remains single-flight and coalescing. It must skip locked vaults and preserve pending intents through local server restarts, logout, and provider outages.

### 6.10 Conflicting changes from multiple devices

Google Drive is the concurrency authority for a cloud-bound vault. Use the Drive file’s revision/ETag or equivalent conditional-write token:

1. Device A reads revision R.
2. Device B reads revision R.
3. A conditionally replaces the file with `ifMatch=R`; Drive returns revision R1.
4. B’s conditional replace with R fails as a remote conflict.
5. B downloads R1, replays its still-pending intents, and retries against R1.

Use provider-neutral `RemoteRevision` in the sync engine. Google-specific revision fields remain in the adapter. Add bounded exponential backoff and jitter for conflicts/rate limits, but always re-read before retrying; never blindly resend an old snapshot.

The existing merge policy remains:

- stable item UUIDs;
- idempotent creates;
- changed-field update intents;
- deterministic `(created_at, intent_id)` ordering;
- delete/update policy from `conflict-resolution.md`;
- quarantine for malformed or undecryptable intents.

The existing local integer `vault_version` may remain as a diagnostic/local-cache revision, but it must not decide cross-device authority. Replace `base_version` with provider-neutral `base_revision` metadata in the new schema; no old-intent compatibility path is required because the browser database is being recreated.

### 6.11 Disconnect Google Drive while preserving the local vault

#### UI/state transition

```text
cloud_backed, unlocked or locked
  -> Settings > Disconnect Google Drive
  -> explain remote data remains
  -> confirm
  -> remove local binding/token
  -> local_only
```

Disconnect means stop using Google Drive. It does not delete the Drive file and does not delete the local encrypted snapshot, vault key, OPFS database, or pending local data.

Before disconnecting, warn about unsynced intents and offer Sync now, Export/copy, or Continue with unsynced local changes. After disconnect, edits continue locally and the cloud copy becomes stale but preserved.

### 6.12 Google Drive vault unavailable or deleted

Classify remote failures:

- transient network/unavailable: keep local vault usable and retry later;
- expired/revoked OAuth: require reauthorization;
- permission/account mismatch: show account switch/reconnect;
- file deleted/not found: set `remote_missing`, preserve local data, and do not silently recreate;
- package invalid/corrupt: preserve local data, stop sync, and offer recovery/import/export.

For `remote_missing`, offer explicit choices: reconnect if the file can be restored, copy this local vault to a new Google Drive file, remain local-only, or delete local data. Recreating a cloud file must require deliberate confirmation because it may create a divergent vault.

### 6.13 Incorrect or forgotten master password

The provider and local server cannot validate the master password by seeing plaintext. The client should:

- derive the wrapping key locally;
- attempt to unwrap the password envelope;
- treat AES-GCM authentication failure as an incorrect password;
- leave the selected local vault and any existing active vault untouched;
- avoid revealing whether a package exists based on password success/failure.

There is no password recovery unless the user has another valid key-encryption path. Add a future recovery key by generating a random recovery secret and storing another vault-key envelope; do not derive it from email. Device keys cannot recover a vault on a new device.

### 6.14 Password change

Keep the stable vault key. After unlocking with the old password:

1. generate new password derivation parameters;
2. derive the new password wrapping key and account verifier as applicable;
3. re-wrap the same vault key;
4. update the local package/cache;
5. conditionally write a new Google Drive package revision;
6. keep the device envelope unchanged.

Do not re-encrypt the vault snapshot merely because the master password changed. Treat a vault-key rotation as a separate, higher-risk migration that re-encrypts the snapshot and requires new device envelopes.

### 6.15 Safe migration/copy to different cloud storage

Implement a provider-independent **Copy vault** operation:

1. Lock or keep the source vault unlocked with a clear confirmation.
2. Read the latest source package and reconcile pending local intents.
3. Verify the source package decrypts with the local vault key and contains the expected `vault_id`.
4. Authorize the destination provider/account.
5. Create a new destination object containing the same `vault_id`, stable vault key envelope, and latest encrypted snapshot.
6. Read back and validate the destination package before changing the active binding.
7. Persist the new binding only after verification; retain the source binding until the user explicitly chooses to disconnect/delete it.

The destination provider file ID changes, but `vault_id` and the vault key do not. Never implement migration as “download plaintext and re-upload.” If the user wants a separate fork, explicitly generate a new `vault_id` and document that it is no longer the same synchronized vault.

## 7. Local Rust server responsibilities

### 7.1 Recommended role

The Rust server remains a per-device local runtime, not a central authority:

- serves the static client and local API;
- stores local account/session data;
- stores the local encrypted vault snapshot/cache;
- manages local OPFS initialization metadata through client APIs;
- performs Google OAuth callback handling and Drive transport on that device;
- stores provider tokens locally, preferably using the OS keychain;
- exposes provider-neutral local APIs for list/read/create/conditional-write/delete;
- never decrypts vault content, derives vault keys, performs merges, or sees plaintext.

For a local-only vault, the local encrypted snapshot is authoritative for that device. For a Google-backed vault, Google Drive’s remote revision is the cross-device authority; the local Rust row is a cache/replica and restart bootstrap source. The browser intent database remains the durable local write-ahead log.

### 7.2 Server schema changes

The current `user.vault_id UNIQUE` relation must be replaced or deprecated. Add concepts equivalent to:

- `user`: local account/profile, email, verifier, session ownership;
- `vault`: portable `vault_id`, encrypted snapshot/cache, crypto metadata, local logical revision, mode;
- `user_vault`: local profile-to-vault selection/ownership relationship;
- `cloud_binding`: `vault_id`, provider kind (`google_drive`), provider account reference, Drive file ID, remote revision/ETag, sync status;
- optional `device` metadata containing device IDs only, never raw device keys.

New local endpoints should be vault-scoped rather than implicitly finding a vault through `session.user_id`:

- create/list/select local vaults;
- get/update local encrypted snapshot/cache;
- begin/complete Google authorization;
- list/read/create/conditional-write/delete provider objects through the local adapter;
- disconnect and binding status.

The existing local CAS may remain for browser-tab/server-cache coordination. It must not be presented as the cross-device conflict mechanism.

### 7.3 Token and secret handling

Do not store Google refresh tokens in the cloud package, browser SQLite, Zustand, logs, or query cache. Store them in the local OS keychain where available. If a fallback local encrypted store is necessary, document its threat model and bind its decryption to the local installation/session. Access tokens should be short-lived and never logged.

## 8. Client repository changes by area

### Crypto

- Add `vault_id` generation and validation.
- Add versioned vault-document/package serialization and authenticated identity binding.
- Keep the existing random vault key, password envelope, and device envelope.
- Add password-envelope rewrap support without snapshot re-encryption.
- Add optional recovery-envelope primitives only in a separate, reviewed phase.

### Auth and UI

- Split account signup/login from vault creation/import.
- Add post-auth vault chooser routes and explicit provider states.
- Add create-local, create-and-connect, enable-sync, start-from-Drive, switch-vault, disconnect, and remote-missing screens.
- Never use email to select a vault.
- Preserve existing lock/unlock route behavior while making lock metadata vault-scoped.

### IndexedDB and SQLite

- Namespace device records by `vault_id` and device ID.
- Change OPFS filename and `initSQLite` validation to the local `user_id` plus portable `vault_id` composite.
- Add the new initial schema with `vault_id`, `base_revision`, provider/file reference, remote revision, binding status, and selected local vault.
- Keep intent payloads encrypted and durable.
- Remove `vault_version`/`base_version` compatibility fields from the new schema; use `base_revision` from the start.
- Ensure switching vaults closes the current worker database before opening another.

### Sync

- Introduce a `VaultRemote` interface consumed by `sync/index.ts`.
- Implement a local-server Google Drive adapter behind that interface.
- Keep `SyncScheduler` single-flight behavior and existing triggers.
- Replace integer CAS with conditional remote revision writes.
- Re-read, re-merge, and retry on `REMOTE_CONFLICT`.
- Mark intents synced only after confirmed remote success/read-back.
- Preserve local-only mode by using a local snapshot repository that implements the same conceptual remote interface without Google.

### Server and migration

- Replace the current SeaORM migration set with a new initial migration and regenerated entities for portable vaults and cloud bindings.
- Decouple `/register` from automatic vault creation.
- Add vault-scoped local repository endpoints.
- Add Google OAuth/Drive transport endpoints and typed error mapping.
- Preserve static serving, CORS, sessions, COOP/COEP, and launcher behavior.

## 9. Testing and acceptance criteria

### Unit and integration tests

- `vault_id` is random, stable across copies, and independent of email/password/user/device IDs.
- Same email plus different master passwords on separate local servers creates independent local vaults.
- Wrong password never overwrites an existing local vault and never creates a new device envelope.
- Google file creation is idempotent after lost responses.
- Multiple valid Voult files in one Drive account are listed and independently selectable.
- Wrong Google account and no-vault states are distinct and actionable.
- A local vault and selected Google vault cannot silently overwrite or merge when switching.
- Disconnect leaves the local vault and remote file intact.
- Remote deletion preserves local data and enters `remote_missing`.
- Offline intents survive browser reload, local server restart, lock, and reconnect.
- Conditional revision conflicts re-read and merge rather than overwrite.
- Lost upload responses do not duplicate vault files or mark intents synced prematurely.
- Password rewrap changes only the password envelope and package revision, not the vault ciphertext or device envelope.
- Copy-to-new-provider verifies destination before switching the binding and preserves the source.

### End-to-end acceptance scenarios

1. Create local vault with network disabled; add logins; restart the local server; reopen successfully.
2. Create a vault and immediately connect Google Drive; confirm one encrypted file and successful read-back.
3. Add logins locally, enable Drive later, and confirm all logins are present after importing on a second device.
4. On a new device, sign in, choose Start from Google Drive, select a vault, enter the correct password, and unlock offline afterward.
5. On the same new device, enter the wrong password; confirm the existing local vault is untouched.
6. Create two independent same-email local vaults with different passwords and confirm no cross-device/cloud discovery occurs without explicit Drive connection.
7. Connect a device holding vault A to Drive vault B and confirm the UI requires an explicit switch/open choice.
8. Put two vaults in one Drive account and confirm both are selectable.
9. Edit offline on two devices; reconnect both; confirm deterministic merge and no stale snapshot overwrite.
10. Disconnect Drive; continue editing locally; confirm no remote deletion.
11. Delete or revoke the Drive file; confirm local use continues and no silent recreation occurs.
12. Copy the vault to a second provider abstraction/test backend; confirm the same `vault_id`, verified package, preserved source, and switchable binding.

## 10. Delivery phases

### Phase 1 — identity and local vault separation

Implement `vault_id`, versioned vault format, composite local-account/vault OPFS/IndexedDB storage, explicit local vault records, and the clean initial database schema. Split account registration from vault creation without adding Google yet.

### Phase 2 — explicit vault chooser and local lifecycle

Implement Create new vault, local-only lock/logout/switch behavior, multiple local vault metadata, and safe handling of an already-open different vault.

### Phase 3 — local Rust Google transport

Implement Google OAuth callback/token storage, Drive appDataFolder listing, package read/create/conditional replace/delete, provider-neutral error mapping, and local API endpoints. Add a fake provider for deterministic tests.

### Phase 4 — immediate and delayed Google enrollment

Implement create-and-connect and enable-later flows, idempotent remote creation, read-back verification, binding persistence, and multiple-vault listing.

### Phase 5 — new-device import and provider-backed sync

Implement Start from Google Drive, password unwrap, new device enrollment, vault-scoped local initialization, remote revision sync, offline reconnect, and conflict retry/merge.

### Phase 6 — lifecycle hardening

Implement disconnect, remote-missing, wrong-account/no-vault UX, password rewrap, safe copy/migration, export/recovery guidance, and destructive-action confirmation.

### Phase 7 — security and operational review

Audit OAuth scopes/token storage, package integrity, logging, migration rollback behavior, local-server permissions, error disclosure, provider rate limits, and all zero-knowledge boundaries. Confirm that no centralized Voult endpoint or hidden remote account database has been introduced.
