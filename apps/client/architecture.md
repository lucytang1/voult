# Architecture

## Table Schemas

### Server-Side (vault-centric)

The vault is the only identity and authorization boundary. There is no account
or user table; `vault_id` resolves the session, password verifier, device
envelope, sync log, and Google OAuth bindings.

- **Vault** (primary identity; `id` is client-generated, stable, embedded in the encrypted vault)
  - `id: string` (UUID)
  - `vault: string` (base64-encoded AES-GCM ciphertext)
  - `vaultiv: string` (base64-encoded IV)
  - `salt: string`
  - `iterations: number` (KDF cost; returned by `/get_vault` and `/get_crypto_params`)
  - `vault_verifier: string` (HMAC-derived verifier from the master password; auth credential only, not the password or any key)
  - `created_at`
  - `version`
  - `crypto_version`
  - `vault_key_wrap: string?` (password-wrapped vault key envelope)
  - `vault_key_wrap_iv: string?`
- **Session** (`session_id` PK, `vault_id` FK to vault)
  - `session_id`, `vault_id`, `created_at`, `expires_at`
- **Google / cloud tables** are all keyed by `vault_id` (see `cloud_binding`, `google_token`, `oauth_state`, `google_pending_token`).

Only ciphertext, salt, iterations, crypto metadata, and a derived verifier are
exposed to the server; the master password, vault key, and all derived keys
never leave the client. The cookie stores only `vault_id` plus framework
session state — never keys, envelopes, or vault plaintext.

### Client-Side (SQLite)

Defined in `src/lib/sqlite/web/migrations.ts`:

- **`intent`**
  - `id TEXT PRIMARY KEY`
  - `operation TEXT NOT NULL`  
    - `"create" | "update" | "delete" | "rename"`
  - `payload TEXT NOT NULL`  
    - encrypted, base64-encoded JSON describing the operation
  - `payload_iv TEXT NOT NULL`  
    - base64-encoded IV for AES-GCM
  - `device_id TEXT NOT NULL`  
    - identifies this client/device instance
  - `base_version INTEGER`  
    - version of the vault the mutation is based on
  - `created_at INTEGER NOT NULL`  
    - timestamp (stored as integer)
  - `synced INTEGER DEFAULT 0`  
    - `0` = pending, `1` = synced
  - `error TEXT`  
    - optional error message if sync fails

- **`client_state`**
  - `key TEXT PRIMARY KEY`
  - `value TEXT`

The intent table is a durable local mutation log; `client_state` is a generic place for client metadata.

## Vault names

A vault's identity is still `vaultId`; its **name** is a display label chosen
during onboarding (between the master password and the recovery file) and
changeable in Settings → Vault. The name lives *inside the encrypted document*
(`DecryptedVault.name`), so the server never receives it and it travels with the
vault across devices and cloud backups.

Because the lock screen and chooser must show a name before the key exists, the
last known name is cached per vault in `localStorage` (see the table above).
Renaming is a durable `rename` intent (`{ name }` encrypted under the vault key)
merged as document-level last-writer-wins; an optimistic pending marker keeps the
new label visible until sync confirms it.

The UUID is no longer shown as a primary label anywhere. Settings → Vault keeps
the full id (with copy) because recovery, storage and the server still use it.

## Folders

A vault's items may be grouped into flat folders. The folder list lives **inside the
encrypted vault document** (`DecryptedVault.folders`), so the server never sees it and it
travels with the vault across devices and cloud backups. Each `VaultItem` carries an optional
`folderId`; an item with no (or a dangling) `folderId` renders under the synthetic
**Unfiled** bucket, which cannot be deleted.

Every vault is created with one folder, **Personal** (`DEFAULT_FOLDER_ID`). Folders are
ordered by their position in the document array (new folders append) and are managed through
three new durable intents — `createFolder`, `renameFolder`, `deleteFolder` — the last of which
cascades to every item in that folder at its replay position. Folder names follow the same
1–48 character normalisation as the vault name.

Because folders are part of the document, **every writer must spread the document** rather
than rebuild `{ name, items }`. The extension does this in `src/background/vault.ts`.

## Login Flow (vault-centric)

End-to-end login flow as implemented today:

1. **No email is collected.** The vault is identified by a client-generated
   `vaultId` (UUID) stored locally. The user is shown a single master-password
   field for the auto-detected vault (Flow A/B in the refactor plan).
2. **Fetch crypto params** using `useGetCryptoParams(vaultId, enabled)`:
   - `GET /get_crypto_params?vault_id=...`
   - Response: `{ salt, iterations }`.
3. **User inputs master password** once salt/iterations are loaded.
4. **Derive login payload** using the crypto helpers:
   - Re-derives an HMAC auth key from the master password and salt.
   - Computes `vaultVerifier` (an HMAC-based verifier, vault-scoped).
   - Returns `{ vault_id, vault_verifier }`.
5. **Authenticate with server** using `useLogIn()`:
   - `POST /auth` with `{ vault_id, vault_verifier }`.
   - On success, the server returns only `vault_id`, salt, iterations,
     crypto_version, and the password-wrapped vault-key envelope — never a user
     object or email.
6. **Derive long-lived keys** for this session:
   - `createEncryptionKey(masterPassword, salt, iterations)` → `encryptionKey: CryptoKey`.
   - `createAuthKey(masterPassword, salt, iterations)` → `authKey: CryptoKey`.
   - Unwrap the vault key from the returned `vault_key_wrap`/`vault_key_wrap_iv`.
7. **Store keys in Zustand** (transient — `authKey` is cleared after auth):
   - `updateEncryptionKey(encryptionKey)`
   - `updateAuthKey(authKey)`
8. **Navigate to `/home`**, where the vault is fetched (`GET /get_vault`) and
   decrypted using these keys.

## Add Item Flow (Intended)

End-to-end flow for adding a new vault item, combining crypto, local intents, and in-memory state:

1. **User fills in item fields** on the home screen (`site`, `username`, `password`).
2. **User taps “Add”**:
   - A `VaultItem` is constructed in memory:
     - `{ site, username, password }`.
3. **Serialize operation payload**:
   - Either the raw `VaultItem` or a richer operation object, e.g.:
     - `{ op: "create", item: VaultItem }`.
   - Convert to JSON string: `JSON.stringify(...)`.
4. **Encrypt payload with AES-GCM** using the already-derived `encryptionKey` from Zustand:
   - Call `encrypt(plainJson, encryptionKey)`:
     - Generates a random IV.
     - Produces ciphertext bytes.
   - Base64-encode:
     - `payload = b64(cipherBytes)`
     - `payloadIv = b64(ivBytes)`
5. **Persist intent to local SQLite** using `createIntent`:
   - Inputs:
     - `operation = "create"` (fixed for now inside `createIntent`).
     - `payload` (ciphertext, base64).
     - `payload_iv` (IV, base64).
     - `device_id` (e.g., from `localStorage`).
     - `base_version`, `created_at` are set in the service.
   - SQLite insert:
     - Row is added to `intent` with `synced = 0`.
6. **Update in-memory decrypted vault** (once the insert succeeds):
   - Read the current `decryptedVault` from Zustand.
   - Append the new plaintext `VaultItem` to `decryptedVault.items`.
   - Call `updateDecryptedVault(...)` with the updated list.
7. **Future sync (not yet implemented)**:
   - A background/sync process will scan `intent` rows with `synced = 0`.
   - It will send encrypted payloads to the server.
   - On success, it will mark those intents as `synced = 1` (and possibly update `base_version`/server state).

In short:

- The **login flow** derives keys and establishes a session without exposing the master password to the server.
- The **add item flow** (design) treats every write as an encrypted intent:
  - Encrypt locally with the vault key.
  - Persist to local SQLite in the `intent` table.
  - Reflect changes immediately in in-memory decrypted state.
  - Sync to the server later via a separate process.

## Local Storage Namespacing (Per-Vault)

All client-side persistence is namespaced by the active vault
(`vaultId`) so multiple vaults in one browser profile can never see each
other's data, and logout prevents one vault's pending intents from ever being
applied by another:

| Store | Namespace | Notes |
|---|---|---|
| SQLite (OPFS) | `file:voult-<vaultId>.db` | One database file per vault (`src/lib/sqlite/web/init-db.ts`). Holds that vault's `intent` log and `client_state`. Opened only after a vault key is in hand; closed on lock and on session loss. |
| IndexedDB `voult` | Records keyed `vault:<vaultId>` | `device_key` + `device_envelope` stores in `src/lib/crypto/device-key.ts`. **Retained on session loss** (see below); deleted only on a real sign-out. |
| TanStack Query cache | In-memory only | Cleared on lock and on 401 via the centralized teardown path. |
| Zustand store | In-memory only | Wiped on lock. `vault: VaultState` is the single source of truth for selection and key presence. |
| `localStorage["voult.selectedVault"]` | Profile-global | The selected vault id. Persisted so the app can restore *its* vault even when the session cookie is gone (M2). |
| `localStorage["voult.lockRecord"]` | Profile-global | `{ vaultId, reason, lockedAt }` (`src/lib/state/selection-store.ts`). `reason` is `manual \| autolock \| peer`: `manual`/`peer` hold until an explicit unlock, `autolock` lapses after the window. Session expiry is deliberately not a lock reason. Replaces the old tab-scoped `sessionStorage["voult.lockedAt"]`. |
| `localStorage["voult.lastActivity.<vaultId>"]` | Per-vault | Epoch ms of the last recorded activity while unlocked (throttled writes). The auto-lock deadline is evaluated against wall-clock time at startup/resume, so closing the tab does not reset the idle window. Not secret. |
| `localStorage["voult.autolock.*"]` | Device-global | Web + extension autolock timeouts (`src/lib/settings/index.ts`). Not vault data: deliberately readable while the vault is locked, which SQLite is not. |
| `localStorage["voult.vaultName.<vaultId>"]` | Per-vault | Last name confirmed by a decrypted document (`src/lib/vault/name.ts`). Exists only so the lock screen and vault chooser can render a label before the key is in memory. A label, never key material. |
| `localStorage["voult.pendingVaultName.<vaultId>"]` | Per-vault | An optimistic rename whose `rename` intent has not reached the server yet. Outranks the cached name for display until sync confirms it. |

Restart behaviour is decided by `decideRestore()` in `src/lib/state/vault-state.ts`,
a pure function over `(selection, lock record, autolock setting, device key
presence, last-activity timestamp)` — so the policy is reviewable in one place
rather than spread across the bootstrap. A finite timer is enforced from the
persisted last activity, not from app launch: reopening after the deadline
stays locked even if the app was closed before the timer fired.

Silent restore needs the **pair** of local device records, not just the key: a
`device_key` with no `device_envelope` has nothing to unwrap, so the bootstrap
reports `stay_locked (no_device_material)` and the lock screen does not offer
"Unlock with this device". Every successful password unlock
(`unlockFromEnvelope` in `src/lib/auth/flows.ts`) re-wraps the vault key into
this browser's envelope, which is what gives a fresh origin — or one whose
envelope was lost — a working device unlock for the *next* reload. Only the
create/login/import/recover flows used to persist it, so an origin entered
through the lock screen could never restore silently.

## Session loss vs. sign-out

These used to be the same code path and they are not the same thing:

- **Session loss** (`SESSION_REQUIRED`, 401) is an *authorization* fact. The
  cookie no longer permits API calls, but the user is still the owner of the
  selected vault on this device. `teardownVaultSession()` marks
  `serverSession: "missing"` only: an **unlocked** vault keeps its key,
  plaintext, version, and open SQLite handle (local use continues; sync/cloud
  work pauses), while a **locked** vault stays locked with its real lock reason.
  The vault selection and the local device key + envelope are retained. Session
  loss is never broadcast as a lock and never writes a lock record.
- **Sign-out** (`clearSessionState`) genuinely deselects: selection, lock record,
  session, and keys all go. There is no user-facing logout button; this runs when
  there is genuinely no vault left (e.g. cleared app data).
- **Vault switch observed from the server** (the cookie now names a different
  vault) is the one case that ends local access to the selected vault:
  `abandonVaultSelection()` closes SQLite, clears the selection and cache, and
  the new vault is adopted locked on its next unlock.

A network outage is neither. It leaves state untouched — offline is a normal
state for the offline-first intent queue, and treating it as a revoked session
would wipe the user's place in the app every time they worked on a plane.

## Switching vaults (M3)

Switching is **atomic around the selected id**. `switchVaultOpen()` in
`src/lib/state/index.ts` verifies that the server authenticated the vault the
user asked for (and that the decrypted document belongs to it), then commits
selection + session + key + document + version + lock epoch in a **single**
store write. The previous path issued five separate writes, so React could
render an intermediate combination — briefly "unlocked with no data", or a
selection for B carrying A's last decrypted document.

Anything async that could outlive a switch captures a **selection epoch** first:

```ts
const guard = captureSelectionEpoch();
const data = await fetchSomething();
if (!guard.stillCurrent()) return; // a switch happened; drop the result
commit(data);
```

`selectionEpoch` increments on every *identity* change. Comparing vault ids is
not sufficient: a switch A→B→A leaves the id unchanged while the captured key
and intents are still stale. Re-selecting the *same* vault deliberately does
not bump it, so a routine re-auth or bootstrap restore does not abort a
legitimate in-flight sync.

Guarded call sites: `sync()` and its `adoptServerSnapshot`, the vault-open and
cloud-import flows in `app/vault/index.tsx`, home's async decrypt effect, and
`useGetVault`'s version write.

`sync()` additionally pins on the **selection** rather than the session —
the cookie can lapse while a vault is still selected, so the old
`session?.vaultId` comparison would have stamped snapshots with an empty id
after session loss.

A failed switch writes nothing: the previous vault keeps its state, so the user
lands on a coherent locked-or-unlocked screen instead of a half-switched one.

OAuth: a **pending provider token never becomes a selection**. Pending state
only lists candidate vaults and links a credential after an explicit,
password-verified import. The only selection writes are a real cookie-backed
session restore, a switch, and a create.
