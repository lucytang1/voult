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
    - e.g. `"create" | "update" | "delete"`
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
| SQLite (OPFS) | `file:voult-<vaultId>.db` | One database file per vault (`src/lib/sqlite/web/init-db.ts`). Holds that vault's `intent` log and `client_state`. Opened only after a session exists; closed on lock and logout. |
| IndexedDB `voult` | Records keyed `vault:<vaultId>` | `device_key` + `device_envelope` stores in `src/lib/crypto/device-key.ts`. Logout deletes only the active vault's records. |
| TanStack Query cache | In-memory only | Cleared on logout/401 via the centralized teardown path. |
| Zustand store | In-memory only | Wiped on lock/logout. |
| `sessionStorage["voult.locked"]` | Profile-global (intentional) | Locking is profile-wide semantics, not vault-specific. |

Teardown is centralized in `src/lib/auth/teardown.ts` and used by all exit
paths (home logout, lock-screen logout, 401 interceptor): capture the vault id →
close the per-vault SQLite handle → delete this vault's device records → wipe
volatile state → clear the query cache. Sync additionally pins the vault id it
started for and aborts mid-run if the session changes.
