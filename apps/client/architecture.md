# Architecture

## Table Schemas

### Server-Side (conceptual)

Based on the client code and request/response types, the server is expected to have at least:

- **User / Auth**
  - `id: string`
  - `email: string`
  - `user_key: string` (HMAC-derived verifier, not the password)
  - `vault_id: string`
- **Vault**
  - `id`
  - `vault: string` (base64-encoded AES-GCM ciphertext)
  - `vaultiv: string` (base64-encoded IV)
  - `salt`
  - `iterations: number` (used to re-derive the key; also returned by `/get_vault`)
  - `created_at`
  - version

Only ciphertext, salt, iterations and a derived verifier are exposed to the server; the master password never leaves the client.

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

## Login Flow

End-to-end login flow as implemented today:

1. **User inputs email** on the login screen (`src/app/auth/login.tsx`).
2. **Fetch crypto params** using `useGetCryptoParams(email, enabled)`:
   - `GET /get_crypto_params?email=...`
   - Response: `{ salt, iterations }`.
3. **User inputs master password** once salt/iterations are loaded.
4. **Derive login payload** using `createLoginPayload(email, masterPassword, salt, iterations)`:
   - Re-derives an HMAC auth key from the master password and salt.
   - Computes `user_key` (an HMAC-based verifier).
   - Returns `{ email, user_key }`.
5. **Authenticate with server** using `useLogIn()`:
   - `POST /auth` with `{ email, user_key }`.
   - On success, the server returns `user` info; client stores `email` in `localStorage`.
6. **Derive long-lived keys** for this session:
   - `createEncryptionKey(email, masterPassword, salt, iterations)` → `encryptionKey: CryptoKey`.
   - `createAuthKey(email, masterPassword, salt, iterations)` → `authKey: CryptoKey`.
7. **Store keys in Zustand**:
   - `updateEncryptionKey(encryptionKey)`
   - `updateAuthKey(authKey)`
8. **Navigate to `/home`**, where the vault is fetched and decrypted using these keys.

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

## Local Storage Namespacing (Per-Account)

All client-side persistence is namespaced by the authenticated account
(`session.user.id`) so multiple accounts in one browser profile can never see
each other's data, and logout prevents one account's pending intents from ever
being applied by another:

| Store | Namespace | Notes |
|---|---|---|
| SQLite (OPFS) | `file:voult-<userId>.db` | One database file per account (`src/lib/sqlite/web/init-db.ts`). Holds that account's `intent` log and `client_state`. Opened only after a session exists; closed on lock and logout. |
| IndexedDB `voult` | Records keyed `user:<userId>` | `device_key` + `device_envelope` stores in `src/lib/crypto/device-key.ts`. Logout deletes only the current user's records. Legacy global `"current"` records are migrated to the logging-in user's namespace on first read. |
| TanStack Query cache | In-memory only | Cleared on logout/401 via the centralized teardown path. |
| Zustand store | In-memory only | Wiped on lock/logout. |
| `sessionStorage["voult.locked"]` | Profile-global (intentional) | Locking is profile-wide semantics, not account-specific. |

Teardown is centralized in `src/lib/auth/teardown.ts` and used by all exit
paths (home logout, lock-screen logout, 401 interceptor): capture the account
id → close the per-user SQLite handle → delete this account's device records →
wipe volatile state → clear the query cache. Sync additionally pins the user id
it started for and aborts mid-run if the session changes.
