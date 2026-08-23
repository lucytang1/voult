# Voult Session and Device-Unlock Architecture

## Summary

Separate authentication from vault encryption:

- Authenticate web and extension requests with an `actix-session` session cookie.
- Encrypt the vault with a randomly generated 256-bit vault key.
- Use the master password to unwrap the vault key during a new login.
- Use a locally generated device key to unwrap the vault key during an existing session.
- Store only encrypted vault data and encrypted vault-key envelopes on the server.
- Never store or transmit the master password, plaintext vault, or plaintext vault key.

This follows the general separation used by Bitwarden between logging in and unlocking a vault. References: [Bitwarden security white paper](https://bitwarden.com/pdf/help-bitwarden-security-white-paper.pdf), [Bitwarden login vs. unlock](https://bitwarden.com/en-gb/help/understand-log-in-vs-unlock/).

## Server plan

### Actix sessions

Add `actix-session` with the `cookie-session` feature and configure:

- `SessionMiddleware`
- `CookieSessionStore`
- `SESSION_COOKIE_KEY` as a required application secret
- an HttpOnly cookie named `voult_session`
- configurable Secure and SameSite attributes
- persistent session expiry with configurable absolute and idle timeouts

The cookie may contain only non-sensitive state such as `user_id`, session timestamps, and a session version. It must never contain vault keys, device keys, encrypted vault-key envelopes, or vault data. See the [Actix session documentation](https://docs.rs/actix-session/latest/actix_session/).

Update CORS to use configured origins, credentials support, and Axios `withCredentials: true`. Do not combine credentials with `allow_any_origin()`.

Remove the unused handwritten implementation under `apps/server/src/session/`. Keep historical migration files intact. The existing `session` database table may remain unused while the first implementation uses `CookieSessionStore`.

### Authentication and protected routes

Update `POST /auth`:

1. Continue accepting `{ email, user_key }` for password authentication.
2. Validate the verifier as today.
3. Rotate or purge an existing session to prevent fixation.
4. Insert the authenticated user ID into the Actix session.
5. Return the authenticated user and crypto metadata needed by the client.

Update `POST /register` to create the account transactionally and establish a session immediately after successful registration.

Add:

- `GET /session` or `GET /me` — validate the session and return user/session status.
- `POST /logout` — purge the current session.
- `POST /session/device-key` — register or replace a device’s encrypted vault-key envelope.
- `GET /session/device-key` — retrieve the authenticated device’s envelope.
- `DELETE /session/device-key` — revoke the device envelope.

Require the session for `GET /get_vault`, `POST /update_vault`, device-key endpoints, and future sync endpoints. These endpoints should no longer accept `email` and `user_key` as authentication parameters. Keep `/get_crypto_params` unauthenticated because it is needed before password authentication.

### Device table

Add a SeaORM entity and migration for a `device` table containing:

```text
device_id
user_id
wrapped_vault_key
wrapped_vault_key_iv
crypto_version
created_at
last_used_at
revoked_at
```

Add a unique constraint on `(user_id, device_id)`. The server stores the encrypted envelope only; the device key remains local and is never uploaded.

This supports future browser-extension devices, native devices, device revocation, multi-device administration, and WebAuthn/platform-key integration.

### Vault encryption version 2

Extend the vault schema and API with:

```text
crypto_version
vault_key_wrap
vault_key_wrap_iv
```

Use `crypto_version = 2` for the new format:

- a random vault key encrypts the vault;
- a password-derived key wraps the vault key for password login;
- a device key wraps the vault key for existing-session unlock.

Retain compatibility with the current password-derived vault format. On the first successful password login for a legacy account:

1. Derive the legacy encryption key.
2. Decrypt the old vault locally.
3. Generate a random vault key.
4. Re-encrypt the vault with the random vault key.
5. Wrap the vault key with the password-derived wrapping key.
6. Create the device envelope.
7. Upload the migrated encrypted vault metadata.

## Client plan

### Cryptographic key hierarchy

Use Web Crypto APIs: `getRandomValues`, `generateKey`, `importKey`, `deriveBits`, `encrypt`, and `decrypt`. Persist non-exportable `CryptoKey` objects through IndexedDB structured cloning.

```text
master password
    ↓ PBKDF2-HMAC-SHA256
password root key
    ├─ HKDF("auth-v1") → authentication key → user_key verifier
    └─ HKDF("vault-wrap-v2") → password wrapping key

random 256-bit vault key
    ↓ AES-256-GCM
encrypted vault ciphertext

password wrapping key
    ↓ AES-256-GCM
password-wrapped vault key

random device key
    ↓ AES-256-GCM
device-wrapped vault key
```

Use distinct HKDF labels for authentication and vault-key wrapping. Do not reuse the existing `"enc"` label for the new wrapping operation. Import the vault key as a non-exportable AES-GCM key after creation or unwrapping.

### Browser device key

Add an IndexedDB-backed key-storage service containing:

```text
device_id
device_key: non-exportable AES-GCM CryptoKey
key_version
created_at
```

Generate one device key per browser profile/device:

```text
AES-GCM, 256 bits, extractable: false
usages: ["encrypt", "decrypt"]
```

The key remains accessible to same-origin JavaScript, so this does not defend against XSS. It protects against raw storage theft and ensures the server cannot decrypt the device envelope.

Continue using SQLite `client_state` for non-secret metadata such as `vault_version`, `device_id`, and `crypto_version`. Never store raw vault keys or password-derived keys in SQLite or `localStorage`.

### Client state

Replace the current encryption state with:

```text
vaultKey: CryptoKey | null
authKey: CryptoKey | null
session: SessionState | null
decryptedVault: DecryptedVault | null
vaultVersion: number | null
isLocked: boolean
isSyncing: boolean
```

Keep `authKey` only during password authentication and verifier generation. Normal vault reads and sync must use the session cookie and `vaultKey`, not `authKey`.

Add state actions for setting the vault key, setting session metadata, locking, clearing volatile keys, logging out, and updating device state.

### API/query changes

Update API schemas and hooks together:

- `/auth` and `/register` establish cookie sessions.
- `/session` checks session state.
- `/get_vault` no longer receives email or `user_key`.
- `/update_vault` no longer receives email or `user_key`.
- `/session/device-key` manages encrypted device envelopes.
- `/logout` clears the session.

Create a shared Axios instance with `withCredentials: true`. Add handling for `401 SESSION_REQUIRED`, expired sessions, missing device envelopes, vault-key unwrap failures, and version conflicts. A session failure must clear volatile state and route to login or recovery.

## Client flows

### Signup

1. Generate a random vault key.
2. Derive the password root, authentication key, and password wrapping key.
3. Generate and persist the browser device key.
4. Encrypt the starter vault with the vault key.
5. Wrap the vault key with the password wrapping key.
6. Wrap the vault key with the device key.
7. Send the encrypted vault and password envelope to `/register`.
8. Establish the server session.
9. Store the device envelope through the authenticated device-key flow if it was not included in registration.
10. Keep the vault key only in memory and open the vault.

### New password login

1. Fetch crypto parameters by email.
2. Derive the authentication key and send the `user_key` verifier to `/auth`.
3. Receive the session cookie.
4. Derive the password wrapping key locally.
5. Fetch the encrypted vault and password-wrapped vault-key envelope.
6. Unwrap and import the vault key locally.
7. Ensure a device key exists and refresh the device envelope.
8. Fetch and decrypt the vault.
9. Clear the password and temporary password-derived keys from application state.

### Existing session after reload

1. Initialize SQLite and IndexedDB.
2. Call `/session` using the session cookie.
3. Load the local device key by `device_id`.
4. Fetch the device-wrapped vault-key envelope.
5. Unwrap and import the vault key locally.
6. Fetch and decrypt the vault.
7. Do not request the master password.

If the session exists but the local device key or envelope is missing, show a recovery/login screen instead of treating the vault as unlocked.

### Lock and logout

Locking clears `vaultKey`, `decryptedVault`, and transient authentication state while retaining the session cookie and device key. Unlocking can reconstruct the vault key from the device envelope.

Logout calls `/logout`, clears the session and volatile keys, and revokes/deletes the device envelope according to policy.

Recommended policy:

- Lock: retain the device key.
- Log out this device: revoke the device envelope and delete the device key.
- Log out everywhere: defer until server-side session/device revocation exists.

### Local-first writes and sync

Keep the current local-first intent architecture:

1. Encrypt intent payloads with `vaultKey`.
2. Store encrypted intents in SQLite.
3. Update decrypted Zustand state optimistically.
4. Sync through the authenticated session cookie.
5. Preserve optimistic vault-version checks.

Update `src/lib/sync` so it no longer computes `user_key` or requires `authKey`.

## Compatibility and migration

Support both formats temporarily:

- legacy vaults encrypted directly with a password-derived encryption key;
- version-2 vaults encrypted with a random vault key.

Legacy migration occurs locally on the next password login. The server must never receive the master password, password-derived encryption key, random vault key in plaintext, device key in plaintext, or decrypted vault data.

## Testing plan

### Server tests

Test session creation for login and signup, invalid credentials, missing/expired/malformed sessions, logout invalidation, protected-route authentication, removal of `user_key` authentication from vault routes, user-scoped device envelopes, device revocation, cookie security attributes, and existing optimistic-concurrency conflicts.

### Client cryptography tests

Test random vault-key generation, vault encryption/decryption, password wrapping/unwrapping, device wrapping/unwrapping, wrong-password and wrong-device failures, tamper detection, distinct password/device envelopes, legacy migration, and absence of plaintext keys in SQLite/localStorage.

### Client flow tests

Test signup, new-browser password login, reload with a valid session/device key, missing-device recovery, explicit lock, logout, session expiry, intent sync using only `vaultKey`, and vault version conflicts.

## Assumptions and defaults

- Target platforms are web and browser extensions only.
- The first implementation uses `CookieSessionStore`.
- Sessions are persistent with configurable absolute and idle expiration.
- The device key is persisted in IndexedDB as a non-exportable Web Crypto key.
- Biometrics and WebAuthn unlock are future work.
- Native support will later use the same device-envelope protocol with Keychain/Keystore-backed keys.
- Legacy vaults migrate on the next password login.
- The server remains zero-knowledge regarding vault plaintext and vault keys.
- The handwritten `apps/server/src/session/` files can be removed; historical migrations remain intact.
- A future phase may replace the cookie store with a database-backed or Redis-backed `actix-session` store when server-side revocation and multi-device administration are required.
