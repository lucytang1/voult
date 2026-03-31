# Pass Manager Client

## What This App Is

This repository is the client for a password manager built with Expo, React Native, and Expo Router, currently with a strong web focus.

The product goal is:

- keep the master password on the client only
- derive cryptographic keys locally in the browser
- fetch and decrypt the vault client-side
- treat local edits as encrypted intents that can be synced later

At a high level, this app is a local-first encrypted vault client, not just a CRUD frontend.

## Current Product State

The app is still early and some parts are intentionally incomplete.

Implemented today:

- landing page with navigation into auth flows
- sign up flow that derives keys locally and uploads an encrypted starter vault
- login flow that fetches crypto params, derives keys locally, authenticates, and loads the vault
- vault fetch + decrypt flow on the home screen
- local SQLite setup in the browser using SQLite WASM + OPFS
- local `intent` table for pending encrypted mutations
- debug page for inspecting local SQLite state

Not fully implemented yet:

- end-to-end sync logic in `src/lib/sync/index.ts`
- robust device identity management
- update/delete intent pipelines
- polished production error handling
- offline conflict resolution

When editing, assume some code is scaffolded or mid-build. Prefer targeted improvements over broad refactors unless the task explicitly asks for cleanup.

## Core Design Philosophy

### 1. Client-side cryptography first

The master password must never leave the client.

The server should only receive:

- a derived auth verifier (`user_key`)
- encrypted vault ciphertext
- IVs
- salt
- PBKDF2 iteration count

Agents should preserve this trust boundary.

### 2. Local-first writes

Writes are intended to become encrypted local intents before they are synced to the server.

The local flow is:

1. build a vault mutation payload in plaintext
2. encrypt it with the session encryption key
3. store it in SQLite `intent`
4. update in-memory decrypted state optimistically
5. sync later

Do not replace this with direct plaintext server writes unless the user explicitly asks for that architectural change.

### 3. Thin screens, logic in `src/lib`

Route files in `src/app` should stay focused on UI composition and user interaction.

Business logic belongs in:

- `src/lib/crypto` for key derivation and encryption
- `src/lib/queries` for network requests
- `src/lib/state` for in-memory session state
- `src/lib/sqlite/web` for browser persistence
- `src/lib/sync` for reconciliation and upload logic

### 4. Preserve the current shape unless asked

This project has some naming inconsistencies and work-in-progress code. Do not silently rename APIs, files, or public helpers as a side quest. Keep changes scoped to the request unless cleanup is explicitly requested.

Examples of current inconsistencies that should not be "fixed" casually:

- `createSingupPayload`
- `getlocalVaultVersion`
- `operation_type` being declared as a type instead of a union helper

## Architecture Overview

### Runtime layers

1. `src/app`
   Expo Router screens and navigation.
2. `src/lib/queries`
   React Query hooks + request/response types for backend calls.
3. `src/lib/crypto`
   Web Crypto key derivation, auth verifier generation, vault encryption/decryption.
4. `src/lib/state`
   Zustand store for session keys, decrypted vault, and local vault version.
5. `src/lib/sqlite/web`
   Browser SQLite worker, DB bootstrapping, migrations, and local services.
6. `src/lib/sync`
   Intended home for sync orchestration between local intents and the server.

## Important screens

- `src/app/index.tsx`
  Entry screen. Initializes SQLite on load and links to login/signup.
- `src/app/auth/login.tsx`
  Multi-step login UI. Fetches crypto params first, then derives client keys after auth.
- `src/app/auth/signup.tsx`
  Creates a new account by encrypting a starter vault locally and posting it to the server.
- `src/app/home/index.tsx`
  Fetches the encrypted vault, decrypts it in memory, renders items, and currently creates local intents for new items.
- `src/app/debug/index.tsx`
  Developer/debug screen for inspecting `client_state` and `intent` tables.

## Data flow

### Sign up flow

1. User enters email + password.
2. `createSingupPayload(...)` derives a root key with PBKDF2.
3. HKDF expands that root key into:
   - an AES-GCM encryption key
   - an HMAC auth key
4. The auth key produces `user_key`.
5. A starter vault JSON payload is encrypted locally.
6. The client sends `{ email, user_key, salt, iterations, vaultiv, vault }` to `/register`.

### Login flow

1. User enters email.
2. Client fetches `{ salt, iterations }` from `/get_crypto_params`.
3. User enters password.
4. Client derives the auth verifier locally and posts `{ email, user_key }` to `/auth`.
5. On success, the client derives:
   - `encryptionKey`
   - `authKey`
6. These keys are stored in Zustand for the session.
7. Home screen fetches the encrypted vault and decrypts it locally.

### Vault read flow

1. `useGetVault(...)` requests `/get_vault`.
2. On success, the server vault version is written to local SQLite `client_state`.
3. `src/app/home/index.tsx` decrypts the vault using the in-memory `encryptionKey`.
4. The plaintext vault is stored in Zustand as `decryptedVault`.

### Local write flow

Current intended write behavior:

1. Build a `VaultItem`.
2. Encrypt the mutation payload with `encrypt(...)`.
3. Base64-encode ciphertext and IV.
4. Insert an intent row in SQLite.
5. Optimistically append the plaintext item into Zustand.

This means local state is split across:

- secure-ish persistent browser storage for encrypted intent metadata
- volatile in-memory decrypted session state for rendering

## Storage Model

### In-memory session state

Zustand store in `src/lib/state` currently keeps:

- `encryptionKey`
- `authKey`
- `decryptedVault`
- `vaultVersion`

These are session/runtime values, not durable persisted app state.

### Browser SQLite

SQLite is initialized through `@sqlite.org/sqlite-wasm` and opened with OPFS:

- filename: `file:app.db?vfs=opfs`

Tables created in `src/lib/sqlite/web/migrations.ts`:

- `intent`
  Durable local mutation log for pending encrypted writes.
- `client_state`
  Generic key/value metadata store, currently used for things like vault version and device id.

### Server contract

The backend endpoints assumed by the client today are:

- `POST /register`
- `GET /get_crypto_params`
- `POST /auth`
- `GET /get_vault`

The client is currently hardcoded to `http://127.0.0.1:8080`.

If changing API behavior, update both the query hooks and the associated `api.schema.ts` files together.

## Project Structure

```text
src/
  app/
    _layout.tsx           # React Query provider + router slot
    index.tsx             # entry screen
    auth/
      login.tsx
      signup.tsx
    home/
      index.tsx
    debug/
      index.tsx
  lib/
    crypto/
      index.web.ts        # browser crypto primitives and key derivation
    queries/
      SignUp/
      logIn/
      cryptoParams/
      vault/
    state/
      index.ts            # Zustand store + update helpers
      type.ts
    sqlite/
      web/
        sqlite-worker.ts
        init-db.ts
        db.ts
        migrations.ts
        utils.ts
        services/
          client-state-service.ts
          intent-service.ts
    sync/
      index.ts            # sync orchestration, currently incomplete
```

## Naming And Code Conventions

Follow the existing codebase style unless the task is explicitly about cleanup.

### Files

- route files are lowercase and colocated under `src/app`
- query modules are grouped by domain under `src/lib/queries/<feature>`
- request/response types live beside hooks in `api.schema.ts`
- SQLite helper modules under `src/lib/sqlite/web/services` should remain focused and small

### Symbols

- React Query hooks use `use...` naming
- Zustand mutators use imperative verbs like `update...`, `add...`, `delete...`
- types/interfaces are simple and literal, for example `VaultItem`, `DecryptedVault`, `AppState`
- SQL helpers are thin wrappers, not ORM abstractions

### Imports

- the alias `@/*` maps to the repository root
- both relative imports and aliased imports exist today; prefer consistency within the file you are editing

### Style

- prefer explicit small helpers over clever abstractions
- keep business logic out of JSX when possible
- keep crypto code readable and conservative
- keep network contracts strongly typed

## Tools And Libraries In Use

- Expo + Expo Router for app shell and routing
- React 19 + React Native 0.83
- React Query for server state
- Zustand for local in-memory session state
- `@sqlite.org/sqlite-wasm` for browser-side SQLite
- OPFS for persistent browser database storage
- Web Crypto API for key derivation, HMAC auth verification, and AES-GCM encryption
- Axios for HTTP
- NativeWind/Tailwind for styling
- Zod in some local service validation paths

## Practical Guidance For Agents

### When working on auth or crypto

- keep all password-derived operations client-side
- preserve base64 encoding boundaries carefully
- do not log secrets or plaintext vault contents in production-facing changes
- avoid changing salt/iteration semantics unless the backend contract is also being updated

### When working on vault features

- treat `decryptedVault` as the UI-facing representation
- treat SQLite intents as the durable source of pending local writes
- think about versioning and sync implications before changing write logic

### When working on SQLite code

- ensure `initSQLite()` has run before calling helpers that depend on `getDbId()`
- preserve the `intent` / `client_state` split unless there is a strong reason to redesign it
- keep migration updates additive and safe for existing users

### When working on API code

- update the hook and its schema types together
- prefer keeping endpoint-specific logic in `src/lib/queries`
- avoid sprinkling raw `axios` calls directly through route components

### When working on UI code

- keep screens simple and move reusable logic into `src/lib`
- preserve the dark visual style unless asked to redesign it
- maintain the current React Native / NativeWind component style

## Known Gaps And Caveats

- sync is not finished, so some local-write flows are only partially wired
- some debug logging is still present in app and service code
- some placeholder/test values exist, such as the starter signup vault and a hardcoded `deviceId`
- the current codebase is web-centric even though the stack is Expo/React Native
- not every type or helper is polished yet; prefer incremental improvement

## Safe Default Approach For Future Work

If a task is ambiguous, the safest default is:

1. keep crypto client-side
2. keep writes local-first
3. keep screens thin
4. preserve existing contracts unless the task explicitly includes a migration
5. favor small, composable service-layer changes over app-wide rewrites
