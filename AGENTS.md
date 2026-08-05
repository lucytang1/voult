# Voult — Local-First Password Manager

## What This Project Is

This monorepo is a **local-first password manager**. It is split into two packages:

- `apps/client/` — an Expo + React Native app (Expo Router), currently with a strong web focus.
- `apps/server/` — an Actix-Web + SeaORM (SQLite) backend that acts as an encrypted, dumb transport.

The product goal:

- keep the master password on the client only
- derive cryptographic keys locally in the browser
- fetch and decrypt the vault client-side
- treat local edits as encrypted intents that can be synced later
- give the user a manager where **everything lives on their own machine** — the server stores only ciphertext, salt, iteration counts, and a derived verifier, never plaintext and never the master password

At a high level this is a local-first encrypted vault client + a storage service, not a CRUD frontend with a plaintext backend.

## End Goal & Product Philosophy

The design is guided by four principles. Preserve them when editing.

### 1. Client-side cryptography first

The master password must never leave the client.

The server should only receive:

- a derived auth verifier (`user_key`, an HMAC digest — not the password)
- encrypted vault ciphertext
- IVs
- salt
- PBKDF2 iteration count

Agents should preserve this trust boundary. Do not introduce server-side password storage, server-side key derivation with the password, or plaintext vault writes.

### 2. Local-first writes

Writes are intended to become **encrypted local intents** before they are synced to the server.

The local flow is:

1. build a vault mutation payload in plaintext
2. encrypt it with the session encryption key
3. store it in SQLite `intent`
4. update in-memory decrypted state optimistically
5. sync later

Do not replace this with direct plaintext server writes unless the user explicitly asks for that architectural change.

### 3. Thin screens, logic in lib

Route files in `src/app` should stay focused on UI composition and user interaction. Business logic belongs in the `src/lib` modules (client) and in small endpoint modules (server).

### 4. Preserve the current shape unless asked

The project has naming inconsistencies and work-in-progress code. Do not silently rename APIs, files, or public helpers as a side quest. Keep changes scoped to the request unless cleanup is explicitly requested.

Examples of current inconsistencies that should not be "fixed" casually:

- `createSingupPayload`
- `getlocalVaultVersion`
- `operation_type` being declared as a type instead of a union helper

## Repository Layout

```text
voult/
  AGENTS.md            # this file — project context for agents
  apps/
    client/            # Expo + React Native app (web-centric today)
      src/
        app/           # expo-router screens
        lib/
          crypto/      # key derivation, auth verifier, vault encrypt/decrypt
          queries/     # React Query hooks + typed API contracts
          state/       # Zustand in-memory session state
          sqlite/web/  # browser SQLite (WASM + OPFS): worker, db, migrations, services
          sync/        # sync orchestration between local intents and the server
    server/            # Actix-Web + SeaORM backend
      src/
        endpoints/     # one file per HTTP endpoint
        entity/        # SeaORM generated entities (user, vault, session)
        session/       # session auth scaffold (NOT wired up — see below)
        db.rs          # database connection
        main.rs        # app bootstrap, CORS, route registration
      migration/       # SeaORM migrations (workspace member)
  TODO.md              # feature-by-feature status (completed vs remaining)
```

## Current Product State

The app is early and some parts are intentionally incomplete. Implemented today:

### Client

- landing page with navigation into auth flows
- sign up flow that derives keys locally and uploads an encrypted starter vault
- login flow that fetches crypto params, derives keys locally, authenticates, and loads the vault
- vault fetch + decrypt flow on the home screen
- local SQLite setup in the browser using SQLite WASM + OPFS
- local `intent` table for pending encrypted mutations (`create` only)
- add-item flow that writes an encrypted intent and updates in-memory state optimistically
- manual sync orchestration in `src/lib/sync/index.ts` (create-intent replay, version-gated)
- debug page for inspecting local SQLite state

### Server

- `POST /register` — creates user + vault in a transaction
- `GET /get_crypto_params` — returns salt + iterations for an email
- `POST /auth` — verifies email + `user_key`
- `GET /get_vault` — returns encrypted vault + version
- `POST /update_vault` — optimistic-concurrency write (version check → 409 on conflict)
- SeaORM migrations + entities (`user`, `vault`, `session`)

### Not fully implemented

- update/delete intent pipelines (sync only handles `create`)
- real device identity management (client hardcodes `"test_device_id"`)
- server sessions (module is scaffolded but commented out of `main.rs`)
- master password change / key rotation (server `update_key.rs` is an empty stub)
- offline vault cache / conflict resolution UI
- auto-sync triggers (sync currently runs on a manual button press)
- polished production error handling and tests

When editing, assume some code is scaffolded or mid-build. Prefer targeted improvements over broad refactors unless the task explicitly asks for cleanup. See `TODO.md` for the full feature-by-feature status.

## Architecture

### Client runtime layers

1. `src/app` — Expo Router screens and navigation.
2. `src/lib/queries` — React Query hooks + request/response types for backend calls.
3. `src/lib/crypto` — Web Crypto key derivation, auth verifier generation, vault encryption/decryption.
4. `src/lib/state` — Zustand store for session keys, decrypted vault, and local vault version.
5. `src/lib/sqlite/web` — browser SQLite worker, DB bootstrapping, migrations, and local services.
6. `src/lib/sync` — sync orchestration between local intents and the server.

### Server runtime layers

1. `src/main.rs` — app bootstrap: env, logger, DB connection, migrations, CORS, route registration.
2. `src/endpoints/` — one module per endpoint. Handlers are async, take `web::Data<DbPool>`, return `HttpResponse` directly.
3. `src/entity/` — SeaORM generated models. Treated as data access, not business logic.
4. `src/db.rs` — `DbPool = DatabaseConnection` type alias + connection factory.
5. `src/session/` — session auth scaffold: `SessionStore` trait, `CookieSessionStore`, `SessionKey`, `CookieConfiguration`. **Not compiled into the app** (`mod session;` is commented out in `main.rs`). Treat it as design notes unless a task explicitly asks to wire it up.
6. `migration/` — SeaORM migrations run automatically on server start.

### The trust boundary

| Data | Where it lives |
|---|---|
| master password | client memory only, during entry; never persisted, never sent |
| derived encryption key (AES-256-GCM) | client memory (Zustand) |
| derived auth key (HMAC-SHA256) | client memory (Zustand) |
| `user_key` auth verifier | client derives it; server stores it (HMAC digest, not reversible to the password) |
| encrypted vault ciphertext + IV | server DB + encrypted local intents |
| salt + PBKDF2 iterations | server DB (also needed locally to re-derive keys) |
| plaintext vault | client memory only |

## Schemas

### Server DB (SQLite via SeaORM)

Created by `migration/src/m20260226_160000_intent_vault_users.rs`, modified by `m20260314_000001_replace_intent_with_session.rs`. UUIDs are stored as strings (`id_codec.rs`).

**`vault`**
| column | type | notes |
|---|---|---|
| `id` | string PK | uuid as string |
| `vault` | string | base64 AES-GCM ciphertext of the whole vault |
| `salt` | string | base64 salt |
| `iterations` | integer | PBKDF2 iteration count |
| `vaultiv` | string | base64 IV |
| `created_at` | string (ISO UTC) | default now |
| `version` | integer | optimistic-concurrency counter, incremented on every update |

**`user`**
| column | type | notes |
|---|---|---|
| `id` | string PK | uuid as string |
| `email` | string | unique-ish (indexed by lookup); not normalized today |
| `user_key` | string | HMAC auth verifier (base64), the only "credential" stored |
| `vault_id` | string | FK → `vault.id`, one-to-one |

**`session`** (table exists via migration, but the session module is not wired up)
| column | type | notes |
|---|---|---|
| `session_id` | string PK | |
| `user_id` | string | FK → `user.id`, cascade delete |
| `created_at` | string (ISO UTC) | |
| `expires_at` | string (ISO UTC) | |

### Client SQLite (browser, SQLite WASM + OPFS)

Defined in `src/lib/sqlite/web/migrations.ts`. Opened as `file:app.db?vfs=opfs`.

**`intent`** — durable local mutation log for pending encrypted writes.
| column | notes |
|---|---|
| `id` | uuid PK |
| `operation` | `"create"` today; `"update" \| "delete"` intended |
| `payload` | base64 AES-GCM ciphertext of the mutation |
| `payload_iv` | base64 IV |
| `device_id` | identifies the client device (hardcoded today) |
| `base_version` | vault version the mutation was based on |
| `created_at` | ISO timestamp (stored as string; schema comment says integer — known inconsistency) |
| `synced` | 0 = pending, 1 = synced |
| `error` | nullable; currently never written by the sync path |

**`client_state`** — generic key/value metadata store. Currently used for `vault_version` (and `device_id` is intended).

### API contract

All bodies are JSON. The client's `EXPO_PUBLIC_API_URL` env var points at the server (default dev target `http://127.0.0.1:8080`). Client request/response types live beside the hooks in `api.schema.ts` — **if you change API behavior, update the hook and its schema together.**

- `POST /register` — `{ email, user_key, salt, iterations, vaultiv, vault }` → `{ user: { id, email }, vault, salt, iterations, vaultiv }` (201)
- `GET /get_crypto_params?email=` → `{ salt, iterations }` (404 if user not found — leaks account existence)
- `POST /auth` — `{ email, user_key }` → `{ user: { id, email } }` (401 on mismatch)
- `GET /get_vault?email=&user_key=` → `{ vault: { vault, vaultiv, iterations, version } }`
- `POST /update_vault` — `{ email, user_key, vault, vaultiv, version }` → `{ vault, vaultiv, iterations, version }`. Returns `409 VERSION_CONFLICT` if `version` doesn't match the stored vault version.

## Cryptography & Key Model

Implemented in `apps/client/src/lib/crypto/index.web.ts` using the Web Crypto API.

1. **Root key** — `PBKDF2-HMAC-SHA256(masterPassword, salt, 60000 iterations)` → 256 bits.
2. **Key expansion** — HKDF-SHA256 over the root key, empty salt:
   - `info = "enc"` → 32 bytes → AES-GCM encryption key
   - `info = "auth"` → 32 bytes → HMAC-SHA256 auth key
3. **Auth verifier** — HMAC over the static message `auth-v1|` + `|static`, base64 → `user_key`.
4. **Vault encryption** — AES-GCM, random 12-byte IV per operation; ciphertext and IV base64-encoded at every boundary.

Conventions to preserve:

- keep all password-derived operations client-side
- preserve base64 encoding boundaries carefully
- do not log secrets or plaintext vault contents
- avoid changing salt/iteration semantics unless the backend contract is also being updated
- consider Argon2id as a future hardening step (currently PBKDF2 at 60k iterations), but only as an explicit, coordinated change across both packages

## Data Flows

### Sign up flow

1. User enters email + password.
2. `createSingupPayload(...)` derives a root key with PBKDF2, HKDF-expands into an encryption key and an auth key.
3. The auth key produces `user_key`; a starter vault JSON is encrypted locally with AES-GCM.
4. The client sends `{ email, user_key, salt, iterations, vaultiv, vault }` to `/register`.

### Login flow

1. User enters email.
2. Client fetches `{ salt, iterations }` from `/get_crypto_params`.
3. User enters the master password.
4. Client derives the auth verifier locally and posts `{ email, user_key }` to `/auth`.
5. On success the client derives `encryptionKey` + `authKey` and stores them in Zustand.
6. The home screen fetches the encrypted vault and decrypts it locally.

### Vault read flow

1. `useGetVault(...)` requests `/get_vault`.
2. On success the server vault version is written to local SQLite `client_state` (`vault_version`) and to Zustand.
3. The home screen decrypts the vault with the in-memory encryption key.
4. The plaintext vault is stored in Zustand as `decryptedVault`.

### Local write flow

1. Build a `VaultItem` (`{ site, username, password }`).
2. Encrypt the mutation payload with AES-GCM using the session encryption key.
3. Base64-encode ciphertext and IV.
4. Insert an `intent` row (`createIntent`, currently always `operation = "create"`).
5. Optimistically append the plaintext item to Zustand.

Local state is intentionally split:

- **durable**: encrypted intent metadata in browser SQLite (`intent`, `client_state`)
- **volatile**: in-memory decrypted session state in Zustand (for rendering)

### Sync flow (client, manual)

Implemented in `src/lib/sync/index.ts`. This is the current sync algorithm — treat its decisions as deliberate until a task explicitly revises them:

1. Fetch and decrypt the server vault; read the server version.
2. **The local SQLite `vault_version` is the source of truth.** Compare it against the server version; if they don't match, abort sync (no merge, no overwrite).
3. Load pending intents (`synced = 0`, no error). If none, return.
4. Replay pending **create** intents on top of the decrypted server vault.
5. Re-encrypt the merged vault and `POST /update_vault` with the local version as the base.
6. On success: refresh Zustand + local `vault_version`, mark the applied intents as `synced = 1`.

Server-side, `/update_vault` enforces the same optimistic concurrency: it rejects with `409 VERSION_CONFLICT` unless the request version equals the stored version, then atomically increments `version`.

## Code Design & Conventions

### Client

- route files are lowercase and colocated under `src/app`
- query modules are grouped by domain under `src/lib/queries/<feature>` with request/response types in `api.schema.ts`
- React Query hooks use `use...` naming; Zustand mutators use imperative verbs (`update...`, `add...`, `delete...`)
- types/interfaces are simple and literal (`VaultItem`, `DecryptedVault`, `AppState`)
- SQLite helper modules under `src/lib/sqlite/web/services` stay small and focused — thin wrappers, not an ORM
- the alias `@/*` maps to the repository root; both relative and aliased imports exist — prefer consistency within the file you are editing
- prefer explicit small helpers over clever abstractions; keep business logic out of JSX; keep crypto readable and conservative; keep network contracts strongly typed

### Server

- one endpoint module per HTTP route in `src/endpoints/`, registered explicitly in `main.rs` (`mod session;` stays commented out unless wiring sessions)
- handlers use `web::Data<DbPool>`, SeaORM `EntityTrait` find/filter queries, and return `HttpResponse` directly with a consistent `ErrorResponse { error_msg, code }` shape
- UUIDs cross the DB boundary as strings via `id_codec.rs` (`uuid_to_db` / `uuid_from_db`); base64/raw values pass through untouched
- writes that touch multiple tables use a transaction (see `/register`)
- migrations are additive and versioned under `migration/`; they run automatically at server startup
- do not add dependencies casually; the crate list is intentionally small

## Tools And Libraries In Use

### Client

- Expo + Expo Router for app shell and routing
- React 19 + React Native 0.83
- React Query for server state
- Zustand for local in-memory session state
- `@sqlite.org/sqlite-wasm` for browser-side SQLite, OPFS for persistent storage
- Web Crypto API for key derivation, HMAC auth verification, and AES-GCM encryption
- Axios for HTTP
- NativeWind/Tailwind for styling
- Zod in some local service validation paths
- `expo-application` / `expo-device` installed (intended for device identity; not yet used)
- `typegpu` / `react-native-wgpu` / `posthog-react-native` are installed but appear unused

### Server

- Actix-Web 4 + actix-cors
- SeaORM 2 (SQLite) + `sqlx-sqlite` runtime
- SeaORM migrations (workspace member)
- `uuid`, `chrono`, `serde`/`serde_json`, `dotenvy`, `env_logger`/`log`

## Practical Guidance For Agents

### When working on auth or crypto (client)

- keep all password-derived operations client-side
- preserve base64 encoding boundaries carefully
- do not log secrets or plaintext vault contents in production-facing changes
- avoid changing salt/iteration semantics unless the backend contract is also being updated

### When working on vault features (client)

- treat `decryptedVault` as the UI-facing representation
- treat SQLite intents as the durable source of pending local writes
- think about versioning and sync implications before changing write logic

### When working on SQLite code (client)

- ensure `initSQLite()` has run before calling helpers that depend on `getDbId()`
- preserve the `intent` / `client_state` split unless there is a strong reason to redesign it
- keep migration updates additive and safe for existing users

### When working on API code (client)

- update the hook and its schema types together
- prefer keeping endpoint-specific logic in `src/lib/queries`
- avoid sprinkling raw `axios` calls directly through route components

### When working on the server

- keep the trust boundary: never accept or store the master password, plaintext vault, or derived encryption key
- `/update_vault` must stay optimistic-concurrency-safe (version check + atomic increment); changes to the sync contract touch both packages
- UUIDs stored as strings — go through `id_codec.rs`, don't assume the DB stores binary UUIDs
- multi-table writes need a transaction (register is the reference implementation)
- if wiring sessions, the scaffold in `src/session/` (trait + cookie store + entity) is the intended direction; the `session` table already exists via migration

### When working on UI code

- keep screens simple and move reusable logic into `src/lib`
- preserve the dark visual style unless asked to redesign it
- maintain the current React Native / NativeWind component style

## Known Gaps And Caveats

- sync only handles `create` intents; `update`/`delete` pipelines are not wired
- `createIntent` hardcodes `operation = "create"`
- `deviceId` is hardcoded to `"test_device_id"`
- sync runs on a manual button press only — no auto-sync, no offline queue retry, no conflict-resolution UI
- the session module and the `session` table exist but are not wired into the app
- `update_key.rs` is an empty stub; there is no master-password-change or key-rotation flow
- the whole vault is one encrypted blob — every change rewrites the entire vault (a deliberate simplification with per-item-schema implications)
- some debug logging and placeholder/test values remain (starter signup vault, console logs)
- the client is web-centric even though the stack is Expo/React Native; native storage (iOS/Android) is not wired
- no tests on either package
- server CORS is fully open (`allow_any_origin`) — dev-appropriate only
- `get_crypto_params` returns 404 for unknown emails, which leaks account existence

## Safe Default Approach For Future Work

If a task is ambiguous, the safest default is:

1. keep crypto client-side
2. keep writes local-first
3. keep screens thin and endpoint modules small
4. preserve existing contracts unless the task explicitly includes a migration
5. favor small, composable service-layer changes over app-wide rewrites
6. when changing sync or the vault model, update the client and server together
7. when in doubt, add to `TODO.md` rather than silently redesigning
