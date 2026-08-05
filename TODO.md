# Voult — Local-First Password Manager

> Goal: a password manager where **everything lives on the user's machine**. The master password never leaves the client; the server only stores ciphertext, salt, iteration counts, and a derived verifier. The `apps/client/` monorepo half is an Expo/React Native app (currently web-centric), and `apps/server/` is an Actix-Web + SeaORM (SQLite) backend.

Status of each item reflects what's actually wired up in code today, not just designed. `[x]` = implemented, `[ ]` = remaining.

---

## 1. Client (`apps/client/`)

### 1.1 Completed

- [x] **Landing page** — entry screen linking to Log in / Sign up (`src/app/index.tsx`)
- [x] **Sign-up flow** — derives keys locally and uploads an encrypted starter vault
  - [x] PBKDF2 (SHA-256, 60k iterations) → root key, HKDF-expanded into an AES-GCM encryption key and an HMAC auth key (`src/lib/crypto/index.web.ts`)
  - [x] HMAC-based auth verifier (`user_key`) derived locally; master password never leaves the client
  - [x] Starter vault encrypted locally with AES-GCM before upload (`src/app/auth/signup.tsx`)
- [x] **Login flow** — two-step fetch-crypto-params → enter password → authenticate → derive session keys
  - [x] `GET /get_crypto_params?email=` to load salt + iterations (`src/lib/queries/cryptoParams/`)
  - [x] `POST /auth` with `{ email, user_key }` (`src/lib/queries/logIn/`)
  - [x] Session encryption + auth keys derived locally and held in Zustand (`src/lib/state/`)
- [x] **Vault read flow** — fetch encrypted vault, decrypt locally, render
  - [x] `GET /get_vault` → decrypt with in-memory encryption key (`src/lib/queries/vault/`, `src/app/home/index.tsx`)
  - [x] Server vault version persisted to local SQLite `client_state` (`vault_version`)
  - [x] Decrypted vault held in Zustand `decryptedVault`
- [x] **Local-first writes** — mutations become encrypted intents before they touch the network
  - [x] Local SQLite via SQLite WASM + OPFS (`src/lib/sqlite/web/`)
  - [x] `intent` table = durable local mutation log (`operation`, encrypted `payload`/`payload_iv`, `device_id`, `base_version`, `synced`) (`migrations.ts`, `services/intent-service.ts`)
  - [x] `client_state` key/value table (`services/client-state-service.ts`)
  - [x] Add-item flow: encrypt `VaultItem` → insert intent (`synced=0`) → optimistic in-memory update (`src/app/home/index.tsx`)
- [x] **Sync orchestration** — manual sync that reconciles local intents against the server vault (`src/lib/sync/index.ts`)
  - [x] Fetch + decrypt server vault; compare local vs server vault version and abort on mismatch (local sqlite version is the source of truth)
  - [x] Apply pending **create** intents on top of the decrypted server vault
  - [x] Re-encrypt merged vault, `POST /update_vault` with base version
  - [x] On success: update Zustand + local `vault_version`, mark intents `synced=1`
- [x] **Debug screen** — inspect local `client_state` and `intent` tables (`src/app/debug/index.tsx`)
- [x] **In-memory state model** — Zustand store with `encryptionKey`, `authKey`, `decryptedVault`, `vaultVersion` and add/update/delete helpers

### 1.2 Remaining — Crypto & Auth

- [ ] **Session persistence** — keys currently live only in memory; a reload/relaunch loses the session. Persist a derived session securely (WebCrypto `crypto.subtle` + `sessionStorage`, or an encrypted token in AsyncStorage) and auto-restore on launch
- [ ] **Logout** — no way to end the session and clear in-memory keys
- [ ] **Auto-lock / idle timeout** — lock the vault after inactivity or app background; require re-entry of master password or a derived lock
- [ ] **Biometric unlock** — Face ID / Touch ID / Windows Hello on supported platforms
- [ ] **Secure key storage on native** — Keychain / Keystore / SecureStore for derived keys or a device-bound unlock key; the current stack is SQLite-WASM + OPFS, which is web-only
- [ ] **Master password change / key rotation** — re-encrypt the vault with a new derived key and persist new verifier (server `update_key` endpoint is currently empty)
- [ ] **Account recovery** — recovery codes / backup phrase / trust model so the vault is recoverable if the master password is lost
- [ ] **Wrong-password handling UX** — clear "unlock failed" state, lockout backoff on the client

### 1.3 Remaining — Sync & Offline

- [ ] **Update / delete intents** — `createIntent` hardcodes `operation = "create"`; sync only applies `create`. Wire `update`/`delete` end-to-end (intent → apply → push)
- [ ] **Automatic sync triggers** — sync currently only runs on a manual button press. Add: sync on app launch, after each local write, on network-reconnect / app-foreground
- [ ] **Background / debounced sync** — avoid hammering the server; debounce and/or run in a worker
- [ ] **Real device identity** — `deviceId` is hardcoded to `"test_device_id"`. Generate + persist per device (expo-application / expo-device are already installed) and record on the server for multi-device awareness
- [ ] **Conflict resolution** — a version mismatch currently just aborts with a console warning. Define merge behavior: per-item (LWW by timestamp), intent-replay, or manual "keep this device / use server" UI
- [ ] **Offline vault read** — the decrypted vault is not persisted; the user cannot read entries while offline. Cache an encrypted snapshot locally and unlock it with the derived key
- [ ] **Failed-intent retry & quarantine** — intents with an error are skipped forever (`error` column exists but is never written); add retry, error surfacing, and a clear/abandon path
- [ ] **Sync progress & error UI** — surface sync state (pending/offline/failed) to the user instead of `console.warn`

### 1.4 Remaining — Vault Features (a standard PM's feature set)

- [ ] **Item management UI** — full CRUD (edit/delete exist only as in-memory helpers, no screens); show/hide & copy password; per-item metadata (created/updated, favorite, tags)
- [ ] **Search & sort/filter** — search across site/username/notes, filter by tag/favorite
- [ ] **Password generator** — configurable length/character sets, "generate & save" in the add-item form
- [ ] **Import / export** — CSV/JSON import from other managers and export/backup
- [ ] **Secure notes, custom fields, TOTP** — notes with rich text, arbitrary custom fields, and time-based one-time-password (authenticator) entries stored in the encrypted vault
- [ ] **Password health / audit** — reused/weak passwords, strength meter at creation, optional breached-password (HIBP k-anonymity) check that runs client-side
- [ ] **Categories / tags / organizations** — folders, collections, or tags with assignable vault items
- [ ] **Auto-fill / browser integration** — web extension (WebExtension using the same crypto) and mobile autofill service. This is the biggest lever for "alternative password manager" reach
- [ ] **Clipboard hygiene** — clear copied passwords after a timeout; copy-with-preview
- [ ] **History & restore** — per-item change history with rollback (requires a richer item/version model than the current whole-vault blob)
- [ ] **Trash / soft-delete** — reversible deletes before permanent removal

### 1.5 Remaining — Platforms, Quality & Ops

- [ ] **Native platforms** — the app runs on web (SQLite WASM/OPFS); iOS/Android need a native SQLite path (or a documented storage strategy) and SecureStore/Keychain for keys
- [ ] **Tests** — no client tests today. Priorities: crypto helpers (key derivation, verifier, encrypt/decrypt round-trip), intent service, sync reconciliation (mismatch, multi-intent, update/delete)
- [ ] **Error handling polish** — replace scattered `console.log`/`console.error` with typed error paths and user-facing messages
- [ ] **Remove placeholder/debug values** — hardcoded `TEST_VAULT` in sign-up, `"test_device_id"`, debug logging, unused deps (typegpu / react-native-wgpu / posthog appear unused)
- [ ] **Type cleanup** — reconcile inconsistencies noted in AGENTS.md (`createSingupPayload`, `getlocalVaultVersion`, `operation_type`)
- [ ] **Vault item schema evolution** — the item type is only `{ site, username, password }`; plan a versioned, backward-compatible schema (custom fields, notes, timestamps) since the vault is one encrypted blob

---

## 2. Server (`apps/server/`)

### 2.1 Completed

- [x] **`POST /register`** — creates `user` + `vault` in a transaction; returns user + encrypted vault (`src/endpoints/register.rs`)
- [x] **`GET /get_crypto_params`** — returns `{ salt, iterations }` for an email, pre-auth by design (`get_crypto_params.rs`)
- [x] **`POST /auth`** — verifies `email` + `user_key` (constant-time not required: the verifier is an HMAC digest compared as a whole) and returns the user (`auth.rs`)
- [x] **`GET /get_vault`** — returns encrypted vault + `version` after authenticating (`get_vault.rs`)
- [x] **`POST /update_vault`** — optimistic-concurrency write: rejects with `409 VERSION_CONFLICT` on version mismatch, increments `version` atomically (`update_vault.rs`)
- [x] **Database migrations** (SeaORM, `migration/`) — `vault`, `user`, and a later migration that drops `intent` and adds a `session` table
- [x] **Entities** — generated SeaORM models for `user`, `vault`, `session`
- [x] **Session module scaffold** — `SessionStore` trait, `CookieSessionStore`, `SessionKey`, `CookieConfiguration` in `src/session/` (⚠️ not compiled — `mod session;` is commented out in `main.rs`)

### 2.2 Remaining — Auth & Sessions

- [ ] **Wire up sessions** — the session module exists but is dead code. Implement real session creation on `/auth`, session middleware, and cookie-based auth so `user_key` isn't re-sent on every request
- [ ] **`POST /logout`** — invalidate the session server-side
- [ ] **Session expiry / sliding renewal** — enforce `expires_at`, refresh on activity
- [ ] **Device registry** — record device_id at auth; endpoints to list / revoke devices ("sign out other devices")
- [ ] **Brute-force / rate limiting** — protect `/auth` (and `/get_crypto_params`) against credential stuffing; the HMAC verifier makes offline guessing hard, but online guessing still needs a throttle
- [ ] **Timing-safe comparison** — compare `user_key` with a constant-time compare (e.g. subtle `constant_time_eq`) rather than a plain equality

### 2.3 Remaining — Account Lifecycle & Key Management

- [ ] **`POST /update_key`** — endpoint exists as an empty file; implement master-password change / key rotation (re-encrypted vault + new verifier + new salt/iterations)
- [ ] **Email verification & account recovery** — no verification email, no reset/recovery flow. Decide the trust model: with a truly local-first design, recovery may be client-driven (recovery codes) with the server only storing opaque metadata
- [ ] **Email normalization & validation** — lowercase/normalize emails, validate format; prevent duplicate/abuse on register
- [ ] **Delete account** — cascade user + vault; no endpoint today
- [ ] **Account enumeration protection** — `/get_crypto_params` returns `404 USER_NOT_FOUND`; standard PMs return a uniform response so account existence isn't leakable

### 2.4 Remaining — Sync & Concurrency

- [ ] **Intent-based sync API** — today the client pushes a whole re-encrypted vault. A per-intent endpoint (`POST /sync` with a batch of encrypted ops) enables multi-device merge without read-modify-write races and keeps the server a dumb transport
- [ ] **Server-side conflict signal** — on version conflict, return the current server version so the client can rebase instead of a bare `409`
- [ ] **Idempotency** — idempotency keys so a retried sync doesn't double-apply intents
- [ ] **Vault size limits & request hardening** — body-size limits on `update_vault`/`register`, input length caps, and rejection of malformed base64

### 2.5 Remaining — Security & Ops

- [ ] **CORS lockdown** — `allow_any_origin().allow_any_method().allow_any_header()` is dev-appropriate only; restrict to the client origin(s) in production
- [ ] **Secrets & config management** — `DATABASE_URL` via dotenv only; define a real config story (env vars, a prod DB, TLS/reverse-proxy notes)
- [ ] **Audit logging** — log auth events, syncs, and version conflicts for incident response
- [ ] **Server backups** — backup strategy for the SQLite DB (it's ciphertext, but still needs durability)
- [ ] **Rate limiting on sync endpoints** — prevent abuse of `update_vault`
- [ ] **Tests** — no server tests today. Priorities: register/auth round-trip, vault version conflict, update_key, session middleware
- [ ] **Runbook / deployment docs** — how to run, migrate, and deploy both halves; the repo currently has no root README
- [ ] **End-to-end test** — register → login → add item → sync → reload → decrypt, across client + server

---

## Cross-cutting notes

- **Master password / key model** — PBKDF2-HMAC-SHA256 (60k iterations) → HKDF → AES-256-GCM encryption key + HMAC-SHA256 auth key. Reasonable, but consider a memory-hard KDF (Argon2id) for the primary derivation; OWASP guidance currently recommends Argon2id over PBKDF2 when available on the client.
- **Whole-vault-blob trade-off** — the vault is one encrypted JSON document. This makes sync simple but forces full rewrites on every change and makes per-item features (history, per-item conflict, partial sync) harder. A per-item encrypted record model is the standard evolution path for multi-device local-first.
- **Local-first gap** — today the *durable* local artifact is only the `intent` log; the vault itself is fetched from the server. True "everything on the user's machine" requires a local encrypted vault snapshot, offline read, and sync-on-reconnect (client §1.3).
