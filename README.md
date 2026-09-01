# Voult — Zero-Knowledge Password Manager

> **Vault is the only identity.** No email, no user table — a client-generated UUID is the session principal. The server only ever sees ciphertext, KDF params, and a verifier HMAC. Master password, vault key, and plaintext never leave the device.

Voult is a local-first password manager with an **Expo web client** and an **Actix-Web + SQLite API server**. Both sides are zero-knowledge. The client keeps a per-vault SQLite WASM (OPFS) intent log and IndexedDB device envelope; the server stores encrypted vault blobs with optimistic-concurrency versioning.

---

## Features

- **Vault-centric auth** — signup/login with vault ID + verifier, no account collection
- **Zero-knowledge crypto (v2)** — PBKDF2-HMAC-SHA256 → HKDF (auth / vault-wrap) → random 256-bit vault key (AES-GCM), fresh IV per wrap/encrypt, non-exportable CryptoKeys
- **Authenticated states** — `not_authenticated` vs `authenticated` (`locked` / `unlocked`). Lock wipes keys and decrypted vault but keeps session and device envelope; unlock re-derives locally without a network round-trip
- **Per-vault isolation** — one OPFS database file and one IndexedDB record per vault; multiple vaults can coexist in one browser profile without leaking
- **Offline-first sync** — encrypted intent log (create/update/delete) with deterministic merge (idempotent create, last-write-wins update, sticky delete, quarantine) and server compare-and-swap versioning
- **Google Drive appDataFolder** — optional encrypted backup via OAuth under `/api/google/*`
- **Clean UI** — NativeWind/Tailwind, lucide icons, three-pane vault view

---

## Architecture

```
apps/client  (Expo Router, Zustand + TanStack Query, NativeWind)
  └─> SQLite WASM + OPFS (per-vault) + IndexedDB (per-vault device key) + sessionStorage lock flag
            ↕  HTTPS /api  (HttpOnly cookie `voult_session = vault_id`, withCredentials)
apps/server  (crate `pass-manager`, Actix-Web, SeaORM SQLite, single migration)
  └─> vault, google_token, cloud_binding, oauth_state, google_pending_token
launcher     (macOS tray → spawns server binary)
```

**Trust boundary:** the server stores only ciphertext, IV, salt, iterations, crypto version, wrapped vault key, and verifier. It never sees master password, vault key, or plaintext.

High-level flow: master password → PBKDF2 → HKDF(auth) = verifier (sent) + HKDF(vault-wrap) wraps random vault key → encrypt vault JSON → register/auth → cookie session → fetch vault → decrypt locally.

---

## Tech Stack

| Layer | Stack |
|---|---|
| Client | Expo SDK 55, React 19, React Native 0.83, expo-router, Zustand 5, TanStack Query 5, Axios, NativeWind 5 (Tailwind v4), lucide-react, sqlite-wasm (OPFS) |
| Server | Rust `pass-manager` crate, Actix-Web 4, SeaORM 2 (SQLite), cookie session store, CORS |
| Storage | SQLite (server) + SQLite WASM OPFS + IndexedDB (client) |
| Build | patch-package, Tailwind PostCSS, SeaORM migration |

---

## Project Layout

```
voult/
├─ apps/client/               # Expo web app (routes: /, /auth/signup, /lock, /home, /vault/*)
├─ apps/server/               # Rust API (serves /api + static client bundle)
│  └─ migration/              # vault-centric initial migration
├─ launcher/                  # macOS tray launcher
├─ AGENTS.md                  # contributor gotchas & commands
├─ SECURITY_AND_FEATURE_ROADMAP.md  # audited backlog
├─ SESSION_ARCHITECTURE_PLAN.md     # historical session design
└─ .env.example
```

---

## Quick Start

### Prerequisites

- Node 20+ / npm 10+
- Rust stable (cargo)
- macOS for `launcher` (optional)

### 1) Client — install & prepare WASM

```sh
cd apps/client
npm install                 # runs patch-package via postinstall
npm run sync:sqlite-web     # REQUIRED before web export — copies sqlite-wasm assets to public/sqlite
```

### 2) Client — build web bundle

```sh
npm run build:web           # builds to dist/ (same-origin /api)
# or dev server
npm run web                 # http://localhost:8081
npx tsc --noEmit            # typecheck
```

### 3) Server — run API + static site

```sh
cd apps/server
cargo run                   # http://localhost:8080  (API at /api, serves client dist at /)
# Full local run needs client build first — server warns and serves API-only if dist/ missing
```

Build order for a full run is client `build:web` → server `cargo run`. Migrations run automatically on startup.

---

## Configuration

All env vars are optional with per-install defaults. Loaded from the current directory `.env`, then bundled resources, then `~/Library/Application Support/Voult/.env`.

| Var | Default | Notes |
|---|---|---|
| `VOULT_ENV` | `production` | `development` → DB in `apps/server/voult.db`; `production` → `~/Library/Application Support/Voult/voult.db` |
| `DATABASE_URL` | `sqlite://…?mode=rwc` per `VOULT_ENV` | SQLite connection string |
| `SESSION_COOKIE_KEY` | per-install `~/Library/Application Support/Voult/session.key` (0600, 64B base64) | Must be ≥64 chars if provided, else ignored with warning |
| `STATIC_DIR` | probe `Resources/dist` (Voult.app) then `../client/dist` | Override for custom bundle location |
| `CORS_ORIGINS` | `http://localhost:8081,http://127.0.0.1:8081` | Comma-separated, credentials enabled |
| `SESSION_COOKIE_SECURE` | `false` | Set `true` in prod with TLS |
| `SESSION_COOKIE_SAME_SITE` | `lax` | `strict` / `lax` / `none` |
| `SESSION_TTL_SECONDS` | `604800` (7d idle) | Persistent session TTL |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | — | Enable Drive sync; also need `GOOGLE_OAUTH_REDIRECT_URI` |

See `.env.example` for a copy-paste template.

---

## Auth & Storage

**Auth machine:** `not_authenticated` → landing page; `locked` → lock screen; `unlocked` → home. The bootstrap tries to restore a session then silently unlock with the device key; a persisted lock flag prevents auto-unlock after an explicit lock.

**Per-vault namespacing:**

| Store | Key | Lifecycle |
|---|---|---|
| SQLite OPFS | `file:voult-<vaultId>.db` (intent + client state) | Opened after session, closed on lock / session expiry |
| IndexedDB `voult` | `vault:<vaultId>` (device key + envelope) | Per-vault; expiry teardown deletes only the active vault's records |
| Zustand | vault key, auth key, session, decrypted vault, lock metadata | In-memory; lock wipes keys but keeps session and envelope |
| Query cache | TanStack Query | Cleared on session expiry |
| `sessionStorage["voult.locked"]` | profile-global flag | Survives reload so the lock screen is not auto-unlocked |

Teardown is centralized (close DB → delete device records → wipe state → clear cache) and invoked by the 401 interceptor. There is **no logout button** — the unauthenticated state is reached only via session expiry or invalidation.

---

## Sync & Conflict Resolution

Offline-first intent table → encrypt operation JSON with vault key → persist intent → optimistic UI update → schedule sync.

Sync pins the vault ID, loads the server snapshot, replays intents with a deterministic merge, re-encrypts the merged vault, and pushes with compare-and-swap. Network errors back off; version conflicts retry (bounded). A scheduler coalesces window-focus / online / intent-created / forced triggers.

Merge policy: idempotent create, last-write-wins update, sticky delete, quarantine on malformed or decrypt-fail intents.

---

## Google Drive Sync

Vault-scoped tokens and bindings under `/api/google/*`. A pending-state OAuth flow handles first-time imports without an existing session. The home screen and vault chooser surface connection status, file ID, revision, and an Enable sync action.

---

## Gotchas

- COOP/COEP headers are required for SharedArrayBuffer (sqlite-wasm OPFS) — set on both server responses and the client's `_headers`. Don't remove.
- Server never handles plaintext — all crypto lives client-side; the session cookie stores only the vault ID.
- Crypto hierarchy: PBKDF2 → HKDF auth / vault-wrap → random vault key (AES-GCM) + device-key wrap.
- There is no server device table or logout endpoint — device envelope is client-only; session invalidation is cookie teardown.

---

## Documentation

- `apps/client/architecture.md` — vault schemas, login and add-item flows, storage table
- `apps/client/conflict-resolution.md` — merge policy
- `apps/server/architecture.md` — server API contracts
- `SECURITY_AND_FEATURE_ROADMAP.md` — audited backlog and release security checklist
- `SESSION_ARCHITECTURE_PLAN.md` — historical session and device-unlock plan
- `AGENTS.md` — build commands, env/config, and contributor gotchas

---

## Security Notes

Zero-knowledge protects honest-but-curious storage, but a compromised server that replaces the web bundle or an XSS / supply-chain compromise in the same origin can still access plaintext while unlocked. See the roadmap for open gaps (KDF strength, static verifier, rate limits, CSP, etc.). This repo is not a certified security audit.

---

## License

Private / unlicensed — all rights reserved unless a `LICENSE` file is added.
