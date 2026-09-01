# Voult: Feature Roadmap and Security Checklist

**Audit date:** 2026-09-01  
**Scope:** `apps/client`, `apps/server`, `apps/server/migration`, `launcher`  
**Purpose:** single honest backlog + release-oriented security checklist. Merges and supersedes `TODO.md` (deleted) and the prior `SECURITY_AND_FEATURE_ROADMAP.md` (2026-08-17). “Implemented” = present in current source and wired at runtime.

> This is an engineering review, not a security certification or penetration test.

## Status legend

- `✅ Implemented` — present in source and usable at current scope (code ref given).
- `🟡 Partial` — initial version exists but incomplete / not production-hardened.
- `⬜ Planned` — not implemented.
- `⚠️ Security gap` — must be addressed before treating the feature as safe for production.

Priority is security-first: **P0** blocker / direct risk to vault confidentiality, account security, or data integrity · **P1** required for a credible password manager · **P2** maturity / scale / UX.

---

## Current trust boundary

Intended boundary is unchanged — vault-centric, zero-knowledge (server only sees ciphertext + KDF params + HMAC verifier):

| Data | Current intended location | Review result |
|---|---|---|
| Master password | Client memory only during derive | ✅ Never sent; `apps/client/src/lib/crypto/index.web.ts:58` derives locally |
| Password-derived keys (auth, wrapping) | Client memory (`CryptoKey`) | ✅ PBKDF2→HKDF `auth`/`vault-wrap-v2` |
| Auth verifier (`vault_verifier`) | Client-derived, server-stored `vault.vault_verifier` | 🟡 Reusable static verifier; rate-limit + PAKE/passkey planned (`auth.rs:98`) |
| Random 256-bit vault key | Client-generated, non-exportable `CryptoKey` | ✅ `generateVaultKeyRaw`/`importVaultKey`, v2 envelope (`crypto/vault.ts`) |
| Plaintext vault | Client memory / Zustand `decryptedVault` | ✅ Server handlers never decrypt (`get_vault.rs:41`, `update_vault.rs:50`) |
| Encrypted vault + metadata (`vault`, `vaultiv`, `salt`, `iterations`, `crypto_version`, `vault_key_wrap*`) | Server SQLite `vault` | ✅ Ciphertext-only persistence (`migration/m20260901_...:7`, `entity/vault.rs:5`) |
| Session cookie (`voult_session` = `vault_id`) | HttpOnly cookie, `CookieSessionStore` | ✅ `main.rs:264`, `session_auth.rs:6` — stores only vault id |
| Device key + device envelope | Browser IndexedDB `voult` keyed `vault:<vaultId>` | 🟡 Implemented & namespaced per-vault (`device-key.ts:11`), but never leaves client; no server device table (intentional) |
| Pending writes | Per-vault SQLite OPFS `file:voult-<vaultId>.db` (`intent`) | ✅ Encrypted before insertion (`home/index.tsx:133`, `sync/index.ts:104`) |

**Hard limit:** E2E encryption protects against honest-but-curious storage. A compromised server that replaces the web bundle, or XSS/supply-chain compromise in same origin, can still access plaintext while unlocked. Web-delivery security is part of the threat model — see §2.4.

---

## Architecture snapshot (as of 2026-09-01)

### High-level

- **Client** `apps/client` — Expo SDK 55, `expo-router`, Zustand (`state/index.ts:1`) + TanStack Query (`queries/http.ts:13`), NativeWind/Tailwind v4. Web export served by server at `/` from `STATIC_DIR` (`main.rs:69`).
- **Server** `apps/server` — crate `pass-manager`, Actix-Web 4 + SeaORM SQLite. Single migration `m20260901_000001_vault_centric_init` creates `vault`, `session` (unused — cookie store used), `google_token`, `cloud_binding`, `oauth_state`, `google_pending_token`. Runs on startup (`main.rs:222`).
- **Launcher** `launcher` — macOS tray that spawns server binary from `../apps/server`.

### Identity is vault-centric

No `user`/`account` table. `vault.id` is a client-generated UUID (`crypto/index.web.ts:38` `uuid()`), embedded in encrypted vault doc, used as session principal (`session_auth.rs:6` `SESSION_VAULT_ID_KEY="vault_id"`). No email anywhere. Google OAuth bindings are keyed by `vault_id`.

### Crypto hierarchy (v2) — `crypto/index.web.ts:1`, `flows.ts:42`

```
master password --PBKDF2-HMAC-SHA256(60k, per-vault salt)--> root 256b
  ├─HKDF("auth")          --> HMAC auth key --> HMAC("auth-v1|...") = vault_verifier (auth only)
  └─HKDF("vault-wrap-v2") --> AES-GCM wrapping key --wrap--> vault_key_wrap (+ iv) stored on server

random vault key (32B, AES-GCM non-exportable) --encrypt--> vault ciphertext (fresh 12B IV each time)
device key (AES-GCM 256b, non-exportable, IndexedDB) --wrap--> device envelope (local only, vault:<id>)
```

`CryptoKey` import uses `extractable:false` (`index.web.ts:201`). Wrapping uses AES-256-GCM with fresh IV.

### Session & auth — `main.rs:183`, `auth.rs:47`, `register.rs:57`

- `SESSION_COOKIE_KEY` ≥64 chars (`main.rs:195` panics otherwise); per-install generated at `~/Library/Application Support/Voult/session.key` (0600) if env missing (`main.rs:100`).
- `SessionMiddleware` with `CookieSessionStore`, `voult_session`, HttpOnly, configurable `SESSION_COOKIE_SECURE/SAME_SITE/TTL_SECONDS` (default 7d idle) (`main.rs:202`).
- `POST /register` transactional vault insert + `establish_vault_session` (`register.rs:88`). Returns `vault`, `vaultiv`, `vault_key_wrap*`. Duplicate `vault_id` → `409 VAULT_EXISTS`.
- `POST /auth` `vault_id`+`vault_verifier` → `establish_vault_session` with purge-before-insert fixation defense (`auth.rs:108`, `session_auth.rs:16`). Unknown vault and bad verifier both → `401 AUTH_FAILED` (no enumeration via timing yet — gap).
- `GET /get_crypto_params?vault_id=` pre-auth (`get_crypto_params.rs:33`), validates UUID shape, `404 VAULT_NOT_FOUND` on miss.
- `GET /get_vault`, `POST /update_vault`, `POST /vault/password` require `session_vault_id` (`get_vault.rs:42`, `update_vault.rs:55`, `update_vault_password.rs:22`) → `401 SESSION_REQUIRED`.
- `GET /session`, `POST /logout` (`session_status.rs`, `logout.rs:12` `purge()`).
- Multi-vault CRUD `POST/GET /vaults` (`vaults.rs`) session-scoped.
- Google Drive OAuth set under `/api/google/*` (`google_endpoints.rs`) — cloud sync bindings.

### Client storage — per-vault namespaced (post-audit hardening)

| Store | Namespace | File |
|---|---|---|
| SQLite OPFS | `file:voult-<vaultId>.db` — one file per vault | `sqlite/web/init-db.ts:15` |
| `intent` (dur ack log: `id, operation, payload, payload_iv, device_id, base_version, created_at, synced, error`) | Per-vault DB | `sqlite/web/migrations.ts` |
| `client_state` (`key/value` — `vault_version`, `vaultId`) | Per-vault DB | `sqlite/web/services/client-state-service.ts` |
| IndexedDB `voult` (`device_key`, `device_envelope` keyed `vault:<vaultId>`) | Per vault | `crypto/device-key.ts:11` |
| Zustand (`vaultKey`, `authKey`, `session`, `decryptedVault`, `vaultVersion`, `isLocked`, `lockMetadata`) | In-memory only | `state/index.ts:5` |
| `sessionStorage["voult.locked"]` | Profile-global (intentional) | `state/index.ts:91` — new `persistLockedFlag` |

Teardown centralized in `auth/teardown.ts:18` `teardownVaultSession()` (close per-vault SQLite → delete only this vault's device records → wipe Zustand → clear query cache). Used by logout, 401 interceptor (`queries/http.ts:39`), and lock screen.

### App flows — `architecture.md`

- **Signup** `auth/flows/signup.ts` + `vault/create.ts` → random vault key, derive auth+wrap keys, encrypt starter vault, wrap vault key, `POST /register`, establish session, persist device envelope locally.
- **Password login** `auth/flows/login.ts` → `GET /get_crypto_params` → derive auth key → `POST /auth` → derive wrapping key → unwrap vault key → ensure device key+envelope → `GET /get_vault` → decrypt.
- **Reload** `_layout.tsx:23` bootstrap: skip `google_pending_state`, check `isLockedFlagSet`, `fetchSession`, then either restore `session`+lock screen or `unlockWithDevice()` (session→device key→envelope→unwrap→fetch/decrypt). SQLite opened per-vault (`initSQLite(vaultId)` with UUID validation `init-db.ts:12`).
- **Lock** `home/index.tsx:91` `handleLock` captures `LockMetadata` (`salt, iterations, vault_key_wrap*`) so `/lock` can `unlockWithPassword` locally (`flows.ts:117` — AES-GCM unwrap failure = wrong password, no network). `lockVaultStorage` (`state/index.ts:124`, `teardown.ts:40`) wipes keys/decrypted vault, keeps session+device envelope, closes SQLite.
- **Logout** `home/index.tsx:117` → `POST /logout` → `teardownVaultSession`.

### Sync & conflict — `sync/index.ts:58`, `sync/merge.ts:73`, `sync/sync-scheduler.ts`

- Local-first: `home/index.tsx:130` `handleCreate/Update/Delete` → `encrypt(JSON.stringify(op), vaultKey)` → `createIntent(operation, {payload,payloadIv,deviceId})` → optimistic Zustand `add/update/deleteVaultItem` → `syncScheduler.requestSync("intent-created")`.
- Device id per-vault via `getOrCreateDeviceKey` (`device-key.ts:100`), cached per vault (`home/index.tsx:25`).
- `sync()` (`sync/index.ts:58`): pins `syncVaultId`, `loadVaultFromServer` (decrypt with `vaultKey`), `getlocalVaultVersion` vs `serverVersion`, replays intents via `mergeVault` (deterministic `created_at, id` order, `merge.ts:83`), handles `quarantinedIds→markIntentError`, `resolvedIds→markIntentsSynced`, re-encrypts merged `{items}`, `updateVault({vault,vaultiv,version:serverVersion})` with CAS. `isNetworkError` → offline backoff, `409 VERSION_CONFLICT` → retry loop (bounded 3, `MAX_SYNC_RETRIES`). Aborts if `sessionChanged()` mid-run.
- **Conflict policy** (`conflict-resolution.md:5`, `merge.ts:24`): `create` idempotent no-op if id exists, duplicate natural key `(site,username)` keeps both + warn; `update` LWW per-field `{...serverItem, ...fields}` if exists else dropped (deletes stick); `delete` no-op if absent. Malformed/decrypt-fail → quarantined. Never aborts whole sync for one bad intent.
- Server CAS `update_vault.rs:98` `UPDATE ... WHERE id=? AND version=?` + `rows_affected` check → `409 VERSION_CONFLICT`, atomic `version+1`. `get_vault.rs`/`update_vault.rs` preserve `vault_key_wrap*` if not supplied.
- Scheduler + triggers: `sync-scheduler.ts` debounces (exposed `requestSync`, tracks `isSyncing` via `setSyncStatus`), `use-sync-triggers.ts:4` subscribes to `focus`/`online` → `requestSync("window-focus"/"network-reconnect")`. **Currently disabled in `_layout.tsx:21` (`// useSyncTriggers()`).**

### UI — `home/index.tsx:52`, `vault/`, `auth/`

- Home: three-pane (vault list, search+filter item list, detail), add/edit/delete modals driving intents, Google Drive status/binding panel (`google/api.ts`), lock/sync/logout actions. Search across `site,username` (`home/index.tsx:277`), time grouping (demo). Debug route `debug/index.tsx` inspects `client_state`/`intent`.

---

## 1. Feature backlog — consolidated (TODO.md merged)

Original TODO checklists are mapped to current status. `[x]` in old TODO = ✅ here. Evidence `file:line` added for ✅.

### 1.1 Client

#### ✅ Implemented

- ✅ Expo Router shell + dark vault UI — landing, sign-up, login, lock, home, debug, vault chooser (`app/index.tsx`, `app/home/index.tsx:52`, `app/lock.tsx`, `app/debug/index.tsx`, `app/vault/index.tsx`).
- ✅ Vault-centric signup & login — `signupFlow`/`login flows` derive locally, `POST /register|/auth` with `vault_id+vault_verifier` (`lib/auth/flows/signup.ts`, `lib/auth/flows/login.ts`, `lib/queries/SignUp/query.ts`, `lib/queries/logIn/query.ts`).
- ✅ Version-2 vault key hierarchy — random vault key, AES-GCM, PBKDF2→HKDF labels `auth`/`vault-wrap-v2` (`crypto/index.web.ts:10`, `crypto/vault.ts`).
- ✅ Authenticated encrypted vault blob — fresh 12B IV per encrypt/wrap (`crypto/index.web.ts:168`, `crypto/index.web.ts:209`).
- ✅ Cookie-based API client — `http` `withCredentials:true`, 401 `SESSION_REQUIRED` teardown (`queries/http.ts:13`).
- ✅ Session auto-restore + device unlock — bootstrap tries `fetchSession` then `unlockWithDevice` (`app/_layout.tsx:38`, `auth/flows.ts:73`). Lock flag (`state/index.ts:91`) routes to `/lock` when set.
- ✅ Local SQLite bootstrap (WASM+OPFS) — `init-db.ts:15`, `migrations.ts`, `sqlite-worker.ts`, COOP/COEP headers (`main.rs:280` + `public/_headers`).
- ✅ Per-vault SQLite isolation — `file:voult-<vaultId>.db` (`init-db.ts:31`), UUID guard, `closeSQLite` (`init-db.ts:43`).
- ✅ Per-vault IndexedDB device key/envelope — `vault:<vaultId>` (`crypto/device-key.ts:11`), `getOrCreateDeviceKey`, `saveDeviceEnvelope`.
- ✅ Lock with metadata + password unlock — `handleLock` captures `LockMetadata` (`home/index.tsx:92`), `unlockWithPassword` unwraps locally (`flows.ts:117`).
- ✅ Centralized teardown — `auth/teardown.ts:18` closing DB per-vault, deleting only this vault's device records.
- ✅ Local-first mutation log — `operation` `create|update|delete`, encrypted `payload/payload_iv`, `device_id`, `base_version`, `synced`, `error` (`sqlite/web/services/intent-service.ts`, `sqlite/web/migrations.ts`).
- ✅ Optimistic UI — Zustand helpers `add/update/deleteVaultItem` (`state/index.ts:45`).
- ✅ Deterministic conflict merge — `merge.ts:73` + `sync/index.ts:58` (CAS retry, quarantine, idempotent).
- ✅ Basic vault operations — add/edit/delete via intents, search, selection, password masking (`home/index.tsx:130`, `home/index.tsx:277`).
- ✅ Local logout cleanup — `POST /logout` + `teardownVaultSession` + routing (`home/index.tsx:117`).
- ✅ Auth state machine — `not_authenticated|locked|unlocked` (`state/index.ts:36`), `useAuthGuard`.

#### Left to implement / harden

**P0 — security & data-safety blockers**

- ⚠️ **Harden PBKDF2 KDF** — still 60k iterations (`crypto/index.web.ts:1`). No benchmark/versioning. *Planned:* Argon2id or materially stronger PBKDF2 profile with versioned migration + rewrap on login. (Carried from prior P0 and TODO 1.2.)
- ⚠️ **Fix non-web salt generation** — `generateSalt()` returns empty bytes when `Platform.OS !== "web"` (`crypto/index.web.ts:23`). Native is blocked until CSPRNG path added. P0 before claiming native.
- ⚠️ **Replace/harden static `vault_verifier` auth** — verifier is reusable bearer credential (`auth.rs:98` plain equality). *Planned:* PAKE/aPAKE or WebAuthn/passkey-backed auth, or at minimum verifier stored as salted hash server-side. Rate-limit is still missing (see server P0).
- ⚠️ **Remove plaintext secret logging / demo secrets** — `home/index.tsx:270` still `console.log("decryptedVault"`, `sync/merge.ts:33` logs `site,username`, intent/sync log payloads/ids. Production must never log passwords/vault objects/auth material/request bodies.
- 🟡 **Real lock semantics (partial)** — lock correctly wipes keys/decrypted vault and persists lock flag (`state/index.ts:124`, `_layout.tsx:35`). *Remaining:* inactivity/visibility auto-lock timer, clearing form/search/clipboard buffers, configurable timeout. (TODO 1.2 auto-lock partially done.)
- 🟡 **Account-scoped local storage (partial)** — SQLite + IndexedDB now per-vault namespaced + per-run pinning (`sync/index.ts:66`). *Remaining:* audit `QueryClient` cache scoping and any `localStorage` fallbacks; test cross-vault intents can't be replayed.
- ⬜ **Security tests before crypto/sync changes** — no client tests exist. Needed: known-answer vectors, wrong-password/tamper/IV/base64/migration/lost-response-retry/conflict/account-switch/lock-clearing tests (prior P0).
- ⬜ **Web hardening against XSS/supply-chain** — needs strict prod CSP (`frame-ancestors 'none'`, no `unsafe-eval`, minimal `unsafe-inline`), `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, dependency pinning/scan/SBOM, debug route gating. COOP/COEP done; CSP/headers not yet production-enforced.

**P1 — standard password-manager capabilities**

- 🟡 **Password change / key rotation (partial)** — `POST /vault/password` (`update_vault_password.rs:16`) rotates `vault_verifier` + optionally `salt/iterations`, but does **not** re-derive wrapping key or re-encrypt `vault_key_wrap*`/vault blob. Stub replaced with partial. *Needed:* client-driven rewrapping protocol + atomic metadata update.
- ⬜ **Recovery / emergency access** — no recovery codes/phrase, no tested restore path. Do not add server-side password reset bypassing encryption. (TODO 1.2)
- ⬜ **Device management** — browser device key exists, but server `device` entity/migration/routes (`POST/GET/DELETE /session/device-key`) from `SESSION_ARCHITECTURE_PLAN.md` not implemented; server `session` table unused (cookie store). No device listing/revoke/all-devices logout.
- ⬜ **Native secure storage & biometrics** — IndexedDB only. Needs Keychain/Keystore + FaceID/TouchID/Window Hello + screenshot/app-switcher protections. (TODO 1.2)
- 🟡 **Automatic/background sync (partial)** — scheduler + `intent-created` trigger + `_layout` bootstrap done; `useSyncTriggers` exists but **commented out** (`_layout.tsx:21`). *Remaining:* enable focus/reconnect/startup/retry/backoff + sync-status/error UI (TODO 1.3).
- 🟡 **Conflict UX (partial)** — merge engine + quarantine done (`merge.ts:15`, `sync/index.ts:104`), but no user-visible pending/error/quarantined/duplicate-resolution UI. (TODO 1.3/1.1 Partial)
- ⬜ **Password generator** — CSPRNG local generation, policy controls, entropy feedback. Never send to server. (TODO 1.4)
- ⬜ **Password health** — local strength + optional HIBP k-anonymity, no plaintext upload. (TODO 1.4)
- ⬜ **Autofill / browser extension** — origin-bound matching, user confirmation, frame isolation, phishing-resistant URL handling. Largest reach lever. (TODO 1.4)
- ⬜ **TOTP / passkeys** — encrypted seeds, local code gen, clock-skew handling, clipboard/accessibility care. (TODO 1.4)
- ⬜ **Richer item types** — secure notes, identities, payment cards, custom fields, attachments, tags/folders, multiple URLs, per-item history — versioned encrypted schema. Current item is `{id, site, username, password}` only (`state/type.ts`).
- ⬜ **Import / export & backup** — CSV/JSON, encrypted exports, plaintext-export warnings, re-auth before export, temp-file cleanup, restore verification, offline recovery path. (TODO 1.4)
- ⬜ **Vault schema migrations** — `formatVersion:1` present (`flows.ts:39`), but no migration tests from legacy v1 or per-field history migration.
- ⬜ **Cross-platform parity** — native SQLite path, SecureStore, deep links, lifecycle, clipboard controls. (TODO 1.5)
- ⬜ **Accessibility & localization** — keyboard nav, screen-reader, focus/modal, contrast, reduced-motion, localized warnings.

**P2 — product maturity**

- ⬜ Shared/family vaults (encrypted sharing + revocation)
- ⬜ Secure sharing links (expiry, recipient auth, one-time, no plaintext server storage)
- ⬜ Item history, soft-delete/recycle bin, audit activity, restore testing
- ⬜ Privacy-preserving telemetry opt-in (no vault contents/passwords/URLs/usernames/crypto material/error payloads)

### 1.2 Server

#### ✅ Implemented

- ✅ Actix-Web + SeaORM/SQLite, additive migrations, `Migrator::up` on startup (`main.rs:222`).
- ✅ Transactional registration (`register.rs:88`) before session establishment.
- ✅ Cookie session middleware — `CookieSessionStore`, `voult_session`, HttpOnly, configurable SameSite/Secure/TTL, per-install key (`main.rs:264`).
- ✅ Session-protected vault read/write — `GET /get_vault` / `POST /update_vault` derive user from `session_vault_id` (`get_vault.rs:42`, `update_vault.rs:55`).
- ✅ Session lifecycle — `GET /session`, `POST /logout` with rotation/purge on auth (`auth.rs:108`, `session_auth.rs:16`).
- ✅ Configured CORS origins (credentials, no `allow_any_origin`) (`main.rs:230`).
- ✅ Optimistic-concurrency vault updates — conditional `WHERE version=?` + `version+1` + `409 VERSION_CONFLICT` (`update_vault.rs:98`).
- ✅ Ciphertext-only persistence — `vault, vaultiv, salt, iterations, crypto_version, vault_key_wrap*` (`entity/vault.rs:5`); handlers never decrypt.
- ✅ Shared error shape (`code: SESSION_REQUIRED|AUTH_FAILED|VERSION_CONFLICT|VAULT_NOT_FOUND|...`).
- ✅ Multi-vault listing/creation (`vaults.rs`), Google Drive binding/token flows (`google_endpoints.rs`), `voult_data_dir` + per-install DB path (`main.rs:38`), bundled env loading (`main.rs:148`), static site serving (`main.rs:318`) with COOP/COEP.

#### Left to implement / harden

**P0 — production security blockers**

- ⚠️ **Enforce HTTPS in production** — `SESSION_COOKIE_SECURE` defaults false (`main.rs:203`). Production must fail closed without TLS termination + Secure cookies + correct external origin.
- ⚠️ **Rotate/remove committed dev secrets** — `session.key` now per-install, but committed fallback key material (old `.env`) must be rotated; add startup validation + rotation + secret scan; never reuse dev key.
- ⬜ **Rate limits & abuse controls** — throttle `POST /auth`, `POST /register`, `GET /get_crypto_params`, `POST /update_vault`, Google OAuth; IP/vault/device-aware, backoff, credential-stuffing detection, bounded bodies. *Not implemented* (TODO 2.2).
- ⬜ **Account enumeration resistance** — `GET /get_crypto_params` returns `404 VAULT_NOT_FOUND` vs `401` on auth failure — distinguishable. Needs non-enumerating, timing-uniform response. (TODO 2.3 planned.)
- ⬜ **Normalize/constrain identifiers** — vault id is UUID-validated (`get_crypto_params.rs:46`), but need explicit length/syntax enforcement + denial of non-canonical forms before creation.
- ⬜ **Validate encrypted-vault protocol at boundary** — enforce allowed `crypto_version`, exact base64/IV/cipher lengths, non-empty salts, bounded iterations, paired `vault_key_wrap*`, payload size limits, versioned envelope. Reject downgrade/malformed before writes.
- ⬜ **CSRF/origin defenses** — SameSite is defense-in-depth only. Validate `Origin/Referer`/Fetch Metadata on state-changing cookie-authenticated requests; add double-submit/CSRF token if cross-site.
- 🟡 **Harden sessions (partial)** — `__Host-` prefix not yet used, idle vs absolute expiry not distinct, no reauth for high-risk actions, no logout-all revocation (cookie store leaves `session` table unused, `session_auth.rs:19` purges only current cookie).
- ⬜ **DB & backup protection** — least-privilege file perms, 0600 on `session.key` done, need encrypted disks/backups, tested restore, key separation, retention/deletion, no plaintext in dumps/fixtures/logs.
- ⬜ **Server integration/security tests** — auth/session-fixation/cookie-flags/CORS/CSRF/enumeration/rate-limit/input-limit/authz/CAS/migration/downgrade/DB-failure tests missing. (TODO 2.5)

**P1 — reliability & completeness**

- ⬜ **Device-key server lifecycle** — `SESSION_ARCHITECTURE_PLAN.md` device table/routes not implemented; deferred to client-only envelope (note above). If ever needed, add `device` migration/entity + `POST/GET/DELETE /session/device-key` + envelope validation.
- 🟡 **Password change / key rotation endpoint (partial)** — `POST /vault/password` rotates verifier (`update_vault_password.rs:16`), but not vault-key rewrap. Replace with client-driven encrypted rewrap protocol + atomic update; server must never see password/vault key.
- ⬜ **Server rollback / deletion policy** — CAS prevents concurrent overwrite, but trusted server can replay old snapshot. Add retention/history or client-verifiable monotonic/integrity strategy + document adversarial server powers.
- ⬜ **Operationally safe migrations** — run migrations in CI against real schema copies, test rollback, enable `PRAGMA foreign_keys=ON`, verify indexes/constraints each release.
- ⬜ **API versioning & compat** — crypto-version/vault-schema changes need explicit windows, downgrade rejection, migration telemetry (no secrets).
- ⬜ **Cache controls** — vault/session responses should be `Cache-Control: no-store` (incl. reverse proxies/error pages).
- ⬜ **Availability controls** — timeouts, bounded concurrency, body limits, SQLite busy timeouts, health/readiness endpoints, backup monitoring, client retry semantics.
- ⬜ **Privacy-safe audit logging** — auth failures, rate-limit decisions, session revocation, device changes, CAS conflicts — without logging `vault_verifier`, ciphertext, wrapped keys, bodies, or sensitive queries.

**P2 — operational maturity**

- ⬜ Security headers at edge/API: HSTS, `nosniff`, frame restrictions, restrictive `referrer-policy`, API-appropriate CSP.
- ⬜ Dependency governance: lockfiles, `cargo audit`, npm/OSV scan, SBOM, WASM/native review, signed/reproducible releases.
- ⬜ Incident response: revocation, rotation, breach criteria, restore drills, abuse response, disclosure process.
- ⬜ Deployment isolation: private DB networking, restricted admin, separate dev/staging/prod creds, no prod data in local dev.

---

## 2. Deep app security checklist

Every checked item must have a code location, a test, and an owner. “Pass” = verified in target build/deployment.

### 2.1 Threat model & invariants

- [ ] Document assets: master password, `vault_verifier`, vault key, wrapped keys, plaintext vault, pending intents, session cookie, device key/envelope, vault metadata, backups, logs, crash reports, build artifacts.
- [ ] Document actors: malicious web origin, XSS attacker, compromised dep/build pipeline, malicious/compromised storage server, DB thief, network attacker, stolen device, malicious local OS user, credential-stuffing attacker, malicious support/admin.
- [ ] State guarantee precisely: storage server not trusted with plaintext, but can observe metadata, deny service, replay/rollback ciphertext unless prevented, and potentially replace bundle if delivery origin compromised.
- [ ] Define lock model: what stays in RAM / IndexedDB / OPFS / Keychain, reload auto-unlock vs `voult.locked` trusted-device semantics, inactivity, stolen-profile.
- [ ] Define recovery honestly: lost master password + lost recovery material = unrecoverable. No support path implying otherwise.
- [ ] Maintain data-flow diagram for signup, password login, reload unlock, lock, logout, intent create, sync, conflict, password change, export, recovery.

### 2.2 Client crypto & key management

- [ ] Use reviewed CSPRNG for salts/vault keys/IVs/device keys/UUIDs/generator — no empty native salts (`index.web.ts:23` currently fails).
- [ ] Unique random salt per vault; persist exact KDF params; validate length; reject malformed/legacy.
- [ ] Benchmark KDF on slowest device; prefer Argon2id; if PBKDF2 must remain, version stronger profile + migration.
- [ ] Distinct versioned HKDF labels (`auth`, `vault-wrap-v2`) with test vectors (`index.web.ts:10` — add vectors).
- [ ] Keep vault key separate from auth keys; never use verifier as encryption key; never send vault key to server.
- [ ] AES-GCM with fresh 96-bit nonce per key; enforce lengths; never reuse nonce (`encrypt`/`wrapKeyBytes`).
- [ ] Bind ciphertext to context (AAD: vault id/version/crypto_version/envelope type) — currently not used; future hardening.
- [ ] Treat all decryption failures as tamper/auth failure; never fall back parser.
- [ ] Best-effort zeroize temp raw key bytes; document JS GC limits.
- [ ] Tests: wrong password, modified ciphertext/IV/salt/iterations, swapped envelopes, truncated base64, oversized inputs, downgrade.
- [ ] Password change = client-side rewrapping/rotation with atomic recovery on network failure (current server endpoint incomplete).
- [ ] Document that non-exportable `CryptoKey` does not defend same-origin XSS/devtools/compromised runtime.
- [ ] Replace/static-verifier protocol decision — if retained, constant-time compare, rotation, rate-limit every guess.

### 2.3 Plaintext & secret lifecycle

- [ ] Never log passwords/plaintext/decrypted intents/auth keys/raw bytes/wrapped contents/bodies (`home/index.tsx:270`, `merge.ts:33` violate).
- [ ] Remove starter/demo secrets and test vault data from prod paths/bundles.
- [ ] Clear password input state immediately after signup/login success/failure; don't retain in nav params/URL/query caches/analytics.
- [ ] On lock clear: `vaultKey`, `authKey`, `decryptedVault`, `selectedItem`, edit/add/search buffers, clipboard, query cache, any worker copies (`state/index.ts:124` + `teardown.ts:40` covers many; form buffers pending).
- [ ] Inactivity/background/screen-hide/visibility lock policies with user-visible timeout + safe defaults (not yet: timer missing).
- [ ] Decide reload auto-unlock compatibility with lock promise; document `voult.locked` as explicit trusted-device flag (partially done — flag exists, policy not documented).
- [ ] Mask passwords by default; deliberate reveal; native screenshot/app-switcher protections; no secrets in a11y labels/titles.
- [ ] Clear clipboard after timeout where APIs allow; warn when OS cannot guarantee.
- [ ] No vault values in analytics/URLs/DOM/history/error messages (PostHog currently commented out only).

### 2.4 Web client, XSS & supply chain

- [ ] HTTPS + HSTS after validating subdomains/preload.
- [ ] Strict CSP for Expo web; no `unsafe-eval`, minimal `unsafe-inline`, `frame-ancestors 'none'`.
- [ ] `X-Content-Type-Options: nosniff`, restrictive `Referrer-Policy`, `Permissions-Policy`, clickjacking protection (incl. HTML/static/error). COOP/COEP done (`main.rs:280`).
- [ ] Render untrusted `site, username, notes, tags` via safe RN text paths; never raw HTML/unsanitized URL schemes.
- [ ] Review/pin/scan all deps (analytics, fonts, WASM, patches, build plugins); provenance for releases. `patch-package` postinstall present (`AGENTS.md`) — needs review gate.
- [ ] Source maps/debug bundles not publicly deployed if they expose internals/env.
- [ ] Test built artifact (not just dev server) for CSP violations/unexpected calls/source-map/secret exposure.
- [ ] API origin + public env + error pages not controllable by attacker URL params/untrusted storage.
- [ ] Debug route guarded behind dev-only compile flag (currently present `app/debug`).

### 2.5 Browser & local storage

- [ ] No auth token/session id/password/vault key/plaintext in `localStorage`/`sessionStorage`/URL/unencrypted IndexedDB/OPFS (cookies ok; `voult.locked` is non-sensitive flag).
- [ ] Encrypted intents as sensitive ciphertext: namespaced per vault (`file:voult-<id>.db`), bound lifecycle, safe delete/quarantine on logout/switch (`intent-service.ts`, `init-db.ts:15`, `sync/index.ts:66` — partially done).
- [ ] Document storage limits: same-origin script can use vault while unlocked + invoke WebCrypto.
- [ ] Native device keys only in Keychain/Keystore, not AsyncStorage (future — native not claimed).
- [ ] Bind device identity to vault; avoid global `current` record across vaults (done via `vault:<id>`).
- [ ] Device revoke flow — revoked devices cannot obtain envelope or sync post-expiry (future if server device table added).
- [ ] Test multiple tabs/concurrent upgrades/profile copy/OPFS reset/quota/private browsing/abrupt termination.
- [ ] Clear sensitive browser caches, `no-store` for vault/session responses, audit service-worker before enabling.

### 2.6 Network, cookies & sessions

- [ ] Enforce HTTPS; reject prod HTTP API URLs at startup/build.
- [ ] Secure+HttpOnly+Strict/Lax (`__Host-` when topology allows) (`main.rs:264` `cookie_secure`, `cookie_same_site`, `cookie_http_only:true` — `__Host-` not yet).
- [ ] `SameSite=None` never without Secure + documented cross-site need (`main.rs:209` allows but caller must set Secure).
- [ ] Validate `Origin/Referer` or Fetch Metadata on state-changing cookie requests; CORS is not CSRF protection.
- [ ] CORS allowlists exact, env-specific, no wildcards with credentials (`main.rs:230` — exact list, good).
- [ ] Rotate session at auth/privilege changes; test fixation/concurrent/logout/expiry/stolen-cookie (`session_auth.rs:16` `purge` on auth — good).
- [ ] Absolute + idle limits; reauth for password change/recovery/device enrollment/export (idle TTL done; absolute + reauth missing).
- [ ] Generic authenticated errors (no vault/credential existence reveal) — `auth.rs:80` generic `AUTH_FAILED` good; `get_crypto_params.rs:62` `VAULT_NOT_FOUND` still distinguishable from `AUTH_FAILED` — gap.
- [ ] Proxies not logging emails/bodies/cookies/auth/ciphertext (operational).

### 2.7 Local-first writes & sync integrity — **much improved since 2026-08-17**

- [x] Encrypt every intent before insertion, auth its op/vault/device/schema context (`home/index.tsx:133`, `sync/merge.ts:90` decrypt with `vaultKey`).
- [x] Stable UUID ids + idempotent ops; never identify by `(site,username)` alone (`merge.ts:24` `applyCreate` checks `id` first; keeps both on natural-key dup).
- [x] Strict schema + quarantine — `Create/Update/DeleteVaultItemSchema.safeParse`, `quarantinedIds→markIntentError` (`merge.ts:108`), doesn't block others.
- [ ] Fix SQLite type mismatch: schema `created_at INTEGER` vs inserted ISO string vs parser — verify durable queue doesn't silently lose intents (prior gap noted; needs test — check `migrations.ts` stores epoch vs string).
- [x] Single owner for version writes — sync is sole writer of `vault_version` (`sync/index.ts:52` `upsertVaultVersion`, `adoptServerSnapshot`); `home` no longer writes it.
- [x] CAS atomic + tested cases: `update_many ... WHERE version=?` + `rows_affected` (`update_vault.rs:98`), 409 retry, `isNetworkError` offline backoff (`sync/index.ts:84`), session-change abort (`sync/index.ts:66`).
- [x] Bounded retries with backoff, never mark synced before decryptable server snapshot (`sync/index.ts:18` `MAX_SYNC_RETRIES=3` + `loadItemsFromResponse` confirm).
- [ ] Lifecycle safety: logout/revoke/password rotation don't replay old-vault-key intents into new domain (needs test — `teardown` closes DB per-vault; rotation path incomplete).
- [ ] User-visible sync status/quarantined/conflict recovery/manual retry (engine done; UI minimal — `home/index.tsx:346` `isSyncing` only).
- [x] No plaintext ops to server — whole-blob ciphertext transport only (`sync/index.ts:124` `encrypt(JSON.stringify({items:merged}))`).

### 2.8 Authentication & account lifecycle

- [ ] Normalize email — **N/A vault-centric** (no email). Vault id canonicalization/UUID validation done (`get_crypto_params.rs:46`, `init-db.ts:12`).
- [x] Generic auth errors + (planned) constant-time (`auth.rs:80` generic; plain `!=` compare at `auth.rs:98` — needs `constant_time_eq`).
- [ ] Rate-limit auth/signup/param lookup/recovery/device enrollment/export + monitoring (missing — P0).
- [ ] MFA/passkeys as additional authenticator with explicit vault-key/recovery semantics (planned).
- [ ] Password change with reauth + client-side rewrap (partial — endpoint exists, rewrap missing).
- [ ] Recovery/emergency-kit enrollment/rotation/revocation + honest “no plaintext reset” (planned).
- [ ] Log-out-all sessions/devices + device inventory + per-device revoke + notifications (partial — single-device logout done).
- [ ] Test takeover paths: stolen verifier/session cookie/reused envelope/stale session/revoked device/duplicate vault id/rotation race.

### 2.9 Server / API & database

- [ ] Body-size + schema limits on every endpoint incl. base64 decoded-size (not yet enforced).
- [ ] Reject unknown crypto versions, bad IVs, missing paired fields, impossible iterations, oversized vaults, inconsistent versions (not yet).
- [x] Authorization server-side: derive vault from session, fetch only that vault's rows; test IDOR with guessed ids (`get_vault.rs:53`, `update_vault.rs:68` all filtered by `session_vault_id`).
- [x] State changes on POST/PUT/PATCH/DELETE; GET side-effect free (`update_vault.rs:49` POST, `get_vault.rs:40` GET).
- [x] Transactions for multi-row lifecycles (`register.rs:88` `TransactionTrait`, commit/rollback).
- [x] Unique constraints for vault id (`vault.id` PK), vault→* FKs (`migration:82`); device-to-vault unique planned if device table returns.
- [ ] Enable & test `PRAGMA foreign_keys`; verify migration order vs existing installs (migration `lib.rs` should `PRAGMA`).
- [ ] Protect DB files/env/backups/crash dumps/CI artifacts — least privilege + encryption at rest (`session.key` 0600 done; DB perms pending).
- [ ] Logs free of ciphertext/wrapped keys/verifiers/passwords/bodies/sensitive queries (needs audit — `auth.rs:89` logs not sensitive, but add filter test).
- [ ] Structured security-event logging with retention/access/redaction tests + alerting for auth failures/unusual devices/bulk errors.
- [ ] Timeouts, connection limits, DB busy handling, health/readiness, safe degradation.

### 2.10 Testing & release gates

- [ ] Unit: KDF vectors, HKDF labels, AES round-trip, tamper rejection, malformed encoding, wrap separation, schema parse, zeroization.
- [ ] Client integration: signup, login, reload device-unlock, lock, logout, vault switch, password change, offline queue, sync retry, conflict.
- [ ] Server integration: route authz, cookie flags, session rotation, CSRF/origin, CORS, rate limits, enumeration, body limits, CAS, migration, error redaction.
- [ ] Property/fuzz: envelope parsing, JSON migration, replay/idempotency, base64/size boundaries.
- [ ] Dynamic: XSS payloads in `site/username/notes`, clickjacking, CSP reporting, cache inspection, service-worker, network downgrade.
- [ ] Dep/build: lockfile audit, `cargo audit`, npm/OSV, SBOM, secret scan, license scan, reproducible build + artifact inspection.
- [ ] Operational drills: restore encrypted backup, rotate session secrets, revoke all devices, rotate KDF params, handle compromised release, recover failed migration.
- [ ] **Release is blocked if** any P0 open, plaintext secrets in logs/builds, prod uses HTTP or dev secret, migrations untested, or server can receive plaintext.

---

## 3. Suggested implementation order (updated)

1. **P0 trust-boundary cleanup (next)** — remove secret logging (`home:270`, `merge:33`), fix `generateSalt` non-web (`index.web:23`), rec-enable `useSyncTriggers` (`_layout:21`), enforce prod HTTPS/Secure cookie/secret validation, add body-size + `vault_key_wrap` validation + base64 limits. Add baseline crypto/sync tests.
2. **Authentication hardening** — rate limits (`/auth`, `/register`, `/get_crypto_params`, `/update_vault`), enumeration resistance (uniform `get_crypto_params` response), `constant_time_eq` for verifier, CSRF/origin checks, `__Host-` cookie, absolute+idle session expiry + reauth for `POST /vault/password`.
3. **Lock & storage hardening** — inactivity/visibility auto-lock timer, clear remaining form/query buffers on lock, finish password-change rewrap protocol (`update_vault_password.rs` → client re-encrypt wrap+blob), account-storage audit/tests, native Keychain/Keystore scaffolding.
4. **Crypto migration** — benchmark 60k vs stronger PBKDF2/Argon2id, version profile, envelope AAD/schema version, migration path on next login (rewrap + re-encrypt + bump `crypto_version`).
5. **Sync reliability** — enable triggers, fix `created_at` type test, add lifecycle-aware pending-intent handling (no cross-key replay), build quarantine/conflict/duplicate UI, expand integration tests (two writers, lost-response, 409 loop, rollback).
6. **Essentials** — generator, health/HIBP, import/export+backup, TOTP/passkeys, richer item types, vault schema versioning tests.
7. **Autofill & platform** — browser extension + mobile autofill, native SQLite + SecureStore, offline encrypted snapshot, clipboard hygiene.
8. **Production ops** — headers (HSTS/CSP/`nosniff`/frame/referrer), DB/backup controls, dep governance (audit/SBOM), observability, restore/incident drills, external review before launch.

---

## 4. Reference standards

- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)

---

## Changelog

- **2026-09-01:** Re-audited. Merged `TODO.md` (deleted) into this file. Updated trust boundary to vault-centric (no email/user table), per-vault SQLite OPFS (`file:voult-<id>.db`) + per-vault IndexedDB (`vault:<id>`), centralized `teardownVaultSession`, `voult.locked` flag, `LockMetadata` password-unlock, intent `update|delete` support, `mergeVault` deterministic policy + quarantine, CAS + pinned-sync + retry + offline backoff, `vaults` multi-vault, Google Drive bindings. Marked TODO items done/partial above; carried remaining gaps as P0–P2. Prior roadmap was 2026-08-17 (email-centric, no per-vault isolation, `useSyncTriggers` disabled, device table missing, `update_key` empty — all now reflected).
