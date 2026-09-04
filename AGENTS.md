# AGENTS.md

Password manager (voult): Expo web client + Actix-Web API server, both zero-knowledge (server only ever sees vault ciphertext, salt, iterations, `vault_verifier` HMAC, and wrapped vault-key envelopes — never master password, vault key, or plaintext).

Vault is the only identity. There is no `user`/`email` table — `vault.id` is a client-generated UUID (`apps/client/src/lib/crypto/index.web.ts:38`) used as session principal (`apps/server/src/session_auth.rs:6`).

## Layout

- `apps/client` — Expo (SDK 55) web app. Entry: `expo-router`. State: Zustand (`src/lib/state`) + TanStack Query (`src/lib/queries/http.ts:13` `withCredentials:true`). Local DB is SQLite WASM with OPFS **per-vault** (`src/lib/sqlite/web/init-db.ts:15` → `file:voult-<vaultId>.db`). Device key + envelope are per-vault in IndexedDB `voult` (`src/lib/crypto/device-key.ts:11` key `vault:<vaultId>`). Styling: NativeWind/Tailwind v4.
- `apps/server` — Rust crate named **`pass-manager`** (not "server"). Actix-Web 4 + SeaORM (SQLite). Single vault-centric migration `m20260901_000001_vault_centric_init` creates `vault`, `session` (unused — cookie store used), `google_token`, `cloud_binding`, `oauth_state`, `google_pending_token`. Cargo workspace root includes `migration`.
- `apps/server/migration` — SeaORM migration crate; see its README for CLI usage.
- `launcher` — standalone macOS tray app that spawns the server binary from `../apps/server`.

## Commands

Client (run in `apps/client`):
```sh
npm install            # runs patch-package via postinstall — patches in patches/ must apply
npm run sync:sqlite-web   # REQUIRED before web export; copies sqlite-wasm assets into public/sqlite
npm run build:web      # exports to dist/ (clears EXPO_PUBLIC_API_URL so it uses same-origin /api)
npx tsc --noEmit       # typecheck; there is no lint/test script
npm run web            # dev server on :8081
```

Server (run in `apps/server`):
```sh
cargo run              # binds localhost:8080, serves API under /api and client's exported site at /
```

Env / config (`apps/server/src/main.rs:38`): all vars optional with per-install defaults. `DATABASE_URL` defaults to `~/Library/Application Support/Voult/voult.db` (`sqlite://…?mode=rwc`, `resolve_database_url()`). `SESSION_COOKIE_KEY` defaults to per-install `~/Library/Application Support/Voult/session.key` (0600, 64 random bytes base64, `resolve_session_cookie_key()`); if provided must be ≥64 chars else ignored with warn, and panics only if resolved key <64. `STATIC_DIR` defaults to probing `Resources/dist` (Voult.app bundle) then `../client/dist`. Optional: `CORS_ORIGINS` (comma-separated; defaults `http://localhost:8081` + `127.0.0.1:8081`), `SESSION_COOKIE_SECURE`/`SAME_SITE`/`TTL_SECONDS` (default 7d idle), `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` (+ `GOOGLE_REDIRECT_URI`) for Drive sync. `.env` is loaded from CWD, then `Resources/.env`/`google.env`, then `~/Library/Application Support/Voult/.env` (`load_bundled_env()`).

## Gotchas

- Build order for a full local run: `npm run build:web` in `apps/client` first, then `cargo run` in `apps/server` (it serves `../client/dist`; warns and serves API-only if missing).
- The server runs migrations automatically on startup (`Migrator::up` in `main.rs:222`); you don't need to invoke them manually for normal dev.
- COOP/COEP headers are required by sqlite-wasm OPFS (`SharedArrayBuffer`) — set both on the server responses (`main.rs:280` `DefaultHeaders`) and in `public/_headers`. Don't remove them.
- Server never handles plaintext: crypto (v2 hierarchy: PBKDF2-HMAC-SHA256 → HKDF `auth`/`vault-wrap-v2` → random 256-bit vault key AES-GCM, device key wrap) lives entirely client-side in `src/lib/crypto/index.web.ts:10` and `src/lib/crypto/device-key.ts`. Cookie `voult_session` stores only `vault_id` (`session_auth.rs:6`), never keys/envelopes.
- Client storage is **per-vault namespaced** (`apps/client/architecture.md#local-storage-namespacing`): one OPFS file per vault, one IndexedDB record per vault (`vault:<id>`), `sessionStorage["voult.locked"]` is profile-global. SQLite is opened only after a session exists (`initSQLite(vaultId)` validates UUID) and closed on lock/logout. Teardown is centralized in `src/lib/auth/teardown.ts:18` (capture vaultId → close per-vault DB → delete only this vault's device records → wipe Zustand → clear query cache) and used by home logout, lock-screen logout, and 401 interceptor (`src/lib/queries/http.ts:39`).
- Lock semantics: `lockVaultStorage` (`src/lib/state/index.ts:124`) wipes `vaultKey`/`decryptedVault`/`authKey` but keeps session + device envelope; `persistLockedFlag()` makes lock survive reload so `_layout.tsx:35` bootstrap routes to `/lock` instead of silent `unlockWithDevice()` (`src/lib/auth/flows.ts:73`). Unlock with password unwraps locally via `LockMetadata` (no network on wrong password).
- Client sync uses an offline-first `intent` table (durable encrypted mutation log: `operation` `create|update|delete`, `payload/payload_iv`, `device_id` per-vault, `base_version`, `synced`, `error`) with deterministic version-based conflict resolution — see `apps/client/conflict-resolution.md` and `architecture.md` before touching sync code. Merge policy `src/lib/sync/merge.ts:24` (idempotent create, LWW update, sticky delete, quarantine). Server CAS is `UPDATE … WHERE id=? AND version=?` + `rows_affected` → `409 VERSION_CONFLICT` (`src/endpoints/update_vault.rs:98`). Scheduler `src/lib/sync/sync-scheduler.ts` coalesces triggers (window-focus, online, intent-created, forced) but `useSyncTriggers` is currently disabled in `src/app/_layout.tsx:21`.
- Google Drive sync: bindings/tokens keyed by `vault_id` (`google_token`, `cloud_binding`). OAuth under `/api/google/*`; pending-state flow bypasses bootstrap auto-restore (`_layout.tsx:31`).

## Code Style

- Comment generously: explain operations and non-obvious logic, not every line. If code does something subtle (crypto steps, sync/conflict handling, SQL/OPFS quirks), say why in a comment.
- Log meaningfully: add logs for important events and state changes with correct severity levels (e.g. `error` for failures needing action, `warn` for recoverable anomalies, `info` for key lifecycle events). Don't log everything or noisy per-request details. Never log passwords, vault plaintext, `vault_verifier`, raw key bytes, or request bodies.

## Plans

When the user asks to "create a plan", "make a plan", "plan this", or otherwise explicitly requests a development plan:

- The plan MUST be written to a `.md` file in the repository.
- Prefer `plans/<descriptive-name>.md`.
- Create the `plans/` directory if necessary.
- Do not treat the chat response as the canonical copy of the plan.
- The Markdown file should contain the complete plan.
- Don't just transcribe the user's instructions into a plan: research the relevant code first, think through the approach, and proactively suggest alternatives or better ways to accomplish the goal (including trade-offs) before finalizing the plan.

### Plan Style

The taste every plan should aim for:

- Research-first: read the code and docs the plan touches (`architecture.md`, `conflict-resolution.md`, roadmap) before writing. Cite evidence as `file:line` so claims are checkable.
- Alternatives with verdicts: name the approaches considered, give each an honest trade-off, and recommend one explicitly. Rejected options stay in the plan with the reason (prevents re-litigation).
- Concrete over abstract: a files-to-touch index (new / edit / do-not-touch), exact endpoint/payload shapes, and real function/module names — never "update the backend accordingly".
- Trust-boundary aware: state what the change must NOT break (zero-knowledge invariants, session semantics, per-vault namespacing) and call out new attack surface with mitigations.
- No compat baggage by default: this project has no releases — change schemas in place, no version fields, no migrations, no legacy fallbacks, unless the user explicitly asks for backward compatibility.
- No new dependencies without justification: prefer owning small, auditable scripts over unmaintained third-party packages, especially on security-sensitive paths.
- End with open questions: decisions deferred, each with a due-by milestone.

### Phases

Break implementation into ordered phases (`M0` foundations/pipeline first, then feature slices, hardening/store-readiness last). Each phase states its scope plus acceptance criteria concrete enough to verify by hand (what to click, what to observe, what must fail cleanly). Phases are the agent's execution order — each one must leave the tree working.


## Docs

- `apps/client/architecture.md` — canonical vault-centric schemas and login/add-item flows plus per-vault storage table (SQLite OPFS + IndexedDB + Zustand + lock flag). `apps/client/conflict-resolution.md` — merge policy.
- `SECURITY_AND_FEATURE_ROADMAP.md` — **audited 2026-09-01**, single honest backlog + release security checklist; merges and supersedes `TODO.md` (deleted). Evidence `file:line` for implemented items; §3 gives implementation order.
- `SESSION_ARCHITECTURE_PLAN.md` — original session/device-unlock design; largely implemented (cookie session, vault wrapping, device envelope) except server device table and some hardening — treat as historical plan, verify against `session_auth.rs`/`device-key.ts`/`flows.ts`.
- `mindvomit.txt` files are scratch notes, not docs.
