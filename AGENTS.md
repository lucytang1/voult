# AGENTS.md

Password manager (voult): Expo web client + Actix-Web API server, both zero-knowledge (server only ever sees vault ciphertext, salt, iterations, and an HMAC verifier).

## Layout

- `apps/client` — Expo (SDK 55) web app. Entry: `expo-router`. State: Zustand + TanStack Query. Local DB is SQLite WASM with OPFS (`src/lib/sqlite`). Styling: NativeWind/Tailwind v4.
- `apps/server` — Rust crate named **`pass-manager`** (not "server"). Actix-Web 4 + SeaORM (SQLite at `apps/server/voult.db`). Cargo workspace root includes `migration`.
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

Server (run in `apps/server`, needs `.env`):
```sh
cargo run              # binds localhost:8080, serves API under /api and client's exported site at /
```

Required `.env` vars in `apps/server`: `DATABASE_URL`, `SESSION_COOKIE_KEY` (≥64 chars, panics otherwise). Optional: `CORS_ORIGINS` (comma-separated; defaults allow the Expo dev origin `:8081`), `SESSION_COOKIE_SECURE/SAME_SITE/TTL_SECONDS`, `STATIC_DIR`.

## Gotchas

- Build order for a full local run: `npm run build:web` in `apps/client` first, then `cargo run` in `apps/server` (it serves `../client/dist`; warns and serves API-only if missing).
- The server runs migrations automatically on startup (`Migrator::up`); you don't need to invoke them manually for normal dev.
- COOP/COEP headers are required by sqlite-wasm OPFS (`SharedArrayBuffer`) — set both on the server responses and in `public/_headers`. Don't remove them.
- Server never handles plaintext: crypto (AES-GCM vault encryption, PBKDF2/HMAC key derivation) lives entirely client-side in `src/lib/crypto`.
- Client sync uses an offline-first `intent` table (durable encrypted mutation log) with version-based conflict resolution — see `apps/client/conflict-resolution.md` and `architecture.md` before touching sync code.

## Code Style

- Comment generously: explain operations and non-obvious logic, not every line. If code does something subtle (crypto steps, sync/conflict handling, SQL/OPFS quirks), say why in a comment.
- Log meaningfully: add logs for important events and state changes with correct severity levels (e.g. `error` for failures needing action, `warn` for recoverable anomalies, `info` for key lifecycle events). Don't log everything or noisy per-request details.

## Plans

When the user asks to "create a plan", "make a plan", "plan this", or otherwise explicitly requests a development plan:

- The plan MUST be written to a `.md` file in the repository.
- Prefer `plans/<descriptive-name>.md`.
- Create the `plans/` directory if necessary.
- Do not treat the chat response as the canonical copy of the plan.
- The Markdown file should contain the complete plan.
- Don't just transcribe the user's instructions into a plan: research the relevant code first, think through the approach, and proactively suggest alternatives or better ways to accomplish the goal (including trade-offs) before finalizing the plan.

## Docs

`apps/client/architecture.md` documents login/add-item flows and schemas; `SECURITY_AND_FEATURE_ROADMAP.md` and `SESSION_ARCHITECTURE_PLAN.md` at root contain plans (aspirational — verify against code). `mindvomit.txt` files are scratch notes, not docs.
