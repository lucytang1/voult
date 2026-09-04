# Voult Chrome Extension (MV3)

Vite + React popup, vanilla TS service worker + content script. Crypto, schema,
merge policy, and origin matching are shared via `@voult/vault-core`
(`packages/vault-core`) — consumed as compiled `dist`, rebuilt automatically
by `npm run build`. Never fork that logic into the extension.

## Dev loop

```sh
# terminal 1: API server (localhost-only v1)
cd apps/server && cargo run          # :8080, serves /api

# Extension origin needs the session cookie on cross-site subrequests:
SESSION_COOKIE_SAME_SITE=None SESSION_COOKIE_SECURE=true cargo run
# (allowed on http://localhost — localhost is a secure context).
# Once the (dev or store) extension ID is known, also add it to CORS:
# CORS_ORIGINS=http://localhost:8081,chrome-extension://<extension-id>

# terminal 2: extension build (one-shot or watch)
cd apps/extension && npm install && npm run build
```

## Load unpacked (M0 verify checklist)

1. `npm run build` passes (core build + `tsc --noEmit` + `vite build`).
2. `chrome://extensions` → Developer mode → Load unpacked →
   `apps/extension/dist`. No manifest/CSP warnings.
3. No errors in the `chrome://extensions` error log (worker registers).
4. Toolbar icon → popup renders worker state (proves popup ↔ worker).
5. Any `https` login page → `[voult] login form(s) detected` at debug level
   when a password field exists; nothing injected, read, or sent.
6. `dist/popup.html` has no inline `<script>` (MV3 `script-src 'self'`).

## M1 manual matrix (unlock + suggest + fill)

- Onboarding rejects non-UUID vault ids and non-loopback `http` server URLs.
- Wrong password fails locally ("Incorrect password.", no distinguishing
  network behavior); correct password unlocks, enrolls the device envelope.
- Reload with session alive + no lock flag → silent device unlock; with lock
  flag (after Lock, timeout, or screen lock) → password screen.
- Idle past the configured timeout, screen lock, Lock button, and browser
  restart all return to locked (memory wiped; session + envelope kept).
- Locked extension stays silent on login pages (no dropdown, no badge).
- Unlocked: only same-origin matches suggested (exact/linked first, subdomain
  marked weaker); lookalike host (`examp1e`) gets nothing; cross-origin
  iframes never filled; `http` pages show insecure markers.
- Fill via dropdown click, `Ctrl/Cmd+Shift+L`, and popup Fill all dispatch
  framework-compatible input events; never auto-submits.

## M2 manual matrix (offer to save)

- New login submit → one "Save login?" banner (username + origin, never the
  password); Dismiss/Never leave nothing behind; Save persists across browser
  restart (verify in the web app).
- Changed password → "Update saved login?"; identical re-login is silent.
- Offline save → "will retry" surfaced; candidate kept in memory only (never
  on disk); flushes on the next online save trigger.
- Concurrent web-app + extension edits → `409` retry, per-field LWW, no
  resurrection of web-deleted items, no lost fields.

## M3 notes

- `Cache-Control: no-store` is set on all `/api/*` responses (server
  `main.rs`); verify in DevTools on `/api/get_vault`.
- Secret-logging audit: no passwords/plaintext/verifiers/keys/ciphertext in
  `console.*`, `chrome.storage.*`, notifications, or error payloads.
- `manifest.json` version and `src/background/version.ts` bump together (both
  `0.1.0`); see `STORE_LISTING.md` for the release checklist.
