# Voult Extension — Store Listing Draft (M3)

## Basics

- **Name:** Voult
- **Short description:** Save logins and fill them on login pages. Zero-knowledge — the server only ever sees ciphertext.
- **Category:** Productivity
- **Minimum server version:** Voult server with `/api` vault endpoints (same origin release as extension 0.1.0). Localhost-only in v1.

## Long description (draft)

Voult is a self-hosted, zero-knowledge password manager. This companion
extension does two things: it offers to save logins when you sign in, and it
suggests the right login when you return to a login page. Your master password
and vault key never leave the browser; the server stores only encrypted data
and can never read your passwords.

## Permission justifications (for review + listing)

| Permission | Why (narrowest use) |
|---|---|
| `storage` | Server URL, lock timeout, active vault id, never-list. Never keys/plaintext. |
| `activeTab` | Read the active tab's URL to rank logins + message its content script to fill on click. |
| `scripting` | Reserved for v1.1 programmatic injection tightening (currently unused beyond declared content scripts). |
| `idle` | Lock the vault immediately when the screen locks. |
| `alarms` | Enforce the configurable inactivity auto-lock (default 5 min). |
| `host_permissions: http://localhost:8080/*` | Talk to the local Voult server API (`/api`) with the session cookie. v1 is localhost-only; remote servers must use https. |

Content scripts match `https://*/*`, `http://localhost/*`,
`http://127.0.0.1/*` (top frame only) to detect login forms. No
`<all_urls>` network grant; no `cookies`, `webRequest`, or
`web_accessible_resources`.

## Privacy policy (summary for the listing)

- No analytics, no telemetry, no remote code.
- The extension stores: server URL, settings, per-vault device envelope
  (already known to your own server), and encrypted vault data fetched from
  **your** configured server.
- Passwords exist only in memory while unlocked and in the decrypted instants
  of fill/save. Nothing is transmitted anywhere except your configured Voult
  server, and the server receives only ciphertext, KDF parameters, and the
  authentication verifier — never passwords or keys.
- Contact / data-deletion: delete the extension (clears extension storage),
  then use the web app to manage server-side vault data.

## Release checklist (before every listing upload)

1. `packages/vault-core`: `npm test` (19 tests) + `npm run build` clean.
2. `apps/extension`: `npm run build` clean; `dist/` loads unpacked with zero
   manifest/CSP errors; popup renders; suggest/fill/save matrices pass (§M1–M2
   in README).
3. `manifest.json` version == `src/background/version.ts` (both `0.1.0`
   today) == listing version.
4. `CORS_ORIGINS` on the target server includes the listing's
   `chrome-extension://<id>`; production servers enforce https +
   `SESSION_COOKIE_SECURE=true`.
5. No `console.*` with secrets in the shipped bundle (`site/username` only in
   local warn paths where unavoidable — none today).
6. Phishing fixtures re-run: lookalike host, IDN, iframe embed, http page,
   multi-credential disambiguation.
