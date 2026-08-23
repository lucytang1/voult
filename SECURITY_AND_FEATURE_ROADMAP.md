# Voult: Feature Roadmap and Security Checklist

**Audit date:** 2026-08-17  
**Scope:** `apps/client`, `apps/server`, and the current database migrations  
**Purpose:** maintain one honest product backlog and one release-oriented security checklist for the password manager.

This is an engineering review, not a security certification or penetration test. “Implemented” means present in the current source code. Items described only in `architecture.md`, `SESSION_ARCHITECTURE_PLAN.md`, or comments are marked as planned or partial until the runtime, migrations, and tests exist.

## Status and priority

- `✅ Implemented` — present in source and usable at the current scope.
- `🟡 Partial` — an initial version exists, but it is incomplete or not production-ready.
- `⬜ Planned` — not implemented in the current source.
- `⚠️ Security gap` — must be addressed before treating the feature as safe for production.

Priority is deliberately security-first:

- **P0:** release blocker or direct risk to vault confidentiality, account security, or data integrity.
- **P1:** required for a credible password-manager product, but can follow the initial security gate.
- **P2:** quality, scale, usability, or advanced product capability.

## Current trust boundary

The intended boundary is good and should not be weakened:

| Data | Current intended location | Review result |
|---|---|---|
| Master password | Client memory only during entry | ✅ No server password field or password-bearing API was found |
| Password-derived keys | Client memory | ✅ PBKDF2 + HKDF is implemented client-side |
| Auth verifier (`user_key`) | Client-derived, server-stored | 🟡 It is currently sent as a reusable static login credential |
| Random vault key | Client-generated, imported as a non-exportable `CryptoKey` | ✅ Used for v2 AES-GCM vault encryption |
| Plaintext vault | Client memory/UI state | 🟡 Correctly client-side, but debug logging currently prints it |
| Encrypted vault and metadata | Server SQLite | ✅ Server handlers operate on ciphertext and metadata |
| Device key | Browser IndexedDB | 🟡 Local device key exists, but server device registration/revocation is not wired |
| Pending writes | Browser SQLite intent table | ✅ Payloads are encrypted before persistence |

Important limitation: end-to-end encryption protects vault contents from an honest-but-curious storage server. A compromised server that can replace the web application bundle, or an XSS/supply-chain compromise in the client, can still access plaintext while the vault is unlocked. Web delivery security is therefore part of the cryptographic threat model.

# 1. Feature TODO

The baseline below is what a normal modern password manager is expected to provide: encrypted vaults, strong authentication, reliable multi-device sync, recovery, secure device lifecycle, autofill, import/export, password generation, and operational security.

## 1.1 Client

### Implemented in the current source

- ✅ **Expo Router application shell and dark vault UI** — landing, sign-up, login, home, debug routes, and basic vault item interaction.
- ✅ **Client-side account setup and login** — `signupFlow` and `passwordLoginFlow` derive credentials locally and send only `email` plus `user_key` to `/auth` or `/register`.
- ✅ **Version-2 vault key hierarchy** — random 256-bit vault key; AES-GCM vault encryption; password-derived wrapping key; HKDF domain labels for authentication and vault wrapping.
- ✅ **Authenticated encrypted vault blob** — AES-GCM uses a fresh 96-bit IV for vault encryption and for key wrapping.
- ✅ **Cookie-based API client** — Axios uses `withCredentials: true`; a shared response interceptor clears volatile state on `SESSION_REQUIRED`.
- ✅ **Session auto-restore attempt** — on reload, the app checks `/session`, loads the local browser device key and local envelope, then decrypts the fetched vault.
- ✅ **Local SQLite bootstrap** — SQLite WASM + OPFS initialization, `intent` table, and `client_state` table.
- ✅ **Local-first mutation log** — create, update, and delete payloads are encrypted with the vault key before insertion into SQLite.
- ✅ **Optimistic UI updates** — add, edit, and delete update Zustand after the encrypted intent is persisted.
- ✅ **Deterministic conflict merge design and initial implementation** — stable item UUIDs, idempotent create/update/delete replay, quarantine of malformed intents, and bounded CAS retries exist in `src/lib/sync`.
- ✅ **Basic vault operations** — add, edit, delete, search, selection, and password masking in the current home screen.
- ✅ **Local logout cleanup attempt** — logout calls the server, deletes the browser device key/envelope, clears volatile Zustand state, and routes away.

### Left to implement or harden

#### P0 — security and data-safety blockers

- ⬜ **Replace or harden the password KDF.** Current PBKDF2-HMAC-SHA-256 uses `60,000` iterations. Benchmark per platform and migrate to a modern memory-hard profile such as Argon2id; if PBKDF2 must remain for compatibility, use a materially stronger, versioned parameter profile and migrate existing vaults.
- ⚠️ **Fix non-web salt generation.** `generateSalt()` returns an empty byte array when `Platform.OS !== "web"`. Native builds must use a platform CSPRNG and a non-empty per-account salt before native support is claimed.
- ⬜ **Replace static `user_key` authentication with a safer protocol.** The current verifier is effectively a reusable bearer credential: anyone who obtains it can attempt `/auth` without the master password. Evaluate a PAKE/augmented PAKE, WebAuthn/passkey-backed authentication, or a carefully designed challenge-response protocol without exposing the password or vault key.
- ⚠️ **Remove plaintext secret logging and demo secrets.** `decryptedVault` is logged in the home screen; signup contains starter entries using `password`; intent and sync code log payloads, IDs, and errors. Production builds must not log passwords, vault objects, decrypted intent content, auth material, or request bodies.
- ⬜ **Implement real lock semantics.** Lock must clear all plaintext form state, selected item state, query caches, decrypted data, and pending UI buffers; it must support inactivity/visibility auto-lock and require password or an approved local authenticator to unlock. Current reload auto-restore can undermine the meaning of “lock” while the session and browser envelope remain available.
- ⬜ **Separate accounts in local storage.** Namespace SQLite intents, `client_state`, IndexedDB envelopes, and cached query data by authenticated account. Logout must prevent pending intents from one account being considered for another account in the same browser profile.
- ⬜ **Add security tests before changing crypto or sync.** Include known-answer crypto tests, wrong-password/tamper tests, IV and base64 validation tests, migration tests, lost-response retry tests, conflict tests, account-switch tests, and lock/logout memory-clearing tests.
- ⬜ **Protect the web client from XSS and supply-chain compromise.** Add a strict production CSP, frame protection, safe dependency/release controls, and a review process for any code that can run in the vault origin. A client-side vault cannot withstand arbitrary JavaScript executing in its origin.

#### P1 — standard password-manager capabilities

- ⬜ **Password change and key rotation.** Re-derive the password keys, rewrap the vault key, rotate the auth credential, preserve all vault data, and make the operation recoverable if interrupted.
- ⬜ **Recovery and emergency access.** Design a zero-knowledge recovery story: recovery key/emergency kit, explicit warnings about unrecoverability, and a tested recovery flow. Do not add a server-side password reset that silently bypasses vault encryption.
- ⬜ **Device management.** Add device enrollment, device names, last-used metadata, per-device revoke, “log out all devices,” and recovery after device loss. The browser-local device key exists, but the server-side `device` entity, migration, and routes are not currently present or registered.
- ⬜ **Native secure storage and biometrics.** Use iOS Keychain/Android Keystore (prefer hardware-backed keys where available), biometric/PIN-gated unlock, and platform screenshot/app-switcher protections. IndexedDB is only a browser storage mechanism, not a hardware-backed secure enclave.
- 🟡 **Automatic/background sync.** A scheduler exists and item creation requests a sync, but `useSyncTriggers()` is disabled in `_layout.tsx`. Add focus, reconnect, timer, startup, retry/backoff, and explicit sync-status/error UI.
- 🟡 **Finish conflict UX.** The merge engine has defined policies, but users need a visible pending/error/quarantine state, duplicate detection, conflict history, and a safe way to restore or re-create deleted items.
- ⬜ **Password generator.** Generate passwords/passphrases locally using a CSPRNG; provide policy controls, length/entropy feedback, and never send generated candidates to the server or analytics.
- ⬜ **Password health.** Add local strength checks and an optional privacy-preserving breached-password check. Never upload plaintext passwords for a health report.
- ⬜ **Autofill and browser extension.** Implement origin-bound matching, user confirmation for filling, frame/iframe protections, isolated extension storage, phishing-resistant URL handling, and a secure fill protocol. Do not match on arbitrary display names alone.
- ⬜ **TOTP and other secrets.** Add encrypted TOTP seeds, local code generation, clock-skew handling, and careful clipboard/accessibility behavior. Consider passkeys as a first-class credential rather than treating them as ordinary notes.
- ⬜ **Richer item types.** Secure notes, identities, payment cards, custom fields, attachments, tags/folders, multiple URLs, and per-item history should use a versioned encrypted schema.
- ⬜ **Import/export and backup.** Support well-defined formats, encrypted exports, explicit plaintext-export warnings, re-authentication before export, secure temporary-file cleanup, and restore verification. Include a recovery path that does not depend on a live server.
- ⬜ **Vault schema migrations.** Add a schema version inside the encrypted payload and test migrations from legacy v1 items, including IDs, tombstones/history, new item types, and crypto-version transitions.
- ⬜ **Cross-platform parity.** Native storage, crypto availability, deep links, app lifecycle, autofill APIs, and clipboard controls must be implemented and tested separately from the current web-centric path.
- ⬜ **Accessibility and localization.** Keyboard navigation, screen-reader labels, focus management for modals, contrast, reduced motion, and localized security warnings are part of safe use.

#### P2 — product maturity

- ⬜ Shared/family vaults with explicit encrypted sharing and revocation semantics.
- ⬜ Secure sharing links with expiry, recipient authentication, one-time use, and no plaintext server storage.
- ⬜ Item history, soft-delete/recycle bin, audit activity visible to the user, and restore testing.
- ⬜ Privacy-preserving telemetry opt-in, with a documented policy that excludes vault contents, passwords, URLs, usernames, crypto material, and full error payloads.

## 1.2 Server

### Implemented in the current source

- ✅ **Actix-Web service with SeaORM/SQLite** and additive migrations.
- ✅ **Transactional registration** — vault and user rows are inserted in a transaction before the session is established.
- ✅ **Cookie session middleware** — `CookieSessionStore`, HttpOnly cookie, configurable SameSite, persistent TTL, and a configured session signing/encryption key.
- ✅ **Session-protected vault read/write endpoints** — `/get_vault` and `/update_vault` derive the user from the session instead of accepting `email`/`user_key` for vault access.
- ✅ **Session lifecycle endpoints** — `/session`, `/logout`, and session rotation during `/auth` are present.
- ✅ **Explicit configured CORS origins** with credentials support; the runtime does not use `allow_any_origin()` with credentials.
- ✅ **Optimistic-concurrency vault updates** — `/update_vault` uses a conditional update on vault ID and version and returns `409 VERSION_CONFLICT` when it loses the compare-and-swap.
- ✅ **Ciphertext-only vault persistence** — the server schema stores vault ciphertext, IV, salt, iterations, crypto version, and optional password-wrapped vault-key fields; handlers do not decrypt the vault.
- ✅ **Shared structured error shape** with stable error codes such as `SESSION_REQUIRED`, `AUTH_FAILED`, and `VERSION_CONFLICT`.

### Left to implement or harden

#### P0 — production security blockers

- ⚠️ **Enforce HTTPS in production.** The committed development configuration uses HTTP and does not enable `SESSION_COOKIE_SECURE`. Production must fail closed unless TLS is terminated by a trusted reverse proxy, set Secure cookies, and preserve the correct external origin.
- ⚠️ **Remove/rotate committed development secrets.** `apps/server/.env` contains a development session key. Use environment/secret-manager injection, startup validation, rotation procedures, and secret scanning. Never reuse the development key.
- ⬜ **Add rate limits and abuse controls.** Protect `/auth`, `/register`, `/get_crypto_params`, and expensive vault operations with IP/account/device-aware throttles, exponential backoff, credential-stuffing detection, and bounded request sizes.
- ⬜ **Stop account enumeration.** `/get_crypto_params` currently returns `404 USER_NOT_FOUND` for unknown email addresses. Use a non-enumerating response strategy and identical timing/error behavior where practical.
- ⬜ **Normalize and constrain account identifiers.** Normalize email consistently, add a real unique index/constraint, validate length and syntax, and define case-folding behavior before account creation.
- ⬜ **Validate the encrypted-vault protocol at the boundary.** Enforce allowed crypto versions, exact base64/IV/ciphertext limits, non-empty salts, bounded iterations, paired key-wrap fields, payload size limits, and a versioned envelope schema. Reject malformed or downgrade attempts before database writes.
- ⬜ **Add CSRF/origin defenses.** SameSite is defense in depth, not the whole policy. Validate `Origin`/`Referer` or Fetch Metadata on state-changing requests and add a CSRF token/double-submit design if cross-site deployment requires it.
- ⬜ **Harden sessions for production.** Use a `__Host-` cookie where deployment allows, Secure + HttpOnly + Strict/Lax, absolute and idle expiry, reauthentication for high-risk actions, logout-all/revocation, no-store responses, and session-cookie rotation tests. The current runtime uses a cookie store and leaves the database `session` table unused.
- ⬜ **Database and backup protection.** Require least-privilege file permissions, encrypted disks/backups, tested restore access controls, key separation, retention/deletion rules, and no plaintext vaults in dumps, fixtures, support tools, or logs.
- ⬜ **Add server integration/security tests.** Cover auth/session fixation, cookie flags, CORS, CSRF, enumeration, rate limits, input limits, authorization, CAS concurrency, migrations, downgrade attempts, and database failure behavior.

#### P1 — reliability and product completeness

- ⬜ **Implement device-key server lifecycle.** Add the `device` migration/entity, authenticated `POST/GET/DELETE /session/device-key` endpoints, envelope validation, last-used/revoked state, device listing, and route registration. Current comments in the v2 migration mention a device table, but the table/entity/routes are absent.
- ⬜ **Implement password change/key rotation endpoint.** Replace the empty `update_key.rs` stub with a client-driven encrypted rewrap protocol and atomic metadata update. The server must never receive the password or plaintext vault key.
- ⬜ **Define server-side rollback and deletion policy.** Version CAS prevents concurrent overwrite, but a trusted server can still restore an older ciphertext snapshot. Add retention/history or a client-verifiable monotonic/integrity strategy and document what a malicious server can and cannot do.
- ⬜ **Make migrations operationally safe.** Run migrations in CI against a copy of real schema versions, test rollback expectations, enable foreign-key enforcement, and verify indexes/constraints for every release.
- ⬜ **Add API versioning and compatibility rules.** Crypto-version and vault-schema changes need explicit compatibility windows, downgrade rejection, and migration telemetry that contains no secrets.
- ⬜ **Add request/response caching controls.** Sensitive vault/session responses should use `Cache-Control: no-store`; verify reverse proxies and error pages do not cache or echo request bodies.
- ⬜ **Improve availability controls.** Timeouts, bounded concurrency, body limits, database busy timeouts, health/readiness endpoints, backup monitoring, and clear client retry semantics are required for sync reliability.
- ⬜ **Privacy-safe audit logging.** Log security events such as auth failures, rate-limit decisions, session revocation, device changes, and CAS conflicts without logging passwords, `user_key`, vault ciphertext, wrapped keys, request bodies, or raw sensitive query values.

#### P2 — operational maturity

- ⬜ Security headers at the edge/API: HSTS, `X-Content-Type-Options: nosniff`, frame restrictions, restrictive referrer policy, and an API-appropriate CSP where applicable.
- ⬜ Dependency governance: lockfiles, automated vulnerability scanning, `cargo audit`, npm/OSV scanning, SBOM generation, review of native/WASM packages, and signed/reproducible release artifacts.
- ⬜ Incident response: credential/session revocation, key rotation, breach notification criteria, restore drills, abuse response, and a documented vulnerability disclosure process.
- ⬜ Deployment isolation: private database networking, restricted admin access, separate dev/staging/prod credentials, and no production data in local development.

# 2. Deep app security checklist

Use this section as a verification checklist. Every checked item should have a code location, a test, and an owner. “Pass” means verified in the target build/deployment—not merely present in a comment.

## 2.1 Threat model and security invariants

- [ ] Document assets: master password, auth verifier, vault key, wrapped keys, plaintext vault, pending intents, session cookie, device key, email/account metadata, backups, logs, crash reports, and build artifacts.
- [ ] Document actors: malicious web origin, XSS attacker, compromised dependency/build pipeline, malicious or compromised storage server, database thief, network attacker, stolen device, malicious local OS user, credential-stuffing attacker, and malicious support/admin user.
- [ ] State the guarantee precisely: the server is not trusted with plaintext vault contents, but it can observe metadata, deny service, replay/rollback ciphertext unless prevented, and potentially replace client code if the delivery origin is compromised.
- [ ] Define the lock model: what remains in RAM, what remains in IndexedDB/OPFS/Keychain, whether reload auto-unlocks, what inactivity means, and whether a stolen browser profile is considered an unlocked device.
- [ ] Define recovery honestly: if the user loses both the master password and approved recovery material, the vault is unrecoverable. No support path should imply otherwise.
- [ ] Maintain a data-flow diagram for signup, password login, reload unlock, lock, logout, device enrollment, intent creation, sync, conflict, password change, export, and recovery.

## 2.2 Client cryptography and key management

- [ ] Use a reviewed, platform-supported CSPRNG for salts, vault keys, IVs, device keys, UUIDs, and password-generator output. Do not use empty native salts or predictable fallbacks.
- [ ] Use a unique random salt per account and persist the exact KDF parameters with the vault. Validate salt length and reject malformed/legacy values explicitly.
- [ ] Benchmark KDF settings on the slowest supported device and record the target. Prefer Argon2id; if compatibility requires PBKDF2-HMAC-SHA-256, use a versioned stronger profile and a migration path.
- [ ] Keep domain separation labels distinct and versioned (`auth`, `vault-wrap-v2`, legacy encryption). Add test vectors so labels cannot be accidentally reused.
- [ ] Keep the random vault key separate from authentication keys. Never use `user_key` as an encryption key, and never send a vault key or derived encryption key to the server.
- [ ] Use AES-GCM or another reviewed AEAD with a fresh 96-bit nonce per key. Enforce nonce/ciphertext lengths and never reuse a nonce under the same key.
- [ ] Bind ciphertext to context with authenticated additional data where appropriate: account ID, vault ID, crypto version, schema version, envelope type, and possibly record/version. This makes cross-account or cross-context substitution fail closed.
- [ ] Treat all decryption failures as authentication failures/tampering, not as a reason to fall back to another key or parser.
- [ ] Keep raw key bytes alive only for the shortest possible wrapping operation. Use best-effort zeroization for temporary buffers, while documenting that JavaScript garbage collection cannot guarantee memory erasure.
- [ ] Test wrong passwords, modified ciphertext, modified IV, modified salt, modified iteration count, swapped envelopes, truncated base64, oversized inputs, and crypto-version downgrades.
- [ ] Design password change as rewrapping/rotating keys on the client, with atomic recovery if the network fails halfway through.
- [ ] Do not treat non-exportable `CryptoKey` as protection from same-origin XSS, browser malware, devtools, or a compromised runtime. The threat model and web hardening must say this plainly.
- [ ] Replace the static verifier-login protocol with an approved authentication design. If a password-derived verifier must remain, protect it as a credential, use constant-time verification where applicable, support rotation, and rate-limit every online guess.

## 2.3 Plaintext and secret lifecycle

- [ ] Never log passwords, plaintext vaults, decrypted intents, auth keys, raw key bytes, wrapped-key contents, or request/response bodies.
- [ ] Remove starter/demo secrets and test vault data from production paths and production bundles.
- [ ] Clear password input state immediately after signup/login succeeds or fails; do not retain it in navigation params, URL state, query caches, analytics, crash reports, or form snapshots.
- [ ] On lock, clear vault key references, auth key references, decrypted vault, selected item, edit/add form fields, search results if sensitive, clipboard state, React Query sensitive cache, and any worker copies.
- [ ] Add inactivity, background, screen-hide, and visibility lock policies with a user-visible timeout setting and safe defaults.
- [ ] Decide whether reload auto-unlock is compatible with the lock promise. If it is retained, make it an explicit “trusted device” setting and provide a password-required lock mode.
- [ ] Mask passwords by default, make reveal deliberate, prevent accidental screen capture on native platforms, and do not show secrets in accessibility labels or browser titles.
- [ ] Clear clipboard contents after a bounded timeout where platform APIs allow it; warn users when the OS cannot guarantee clearing.
- [ ] Do not include vault values in PostHog/analytics events, URLs, DOM attributes, browser history, or error messages.

## 2.4 Web client, XSS, and supply chain

- [ ] Deploy only over HTTPS with HSTS after validating all subdomains and preload implications.
- [ ] Add a strict CSP appropriate for Expo web; prohibit `unsafe-eval` and minimize/avoid `unsafe-inline`. Use `frame-ancestors 'none'` or an explicit trusted parent policy.
- [ ] Add `X-Content-Type-Options: nosniff`, restrictive `Referrer-Policy`, `Permissions-Policy`, and clickjacking protection. Confirm headers apply to HTML, static assets, and error responses.
- [ ] Keep untrusted site names, usernames, URLs, tags, notes, and imported content in safe React Native text/rendering paths. Never introduce raw HTML or unsanitized URL schemes.
- [ ] Review all third-party packages, analytics, fonts, WASM, patches, and build plugins. Pin versions, review lockfile diffs, scan advisories, and record provenance for release artifacts.
- [ ] Ensure source maps and debug bundles are not publicly deployed if they expose sensitive internals or environment values.
- [ ] Test the built web artifact, not just the development server, for CSP violations, unexpected network calls, source-map exposure, and accidental secrets.
- [ ] Ensure the API origin, public environment variables, and error pages cannot be controlled by attacker-supplied URL parameters or untrusted storage.
- [ ] Keep the debug route out of production builds or protect it behind an explicit development-only compile flag.

## 2.5 Browser and local storage

- [ ] Store no auth token, session ID, master password, vault key, or plaintext vault in `localStorage`, `sessionStorage`, URL parameters, or unencrypted IndexedDB/OPFS.
- [ ] Treat encrypted SQLite intents as sensitive ciphertext: namespace them per user/device, bound their lifecycle, and delete/quarantine safely on logout/account switch.
- [ ] Document browser storage limitations: an attacker with same-origin script execution can read/use the vault while unlocked and can invoke Web Crypto operations.
- [ ] Store native device keys only in Keychain/Keystore or an approved secure-storage abstraction; do not use AsyncStorage for keys or envelopes.
- [ ] Bind local device identity to the authenticated account and server enrollment. Avoid a global `current` record that can be confused across accounts.
- [ ] Add a device revoke flow and verify that revoked devices cannot obtain a fresh envelope or continue sync after session expiry.
- [ ] Test multiple tabs, concurrent IndexedDB upgrades, browser profile copying, OPFS reset, storage quota errors, private browsing, and abrupt tab termination.
- [ ] Clear sensitive browser caches and use `Cache-Control: no-store` for vault/session responses. Review service-worker behavior before enabling one.

## 2.6 Network, cookies, and browser sessions

- [ ] Enforce HTTPS and reject production HTTP API URLs at startup/build time.
- [ ] Configure the session cookie as Secure, HttpOnly, and Strict or carefully justified Lax; use a `__Host-` prefix when the deployment topology permits it.
- [ ] Ensure `SameSite=None` is never accepted without Secure and a documented cross-site requirement.
- [ ] Validate `Origin`/`Referer` or Fetch Metadata for every state-changing cookie-authenticated request; do not rely on CORS as CSRF protection.
- [ ] Keep CORS allowlists exact, environment-specific, and free of wildcard origins when credentials are enabled.
- [ ] Rotate the session at authentication and privilege changes; test fixation, concurrent logins, logout, expiry, revocation, and stolen-cookie behavior.
- [ ] Set absolute and idle session limits. Require reauthentication for password changes, recovery, device enrollment/revocation, and plaintext export.
- [ ] Make authenticated errors generic enough not to reveal account existence, credential validity, vault existence, or internal database state.
- [ ] Ensure proxies do not log query-string emails, request bodies, cookies, authorization material, or ciphertext payloads unnecessarily.

## 2.7 Local-first writes and sync integrity

- [ ] Encrypt every intent before SQLite insertion and authenticate its operation type, account, device, and schema context.
- [ ] Use stable UUID item IDs and idempotent operations. Never identify an item solely by `(site, username)`.
- [ ] Validate intent operation and decrypted payload with a strict schema; quarantine malformed rows without blocking unrelated valid rows.
- [ ] Fix and test the current SQLite type mismatch: the schema declares `created_at INTEGER`, while the service inserts an ISO string and the parser expects a string. A durable queue must not silently lose or skip intents because of this mismatch.
- [ ] Ensure all version writes have one owner. The sync algorithm should define whether server version or local base version is authoritative and test adoption, rollback, no-intent divergence, and pending-intent divergence.
- [ ] Keep CAS atomic and test two simultaneous writers, lost success responses, repeated retries, 409 loops, server rollback, and malformed server snapshots.
- [ ] Use bounded retries with backoff and leave unresolved intents pending. Never mark an intent synced before the server response is authenticated and the resulting snapshot is locally decryptable.
- [ ] Make account logout, device revoke, and password rotation interact safely with pending intents. Do not replay intents encrypted under an old vault key into a new key domain.
- [ ] Add user-visible sync status, failed/quarantined intent recovery, conflict explanations, and a manual retry path.
- [ ] Do not send plaintext operations to the server for “easier” conflict resolution. The server should remain a ciphertext transport and version gate.

## 2.8 Authentication and account lifecycle

- [ ] Normalize email before lookup and registration; enforce a unique constraint and consistent case behavior.
- [ ] Use generic login/parameter errors and constant-time comparisons where secrets are compared in application code.
- [ ] Rate-limit authentication, signup, parameter lookup, recovery, device enrollment, and export. Add monitoring for credential stuffing and automated guessing.
- [ ] Support phishing-resistant MFA/passkeys as an additional account authenticator, while keeping vault-key protection and recovery semantics explicit.
- [ ] Provide password change with reauthentication and client-side vault-key rewrap.
- [ ] Provide recovery/emergency-kit enrollment, rotation, revocation, and clear “no plaintext reset” behavior.
- [ ] Provide “log out all sessions/devices,” device inventory, per-device revoke, and notifications for high-risk lifecycle events.
- [ ] Test account takeover paths: stolen `user_key`, stolen session cookie, reused device envelope, stale session after logout, revoked device, duplicate email, and password rotation races.

## 2.9 Server/API and database

- [ ] Require body-size limits and schema validation on every endpoint, including base64 decoded-size limits.
- [ ] Reject unknown crypto versions, invalid IV sizes, missing paired fields, impossible iteration counts, oversized vaults, and inconsistent version fields.
- [ ] Keep authorization server-side: derive the user from the session and fetch only that user’s vault/device rows. Test IDOR cases with guessed IDs and altered payload metadata.
- [ ] Keep all state changes on POST/PUT/PATCH/DELETE; ensure GET endpoints are side-effect free.
- [ ] Use transactions for multi-row lifecycle operations and verify rollback on every failure path.
- [ ] Add unique/index constraints for email, user-to-vault ownership, device-to-user identity, and any idempotency key.
- [ ] Enable and test SQLite foreign-key enforcement; verify migration order against existing installations.
- [ ] Protect database files, environment variables, backups, crash dumps, and CI artifacts with least privilege and encryption at rest.
- [ ] Keep server logs free of vault ciphertext, wrapped keys, auth verifiers, passwords, request bodies, and sensitive query values.
- [ ] Add structured security-event logging with retention, access control, redaction tests, and alerting for repeated auth failures, unusual device changes, and bulk errors.
- [ ] Add timeouts, connection limits, database busy handling, health/readiness checks, and safe degradation for dependency/database outages.

## 2.10 Testing and release gates

- [ ] Unit tests: KDF vectors, HKDF labels, AES-GCM round trips, tamper rejection, malformed encoding, key-wrap separation, schema parsing, and zeroization best-effort behavior.
- [ ] Client integration tests: signup, login, reload unlock, lock, logout, account switch, password change, device revoke, offline queue, sync retry, and conflict resolution.
- [ ] Server integration tests: route authorization, cookie attributes, session rotation, CSRF/origin, CORS, rate limits, enumeration, body limits, CAS, migration, and error redaction.
- [ ] Property/fuzz tests: encrypted envelope parsing, JSON/schema migration, intent replay/idempotency, server response parsing, and base64/size boundaries.
- [ ] Dynamic tests: XSS payloads in every user-controlled field, clickjacking, CSP reporting, cache inspection, service-worker behavior, and network downgrade attempts.
- [ ] Dependency/build tests: lockfile audit, `cargo audit`, npm/OSV audit, SBOM, secret scan, license scan, reproducible build comparison, and release artifact inspection.
- [ ] Operational drills: restore an encrypted backup, rotate session secrets, revoke all devices, rotate crypto parameters, handle a compromised client release, and recover from a failed migration.
- [ ] Release is blocked if any P0 item is open, if plaintext secrets appear in logs/builds, if production uses HTTP or a development secret, if migrations are untested, or if the server can receive plaintext vault data.

# 3. Suggested implementation order

1. **P0 trust-boundary cleanup:** remove logs/demo secrets, fix native CSPRNG/salt behavior, add input/size validation, enforce production HTTPS/secret handling, and add baseline tests.
2. **Authentication hardening:** rate limits, enumeration resistance, email uniqueness/normalization, CSRF/origin checks, production cookie policy, and a decision on PAKE/passkeys/static verifier compatibility.
3. **Lock and storage hardening:** real lock/autolock, account-scoped local storage, native secure storage, device enrollment/revocation, and explicit trusted-device policy.
4. **Crypto migration:** benchmark and version a stronger KDF, add envelope AAD/schema versioning, and implement password change/key rotation with recovery-safe migration.
5. **Sync reliability:** fix the SQLite timestamp schema, add lifecycle-aware pending-intent handling, enable triggers with backoff, build conflict/error UI, and expand integration tests.
6. **Password-manager essentials:** generator, password health, autofill, import/export/recovery, TOTP/passkeys, richer item types, and native platform support.
7. **Production operations:** headers, DB/backup controls, dependency governance, observability, restore/incident drills, and external security review.

# 4. Reference standards and guidance

- [OWASP Application Security Verification Standard (ASVS) 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP Cross-Site Scripting Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [NIST SP 800-63B-4: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html)

