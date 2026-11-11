# P0 — Restrictive web security headers, debug-route removal, and a built-artifact gate

**Status:** implemented in this worktree (M0–M3); see §11 for evidence, deviations, and the manual checks that still need a browser.
**Branch:** `p0/web-headers`
**Baseline citations:** the `file:line` references in §1–§2 describe the pre-change tree at `9a30011`; the implemented policy now lives in `apps/server/src/security_headers.rs` and the old `main.rs:300-306` block has moved.
**Source item:** `SECURITY_AND_FEATURE_ROADMAP.md:63`
**Scope:** the Actix response policy, the exported Expo web artifact, `apps/client/public/_headers`, the production debug route, and a release gate over `apps/client/dist`.
**Not in scope:** TLS termination, cookie transport policy, CSRF, rate limits, request bounds, log redaction, KDF/verifier work, extension manifest CSP. Overlaps are listed in §10.

---

## 1. Problem statement

### 1.1 What the code does today

The server sets exactly two browser-security headers, globally:

- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Embedder-Policy: require-corp`

at `apps/server/src/main.rs:300-306`. COOP/COEP are load-bearing: sqlite-wasm OPFS needs `SharedArrayBuffer`, and `crossOriginIsolated` is false without them. The API scope adds `Cache-Control: no-store` at `apps/server/src/main.rs:310-314`. The static Expo export is served by `static_site()` at `apps/server/src/main.rs:363` / `apps/server/src/static_site.rs:12-31`.

`apps/client/public/_headers:1-4` contains only the same COOP/COEP pair. That file is a **static-host** artifact (Cloudflare Pages/Netlify syntax); Actix does not read it. It is copied into `dist/` but has no runtime effect when the app is served by `apps/server`. COOP/COEP are additionally set by the Expo dev middleware at `apps/client/metro.config.js:27-32`, so there are three places with the pair, not two.

There is no `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, `Referrer-Policy`, `Permissions-Policy`, or HSTS on any response. The debug route is a normal Expo Router file at `apps/client/src/app/debug/index.tsx`; because `app.json:25-28` uses `web.output: "static"`, every route becomes an exported HTML file. A fresh `npm run build:web` at commit `9a30011` exported 13 routes including `/debug` and produced `dist/debug/index.html` (and the debug component is part of the single 4.7 MB entry bundle).

### 1.2 What an attacker actually gains

- **No CSP.** The app has no script-injection boundary. If any future item field is rendered as HTML, a dependency is compromised, or a browser extension injects a script, that script runs with the app origin, can read the in-memory vault key from the Zustand store, decrypt the vault, and call `/api/*` with the session cookie. A strict CSP does **not** save you from a malicious replacement bundle served from the same origin (that is the known limit in `README.md:202`), but it removes the much larger class of inline/remote-script injection and `eval` execution. For a password manager this is the main web defense-in-depth control.
- **No frame restriction.** Any website can iframe `http://localhost:8080` while the local server is running. The attacker cannot read the cross-origin DOM, but can overlay the app and induce clicks (reveal/copy/delete, settings changes). Precondition: the user visits the attacker's page while Voult is running and unlocked. This is classic clickjacking and is cheap to prevent.
- **No `nosniff`.** MIME confusion is a lower risk here, but the favicon proxy is the one place that serves attacker-influenced bytes (`apps/server/src/endpoints/favicon.rs:569-584`). A mislabeled response should not be re-interpreted as HTML/script.
- **No referrer policy.** The app has vault identifiers in query strings (`?recover=<vault_id>`, `?cloud_state=...`; `apps/client/src/app/_layout.tsx:83,92`). The default `strict-origin-when-cross-origin` limits cross-origin leakage to the origin, so this is not a vault-key leak, but `no-referrer` is the correct default for a password manager and removes the whole question.
- **No Permissions-Policy.** If script execution or framing is ever achieved, camera/microphone/geolocation/payment/USB/serial/HID are unnecessary capabilities. Least privilege; low direct risk, cheap to add.
- **No HSTS.** Only meaningful when the browser-facing origin is HTTPS. Today the server binds `localhost` (`apps/server/src/main.rs:365`) and speaks HTTP, so HSTS is inapplicable to the shipped Voult.app. For a future TLS/reverse-proxy deployment, its absence permits a first-visit SSL-stripping window. The precondition must be explicit, not an unconditional header on loopback.
- **Debug route.** The page opens SQLite for a hard-coded dummy ID, `DEV_USER_ID = "00000000-0000-4000-8000-000000000000"` (`apps/client/src/app/debug/index.tsx:9`), and dumps `client_state`/`intent` rows (`:24-38`). It does **not** open the user's vault, so this is not a direct plaintext leak. The concrete harm is different: `initSQLite()` calls `closeSQLite()` first (`apps/client/src/lib/sqlite/web/init-db.ts:23`), closes the active vault handle, then `setDb()` switches the process-global handle to the dummy database (`:34`). Any client-side navigation to `/debug` can therefore detach the live app from its real OPFS database and send subsequent service calls to an empty DB until reload. It is also an unnecessary production route and a visible internal-structure dump. Delete it.
- **No source-map/secret/network gate.** The current artifact happens to be clean: no `.map`, no `sourceMappingURL`, no server env values, no telemetry SDK in the bundle. But nothing prevents a future build flag, dependency, or accidental asset from shipping maps, a secret, or a third-party endpoint. The roadmap is right that the *test* is missing; it is wrong if read as "there is a current leak". See §1.4.

### 1.3 What "fixed" looks like

1. Every document and API response from Actix carries a tested production policy: strict CSP, `nosniff`, frame denial (CSP + legacy XFO), `no-referrer`, a minimal Permissions-Policy, and the existing COOP/COEP unchanged.
2. The CSP allows exactly what the real export needs: the one fixed Expo hydration snippet by SHA-256, the main same-origin bundle, inline styles (React Native Web injects them), `data:`/`blob:` images (the favicon cache stores data URLs), same-origin workers, `wasm-unsafe-eval` for SQLite WASM, and same-origin `connect-src`. It does **not** contain `script-src 'unsafe-inline'` or `'unsafe-eval'`.
3. HSTS is emitted only when the deployment declares HTTPS (`VOULT_HTTPS=1`); the loopback default emits neither HSTS nor `upgrade-insecure-requests`.
4. `/debug` is gone from source and from `dist/`; a regression check fails if it returns.
5. `npm run build:web` runs a dependency-free checker over `dist/` that fails on source maps, inline scripts outside the allowlist, debug artifacts, secret-shaped strings, telemetry SDKs, and unknown network hosts.
6. `public/_headers` mirrors the TLS policy for static-host deployments, and a Rust test keeps it from drifting from the server.
7. The favicon proxy's attacker-influenced bytes are served with `Content-Security-Policy: sandbox` so a directly navigated SVG cannot execute script in the app origin.

### 1.4 Roadmap accuracy check

| Claim | Verdict | Correction / evidence |
|---|---|---|
| "Only COOP/COEP and API `no-store` are present" | Mostly accurate | Accurate for Actix. COOP/COEP also exist in `apps/client/public/_headers:1-4` and the dev server `apps/client/metro.config.js:27-32`. `_headers` is not read by Actix. |
| "CSP, HSTS, nosniff, frame restrictions, referrer/permissions absent" | Accurate | No matches in server or client config. |
| "Expo debug route is part of the app route tree" | Accurate | `apps/client/src/app/debug/index.tsx`; fresh export produced `dist/debug/index.html` and 13 routes. |
| "Test the built artifact for source maps" | Accurate as a process gap | Current build has zero `.map` files and zero `sourceMappingURL` occurrences. Nothing enforces that. |
| "unexpected network access" | Accurate as a process gap | Current bundle has no telemetry-host literals and `posthog` occurs 0 times, although `posthog-react-native` is declared at `apps/client/package.json:33`. Remove the unused dependency. |
| "secret exposure" | Accurate as a process gap | Current bundle contains no server env names/values (`SESSION_COOKIE_KEY`, `GOOGLE_CLIENT_SECRET`, `DATABASE_URL` all 0). `vault_verifier` appears 5 times as a wire field name, not a value; do not flag it. |
| "HSTS (for HTTPS deployments)" | Needs a precondition | The server binds loopback HTTP (`main.rs:365`); there is no TLS deployment in the repo. HSTS must be opt-in, not default. |

---

## 2. Evidence

### 2.1 Source evidence

| Fact | Location |
|---|---|
| Global headers are only COOP/COEP | `apps/server/src/main.rs:300-306` |
| API `no-store` is scoped to `/api` | `apps/server/src/main.rs:310-314` |
| Static export served at `/` | `apps/server/src/main.rs:363`, `apps/server/src/static_site.rs:12-31` |
| Server binds loopback HTTP | `apps/server/src/main.rs:365` |
| Cookie `Secure` defaults false | `apps/server/src/main.rs:196-198` |
| Static-host headers are COOP/COEP only | `apps/client/public/_headers:1-4` |
| Dev server also sets COOP/COEP | `apps/client/metro.config.js:27-32` |
| Static export mode | `apps/client/app.json:25-28` |
| Debug route and dummy vault id | `apps/client/src/app/debug/index.tsx:9,24-38` |
| `initSQLite` closes the current DB before opening another | `apps/client/src/lib/sqlite/web/init-db.ts:23` |
| `initSQLite` switches the global DB handle | `apps/client/src/lib/sqlite/web/init-db.ts:34` |
| API is same-origin by default | `apps/client/src/lib/queries/http.ts:21-24`, `apps/client/src/lib/queries/api-url.ts:13` |
| OAuth is a top-level redirect, not a fetch | `apps/client/src/lib/cloud/api.ts:108-113` |
| Favicon cache renders `data:` URLs | `apps/client/src/lib/favicon/index.ts:118`, `apps/client/src/app/home/index.tsx:129-131` |
| Clipboard write is used | `apps/client/src/lib/settings/vault-section.tsx:58` |
| Recovery PDF uses a blob download | `apps/client/src/lib/auth/recovery-file.ts:53-64` |
| Favicon sniffing accepts SVG | `apps/server/src/endpoints/favicon.rs:380-407` |
| Declared `image/*` is trusted; otherwise sniffed | `apps/server/src/endpoints/favicon.rs:569-584` |
| Favicon response sets `CORP: cross-origin` | `apps/server/src/endpoints/favicon.rs:884-891` |
| Build command and release pipeline | `apps/client/package.json:10`, `scripts/build-release.sh:29-33` |

### 2.2 Built-artifact observations

A fresh export was run on 2026-10-28 at commit `9a30011` (same tree as `main`), using `EXPO_PUBLIC_API_URL= npx expo export --platform web`:

- 13 static routes exported, including `/debug`; `dist/debug/index.html` exists (18 KB).
- Every HTML route contains exactly one inline script:
  `globalThis.__EXPO_ROUTER_HYDRATE__=true;`
  Its SHA-256 is `sha256-67fhrP0+BkBqmgGGXTtgiVO/9EQs3QruYNU/7fnRkI8=`.
- One JS entry bundle (`entry-*.js`, ~4.7 MB); no route chunks.
- The bundle creates:
  - `new Worker("/sqlite/sqlite3-worker1.mjs", { type: "module" })`
  - `new Worker("/sqlite/sqlite3-opfs-async-proxy.js")`
  - loads `/sqlite/sqlite3.wasm` for `WebAssembly.instantiate`
- The bundle contains `data:image/svg+xml;base64,...` strings; the favicon cache also generates `data:` URLs. `img-src data:` is required.
- No `.map` files, no `sourceMappingURL` in JS/CSS/HTML.
- `posthog` occurs 0 times in the bundle; the dependency is unused.
- URL literals are documentation strings only (`www.w3.org`, `json-schema.org`, `reactnavigation.org`, `github.com`, `react.dev`, `emscripten.org`, `sqlite.org`) plus a library fallback `http://localhost` string. No analytics/telemetry host.
- `dist/_headers` is copied verbatim from `apps/client/public/_headers`.
- `eval(` occurs twice (uuidv4's node fallback, unreachable in a browser); `new Function` occurs twice (Zod's JIT probe inside `try/catch`, so a CSP block degrades to "no JIT", not a crash). This is why `script-src` can omit `'unsafe-eval'`.

These facts are reproducible with the commands in §9; the `dist/` directory is gitignored, so cite the build, not a tracked path.

---

## 3. Decisions

Each decision is final for this plan; rejected alternatives stay here so they are not reopened.

### D1 — Delete the debug route; do not `__DEV__`-gate it

Delete `apps/client/src/app/debug/` entirely.

**Why:** Expo Router has no supported route-exclusion key in `app.json` for this app. A `__DEV__` guard inside the component would still emit `debug/index.html`, keep the route discoverable, and keep the component + `DEV_USER_ID` in the entry bundle. That fails the roadmap's "remove from release bundles" requirement and leaves the DB-handle hazard one navigation away. The page has no references (`grep` finds only its own file) and no tests. Developer DB inspection remains available through browser devtools/OPFS, so nothing is lost.

**Rejected:** `if (!__DEV__) return null` (ships the route and code); moving the file outside `app/` and dynamically registering a dev-only route (Expo Router is filesystem-routed; fragile and unsupported); keeping it "because it only reads a dummy DB" (it still calls `initSQLite`, which closes the live handle).

### D2 — Enforce CSP; do not ship report-only

Ship `Content-Security-Policy` in M2. A temporary local `Content-Security-Policy-Report-Only` may be used while bringing the policy up, but it must not be in the tree at the end of M2.

**Why:** There is no CSP report collector, and adding one would create a new pre-auth endpoint plus a URL-logging surface — directly colliding with the P0 log-redaction item. Report-only would give a false sense of release readiness. The app has a small, fixed document surface; the policy can be verified in one browser pass.

**Rejected:** `Content-Security-Policy-Report-Only` as the shipped state; `report-uri`/`report-to` to the API.

### D3 — Hash the one inline Expo script; no script nonces and no `'unsafe-inline'`

`script-src 'self' 'sha256-67fhrP0+BkBqmgGGXTtgiVO/9EQs3QruYNU/7fnRkI8=' 'wasm-unsafe-eval'`.

**Why:** The export has exactly one inline script, identical on every route, and it is a fixed 40-byte constant. A hash is verifiable from the artifact and works on both Actix and static hosts. `'unsafe-inline'` would defeat the main control. A nonce requires rewriting every HTML response (Actix serves `NamedFile` unchanged, `apps/server/src/static_site.rs:12-31`) and cannot be mirrored in `_headers`; `'strict-dynamic'` would ignore `'self'` and break the plain bundle.

**Rejected:** `'unsafe-inline'`; per-response nonces; `'strict-dynamic'`; computing the hash from `dist/` at server startup (attacker-controlled `dist` would define its own allowlist, and it adds HTML parsing to boot).

**Maintenance:** if Expo changes the snippet, `npm run build:web` fails with the new hash; update `security_headers.rs` and `public/_headers`, and `cargo test` confirms both. That is two lines, gated by two tests.

### D4 — Keep `'wasm-unsafe-eval'`, do not add `'unsafe-eval'`

**Why:** `SharedArrayBuffer` is not enough; `WebAssembly.instantiate` needs `'wasm-unsafe-eval'` under CSP. The bundle's `eval` usage is the uuidv4 node fallback (unreachable because `crypto` exists in the browser), and `new Function` is Zod's JIT probe inside `try/catch` — blocking it only disables JIT. No app code needs JS eval.

**Rejected:** `'unsafe-eval'` (unnecessary and much broader); dropping SQLite WASM (not an option).

### D5 — `style-src 'self' 'unsafe-inline'`

**Why:** Expo's HTML contains two inline `<style>` blocks (`expo-reset`, `react-native-stylesheet`) and React Native Web injects style rules at runtime; nonces/hashes do not cover runtime style elements. The residual risk is CSS-only (overlay/phishing). External exfiltration through CSS is blocked because `img-src`, `font-src`, and `connect-src` are `'self'` (+ `data:`/`blob:` for images).

**Rejected:** `style-src 'self'` alone (breaks the app's styles); `'unsafe-inline'` for scripts (different and unacceptable).

### D6 — `worker-src 'self' blob:`

**Why:** Both real SQLite workers are same-origin (`/sqlite/sqlite3-worker1.mjs`, `/sqlite/sqlite3-opfs-async-proxy.js`). `blob:` is retained for React Native Web's `unstable_createWorker` helper, which constructs a blob worker when `crossOriginIsolated` is true; tightening it to `'self'` would be a follow-up only after a browser pass shows the helper is unreachable. The script itself is still constrained by `script-src`; a blob worker cannot import remote code.

**Rejected:** `worker-src 'none'` (breaks SQLite); `worker-src *` (unnecessary).

### D7 — `img-src 'self' data: blob:`

**Why:** The favicon cache turns proxied bytes into `data:image/...;base64` URLs (`apps/client/src/lib/favicon/index.ts:118`) and renders them through `<Image>` (`apps/client/src/app/home/index.tsx:129-131`). Expo also embeds `data:image/svg+xml` assets. `blob:` covers any future object-URL image preview; the recovery PDF's blob download (`apps/client/src/lib/auth/recovery-file.ts:56`) is not an image load, so it does not require `img-src`, but allowing `blob:` is harmless.

**Rejected:** `img-src 'self'` only (breaks every cached favicon); `img-src https:` (would re-open direct third-party image loads and defeat the favicon proxy's privacy design).

### D8 — `connect-src 'self'`

**Why:** The only API origin is the same-origin `/api` (`apps/client/src/lib/queries/http.ts:21-24`, `api-url.ts:13`). Google/Dropbox OAuth is a full-window navigation to a server-provided URL (`apps/client/src/lib/cloud/api.ts:108-113`), not a `fetch`, so it is unaffected. This also fails closed if a future dependency tries to phone home.

**Rejected:** listing provider origins (the client never calls them); `connect-src *` (no).

**Deployment constraint:** same-origin production is the only supported web deployment. `build:web` deliberately clears `EXPO_PUBLIC_API_URL` (`apps/client/package.json:10`). Split-origin is a dev-only mode and is served by Metro, which does not apply this CSP. A future split-origin production build would need its own policy; do not silently widen this one.

### D9 — HSTS only behind `VOULT_HTTPS=1`; never infer from `X-Forwarded-Proto`

Add `VOULT_HTTPS` (boolean, default off). When set, add `Strict-Transport-Security: max-age=31536000` and append `upgrade-insecure-requests` to the CSP. Do not add `includeSubDomains` or `preload`.

**Why:** The shipped server binds `localhost` and speaks HTTP (`main.rs:365`); HSTS is meaningless there and `upgrade-insecure-requests` would break the app by rewriting `http://localhost:8080` to HTTPS. There is no trusted-proxy configuration in the repo, so reading `X-Forwarded-Proto` would let a client spoof the scheme. `includeSubDomains`/`preload` are domain-owner decisions that can break sibling services and are hard to undo; leave them out.

**Rejected:** emitting HSTS unconditionally (wrong on loopback); deriving it from `SESSION_COOKIE_SECURE` (that flag can be true on localhost and is owned by the P1 transport item); trusting `X-Forwarded-Proto` without a proxy allowlist.

**Precondition recorded for operators:** set `VOULT_HTTPS=1` only when the browser-facing origin is HTTPS, either direct TLS or a trusted TLS-terminating reverse proxy that forwards HTTP to Actix. `SESSION_COOKIE_SECURE` remains a separate switch (P1 transport item); a correct remote deployment sets both.

### D10 — Keep COOP/COEP exactly; do not add a global CORP

`Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp` stay on every response. No `Cross-Origin-Resource-Policy` is added globally.

**Why:** COOP/COEP are required for `SharedArrayBuffer` and are the one header pair that must not regress. A global `CORP: same-origin` would conflict with the favicon proxy's deliberate `CORP: cross-origin` (`favicon.rs:884-891`) and can break the extension/split-origin dev page that embeds proxied icons. The favicon handler already owns its CORP value.

**Rejected:** `CORP: same-origin` globally; `COEP: credentialless` (not needed; would change isolation semantics).

### D11 — `public/_headers` mirrors the TLS policy; it is not deleted

Keep `_headers` and make it the static-host mirror of the Rust policy. A Rust test parses it with `include_str!` and compares it to `HeaderPolicy { https: true }`.

**Why:** `_headers` is the only way a plain static-host deployment (Cloudflare Pages/Netlify) gets COOP/COEP; deleting it would silently break sqlite-wasm there. It is also named in `README.md:182` and the roadmap. The duplication is contained by the parity test.

**Rejected:** deleting `_headers` (breaks static-host COOP/COEP); generating it at build time (adds a generated tracked file and a second writer for a 10-line policy); relying on host dashboards (not reproducible).

**Note:** `_headers` is TLS-only (HSTS + `upgrade-insecure-requests`) because the hosts that honor this format serve HTTPS. The Actix server, which is the shipped path, computes HTTP vs HTTPS from `VOULT_HTTPS`.

### D12 — Wire the artifact gate into `build:web`, fail closed

`"build:web": "npm --prefix ../../packages/vault-core run build && EXPO_PUBLIC_API_URL= expo export --platform web && node scripts/check-web-dist.mjs"`, plus `"check:web-dist": "node scripts/check-web-dist.mjs"`.

**Why:** A separate script that nobody runs is not a release control. `scripts/build-release.sh:29-33` runs `npm run build:web`, so the gate runs in the release build automatically. No new dependency; Node built-ins only.

**Rejected:** a CI-only job (there is no client CI job today, and local/release builds would still ship maps); a shell script with `grep` (harder to parse HTML/hashes portably).

### D13 — Remove `posthog-react-native`

`npm uninstall posthog-react-native` in `apps/client`; update the tracked `package-lock.json`.

**Why:** No source imports it (`grep` finds only `package.json` and lockfile). It is an unused analytics SDK in a password manager, and its presence invites accidental telemetry. The bundle already contains zero posthog references, so removal is a supply-chain/dependency hygiene change, not a runtime change. The lockfile is tracked, so the change is reviewable.

**Rejected:** leaving it "for later" (no code uses it); adding it to a denylist only (still installed, still upgradable).

### D14 — `Content-Security-Policy: sandbox` on favicon responses

Add a handler-level `Content-Security-Policy: default-src 'none'; sandbox` on `icon_response()` (`favicon.rs:887-891`). Keep `CORP: cross-origin` and the existing content-type checks.

**Why:** The proxy can return `image/svg+xml`, either declared `image/*` or sniffed (`favicon.rs:380-407,569-584`). An SVG navigated directly is a document and can carry script; `nosniff` does not stop SVG scripting. `sandbox` gives the document an opaque origin and blocks scripts/forms; `default-src 'none'` blocks its subresources. Actix's `DefaultHeaders` deliberately does **not** overwrite an existing response header (`actix-web-4.12.1/src/middleware/default_headers.rs:177`), so this handler-level CSP is what a favicon response carries; that is safe because the response is an image, not the app document. It does not affect `<img>` rendering or the client's `fetch` of icon bytes.

**Rejected:** banning SVG (loses real favicons); `Content-Disposition: attachment` (may prevent `<img>` rendering and is a behavior change); relying on the global CSP alone (correct today, but one handler-level header replacement would remove it).

### D15 — No CSP reporting endpoint, no Trusted Types, no static cache-header redesign

**Why:** A report endpoint would add a pre-auth route and a URL/log surface (P0 log-redaction overlap). Trusted Types would require auditing React Native Web/Expo DOM sinks and is not release-ready. Static caching is not a security-header requirement; changing it risks stale-shell behavior. These are explicitly out of scope, not forgotten.

**Rejected:** `report-to`/`report-uri`; `require-trusted-types-for 'script'`; global `Cache-Control: no-store`.

---

## 4. Target policy

### 4.1 CSP (HTTP, default)

One line, semicolon-separated:

```text
default-src 'none'; script-src 'self' 'sha256-67fhrP0+BkBqmgGGXTtgiVO/9EQs3QruYNU/7fnRkI8=' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; manifest-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

With `VOULT_HTTPS=1`, append `; upgrade-insecure-requests`.

`'wasm-unsafe-eval'` is supported by the browsers that can run this app at all (OPFS + `SharedArrayBuffer` already require a modern engine: Chrome 97+/Firefox 102+/Safari 16.4+ for the CSP token). A browser that does not understand it fails closed with a console error and no SQLite; that is preferable to shipping `'unsafe-eval'`. Record this in the README support note rather than adding a fallback.

Directive rationale:

| Directive | Value | Why |
|---|---|---|
| `default-src` | `'none'` | Everything else is explicit. |
| `script-src` | `'self'` + hydration hash + `'wasm-unsafe-eval'` | Main bundle, the one inline Expo script, SQLite WASM. No inline event handlers, no eval, no remote scripts. |
| `style-src` | `'self' 'unsafe-inline'` | Expo's inline `<style>` blocks and React Native Web runtime styles. |
| `img-src` | `'self' data: blob:` | Favicon proxy (same-origin), cached favicon data URLs, object URLs. |
| `font-src` | `'self'` | `/fonts/InterVariable-*.woff2` (verified in the built CSS). |
| `connect-src` | `'self'` | The only API origin; `/api/favicon`; no provider calls. |
| `worker-src` | `'self' blob:` | SQLite module/classic workers; RN-Web blob-worker helper. |
| `manifest-src` | `'self'` | Future web manifest; harmless if absent. |
| `object-src` | `'none'` | No plugins/embeds. |
| `frame-src` | `'none'` | No iframes. |
| `frame-ancestors` | `'none'` | No framing; modern clickjacking control. |
| `base-uri` | `'none'` | No `<base>` injection. |
| `form-action` | `'self'` | No cross-origin form posts; OAuth is a navigation, not a form. |
| `upgrade-insecure-requests` | TLS only | Avoid breaking loopback HTTP. |

**Not present, deliberately:** `'unsafe-eval'`, `script-src 'unsafe-inline'`, `connect-src *`, `img-src https:`, `frame-ancestors *`, `report-uri`, `sandbox` (except favicon responses).

### 4.2 Header table

| Header | Value | Notes |
|---|---|---|
| `Content-Security-Policy` | §4.1 | All responses (JSON/CSS/JS ignore it; one code path is simpler and avoids bypasses). Favicon responses carry the handler-level §4.4 sandbox policy instead, because `DefaultHeaders` does not overwrite an existing value. |
| `Cross-Origin-Opener-Policy` | `same-origin` | Unchanged; required for `crossOriginIsolated`. |
| `Cross-Origin-Embedder-Policy` | `require-corp` | Unchanged; required for `SharedArrayBuffer`. |
| `X-Content-Type-Options` | `nosniff` | All responses. |
| `X-Frame-Options` | `DENY` | Legacy complement to `frame-ancestors`. |
| `Referrer-Policy` | `no-referrer` | All responses; no vault IDs in `Referer`. |
| `Permissions-Policy` | `accelerometer=(), browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(self), display-capture=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=()` | `clipboard-write=(self)` is required by `vault-section.tsx:58`. Everything else is denied. |
| `Strict-Transport-Security` | `max-age=31536000` | Only when `VOULT_HTTPS=1`. No `includeSubDomains`, no `preload`. |
| `Cache-Control` | `no-store` | Existing `/api` scope only (`main.rs:310-314`); do not globalize. |

No `Cross-Origin-Resource-Policy` is added by the policy. The favicon handler keeps its own `CORP: cross-origin` (`favicon.rs:890`).

### 4.3 HSTS / TLS decision record

- Default deployment: `http://localhost:8080`, loopback, no HSTS, no `upgrade-insecure-requests`.
- Remote/TLS deployment: operator sets `VOULT_HTTPS=1` and `SESSION_COOKIE_SECURE=true`; TLS terminates before Actix (directly or via a trusted proxy). Actix never inspects `X-Forwarded-Proto`.
- The static-host `_headers` file is TLS-only because static hosts that honor it serve HTTPS; it carries HSTS and `upgrade-insecure-requests`.
- HSTS `max-age` is one year without subdomains/preload. This is intentionally conservative; a domain owner can add those at the proxy/host layer after deciding the blast radius.

### 4.4 Favicon response

- Keep `content_type` from the existing declared/sniffed logic (`favicon.rs:569-584`).
- Keep `Cross-Origin-Resource-Policy: cross-origin`.
- Add `Content-Security-Policy: default-src 'none'; sandbox`.
- Global `nosniff` applies.
- Do not change the SSRF, redirect, size, or cache behavior in this item (P1 favicon SSRF owns that).

### 4.5 Static-host `_headers`

`apps/client/public/_headers` becomes:

```text
# Static-host deployment headers (Cloudflare Pages / Netlify syntax).
# Voult.app is normally served by apps/server, which sets the same policy in
# apps/server/src/security_headers.rs. This file is the TLS static-host mirror;
# keep it in sync — `cargo test` compares the two.
/*
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Embedder-Policy: require-corp
  Content-Security-Policy: default-src 'none'; script-src 'self' 'sha256-67fhrP0+BkBqmgGGXTtgiVO/9EQs3QruYNU/7fnRkI8=' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self' blob:; manifest-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; upgrade-insecure-requests
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Permissions-Policy: accelerometer=(), browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(self), display-capture=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=()
  Strict-Transport-Security: max-age=31536000
```

`_headers` has no `Cache-Control`; API `no-store` is a server concern. It is copied to `dist/_headers` by Expo and ignored by Actix. A static-host deployment is only usable if `/api` is reverse-proxied on the **same origin**; otherwise `connect-src 'self'` blocks the app. Cloudflare also does not apply `_headers` to Pages Functions, so an API implemented as a Function needs its own header code. Do not enable Cloudflare Web Analytics on this project: it injects a third-party script that the CSP blocks.

---

## 5. Files to touch

### New

| File | Purpose |
|---|---|
| `apps/server/src/security_headers.rs` | Policy constants/constructor, `DefaultHeaders` builder, unit + integration tests, `_headers` parity test. |
| `apps/client/scripts/check-web-dist.mjs` | Dependency-free built-artifact gate (maps, inline scripts/hash, debug route, secrets, telemetry, hosts). |

### Edit

| File | Change |
|---|---|
| `apps/server/src/main.rs` | `mod security_headers;`; read `VOULT_HTTPS`; replace the COOP/COEP-only `DefaultHeaders` at `:300-306` with the policy builder registered **last** (outermost, after CORS) so preflight/error responses get headers; keep the `/api` `no-store` scope at `:310-314`; log one startup line with `https`/`hsts` booleans (no header values/secrets). |
| `apps/server/src/config.rs` | Add `ENV_VOULT_HTTPS: &str = "VOULT_HTTPS"` and `pub fn https_enabled() -> bool` (accept `1`/`true`, case-insensitive; default false); add the env-table row in the module docs. |
| `apps/server/src/endpoints/favicon.rs` | Add `Content-Security-Policy: sandbox` to `icon_response()` (`:887-891`); extend the existing response test. Do not touch fetch/SSRF/cache logic. |
| `apps/client/public/_headers` | Replace COOP/COEP-only content with the §4.5 TLS mirror. |
| `apps/client/package.json` | Add `check:web-dist`; chain it after `expo export` in `build:web`; remove `posthog-react-native` from dependencies. |
| `apps/client/package-lock.json` | Regenerated by `npm uninstall posthog-react-native`. Tracked; include it. |
| `apps/client/src/app/debug/index.tsx` | **Delete** the file and its directory. No imports/tests reference it. |
| `.env.example` | Document `VOULT_HTTPS` with the TLS precondition and default-off warning. |
| `README.md` | Add `VOULT_HTTPS` to the config table; update the COOP/COEP gotcha to mention CSP/`_headers` and the artifact check; update the Security Notes sentence that lists CSP as an open gap (`README.md:202`); keep the "same-origin bundle compromise is not fixed by CSP" caveat. |
| `apps/server/architecture.md` | Add a short "Response headers" subsection: the policy lives in `security_headers.rs`, is applied outermost, favicon carries its own sandbox CSP, and HSTS is `VOULT_HTTPS`-gated. |
| `AGENTS.md` | Update Commands (`build:web` now checks `dist`), Env/config (add `VOULT_HTTPS`), and Gotchas (CSP hash maintenance; `/debug` is deleted; `_headers` is a static-host mirror). |
| `SECURITY_AND_FEATURE_ROADMAP.md` | Mark the item `[x]` with the implementation evidence and a changelog entry; correct "only COOP/COEP" to note the third dev-server location. |

### Do not touch

| File / area | Why |
|---|---|
| `apps/client/app.json` | `web.output: "static"` stays; Expo Router has no route-exclusion config, and deleting the source route is the correct exclusion. `headers` is not an Expo app config key. |
| `apps/client/metro.config.js` | Dev server COOP/COEP stays; CSP is a production/Actix concern. Adding CSP here would fight Metro HMR (`eval`, websockets, blob workers) without protecting the shipped app. |
| `apps/server/src/static_site.rs` | The extensionless-path fallback is how Expo Router handles client routes. After deleting `/debug`, `GET /debug` still returns `index.html` (200) and the client renders `+not-found`; do **not** turn extensionless routes into server 404s. |
| `apps/client/src/lib/queries/http.ts`, `api-url.ts` | Already same-origin; `connect-src 'self'` matches. No code change needed. |
| `apps/client/src/lib/state/*`, `_layout.tsx` bootstrap, `session_auth.rs`, `auth.rs`, recovery endpoints | Header work must not alter session, lock, vault-selection, or recovery semantics. |
| `packages/vault-core` crypto/schema | Zero wire/format change. |
| `apps/extension` | Its own MV3 CSP/manifest is a separate surface; server headers do not apply to extension pages. |
| Favicon SSRF/redirect/size/cache logic | Only add the response header; P1 favicon SSRF owns the rest. |
| `apps/server/src/main.rs` logger/session/CORS setup | Other P0/P1 items own log redaction, cookie transport, and CSRF. |

---

## 6. Concrete implementation shapes

### 6.1 `apps/server/src/security_headers.rs`

```rust
use std::str::FromStr;
use actix_web::http::header::HeaderValue;
use actix_web::middleware::DefaultHeaders;

pub const INLINE_HYDRATE_SCRIPT: &str = "globalThis.__EXPO_ROUTER_HYDRATE__=true;";
pub const INLINE_HYDRATE_SHA256: &str =
    "sha256-67fhrP0+BkBqmgGGXTtgiVO/9EQs3QruYNU/7fnRkI8=";
pub const PERMISSIONS_POLICY: &str = "accelerometer=(), browsing-topics=(), camera=(), clipboard-read=(), clipboard-write=(self), display-capture=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), serial=(), usb=()";

pub struct HeaderPolicy {
    /// True only when the browser-facing origin is HTTPS (direct or trusted proxy).
    pub https: bool,
}

impl HeaderPolicy {
    pub fn new(https: bool) -> Self { Self { https } }

    pub fn csp(&self) -> String {
        let script_src = format!(
            "script-src 'self' '{INLINE_HYDRATE_SHA256}' 'wasm-unsafe-eval'"
        );
        let mut directives = vec![
            "default-src 'none'".to_string(),
            script_src,
            "style-src 'self' 'unsafe-inline'".to_string(),
            "img-src 'self' data: blob:".to_string(),
            "font-src 'self'".to_string(),
            "connect-src 'self'".to_string(),
            "worker-src 'self' blob:".to_string(),
            "manifest-src 'self'".to_string(),
            "object-src 'none'".to_string(),
            "frame-src 'none'".to_string(),
            "frame-ancestors 'none'".to_string(),
            "base-uri 'none'".to_string(),
            "form-action 'self'".to_string(),
        ];
        if self.https {
            directives.push("upgrade-insecure-requests".to_string());
        }
        directives.join("; ")
    }

    /// The full header set, used by both the server and the `_headers` parity test.
    pub fn headers(&self) -> Vec<(&'static str, String)> {
        let mut out = vec![
            ("Content-Security-Policy", self.csp()),
            ("Cross-Origin-Opener-Policy", "same-origin".into()),
            ("Cross-Origin-Embedder-Policy", "require-corp".into()),
            ("X-Content-Type-Options", "nosniff".into()),
            ("X-Frame-Options", "DENY".into()),
            ("Referrer-Policy", "no-referrer".into()),
            ("Permissions-Policy", PERMISSIONS_POLICY.into()),
        ];
        if self.https {
            out.push(("Strict-Transport-Security", "max-age=31536000".into()));
        }
        out
    }
}

pub fn default_headers(https: bool) -> DefaultHeaders {
    let mut headers = DefaultHeaders::new();
    for (name, value) in HeaderPolicy::new(https).headers() {
        headers = headers.add((
            name,
            HeaderValue::from_str(&value).expect("static security header value"),
        ));
    }
    headers
}
```

`PERMISSIONS_POLICY` is the exact §4.2 string. `HeaderValue::from_str` runs once per worker; all values are static constants, so the `expect` is a programming-error guard, not input handling.

The sketch is the final shape. M1 adds only the non-CSP rows; M2 adds `csp()`/the CSP row; M3 enables the `https` branch through `VOULT_HTTPS`.

**Tests in the module:**

1. `inline_hash_is_pinned`: `sha2::Sha256::digest(INLINE_HYDRATE_SCRIPT)` + `base64::STANDARD` equals `INLINE_HYDRATE_SHA256`. Uses existing `sha2`/`base64` deps; no new dependency.
2. `csp_is_strict`: contains `'wasm-unsafe-eval'`, `worker-src 'self' blob:`, `img-src 'self' data: blob:`, `connect-src 'self'`, `frame-ancestors 'none'`, `base-uri 'none'`; does **not** contain the exact quoted `'unsafe-eval'` token, and the parsed `script-src` directive contains no `'unsafe-inline'`.
3. `coop_coep_are_exact`: values are `same-origin` / `require-corp`.
4. `hsts_is_tls_only`: `HeaderPolicy::new(false)` has no HSTS/`upgrade-insecure-requests`; `new(true)` has both.
5. `static_headers_file_matches_tls_policy`: parse `include_str!("../../client/public/_headers")` (skip `#` comments, blank lines, and the `/*` scope line; split `Key: Value` on the first colon), compare the map to `HeaderPolicy::new(true).headers()`. This is the drift guard between Rust and `_headers`.
6. `headers_are_applied_to_routes`: `actix_web::test` app with `wrap(default_headers(false))` and a trivial handler; assert every header on `/`, a 404, and an `OPTIONS` response. This proves the middleware is outermost and includes error/preflight responses.
7. `static_html_gets_headers`: temporary dir with `index.html`, `static_site()` + middleware, assert `Content-Type: text/html` and the policy headers. Use `std::fs`/`std::env::temp_dir`; no `tempfile` dependency.
8. `favicon_response_is_sandboxed` (in `favicon.rs` tests): `icon_response(b"<svg/>".to_vec(), "image/svg+xml".into())` has `Content-Security-Policy: default-src 'none'; sandbox` and `CORP: cross-origin`.

### 6.2 `main.rs` wiring

```rust
mod security_headers;
// ...
let https = config::https_enabled();
SERVER_LOG.log(
    format_args!("web security: https={https} hsts={https}"),
    logger::metadata! { "https" => https },
);
// ...
.wrap(middleware::Logger::default())
.wrap(session_middleware)
.wrap(cors)
// Last wrap = outermost, so CORS short-circuits (preflight) and error
// responses still pass through the security headers. The old COOP/COEP
// DefaultHeaders was registered first (innermost).
.wrap(security_headers::default_headers(https))
```

`https` is `Copy`, so it moves into the `HttpServer::new(move || …)` closure without cloning state. Keep the `/api` scope's `no-store` exactly where it is. Do not log the CSP or any header value. If the integration test shows a response path that bypasses the outermost wrap (it should not), that is a bug in the test setup, not a reason to move the headers inward.

### 6.3 `apps/client/scripts/check-web-dist.mjs`

Node built-ins only (`node:fs`, `node:path`, `node:crypto`). Read `dist/` recursively and fail with a clear message. Checks:

1. **Shape:** `dist/index.html` exists; `dist/debug/` does not; no HTML contains `Debug Page` or `DEV_USER_ID`; no JS contains those markers.
2. **Source maps:** no file ending `.map`; no `sourceMappingURL` in any `.js`/`.css`/`.html`.
3. **Inline scripts:** for every HTML file, every `<script>` without `src` must have body exactly `globalThis.__EXPO_ROUTER_HYDRATE__=true;`. Compute its SHA-256/base64. M0 prints/reports it; M2 additionally requires the `sha256-…` token in `dist/_headers`' CSP to match. Also fail on `on<event>=` attributes or `javascript:` in HTML.
4. **Header file:** `dist/_headers` exists; parse its `/*` block; assert exact COOP/COEP, HSTS, and that the CSP has the required directives, the hash from step 3, and **no** `script-src` `'unsafe-inline'`/`'unsafe-eval'`.
5. **Secrets:** fail on filenames `.env*`, `*.pem`, `*.key`, `*.p12`, `*.mobileprovision`, `vault.db`, `session.key`; fail on strings `SESSION_COOKIE_KEY`, `GOOGLE_CLIENT_SECRET`, `DROPBOX_CLIENT_SECRET`, `DATABASE_URL`, `-----BEGIN`, `AKIA`, `ghp_`, `xoxb-`, `xoxp-`. Do **not** flag `vault_verifier` (wire field name) or `process.env` (library internals). Additionally scan `apps/client/src` and `packages/vault-core/src` for `process.env.`: allow only `EXPO_PUBLIC_API_URL` and `NODE_ENV`; fail on any other `EXPO_PUBLIC_*`, and fail on any `EXPO_PUBLIC_*` name containing `SECRET`, `KEY`, `TOKEN`, or `PASSWORD`.
6. **Telemetry:** fail on SDK identifiers/hosts, not common words, using word-boundary matching: `posthog`, `sentry`, `amplitude`, `mixpanel`, `datadog`, `bugsnag`, `fullstory`, `hotjar`, plus `segment.io`/`api.segment.io`/`analytics.js`. Boundary matching matters: bare `segment` occurs 20 times in the router bundle, and `sentry` occurs inside `fsEntryName` in the sqlite worker. Current bundle: 0 for all of these; keep it that way.
7. **Hosts:** extract `https?://host` from JS/HTML. Normalize with `new URL(...).hostname` where parseable, trim trailing punctuation/colon, and skip unparseable strings and single-label hosts except `localhost`. Allowlist with reasons: `www.w3.org`, `json-schema.org`, `reactnavigation.org`, `github.com`, `react.dev`, `emscripten.org`, `sqlite.org`, `developer.chrome.com` (sqlite OPFS comment link), `tailwindcss.com` (CSS license comment), `localhost` (library fallback). Any other host fails with "new network destination — review and add to allowlist only if it is inert documentation". Also fail on `url(http` in CSS (remote CSS asset).
8. **Summary:** print counts (HTML routes, JS bundles, maps, unknown hosts, secret markers, telemetry markers). Never print file contents or env values.

The script must be careful about false positives: the host scan is a tripwire for *new* dependencies, not a proof that a string is a request; `connect-src 'self'` is the runtime proof.

### 6.4 Package scripts

```json
"build:web": "npm --prefix ../../packages/vault-core run build && EXPO_PUBLIC_API_URL= expo export --platform web && node scripts/check-web-dist.mjs",
"check:web-dist": "node scripts/check-web-dist.mjs"
```

`EXPO_PUBLIC_API_URL=` remains scoped to `expo export`. `scripts/build-release.sh:29-33` already invokes `npm run build:web`, so the gate runs in the DMG build.

---

## 7. Trust boundary — what this must NOT break

- **SQLite / `SharedArrayBuffer`:** COOP/COEP must remain byte-for-byte `same-origin` / `require-corp` on every document. `crossOriginIsolated === true`, `new Worker("/sqlite/sqlite3-worker1.mjs")`, `/sqlite/sqlite3-opfs-async-proxy.js`, and `/sqlite/sqlite3.wasm` must all work. The CSP contains `worker-src 'self' blob:` and `'wasm-unsafe-eval'` for exactly this reason.
- **Per-vault isolation:** no change to OPFS names, IndexedDB keys, or the `VaultState` union. Header work is response-only.
- **Zero-knowledge:** no new request fields, no plaintext/key material in headers, logs, or build output. The server still sees only ciphertext/salt/iterations/verifier/envelopes.
- **Session semantics:** no change to `session_auth.rs`, cookie flags, 401/`SESSION_REQUIRED` handling, or the `http.ts` interceptor. `no-referrer`/CSP must not prevent the session cookie from being sent to same-origin `/api`.
- **Recovery Rule R1:** no crypto/envelope change. The recovery PDF download must still work under `default-src 'none'`/`frame-src 'none'` (it is an `<a download>` to a blob URL, not a frame/navigation policy target).
- **OAuth:** the client's full-window `window.location.href = authUrl` (`cloud/api.ts:112`) must still leave and return. Do not add `form-action` restrictions that treat it as a form; it is not one. Do not add `navigate-to` (unsupported/overbroad).
- **Extension:** server headers do not apply to extension pages. Do not add global CORP or change the favicon `CORP: cross-origin`; extension/split-origin icon loads depend on it. Extension fetches are CORS, not documents.
- **Favicon privacy:** keep the proxy same-origin and `no-store`; `img-src 'self'` is deliberate, not an accident.
- **Static routing:** `/debug` after deletion must render the client `+not-found` via the extensionless `index.html` fallback (HTTP 200), not a server 404. Do not "fix" `static_site.rs` to 404 client routes.
- **Dev workflow:** `npm run web` (Metro) keeps only COOP/COEP; it is not the production CSP. A developer seeing no CSP in dev is expected. Do not add a CSP that breaks HMR.
- **No secret in headers:** CSP/HSTS/Permissions values are static. Do not log them per request or include vault IDs.

---

## 8. Phases

Each phase leaves the tree working. M0 is pipeline/foundation; M3 is the final hardening pass.

**Failure policy:** a CSP violation is a blocker, not a reason to add `'unsafe-inline'`/`'unsafe-eval'` or ship report-only. Add only the narrowest missing source and record it in §4.1 with evidence. If the Expo hydration snippet changes, the build check fails and the fix is to update the hash in `security_headers.rs` and `public/_headers` (the Rust test then confirms both match).

### M0 — Remove the debug route and add the artifact gate

**Changes:**
- Delete `apps/client/src/app/debug/` (`index.tsx` only; no references).
- Add `apps/client/scripts/check-web-dist.mjs` with checks 1, 2, 3 (inline-script allowlist; compute and report the hash, but do not require a CSP entry yet), and 5–8 from §6.3.
- Add `check:web-dist`; chain it into `build:web`.
- Remove `posthog-react-native` and regenerate `package-lock.json`.
- Do not touch server headers yet.

**Why first:** it removes the production debug surface and makes every later CSP change verifiable against the real artifact. It is independent of the header work and cannot break the app.

**Acceptance:**
1. `cd apps/client && npm run build:web` succeeds; the export lists **12** routes (not 13) and `dist/debug/` does not exist.
2. `find dist -name '*.map'` prints nothing; `grep -R "sourceMappingURL" dist` prints nothing.
3. `npm run check:web-dist` exits 0 and prints a summary.
4. Negative test: `touch dist/check-map.map && npm run check:web-dist` exits non-zero with a source-map message; `rm dist/check-map.map` and re-run exits 0. (This proves the gate is not a no-op.)
5. `grep -R "Debug Page\|DEV_USER_ID" dist` prints nothing.
6. `npx tsc --noEmit` passes after the export (typed routes regenerate).
7. `/debug` no longer has a dedicated artifact: `ls dist/debug` fails. A browser at `/debug` loads the app shell via `static_site`'s extensionless fallback (`static_site.rs:21-28`) and renders the client `+not-found` screen; HTTP status is 200, which is correct for client-side routing. Do not expect a server 404.

### M1 — Add the non-CSP security headers and their tests

**Changes:**
- Add `security_headers.rs` with `HeaderPolicy`, `PERMISSIONS_POLICY`, `default_headers`, and tests 1, 3, 6, 7 from §6.1 (the hash-pin test is already useful; the CSP strictness test lands in M2 and the HSTS test in M3).
- Replace the COOP/COEP-only wrap at `main.rs:300-306` with `security_headers::default_headers(false)` in this phase (no env yet).
- Keep `/api` `no-store` untouched.
- Do **not** add CSP or HSTS yet.

**Why:** non-CSP headers are low-risk and prove the middleware is applied to documents, 404s, preflights, and static files before the CSP can break anything.

**Acceptance:**
1. `cd apps/server && cargo test` passes (existing + new tests).
2. `cargo run`; `curl -s -D - -o /dev/null http://localhost:8080/` shows COOP, COEP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`; no HSTS; no CSP yet.
3. `curl -s -D - -o /dev/null http://localhost:8080/api/session` shows the same security headers **plus** `Cache-Control: no-store`.
4. `curl -s -o /dev/null -w '%{http_code}' -X OPTIONS http://localhost:8080/api/session` (or the CORS preflight for a real origin) still returns the expected status and carries the headers.
5. Browser: `crossOriginIsolated` is `true`; create/open a vault, add an item, reload, lock/unlock — all still work (no CSP yet, so this is a regression check for header middleware ordering).
6. Framing test: a local page with `<iframe src="http://localhost:8080/">` is refused (XFO) and the console reports it.

### M2 — Enforce CSP and sandbox favicon responses

**Changes:**
- Add `csp()` to `HeaderPolicy` with the §4.1 HTTP string and the hash constant.
- Add `Content-Security-Policy` to `headers()`.
- Update `public/_headers` with the §4.5 **TLS** policy (CSP + non-CSP headers; HSTS/upgrade are included here because `_headers` is TLS-only).
- Add the `_headers` parity test (test 5) and the CSP strictness test (test 2).
- Add `Content-Security-Policy: sandbox` to `icon_response()` and test 8.
- Extend the Node checker: require the computed hash to match `dist/_headers`, and assert the CSP directives/no-unsafe rules.
- Keep `https = false` in `main.rs` for this phase (no HSTS/upgrade yet).

**Why:** this is the risky phase; it is isolated after the artifact gate and non-CSP headers are proven.

**Acceptance:**
1. `cargo test` passes, including the parity test and the inline-hash pin.
2. `npm run build:web` passes the checker; the hash in `dist/_headers` matches the HTML inline script.
3. `curl -s -D - -o /dev/null http://localhost:8080/` shows the exact CSP; no `'unsafe-eval'`, no `script-src 'unsafe-inline'`, no HSTS/upgrade (https=false).
4. Browser `/`, `/auth/signup`, `/auth/login`, `/home`, `/settings`: DevTools console has **no** CSP violations; `crossOriginIsolated === true`.
5. Full local flow: create vault → save recovery PDF → add an item → reload → lock → unlock with password/device. SQLite works; no data loss; no `initSQLite`-related errors.
6. Favicon: an item with a site icon renders the cached icon (data URL) under `img-src data:`; no CSP violation.
7. Settings → Vault → copy ID succeeds (`clipboard-write=(self)`).
8. Recovery PDF downloads and opens (blob download under CSP).
9. Backup → connect: the OAuth full-window redirect starts (if provider env is configured; otherwise record "not exercised").
10. Direct navigation to a favicon SVG response shows `Content-Security-Policy: sandbox` and cannot execute script (inspect header + a console check with a test SVG URL).
11. `/debug` renders the app not-found screen; no debug page.

### M3 — HSTS/TLS opt-in, static-host parity, docs, final audit

**Changes:**
- Add `VOULT_HTTPS` to `config.rs` (`https_enabled()`), `.env.example`, and README.
- In `main.rs`, use `let https = config::https_enabled();` instead of `false`; log `https`/`hsts` booleans.
- Update `AGENTS.md` and `SECURITY_AND_FEATURE_ROADMAP.md`.
- Final artifact audit and browser matrix.

**Acceptance:**
1. Default `cargo run`: no HSTS, no `upgrade-insecure-requests`.
2. `VOULT_HTTPS=1 cargo run` (curl only; do not browse over HTTP): `/` has `Strict-Transport-Security: max-age=31536000` and CSP ends with `upgrade-insecure-requests`. Stop the server and restart without the flag.
3. `cargo test` passes the `_headers` parity test against the TLS policy.
4. `npm run build:web` passes the checker; `dist/_headers` has COOP/COEP/CSP/nosniff/XFO/referrer/permissions/HSTS.
5. Manual final audit:
   - `find dist -name '*.map'` empty; `grep -R sourceMappingURL dist` empty.
   - `find dist -maxdepth 2 \( -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name 'vault.db' -o -name 'session.key' \)` empty.
   - `node scripts/check-web-dist.mjs` reports 0 secret/telemetry markers and only allowlisted hosts.
   - DevTools Network on signup/unlock/home: only `http://localhost:8080` (plus the intentional OAuth navigation, if exercised); no third-party requests.
   - `/debug` is gone; `dist/debug` absent.
6. Extension regression: pair/refresh the extension, unlock/fill from the popup; server headers/CORS still work; proxied icons still render (CORP cross-origin unchanged).
7. Session regression: `/api/session` still 401s with `SESSION_REQUIRED` when the cookie is absent; the web 401 interceptor still marks the session missing without dropping the vault (no code changed, but verify headers didn't interfere).
8. Roadmap item marked `[x]` with evidence.

---

## 9. Verification commands (copy/paste)

```sh
# Client artifact
cd apps/client
npm install                      # fresh worktree; postinstall runs patch-package
npm run sync:sqlite-web          # required before web export
npm run build:web                # export + check-web-dist
find dist -name '*.map'
grep -R "sourceMappingURL" dist || true
ls dist/debug                    # must fail
npx tsc --noEmit

# Negative gate check
touch dist/check-map.map
npm run check:web-dist           # must fail
rm dist/check-map.map

# Server policy
cd ../server
cargo test
cargo run                        # terminal 1

# terminal 2
curl -s -D - -o /dev/null http://localhost:8080/ | grep -iE 'content-security|origin-|x-content|x-frame|referrer|permissions|strict-transport'
curl -s -D - -o /dev/null http://localhost:8080/api/session | grep -iE 'cache-control|content-security|origin-|x-content|x-frame|referrer|permissions|strict-transport'

# TLS variant (curl only; do not open a browser over HTTP with this on)
VOULT_HTTPS=1 cargo run
curl -s -D - -o /dev/null http://localhost:8080/ | grep -iE 'strict-transport|content-security'
```

Browser checks (manual, no new dependency):

1. `http://localhost:8080/` → `crossOriginIsolated` true in DevTools; no CSP errors.
2. Full signup → recovery PDF → add item → reload → lock/unlock.
3. `/debug` → app not-found, not a debug dump.
4. Local `file://` page with `<iframe src="http://localhost:8080/">` → refused.
5. Network tab → only `localhost:8080`; no third-party requests.
6. Settings → Vault → copy ID; Settings → Backup → connect (if configured).
7. Extension popup → unlock/fill; icons render.

---

## 10. Overlaps and non-goals

| Item | Relationship |
|---|---|
| P0 log redaction (`main.rs` logger, OAuth logs) | No overlap in behavior. This plan deliberately avoids CSP reporting/URL logging. Do not modify `Logger::default()` here. |
| P0 request bounds (`endpoints::json_config`, body limits) | No overlap. No payload/schema changes. |
| P0 security tests | This plan adds header tests in `security_headers.rs`/`favicon.rs`; the security-tests worktree may add broader suites. Do not share/move test helpers blindly. |
| P1 transport/cookie invariants (`SESSION_COOKIE_SECURE`, SameSite, proxy trust) | `VOULT_HTTPS` only controls response headers. It does not set/validate cookie flags. A remote deployment needs both; the P1 item owns enforcement. |
| P1 favicon SSRF | This plan adds only `CSP: sandbox` to `icon_response()`. Do not alter redirect/DNS/size/timeout logic. |
| P1 CSRF/origin checks | CSP/frame/referrer are not CSRF controls. No Origin/Fetch-Metadata enforcement here. |
| P1 extension release review | Extension manifest CSP is separate. Server headers do not apply to extension pages; keep favicon CORP. |
| P2 crypto-context binding | No crypto change; recovery Rule R1 untouched. |

---

## 11. Implementation record (2026-10-29)

**Implemented:** M0–M3 in this worktree.

| Area | Result |
|---|---|
| Server policy | `apps/server/src/security_headers.rs` added; registered outermost in `main.rs`; `VOULT_HTTPS` added to `config.rs`. |
| Favicon | `icon_response()` now carries `Content-Security-Policy: default-src 'none'; sandbox` alongside `CORP: cross-origin`. |
| Static mirror | `apps/client/public/_headers` carries the TLS policy; Rust parity test passes. |
| Debug route | `apps/client/src/app/debug/` deleted; fresh export has 12 routes and no `dist/debug`. |
| Artifact gate | `apps/client/scripts/check-web-dist.mjs` added; `build:web` runs it; `check:web-dist` is a standalone script. |
| Dependency | `posthog-react-native` removed from `package.json` and the tracked lockfile. |
| Docs | `.env.example`, `README.md`, `AGENTS.md`, `apps/server/architecture.md`, and the roadmap updated. |

**Automated verification:**

- `cargo test` (full server suite): **109 passed, 0 failed** after the final CORS-preflight test — includes the hash pin, CSP strictness, COOP/COEP, HSTS on/off, `_headers` parity, static HTML, 404, OPTIONS, and CORS-preflight cases, plus the favicon sandbox test.
- `cargo fmt -- --check`: clean.
- `npx tsc --noEmit`: clean.
- `npm run build:web`: exports 12 static routes, then the gate passes with no debug route, source maps, secrets, telemetry, or unlisted hosts.
- Negative gate check: a synthetic `dist/check-map.map` fails the checker (`dist/check-map.map is a source map`); removing it passes again.

**Deviations discovered during implementation (and folded into the policy/tests):**

- The sqlite OPFS proxy comment links to `developer.chrome.com`; it is an inert documentation host, added to the checker allowlist with that reason.
- A naive telemetry substring check false-positives on `sentry` inside `fsEntryName` (sqlite worker) and `segment` throughout the router. The gate uses word-boundary matching and SDK/host markers instead.
- `DefaultHeaders` does not overwrite an existing header, so the favicon response's handler-level CSP is the one that applies (safe because it is an image, not the app document). `default-src 'none'; sandbox` is therefore used on that response.
- The Actix wrap order was corrected: the security policy is now registered **last** (outermost), so CORS preflights and middleware errors receive it. A test reproduces the CORS + security ordering.

**Not yet exercised (manual browser pass still required):** the local browser tools in this session are disconnected (`[browser.disconnected]`), and TCP 8080 is held by another worktree's dev server, so the live `curl` matrix and full signup → SQLite → recovery-PDF → OAuth browser flow from §9 have **not** been run here. The Actix header tests cover the response paths, and the export gate covers the artifact; the browser run remains the release check listed in M2/M3.

**No open questions.** All product-level choices that affect the release are recorded above as decisions with their rationale; the remaining unknowns (an Expo upgrade changing the inline snippet) are handled by a failing build check with a one-line fix, not by a question.
