# P0 — Sanitize HTTP/access logs and OAuth redirect errors

**Status:** implemented 2026-10-29. Automated checks pass (`cargo test`,
`npx tsc --noEmit`, `scripts/check-log-hygiene.sh`); the live-provider rows of
§12 are **not** exercised in this environment (no Google/Dropbox credentials).

**Scope:** the server's request log, every first-party log call site that can
carry a secret, the OAuth callback's redirect/error contract, and the client's
rendering of that contract. This is a **logging and wire-hygiene** change: no
crypto, schema, storage, session, or zero-knowledge change.

**Out of scope (separate items, see §13):** the pending OAuth `state` being a
bearer credential (`/cloud/vaults/pending`, `/cloud/link-pending`), plaintext
provider tokens in SQLite, client-side `console.*` error logging, and log-file
permissions.

---

## 1. The actual problem

The server writes a request log to stderr, and the launcher persists stderr to
`~/Library/Logs/Voult/server.log` (`launcher/src/main.rs:276-281`,
`launcher/src/main.rs:297-311`). The logger middleware is Actix's default
(`apps/server/src/main.rs:307`), whose format is
`%a "%r" %s %b "%{Referer}i" "%{User-Agent}i" %T`
(`actix-web-4.12.1/src/middleware/logger.rs:491-493`). `%r` is the request line
**including the query string** when one is present
(`actix-web-4.12.1/src/middleware/logger.rs:673-689`), and the shared logger
keeps that target verbatim in the message:

```text
2026-10-28T04:05:23+00:00 LOG   (actix_web::middleware::logger) GET /api/favicon?u=https%3A%2F%2Fbank.example%2Flogin 200 {
  remote: '::1',
  size: 1501,
  duration: '0.534ms',
  referer: 'http://localhost:8080/vault?cloud_state=6f1c…&email=alice@gmail.com',
  user_agent: 'Mozilla/5.0 …'
}
```

`crates/logger/src/formatter/actix_web.rs:36-37` is where the raw target becomes
the message; `crates/logger/src/formatter/actix_web.rs:55-60` puts the **Referer**
and **User-Agent** headers into metadata. The Referer is the previous page, so
after an OAuth return it is itself a URL carrying `cloud_state` and `email`.

This matters because the design promise is that the server's stored data is
ciphertext plus public KDF metadata. The log is **not** ciphertext: it is a
plaintext, append-only record of which sites are in the vault (`?u=`), which
vault is being opened (`?vault_id=`, also sent pre-auth by
`GET /api/get_crypto_params`), and live OAuth capabilities (`code`, `state`).
The actionable one is `state`. It is valid for 10 minutes as the CSRF token
(`apps/server/src/cloud/oauth_state.rs:18-21`), and while it is live it can be
used **without a session** to list the provider's vault files
(`apps/server/src/endpoints/cloud_endpoints.rs:1455-1503`) and to read an
encrypted package
(`apps/server/src/endpoints/cloud_endpoints.rs:1511-1563`). Worse, after a
successful pre-session exchange the *same value* becomes the primary key of
`cloud_pending_token` (`apps/server/src/cloud/oauth_flow.rs:216-238`), and that
row has **no TTL or sweeper** — `expires_at` is the provider access token's
expiry, copied when the token is claimed
(`apps/server/src/cloud/oauth_flow.rs:138-144`), not a row lifetime. A state
read from an old log therefore remains claimable. It can be redeemed by a
*different* logged-in vault to bind the pending provider token to that vault
(`apps/server/src/endpoints/cloud_endpoints.rs:1429-1448` →
`apps/server/src/cloud/oauth_flow.rs:118-166`) — the serious case: the attacker
gains the victim's provider credential and with it the ability to read
ciphertext, overwrite, or delete the victim's remote backup. The precondition
is read access
to the log — same-user local access, a hosted deployment's operator, or a
support bundle. For the initial CSRF window that is 10 minutes; for the pending
claim it is **until the user claims the pending token**, so an old log line is
still actionable. The durable fields (site URLs, vault ids, emails) remain
exposed in older logs and backups.
The OAuth `code` is not
directly redeemable because the exchange requires the server-side
`client_secret` (`apps/server/src/cloud/providers/google_drive/oauth.rs:41-56`)
and the flow has no PKCE, but it is still an OAuth credential and must not be
written down.

The other direction is also wrong: the OAuth handler puts the provider account's
**email** in the redirect URL (`cloud_endpoints.rs:326-337`,
`cloud_endpoints.rs:375-386`), so it lands in browser history and in the log of
the subsequent `GET /vault?...&email=alice@gmail.com` request. It also echoes the
provider's raw `error` query parameter into both the log and the redirect
(`cloud_endpoints.rs:273-288`), and passes the exchange failure's diagnostic text
as `cloud_error_detail` (`cloud_endpoints.rs:300-313`) — the text is currently
constant, but the parameter shape invites a future leak. The client renders both
strings directly (`apps/client/src/app/vault/index.tsx:391-395`), so provider
text (or an attacker-crafted link to the callback) becomes UI text.

**What "fixed" looks like:** the access log never receives the request target,
headers, or body — only method, matched route pattern (or a closed label),
status, and duration. First-party logs never contain an email, OAuth
code/state, full vault id, favicon URL, provider error text, or DB URL
credentials. Every browser-visible OAuth failure is one of a small fixed set of
codes, and the client maps codes to its own copy and never renders server text.
The pending flow still receives the `state` it needs, but the state no longer
appears in any log.

---

## 2. Roadmap claim: verified, with corrections

The roadmap item (`SECURITY_AND_FEATURE_ROADMAP.md:60`) is **accurate in
substance but stale in several specifics**. Corrected record:

| Roadmap claim | Verdict | Evidence |
|---|---|---|
| `main.rs` uses `Logger::default()` | **Stale naming.** It uses `actix_web::middleware::Logger::default()`; the shared logger's `Logger::default()` is not involved. | `apps/server/src/main.rs:307`; `crates/logger/src/lib.rs:123-127` |
| Default request-line format includes query strings | **True.** `%r` appends `?{query}` when non-empty. | `actix-web-4.12.1/src/middleware/logger.rs:491-493`, `:673-689`; `crates/logger/src/formatter/actix_web.rs:36-37` |
| OAuth callback `code`/`state` can enter logs | **True**, via the request line only; no handler logs them directly. | `main.rs:307`; `cloud_endpoints.rs:243-256` |
| Pending state, vault IDs, favicon URLs can enter logs | **True**, all via query strings (`?state=`, `?vault_id=`, `?u=`). | client call sites in §3.1; `favicon.rs:45-48` |
| OAuth handler logs include provider email | **True.** | `cloud_endpoints.rs:318-325`, `:367-374` |
| Redirects include provider email | **True.** | `cloud_endpoints.rs:326-337`, `:375-386` |
| Redirects include error detail | **Partially stale.** Exchange failures already use `redacted_detail()` (constant `"provider request failed"`). The live leak is the raw provider `error` echo and the existence of the `cloud_error_detail` parameter. | `cloud/error.rs:99-104`; `cloud_endpoints.rs:273-288`, `:300-313` |
| File `apps/server/src/endpoints/google_endpoints.rs` | **Stale path.** The file does not exist. Code moved to `endpoints/cloud_endpoints.rs` and `cloud/providers/{google_drive,dropbox}/`. | `apps/server/src/endpoints/` listing |
| "Log path templates/status only" | **Not implemented.** Nothing normalizes to a route pattern; Actix exposes `match_pattern()`, which is unused. | `actix-web-4.12.1/src/service.rs:256-259`, `src/request.rs:187-189` |

One more finding not in the roadmap: the client has a **dead** helper
`startCloudAuthPublic(email, provider)` that would send an email as a query
parameter to `/cloud/auth/start` (`apps/client/src/lib/cloud/api.ts:62-67`); the
server ignores the parameter. It is unused, and it is a one-call-away leak into
the access log. Remove it.

---

## 3. What is exposed today

### 3.1 Request-line inventory

| Route | Sensitive input | Where it lands today |
|---|---|---|
| `GET /api/get_crypto_params` | `vault_id` | Request line. Sent before login (`apps/client/src/lib/queries/cryptoParams/query.ts:8-11`), so a full vault UUID is logged for unauthenticated traffic. The endpoint also answers `VAULT_NOT_FOUND`, i.e. it is an existence oracle (`get_crypto_params.rs:75-78`), acknowledged at `:24-28`. |
| `GET /api/favicon` | `u` (absolute site URL) | Request line, plus `reqwest::Error`'s `Display`, which includes the URL (`favicon.rs:464-474`, `:542-552`; `reqwest-0.12.28/src/error.rs:268`). This is the vault's site list in plaintext. |
| `GET /api/cloud/oauth/callback` | `code`, `state`, `error` | Request line. `error` is also logged and reflected (`cloud_endpoints.rs:273-288`). |
| `GET /vault` after the callback | `cloud_state`, `email`, `cloud_error`, `provider` | Request line of the redirect follow, and Referer metadata. `email` is server-generated (`cloud_endpoints.rs:330-334`, `:379-384`). |
| `GET /vault?recover=<vault_id>` | vault id | Request line (`apps/client/src/app/_layout.tsx:92-96`). |
| `GET /api/cloud/vaults/read` | `file_id`, `vault_id` | Request line (`cloud_endpoints.rs:979-983`). |
| `GET /api/cloud/vaults/pending`, `/pending/read`, `/cloud/pending` | `state`, `file_id` | Request line (`cloud_endpoints.rs:1451-1453`, `:1505-1509`, `:568-614`). |
| `GET /api/cloud/binding` | `vault_id` | Request line (`cloud_endpoints.rs:616-635`). |
| `POST /api/auth` | `vault_verifier` in body | **Not logged**: no body logging; SQLx's formatter keeps only the SQL summary and counters, not bound values (`crates/logger/src/formatter/sqlx.rs:31-41`). Audited pass. |
| `POST /api/register`, `/update_vault`, `/vault/password`, `/recovery/*`, `/pair/*` | ciphertext, verifier, envelopes, recovery proof, pairing code | Bodies are never logged. Recovery logs interpolate the **full `vault_id`** (13 sites, §3.4); the pairing code is never logged (`pair.rs:187`, `:294-297`). |
| `GET /api/session`, `/vaults`, `/get_vault` | none | Pass. |

### 3.2 Handler logs that carry a secret

- Provider email: `cloud_endpoints.rs:318-325` and `:367-374`.
- Raw provider `error` text: `cloud_endpoints.rs:273-288` (logged and reflected).
- Full vault id in recovery: `recovery.rs:373, 393, 400, 432, 453, 461, 588, 648, 662, 682, 701, 941, 1140`.
- Favicon URL via `{e}`: `favicon.rs:465-468`, `:542-546`.
- DB URL: `main.rs:181-184`, `config.rs:201-204`, `config.rs:213-217`.
- Hardcoded "Google" copy in a provider-neutral path: `cloud_endpoints.rs:216-219`.

### 3.3 Why formatter-level redaction is not enough

Two properties make the current pipeline impossible to fix at the formatting
layer:

1. **Parse failure falls back to the raw line.** The logger parses Actix's line
   and, on any mismatch, prints the original message unchanged
   (`crates/logger/src/backend.rs:44-51`). Actix does not escape quotes in the
   quoted fields, so a User-Agent containing `"` makes the parse fail — and the
   raw line (with the query) is printed. The parser's own comment says this
   (`crates/logger/src/formatter/actix_web.rs:129-131`). User-Agent is
   attacker-controlled, so redaction can be switched off by the caller.
2. **The Referer is a second URL.** Even a query-stripped request line leaves
   the previous URL in `referer` metadata (`actix_web.rs:55-57`), which after an
   OAuth return is exactly the URL carrying `cloud_state`/`email`.

The fix must prevent the query and headers from entering the log *record* at
all, not sanitize them afterwards.

### 3.4 The audit of existing log call sites (pre-change baseline)

Method: `grep -rEn "LOG\.(log|warn|error|debug)|CONFIG_LOG\.(log|warn|error|debug)|SERVER_LOG\.(log|warn|error|debug)" apps/server/src`
— **146 first-party call sites across 19 modules** in the pre-change tree. Each
was read and classified against the policy in §5. Result: **21 lines failed**,
125 passed.

| Module | Sites | Verdict |
|---|---|---|
| `endpoints/cloud_endpoints.rs` | 31 | **3 fail:** raw provider error log (`:274`), email logs (`:319`, `:369`). 11 manual vault-id `&id[..8]` slices are safe but should use the shared helper (`:100, 159, 234, 321, 496, 717, 725, 863, 956, 966, 1277`); `:957` truncates a provider file id. |
| `endpoints/recovery.rs` | 38 | **13 fail:** full `vault_id` interpolations (lines in §3.2). No selector, proof, challenge, or key is logged. |
| `endpoints/favicon.rs` | 5 | **2 fail:** `{e}` at `:466` and `:544` (URL in `Display`). The other three are fixed text. |
| `main.rs` | 11 | **1 fail:** `DATABASE_URL` at `:182`. Paths and config flags pass. |
| `config.rs` | 5 | **2 fail:** normalized URL at `:202`, raw URL at `:215`. |
| `cloud/mirror.rs` | 24 | Pass: all identifiers use `short_id` (`:1047-1050`); provider revisions are opaque, not key material. |
| `cloud/oauth_flow.rs` | 1 | Pass: `{kind} account lookup failed: {e}`; `e` is first-party text/status, not a provider body (`google_drive/oauth.rs:37-40` documents that policy). |
| `cloud/providers/google_drive/oauth.rs` | 3 | Pass: status only. |
| `cloud/token_store.rs` | 1 | Pass: DB error only. |
| `endpoints/pair.rs` | 4 | Pass: never logs the code. |
| `endpoints/auth.rs`, `register.rs`, `vaults.rs`, `update_vault.rs`, `update_vault_password.rs`, `get_vault.rs`, `get_crypto_params.rs`, `session_status.rs`, `lock.rs` | 23 | Pass: DB errors and fixed text only. |

The audit is a one-time reading, but it must stay true. M3 adds
`scripts/check-log-hygiene.sh` as a tripwire for the exact patterns fixed here
(§10, M3), and the policy is documented in `crates/logger/README.md`.

---

## 4. What the attacker gains, per field

| Field | Gain | Precondition |
|---|---|---|
| `state` | 10-minute unauthenticated access to the pending provider token's Drive listing and encrypted package; after the pending exchange, the same value keys a row with no TTL, so the capability is durable until claimed. A logged-in attacker can bind that pending token to their own vault via `link-pending`, which hands over the victim's provider credential and the ability to overwrite/delete the remote backup. | Read the log at any time after the victim's OAuth attempt; for the binding, an attacker vault/session. |
| `code` | OAuth authorization code. Not directly redeemable without the server-side `client_secret` and exact redirect URI; becomes directly usable if PKCE is added or the secret leaks. | Read the log before the code expires. |
| Provider email | Account↔provider linkage; phishing target. | Read the log or browser history. |
| Favicon `u` | The user's vault site list, sometimes account-specific paths. | Read the log. |
| `vault_id` | Stable pseudonym linking every log line to one vault; pairs with the `/get_crypto_params` existence oracle and the separate verifier-replay item. | Read the log. |
| `DATABASE_URL` | Local filesystem path; credentials if a non-SQLite URL is ever configured. | Read the log. |
| Raw provider error | Log-line forgery (newlines) and arbitrary UI text via the redirect. | Craft a callback link, or a provider that returns attacker text. |

---

## 5. Invariants the implementation must satisfy

- **I1 — Access log input is closed.** The request log receives method, route
  pattern or a fixed label, status, and duration. It cannot receive the query,
  headers, path values, or body. This is enforced by the function signature, not
  by a comment.
- **I2 — No secret in first-party logs.** Never log: an email, an OAuth
  code/state, a provider token, a full vault id, a favicon/site URL, a request
  body, a verifier/proof/recovery key, or a DB URL with credentials.
- **I3 — Browser-visible errors are a closed vocabulary.** The OAuth callback
  returns fixed codes; the client maps them to copy. No server-supplied text is
  rendered.
- **I4 — Redirects carry the minimum.** Success: `provider` + (`cloud_connected`
  or, pending only, `cloud_state`). Failure: `cloud_error` + `provider`. No
  `email`, no `cloud_error_detail`, no provider text.
- **I5 — Log lines cannot be forged.** Control characters in a log message are
  escaped, so `\n` in any untrusted string cannot create a second line.

---

## 6. Alternatives considered

| # | Alternative | Trade-off | Verdict |
|---|---|---|---|
| A1 | Keep Actix's `Logger`, change its format to `%m %U %s` (path without query). | One-line change, but: no route templates, still logs the remote IP, still parses/reformats, and the logger's parser no longer matches the custom format, so lines pass through raw. Any future format change silently changes the guarantee. | **Rejected.** |
| A2 | Keep the default format and strip `?...` inside the logger formatter. | Minimal diff and keeps the existing formatter tests, but the raw-line fallback (`backend.rs:44-51`) is bypassable by a quoted User-Agent, and the Referer still carries the previous URL. | **Rejected** — it cannot meet I1. |
| A3 | Disable request logging entirely. | Zero leak from the request path; but loses the only per-request status/route signal used in support, and does not fix handler logs or redirects. The roadmap asks for sanitized logs, not no logs. | **Rejected.** |
| A4 | First-party `RequestLog` middleware in the server, logging method + `match_pattern()` + status + duration. | ~70 lines of owned code, no new dependency, testable pure label function, no headers/query/IP, and route templates come from Actix's own route table. Slightly more code than A1/A2. | **Chosen.** |
| A5 | Redact in the global `log` backend by regex-scanning every message. | Cannot reliably distinguish secrets from legitimate text; breaks SQL/diagnostics; false sense of safety; affects the launcher too. | **Rejected.** |
| A6 | Hash vault ids with an HMAC for logs. | No stable key to correlate across restarts unless another secret is persisted; more key management for a diagnostic field. | **Rejected.** |
| A7 | Keep the provider email in the redirect but remove it from the log. | Email still lands in browser history and Referer; the client does not read it at all (grep: no `params.email`). | **Rejected** — it is unused. |
| A8 | Keep `cloud_error_detail` and sanitize its value. | The parameter invites future detail; the client renders it as trusted text; no current consumer needs it. | **Rejected.** |
| A9 | Replace the pending `state` in the URL with an HttpOnly cookie now. | Better bearer hygiene, but changes four endpoint contracts, is not tab-scoped (two tabs would collide), and the real problem is that the pending token is authorized by the state at all. It belongs to the separate pending-token item (§13), not this one. | **Rejected for this item; follow-up.** |
| A10 | Log only full vault ids and rely on file permissions. | A log is copied into backups/support bundles far more often than the DB; permissions are not a redaction strategy. | **Rejected.** |

---

## 7. Decided choices

- **D1 — Own middleware, not Actix `Logger`.** `RequestLog` is a first-party
  `Transform` in `apps/server/src/request_log.rs`, logging
  `"<METHOD> <pattern> <status>"` with `duration_ms` metadata at `log` level.
  `match_pattern()` returns the resource's declared pattern (for a future
  `/api/x/{id}` route it returns the literal `{id}`), so no value can appear.
  Verified empirically with a throwaway Actix app: `/api/favicon` inside
  `web::scope("/api")` yields `Some("/api/favicon")`; a `web::resource("/vault")`
  yields `Some("/vault")`; `/nope` yields `None`; and an `actix_files::Files`
  service (which serves the real `/vault`, `/home`, … routes) yields
  **`Some("")`** — an empty pattern that must be treated as "no pattern", or
  the log line gets an empty label.
- **D2 — Closed labels for unmatched/static.** A missing **or empty** pattern
  (Actix's `Files` service returns `Some("")`; verified empirically) under
  `/api` logs `unmatched`; outside `/api` logs `static`. The raw path is never
  logged, even for 404s. Losing the 404 path is accepted: API routes are
  literal, and the client surfaces its own failing URL.
- **D3 — No client IP, no headers, no size.** The roadmap says path/status
  only; the existing formatter's `remote` metadata is the only place client IP
  is logged today, and no throttle reads it (`recovery.rs:505-508` logs
  "rate limited" without an IP), so nothing is lost.
- **D4 — Add `ServerContext::Request`.** Label `request`, so access logs are
  filterable separately from lifecycle logs.
- **D5 — Delete `crates/logger/src/formatter/actix_web.rs` and its dispatch.**
  After D1 it is dead code; leaving it makes re-enabling Actix's logger look
  safe. The generic renderer already prints unknown targets unchanged.
- **D6 — Escape control characters in messages.** `format.rs` escapes `\n`,
  `\r`, `\t`, and other control characters in the message, mirroring the
  existing metadata escaping (`format.rs:129-142`). This is the I5 guarantee,
  independent of any redaction.
- **D7 — `short_id` is 8 characters, shared.** Move `mirror.rs:1047-1050` into
  `apps/server/src/log_safety.rs`, make it char-boundary safe, and use it in
  recovery and cloud. 8 hex chars of a UUID (32 bits) is enough to correlate a
  log line; it is not an authentication value.
- **D8 — No email in the callback's return value.** Change
  `oauth_flow::complete_for_vault` / `complete_pending` to return
  `Result<(), CallbackError>`. The handlers currently use the email only for
  the log and the redirect; removing it from the signature makes the leak
  unconstructible rather than merely forbidden.
- **D9 — Typed state rejection.** `oauth_state::validate` /
  `validate_pending` return a `StateError` (`Invalid` for unknown/expired/
  provider/vault mismatch, `Unavailable` for DB failure) instead of `String`.
  This removes `e.detail().contains("state")` (`cloud_endpoints.rs:341`), which
  is string-sniffing, and lets both the bound and pending callbacks report
  `OAUTH_INVALID_STATE` consistently.
- **D10 — Fixed callback vocabulary.** Codes:
  `OAUTH_CANCELLED`, `OAUTH_INVALID_REQUEST`, `OAUTH_INVALID_STATE`,
  `OAUTH_EXCHANGE_FAILED`, `OAUTH_UNKNOWN_PROVIDER`,
  `OAUTH_PROVIDER_UNCONFIGURED`. The `cloud_error` parameter name is kept; its
  values are the only thing that changes.
- **D11 — Keep `cloud_state` in the pending success redirect.** The client
  cannot recover the pending token otherwise (`vault/index.tsx:60-66`,
  `lib/cloud/api.ts:69-74`), and the flow is defined as URL-based. Its exposure
  is documented as residual (§13). The session-bound success redirect does not
  carry it.
- **D12 — Delete the dead `startCloudAuthPublic`.** It sends an email in a
  query parameter to an endpoint that ignores it (`api.ts:62-67`).
- **D13 — Redact the DB URL, not the whole line.** `database_url_for_log`
  keeps scheme/host/path (useful at startup), drops query/fragment, and clears
  the password; unparseable values become `<invalid database url>`.
- **D14 — No new dependencies.** The request middleware uses Actix types; the
  DB URL helper uses `reqwest::Url` (already a direct dependency) and
  `urlencoding` (already used for redirects). No `url`/`regex`/redaction crate.
- **D15 — Provider error `detail()` stays a server-side diagnostic, never a
  redirect.** The current constructors use only fixed text, HTTP statuses, and
  DB errors — never provider response bodies (`google_drive/oauth.rs:37-40`).
  Keep that invariant, document it in `cloud/error.rs`, and never pass
  `detail()` to a response.
- **D16 — No schema, migration, or session change.** Only log strings and the
  OAuth redirect/JSON shape change. The `SESSION_CLOUD_OAUTH_STATE` write is
  dead (written at `oauth_flow.rs:27-31`, never read anywhere) and is removed.

---

## 8. Target design

### 8.1 `apps/server/src/request_log.rs` (new)

```rust
const LOG: logger::ServerLogger = logger::Logger::create(ServerContext::Request);

#[derive(Clone, Copy, Default)]
pub struct RequestLog;

#[derive(Clone, Copy)]
struct Started(Instant);

/// The only path/identifier function in the access log. It never receives the
/// query string; `pattern` is Actix's declared route pattern (`/api/favicon`,
/// or `/api/vaults/{id}` for a future path-param route).
pub(crate) fn label<'a>(pattern: Option<&'a str>, path: &str) -> &'a str {
    // Defensive: a caller that passes a full target still cannot leak a query.
    let path = path.split(['?', '#']).next().unwrap_or_default();
    match pattern {
        // `actix_files::Files` reports Some("") for a service, not None.
        Some(pattern) if !pattern.is_empty() => pattern,
        _ if path.starts_with("/api") => "unmatched",
        _ => "static",
    }
}

pub(crate) fn line(method: &str, label: &str, status: u16) -> String {
    format!("{method} {label} {status}")
}
```

`label` strips anything at `?`/`#` from `path` defensively (so a caller that
accidentally passes a full target still cannot leak the query). The service
captures `Instant::now()` before awaiting the inner service (no request-
extension state is needed), then logs
`line(req.method().as_str(), label, res.status().as_u16())`
with `metadata! { "duration_ms" => … }`. On an inner `Err` (which Actix will
convert to a 500 after the middleware stack), it logs the same line with status
`500` and `"unhandled" => true` at `warn`, then returns the error unchanged.

Wiring in `main.rs` (last `.wrap` = outermost, so CORS-rejected and unhandled
requests are still logged):

```rust
.wrap(DefaultHeaders::new()
    .add(("Cross-Origin-Opener-Policy", "same-origin"))
    .add(("Cross-Origin-Embedder-Policy", "require-corp")))
.wrap(session_middleware)
.wrap(cors)
.wrap(request_log::RequestLog)   // replaces middleware::Logger::default()
```

`DefaultHeaders` and session/CORS order is unchanged. The middleware adds no
response headers and does not touch the body.

### 8.2 `crates/logger`

- `context.rs`: add `ServerContext::Request` → label `"request"`.
- `format.rs`: escape control characters in `message` before appending
  (`push_escaped_message`), mirroring `push_single_quoted` (`:129-142`).
- `formatter/mod.rs`: remove the `actix_web::middleware::logger` branch.
- Delete `formatter/actix_web.rs`.
- `README.md`: replace the "Actix request records" section with the first-party
  request-log format, add `Request` to the context list (`README.md:65-67`),
  and rewrite "Security" (`README.md:199-205`) to state:
  the logger does not know field semantics; the access log is query-free by
  construction; call sites must follow the no-secret list; messages escape
  control characters.

### 8.3 `apps/server/src/log_safety.rs` (new)

```rust
pub fn short_id(id: &str) -> &str;                 // 8 chars, char-boundary safe
pub fn database_url_for_log(raw: &str) -> String;  // no query/fragment/password
```

`database_url_for_log` parses with `reqwest::Url`; on failure returns the fixed
string `<invalid database url>` (never the input). Tests cover a SQLite URL
with `?mode=rwc`, a credentialed Postgres-style URL, and a malformed value.
`Url`'s `Display` percent-encodes spaces in a path (`…/Application%20Support/…`),
which is cosmetic: the path remains recognisable and no query or password is
present.

### 8.4 OAuth callback contract

Route: `GET /api/cloud/oauth/callback` (`cloud_endpoints.rs:250-257`).

| Situation | Status | Browser-visible result |
|---|---|---|
| Session-bound success | 302 | `{base}?cloud_connected=1&provider={kind}` |
| Pending success | 302 | `{base}?cloud_state={state}&provider={kind}` |
| Provider sent `error` (denied/cancelled) | 302 | `{base}?cloud_error=OAUTH_CANCELLED&provider={kind}` |
| `code` or `state` missing | 302 | `{base}?cloud_error=OAUTH_INVALID_REQUEST&provider={kind}` |
| State unknown/expired/provider/vault mismatch | 302 | `{base}?cloud_error=OAUTH_INVALID_STATE&provider={kind}` |
| Exchange/account/store failure | 302 | `{base}?cloud_error=OAUTH_EXCHANGE_FAILED&provider={kind}` |
| `provider` unparseable | 400 | `{"error_msg":"unknown provider","code":"OAUTH_UNKNOWN_PROVIDER"}` |
| Provider not configured on this server | 503 | `{"error_msg":"provider not configured","code":"OAUTH_PROVIDER_UNCONFIGURED"}` |

`{base}` is `impl_.post_auth_redirect()`; the builder appends with `&` when the
base already has a query and URL-encodes values. An unknown/unconfigured
provider cannot select a provider-specific landing URL, so it returns JSON
instead of a redirect. No failure carries `email`, `cloud_error_detail`,
`code`, `state` (except the pending success), or provider text.

```rust
// cloud_endpoints.rs
pub(crate) fn with_params(base: &str, params: &[(&str, &str)]) -> String;
fn redirect(base: &str, params: &[(&str, &str)]) -> HttpResponse;
fn failure_redirect(base: &str, code: &'static str, kind: ProviderKind) -> HttpResponse;
```

The handler matches `oauth_flow::CallbackError` directly (`StateRejected` →
`OAUTH_INVALID_STATE`, `Provider(_)` → `OAUTH_EXCHANGE_FAILED`); there is no
intermediate outcome enum in the implemented shape.

Tests pin the exact strings for all six redirect outcomes and assert the built
strings contain none of `email`, `detail`, `code=`, `state=` except the pending
success.

Log lines (after M2):

- success: `cloud OAuth connected` / `cloud OAuth connected (pending)`,
  metadata `provider`, `vault` = `short_id` or `(pending)`;
- denied: `cloud OAuth denied by provider`, metadata `provider`;
- bad state: `cloud OAuth state rejected`, metadata `provider` (the specific
  reason is logged by `oauth_state` as a closed word: `unknown`/`expired`/
  `provider`/`vault`);
- exchange failure: `cloud OAuth exchange failed`, metadata `provider`,
  `code` (`e.code()`).

### 8.5 Client

- New `apps/client/src/lib/cloud/oauth-error.ts`:

```ts
const MESSAGES: Record<string, string> = {
  OAUTH_CANCELLED: "Authorization was cancelled or denied.",
  OAUTH_INVALID_REQUEST: "The provider returned an incomplete response. Try again.",
  OAUTH_INVALID_STATE: "This sign-in link expired. Start the connection again.",
  OAUTH_EXCHANGE_FAILED: "The provider could not complete the connection. Try again.",
  OAUTH_UNKNOWN_PROVIDER: "That cloud provider is not supported.",
  OAUTH_PROVIDER_UNCONFIGURED: "Cloud backup is not configured on this server.",
};

export function oauthErrorMessage(raw: string | undefined): string {
  return (raw && MESSAGES[raw]) || "Cloud connection failed. Try again.";
}
```

- `vault/index.tsx`: remove `cloud_error_detail` from the
  `useLocalSearchParams` type (`:59`), render
  `oauthErrorMessage(params.cloud_error)` instead of the raw value (`:393`),
  delete the detail line (`:394`), and rename the label to
  "Cloud connection error".
- No other client changes: the success path uses only `cloud_connected` and
  `provider` (`:92`, `:123`); `pendingState` keeps working via `cloud_state`.
- Delete `startCloudAuthPublic` (`lib/cloud/api.ts:62-67`).

### 8.6 Log call-site changes (the audit fixes)

| File:line | Today | After |
|---|---|---|
| `cloud_endpoints.rs:274-277` | `cloud OAuth error: {raw}` | `cloud OAuth denied by provider`, metadata `provider` |
| `cloud_endpoints.rs:318-325` | logs `email` | `cloud OAuth connected`, metadata `provider`, `vault` |
| `cloud_endpoints.rs:367-374` | logs `email` | `cloud OAuth connected (pending)`, metadata `provider` |
| `cloud_endpoints.rs:341-345` | `e.detail().contains("state")` | typed `CallbackError::StateRejected` |
| `cloud_endpoints.rs:358-362, 388-394` | logs full `Display` | logs `e.code()` only |
| `favicon.rs:465-468` | `favicon fetch failed: {e}` | `favicon fetch failed`, metadata `timeout`, `connect` (booleans) |
| `favicon.rs:542-546` | `favicon read failed: {e}` | `favicon body read failed`, metadata `timeout` |
| `recovery.rs` (13 sites) | full `vault_id` | `short_id(&vault_id)` |
| `main.rs:182` | raw DB URL | `database_url_for_log(&database_url)` |
| `config.rs:202, 215` | raw/normalized DB URL | `database_url_for_log(...)` |
| `cloud_endpoints.rs` 11 slices | `&id[..8.min(len)]` | `short_id(&id)` |
| `mirror.rs:1047-1050` | private helper | import `log_safety::short_id` |
| `cloud_endpoints.rs:217` | "Google" in a generic path | `"{kind} authorization failed"` |

Everything else in §3.4 stays as-is; in particular, do **not** add body or
header logging while touching these files.

---

## 9. Files to touch

**New**

- `plans/p0-log-redaction.md` (this file)
- `apps/server/src/request_log.rs`
- `apps/server/src/log_safety.rs`
- `apps/client/src/lib/cloud/oauth-error.ts`
- `scripts/check-log-hygiene.sh`

**Edit**

- `apps/server/src/main.rs` — module declarations, `RequestLog` wiring, remove
  `middleware::Logger::default()`, redact the DB URL log.
- `apps/server/src/config.rs` — redact both DB URL logs.
- `apps/server/src/endpoints/cloud_endpoints.rs` — callback outcome/redirect
  builder, typed state errors, remove email/detail, short ids, log copy.
- `apps/server/src/endpoints/favicon.rs` — replace the two `{e}` logs; no
  validation/cache/SSRF logic changes.
- `apps/server/src/endpoints/recovery.rs` — `short_id` in the 13 log lines;
  no flow/crypto changes.
- `apps/server/src/cloud/mirror.rs` — import the shared `short_id`; delete the
  local copy.
- `apps/server/src/cloud/oauth_flow.rs` — `CallbackError`, `Result<(), _>`
  returns, remove the dead session-state helper.
- `apps/server/src/cloud/oauth_state.rs` — `StateError`, reason logging.
- `apps/server/src/cloud/error.rs` — document the "detail is first-party only"
  invariant (comment only).
- `apps/client/src/app/vault/index.tsx` — fixed error mapping, remove detail.
- `apps/client/src/lib/cloud/api.ts` — delete `startCloudAuthPublic`.
- `crates/logger/src/context.rs` — `ServerContext::Request`.
- `crates/logger/src/format.rs` — message control-character escaping.
- `crates/logger/src/formatter/mod.rs` — remove the Actix dispatch.
- `crates/logger/README.md` — request-log and security sections.
- `crates/logger/src/formatter/actix_web.rs` — **delete**.
- `AGENTS.md` — one Gotchas line: access logs are query-free by construction;
  never reintroduce `middleware::Logger`; OAuth redirects carry fixed codes.
- `SECURITY_AND_FEATURE_ROADMAP.md` — check the item + changelog (after M3).

**Do not touch**

- `packages/vault-core/**`, `apps/client/src/lib/crypto/**` — no crypto.
- `apps/server/migration/**`, `apps/server/src/entity/**` — no schema.
- `apps/server/src/session_auth.rs`, `endpoints/auth.rs` logic — no session
  semantics. (Auth log lines already pass the audit.)
- `endpoints/recovery.rs` flow, envelopes, proofs, CAS — only log text.
- `endpoints/favicon.rs` SSRF guards, cache, discovery — only log text.
- `main.rs` COOP/COEP `DefaultHeaders` — required by sqlite-wasm OPFS.
- `crates/logger/src/backend.rs` — one global backend; no second install.
- `apps/client/src/app/_layout.tsx` — the `cloud_state` bootstrap check stays.

---

## 10. Trust boundary — what this must not break

- **Zero-knowledge.** The server still sees only ciphertext, salt, iterations,
  `vault_verifier`, and wrapped envelopes. This change removes data from logs;
  it adds no new data collection and touches no crypto. Do not "helpfully" log
  request bodies, verifier values, key bytes, or envelopes.
- **Session semantics.** No change to `voult_session` issuance, rotation,
  expiry, or the cookie's `vault_id` payload (`session_auth.rs:6`). The OAuth
  callback still does not create a local session; only `/auth`,
  `/register`, and `/recovery/rewrap` do.
- **Per-vault namespacing.** No storage change. Logs use an 8-character prefix,
  which is not an identity: it cannot open a vault, OPFS file, IndexedDB
  record, or session.
- **Recovery Rule R1.** Untouched. The recovery envelope still wraps
  `vaultKeyRaw` directly; this plan only changes `vault_id={full}` to
  `vault_id={8 chars}` in log strings.
- **COOP/COEP.** `DefaultHeaders` stays exactly as-is (`main.rs:302-306`);
  `RequestLog` adds no headers and does not buffer or replace the body.
- **CORS.** The allowed-origin list and `supports_credentials()` are unchanged.
  Request logging runs outside CORS, but it does not alter the request.
- **No new attack surface.** The access log no longer contains
  attacker-controlled text at all. Provider text is no longer reflected into a
  redirect, so the callback link cannot be used to inject UI copy. Message
  escaping prevents newline forgery in any remaining untrusted string.
- **No new dependencies.** Verified against `apps/server/Cargo.toml`; the
  middleware uses Actix, the URL helper uses `reqwest::Url`, encoding uses the
  existing `urlencoding`.

---

## 11. Phases

Each phase leaves the tree compiling and the app working. The phases are
ordered so the biggest exposure (the request line) closes before the wire
contract changes.

### M0 — Query-free access log and logger hardening

**Scope**

- New `request_log.rs`; wire it as the outermost middleware; remove
  `middleware::Logger::default()`.
- Delete `crates/logger/src/formatter/actix_web.rs` and its dispatch.
- Add `ServerContext::Request`.
- Escape control characters in `format::render_line` messages.
- Tests: `label` (pattern, **empty pattern**, API 404, static, path-with-query),
  `line`, message escaping, and an `#[actix_web::test]` that the middleware
  leaves a response untouched.

**Acceptance (by hand)**

1. `cd apps/server && cargo test` passes.
2. `cd crates/logger && cargo test` passes.
3. `cargo run`, then `curl -i 'http://localhost:8080/api/get_crypto_params?vault_id=11111111-1111-4111-8111-111111111111'`.
   The log line is `GET /api/get_crypto_params 400` (or 404) — no `?vault_id`,
   no UUID.
4. `curl -i 'http://localhost:8080/api/favicon?u=https%3A%2F%2Fbank.example%2Flogin'`
   → `GET /api/favicon 401`, no `?u=`.
5. `curl -i 'http://localhost:8080/nope?secret=1'` → `GET static 404`; no
   path, no query. `curl -i 'http://localhost:8080/api/nope?secret=1'` →
   `GET unmatched 404`; no path, no query.
6. `curl -i 'http://localhost:8080/vault?cloud_state=SECRET&email=a%40b.c'` →
   `GET static 200` with a built client (`404` without `apps/client/dist` —
   either way `static`); no state/email.
7. Repeat (3) with `-A 'bad"quote'`: the line is identical (no raw fallback).
8. `grep middleware::Logger apps/server/src` is empty.

### M1 — Log call-site remediation

**Scope**

- New `log_safety.rs` (`short_id`, `database_url_for_log`) + tests.
- Apply every fix in §8.6: favicon error classification, DB URL logs, recovery
  ids, cloud manual slices, hardcoded "Google" copy.
- Delete `startCloudAuthPublic`.
- No wire/API changes in this phase.

**Acceptance**

1. `apps/server` `cargo test` passes.
2. Start with `DATABASE_URL='sqlite:///tmp/voult-test.db?mode=rwc'`; the
   startup line is `DATABASE_URL resolved to sqlite:///tmp/voult-test.db` — no
   `?mode=rwc`.
3. Run a recovery attempt with a wrong proof (real vault + recovery file
   needed): the log shows `vault_id=xxxxxxxx` (8 chars), never the full UUID.
4. Point an item at an unreachable public host and load the vault; the favicon
   log says `favicon fetch failed` with `timeout`/`connect` booleans, and the
   host does not appear anywhere in the line.
5. `grep -n 'email=\|cloud_error_detail\|{e}' apps/server/src/endpoints/favicon.rs`
   shows no favicon URL logging.
6. `npx tsc --noEmit` in `apps/client` passes after the dead helper removal.

### M2 — OAuth callback contract and client mapping

**Scope**

- `oauth_state.rs`: `StateError` + closed reason logging.
- `oauth_flow.rs`: `CallbackError`, `Result<(), _>` returns; remove
  `SESSION_CLOUD_OAUTH_STATE`.
- `cloud_endpoints.rs`: `with_params`, outcome handling per §8.4, no email/
  detail/raw error; fixed JSON envelopes.
- Client: `oauth-error.ts`, `vault/index.tsx` mapping.
- Tests: exact redirect strings, `with_params` with an existing query, and the
  unknown-provider 400 envelope. Do not write a test that depends on real
  provider configuration (CI may or may not have OAuth env).

**Acceptance**

These CLI checks assume Google OAuth is configured (otherwise the
`OAUTH_PROVIDER_UNCONFIGURED` 503 is the only reachable provider path).

1. `curl -si 'http://localhost:8080/api/cloud/oauth/callback?provider=google_drive&error=access_denied'`
   → 302, `Location: …?cloud_error=OAUTH_CANCELLED&provider=google_drive`.
   No `email`, no detail, no raw `access_denied` text.
2. Same with `error=%3Cscript%3Ealert(1)%3C%2Fscript%3E` → identical
   `OAUTH_CANCELLED` Location; the string appears nowhere in the response.
3. `?provider=google_drive&code=SECRETCODE&state=SECRETSTATE` with no session
   and no matching state → 302 `cloud_error=OAUTH_INVALID_STATE`; the log line
   is `GET /api/cloud/oauth/callback 302` plus a `reason` metadata value, and
   contains neither `SECRETCODE` nor `SECRETSTATE`.
4. `?provider=bogus` → 400
   `{"error_msg":"unknown provider","code":"OAUTH_UNKNOWN_PROVIDER"}`.
5. In the app: cancel a real Google consent → "Authorization was cancelled or
   denied."; force an expired state → "This sign-in link expired…"; no raw
   server text appears.
6. Complete a real Google connect from Settings → the vault connects (the
   client never needed `email`). Complete a pending import from the landing
   page → the Drive vault list still loads (`cloud_state` preserved).
7. `grep -rn 'cloud_error_detail\|email=' apps/server/src apps/client/src` is
   empty.
8. `cargo test` and `npx tsc --noEmit` pass.

### M3 — Durable audit gate and docs

**Scope**

- `scripts/check-log-hygiene.sh` with the checks below.
- `crates/logger/README.md`, `AGENTS.md`, roadmap entry + changelog.
- Final manual sweep of the 146 sites (re-run the §3.4 command); no new
  failures.

```sh
#!/usr/bin/env bash
# Tripwire, not a parser: catches the exact patterns this P0 removed.
set -euo pipefail
fail=0
check() { # description, pattern, paths...
  local what=$1 pat=$2; shift 2
  if grep -REn "$pat" "$@" >/dev/null; then
    echo "FAIL: $what"; grep -REn "$pat" "$@" || true; fail=1
  fi
}
check "Actix default logger (its %r includes the query)" 'middleware::Logger' apps/server/src
check "Email in an OAuth redirect/query" 'email=' apps/server/src apps/client/src
check "OAuth error detail parameter" 'cloud_error_detail' apps/server/src apps/client/src
check "Favicon logs a reqwest error (Display includes the URL)" 'favicon (fetch|read) failed: [{]e[}]' apps/server/src
exit "$fail"
```

**Acceptance**

1. `./scripts/check-log-hygiene.sh` exits 0.
2. `grep -rn 'middleware::Logger' apps/server/src` is empty.
3. Re-run the §3.4 audit command on the post-change tree: every site must
   contain only closed-vocabulary text, a status, a `short_id`, or a DB error;
   the 21 original failures are gone. New request/state log sites are part of
   the reviewed set.
4. Logger README's Security section states the no-secret list and the fact
   that the access log is query-free by construction.
5. Roadmap item checked with a changelog entry naming the files and the
   manual checks above.

---

## 12. Manual acceptance matrix

| Check | Expected |
|---|---|
| Login / lock screen (triggers `/get_crypto_params`) | Log shows `GET /api/get_crypto_params 200`; no UUID. |
| Home screen with site icons | `GET /api/favicon 200` lines; no `u=`, no host. |
| Click a 404 API URL | `GET unmatched 404`; no path. |
| Load `/vault?recover=<uuid>` | `GET static 200`; no UUID. |
| Cancel Google consent | App shows the mapped cancellation sentence; log has no provider text. |
| Complete Google connect | Settings shows connected; log has no email. |
| Pending Drive import | Drive list loads; log has no `state`. |
| Recovery with wrong key | Log shows an 8-char vault id only. |
| Start with a DB URL containing `?mode=rwc` | Log shows the URL without the query. |
| `VOULT_LOG_LEVEL=warn` | Access logs (level `log`) are filtered; warnings/errors remain. |
| COOP/COEP after the middleware change | `curl -I` still returns both headers (sqlite-wasm still opens). |

---

## 13. Residual risk, follow-ups, and overlaps

**Residual risk left by this plan**

- **`cloud_state` in the pending redirect.** It is a bearer capability: for 10
  minutes as the CSRF token, and — after the pending exchange — for as long as
  the `cloud_pending_token` row exists, because that table has no TTL or sweep
  (`cloud/oauth_flow.rs:216-238`; `expires_at` is copied from the provider
  token, `:138-144`). With it, an unauthenticated caller can list the provider's
  vault files (`cloud_endpoints.rs:1455-1503`) and read an encrypted package
  (`:1511-1563`); a logged-in attacker can bind the pending provider token to
  their own vault (`:1429-1448`), taking over the backup binding. This plan
  removes it from logs and from the
  error redirects, but does not change the capability model. **Recommend a
  separate P0:** make the pending handle a distinct, single-use, session-bound
  value (or a short-lived HttpOnly cookie) with a TTL and sweeper, and/or add
  PKCE. Do not treat this item as closing that issue.
- **Provider tokens remain plaintext in SQLite** (`cloud_token`,
  `cloud_pending_token`) — the existing P1 credential-encryption item.
- **Log-file permissions.** The launcher creates `~/Library/Logs/Voult/server.log`
  with `OpenOptions::create/append` and no explicit mode
  (`launcher/src/main.rs:297-311`). This plan makes the contents much less
  sensitive; an explicit `0600` is a cheap follow-up but is not part of this
  item.
- **Debug level.** At `VOULT_LOG_LEVEL=debug`, SQLx emits SQL text (the
  formatter keeps the statement, not bound values —
  `crates/logger/src/formatter/sqlx.rs:31-41`) and dependencies emit debug
  records. Keep production at `log`/`info`; this is already the documented
  default.
- **Reverse proxies.** A proxy in front of the server may log the full URL if
  the operator configures it to. This plan can only control Voult's own log.

**Overlaps with other P0s (do not fix them here)**

- **P0 rate limits** (`SECURITY_AND_FEATURE_ROADMAP.md:58`): access logs no
  longer contain a client IP. If that item needs per-IP request telemetry, it
  must add a separate, explicit field (and justify the PII), not restore `%a`.
  The recovery throttle already logs decisions without an IP
  (`recovery.rs:505-508`).
- **P0 verifier replay** (`:57`): this plan never logs the verifier and does
  not change `/auth`. The full-vault-id log removal reduces the pairing of a
  leaked id with a replayed verifier, but does not fix replay.
- **P0 web headers** (`:63`): both items edit the `App::new().wrap(...)` block
  in `main.rs:295-309`. Land M0 with the header work in mind; the
  `DefaultHeaders` COOP/COEP values must not move or change.
- **P0 request bounds** (`:61`): `endpoints/mod.rs:34-54` echoes serde's
  field-path text to the client; it does not contain submitted values and is
  not a log leak. Leave it; the bounds item owns that contract.
- **P0 security tests** (`:62`): the callback/`RequestLog` tests added here are
  reusable for that item's release gate.
- **P1 client error logging** (`:73`): `vault/index.tsx:265` logs an axios
  error that may carry the request body (including `pendingState`) to the
  browser console. That is the client-logging item's seam; this plan only
  removes the server-side copies.

---

## 14. Definition of done

- The access log contains only `METHOD`, a route pattern or `static`/
  `unmatched`, status, and `duration_ms`.
- No first-party log line contains an email, OAuth code/state, token, full
  vault id, favicon URL, provider error text, or DB URL credentials.
- The OAuth callback returns only the codes in §8.4; the client renders its own
  copy and never server text.
- No success redirect carries an email or an error detail; the pending redirect
  carries only `cloud_state` + `provider`.
- `cargo test` (logger + server) and `npx tsc --noEmit` pass; the manual matrix
  in §12 has been exercised; `scripts/check-log-hygiene.sh` exits 0.
- The roadmap item is checked with a changelog entry; the pending-state
  capability issue is recorded as a separate follow-up, not silently dropped.
