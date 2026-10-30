# P0 — Rate-limit authentication and pre-auth endpoints

**Roadmap item:** `SECURITY_AND_FEATURE_ROADMAP.md:58` — "Rate-limit authentication and pre-auth endpoints."
**Scope:** `apps/server` (primary), plus the minimum `apps/client` / `apps/extension` handling that keeps a
`429` from becoming a data-loss bug. No crypto, schema-of-the-vault, or wire-payload changes.
**Status of this document:** implemented in this worktree (M0–M4). See §16 for the
as-built notes and the one correction to the design (D2 extractor ordering).
**Decision round:** the per-vault auth lockout trade-off was settled with the product owner (D5).

---

## 1. The issue

### 1.1 What is exposed today

Four unauthenticated (or cheaply authenticated) surfaces have no application-level budget:

| Surface | Evidence | Cost to the attacker | Cost to the server |
|---|---|---|---|
| `POST /api/auth` | `apps/server/src/endpoints/auth.rs:48-53` | one PBKDF2-60k + one HTTP request per password guess | one `SELECT` + string compare |
| `GET /api/get_crypto_params` | `apps/server/src/endpoints/get_crypto_params.rs:52-56` | one request | one `SELECT` |
| `POST /api/register` | `apps/server/src/endpoints/register.rs:75-80` | one request, up to a 2 MB body (`actix-web/src/types/json.rs:279`) | one transaction + one row + a session cookie |
| `POST /api/update_vault` | `apps/server/src/endpoints/update_vault.rs:51-56` | one request (needs a session) | CAS write + a detached provider upload (`update_vault.rs:160-163`) |

`POST /api/pair/consume` and `POST /api/recovery/challenge` do have throttles, but both are keyed on
`connection_info().realip_remote_addr()` (`pair.rs:81-86`, `recovery.rs:148-153`), and actix resolves that from the
**client-supplied** `Forwarded` / `X-Forwarded-For` header before falling back to the socket peer
(`actix-web/src/info.rs:142-146,168-173`). Rotating that header therefore mints a fresh budget per request on a
directly exposed server, and behind a proxy that does not overwrite it, the header is still attacker-controlled.

### 1.2 What an attacker actually gains

**Online master-password guessing (the real one).** The verifier is deterministic:
`vault_verifier = HMAC-SHA256(HKDF(PBKDF2(password, salt, iterations), "auth"), "auth-v1||static")`
(`packages/vault-core/src/crypto.ts:12,185-194,324-334`). The salt and iteration count are public pre-auth
(`get_crypto_params.rs:92-101`), and the iteration count is 60,000 (`crypto.ts:12`). So an attacker who knows a
vault id can compute one candidate verifier locally and post it to `/auth`. There is no lockout, no delay and no
per-request server work beyond a `SELECT`, so the server is a **password oracle at hardware speed**: roughly
`10^3`–`10^4` guesses/s on one modern 16-core host (order of magnitude at ~10 ms/PBKDF2-60k/thread). A password
from a 10^7-entry breach list falls in about two hours; a 6-character lowercase password in about two days. The
precondition is only the vault UUID — which the server itself writes into its own access log, because the client
puts it in the query string (`apps/client/src/lib/queries/cryptoParams/query.ts:9,20`) and the default actix logger
records the full request line (`main.rs:307`, `actix-web/src/middleware/logger.rs:492`), an already open P0
(`ROADMAP:60`).

**Registration disk fill.** `/register` accepts a 2 MB body and inserts it with no limit. Ten thousand requests is
~20 GB and as many rows; the vault key, envelopes and ciphertext are all attacker-chosen. Precondition: network
reachability only.

**Pairing-code brute force.** 31^6 ≈ 8.9×10^8 codes, 5-minute TTL (`pair.rs:28-30`). The per-code attempt cap is a
process-local `HashMap` (`pair.rs:111-130`) so with N workers it is effectively 10·N attempts per code, and the map
never shrinks. The TTL still makes brute force impractical, but the throttle is not the control the roadmap thinks
it is.

**Write / mirror amplification.** A session holder (or a runaway client loop) can push unbounded ciphertext into the
vault row and, for a provider-bound vault, drive a continuous backup upload (`update_vault.rs:160-163`,
`cloud/mirror.rs:232-249`). Precondition: one valid session cookie.

### 1.3 What "fixed" looks like

Every route above has a **named budget**, keyed on an identity the caller cannot choose freely, enforced through a
store that **every worker and every server instance sharing the database** consults; a refusal is `429` with a
machine-readable `code` and an honest `Retry-After`; the client treats that refusal as *retryable* rather than
fatal; and the counters/logs contain no password, verifier, key, or body.

---

## 2. What the code does today — and where the roadmap is stale

### 2.1 Verified as accurate

- `/auth` has no limiter at all (`auth.rs:48-53`). The only protection is the uniform 401 for unknown-vault and
  bad-verifier (`auth.rs:77-85,99-105`).
- `/register` has no limiter (`register.rs:75-80`); the transaction starts at `register.rs:127`.
- `/get_crypto_params` has no limiter (`get_crypto_params.rs:52-56`) and is a vault-existence oracle by design
  (`:75-78`, tracked separately at `ROADMAP:70`).
- `/update_vault` has no limiter (`update_vault.rs:51-56`).
- `/pair/consume` throttling is process-local (`pair.rs:90-107`) and the per-code counter is process-local and
  unbounded (`pair.rs:111-130`).
- Single-process in-memory state is *not* shared between instances. `main.rs:261` is the only thing that makes the
  recovery throttle shared **within** one process, and `main.rs:257-260` documents why.

### 2.2 Corrections to the roadmap text

1. **It is not a sliding window.** `ChallengeThrottle::allow` stores `(count, started)` per key and resets only when
   `started.elapsed() >= window` (`recovery.rs:136-144`). That is a fixed window anchored at the first request of
   the window, i.e. a burst-2×-at-the-boundary limiter. The plan below says "fixed window" and means it.
2. **"Per-IP" is weaker than it sounds.** Both existing limiters key on `realip_remote_addr()`
   (`recovery.rs:148-153`, `pair.rs:81-86`), which prefers `Forwarded` / `X-Forwarded-For`
   (`actix-web/src/info.rs:142-146`). Header rotation resets the budget; behind a proxy that appends rather than
   replaces, the leftmost (attacker-chosen) value is the one used. This is a live bypass on any deployment that is
   not strictly loopback-only.
3. **Recovery is only partly covered.** `challenge` is limited; `unlock` and `rewrap` are not (`recovery.rs:632`,
   `:747`) even though `rewrap` is the only irreversible write in the flow and both are unauthenticated.
4. **The pair per-code cap has no tests and no expiry.**
5. The roadmap's cross-reference "§3 gives implementation order" no longer resolves (there is no §3 in the current
   document). Cosmetic; not fixed here.

---

## 3. Decisions

Each decision below is final. Rejected options stay in so they are not re-litigated.

### D1 — Store: the SQLite database is the shared store

**Chosen.** A new `rate_limit` table in the existing database, written through one atomic upsert per charge.

- It is the only state every instance already shares. Multi-instance for this project means multiple server
  processes over one vault database; if two instances have *different* databases they are different vault universes
  and their budgets are per-universe by construction.
- It survives process restart, so an attacker cannot refill a budget by crashing the server.
- It closes the exact gap the roadmap names ("do not coordinate across instances") rather than documenting it.
- It doubles as the abuse-monitoring ledger (D8).

**Rejected — process-local map (the `ChallengeThrottle` shape).** Simplest and already proven
(`recovery.rs:102-146`), but it is a per-worker budget if constructed inside the closure and a per-process budget
otherwise; with N instances the real budget is N×. The roadmap explicitly calls this out. A single-process
in-memory limiter is **not** a security boundary for a multi-instance deployment — it is a speed bump.

**Rejected — Redis / external store.** A new runtime dependency and an operational component for a local-first
password manager. There is no second datastore in this project and no operator to run one.

**Rejected — reverse-proxy limits only (`limit_req` in nginx, etc.).** Not application-level: cannot key on a vault
id, cannot produce the API's `{error_msg, code}` envelope, is absent from the shipped launcher (which spawns the
binary directly and serves on `localhost:8080`, `main.rs:365`), and is invisible to the client. A proxy limit is a
reasonable *additional* layer for a remote deployment; it is not the control.

**Cost accepted:** one small UPSERT on the hot path of a limited request. Volume is tiny (the busiest policy is
60/min per vault) and the deny cache (D6) absorbs floods. Measured risk of write contention is low because sqlx
sets `busy_timeout = 5 s` (`sqlx-sqlite-0.8.6/src/options/mod.rs:201`) and the statement is single-row.

### D2 — Enforcement point: a typed extractor for per-IP budgets, explicit handler calls for per-target budgets

Actix runs every extractor before the handler, so `Limited<AuthIp>` prevents all handler work. It does **not**
prevent the body from being parsed: Actix polls the extractor futures of one handler concurrently
(`actix-web/src/extract.rs:327-380`), so a malformed body can still be answered by the JSON layer with a 400. That
request never reaches the handler either, and the existing 2 MB body cap bounds its cost. Per-vault budgets cannot
work as an extractor anyway — the vault id is inside the body — so those are an explicit call in the handler.

- The budget is named in the handler signature (`_limit: Limited<AuthIp>`), which is greppable and impossible to
  satisfy by accident.
- The policy name is a type (`AuthIp`, `RegisterIp`, …) resolved against a startup-validated budget table, so a typo
  is a compile error and a missing budget is a startup panic, not a silently unlimited route.
- If the extractor cannot find the limiter in `app_data`, it **fails closed** (500 + `error` log). A forgotten
  `.app_data(...)` must break tests, not disable the control in production.

**Rejected — one scope-wide middleware with a route→budget table.** Central, but a middleware cannot see the body,
so the per-vault axis is impossible; and a *global* per-IP budget would have to be sized around icon traffic, not
security: opening a vault prefetches up to 80 icons at concurrency 4 (`apps/client/src/lib/favicon/index.ts:49,409`)
plus one per visible row through `GET /api/favicon` (`main.rs:321`).

**Rejected — handler-level calls only.** Works, but the body has already been parsed by then, and a forgotten call
is invisible in review.

### D3 — Identity: socket peer by default, opt-in trusted proxies, never a client-supplied header

`client_ip(req)`:

1. Take `req.peer_addr()` (`actix-web/src/request.rs:274-277`). If absent (non-TCP transport), use `127.0.0.1` and
   log once at `warn`.
2. If — and only if — the peer is in `TRUSTED_PROXY_IPS`, walk `X-Forwarded-For` **right to left**, skipping entries
   that are themselves trusted proxies, and take the first untrusted address. Fall back to the peer.
3. Otherwise ignore `Forwarded` and `X-Forwarded-For` entirely.

`TRUSTED_PROXY_IPS` is a comma-separated list of **exact** IPs (`127.0.0.1,::1`). Invalid entries panic at startup
with the offending value, matching the module's stated fail-fast policy (`config.rs:8-9`). No CIDR parser: the
documented deployment has one proxy on a stable address, and a hand-rolled CIDR matcher is security-relevant code
with no current caller.

Why opt-in: in the shipped launcher there is no proxy, so a forwarded header is either an attacker or a
misconfiguration. Trusting it by default is exactly the bug in `recovery.rs:148-153`. Behind a proxy, the *default*
would collapse every client into one bucket and let one attacker deny service to all — so the proxy case must be
configured, and the server logs `warn` (once) the first time it sees a forwarded header from an untrusted peer:
that line means either "spoofing attempt" or "you forgot TRUSTED_PROXY_IPS", and both deserve attention.

**Rejected — `realip_remote_addr()`.** Client-spoofable as shown above.
**Rejected — trusting XFF whenever the peer is loopback.** Ambiguous: a local proxy and a local attacker are
indistinguishable, and the shipped product binds loopback.
**Rejected — keying on the session cookie or device id.** Attacker-controlled pre-auth; the device id is not even
sent to the server.
**Rejected — `Forwarded` (RFC 7239) support.** Rarely emitted by the proxies this project would sit behind; adds a
second parser and a second place to get the trust walk wrong.

Second axis: **vault id**. It is the only stable identity an attacker cannot mint for free (a v4 UUID), and it
bounds guessing across IP rotation. `/auth` uses the *supplied* id so that unknown and known vaults are counted
identically (no existence oracle). Authenticated routes use the **session's** id, never a body-supplied one, so a
stolen cookie cannot spend another vault's budget.

### D4 — Algorithm: fixed window, one row per (policy, subject)

`window_start = floor(now / window) * window` computed from SQLite's clock, so instances with skewed wall clocks
agree on window boundaries. One row holds the current window's count; a rollover resets it inside the same
statement. No per-request timestamps, so the table is bounded by the number of distinct subjects, not by request
volume.

Accepted downside: up to 2× the budget across a window boundary. At these budgets (10 auth attempts per 10 minutes)
that is a rounding error, and it is the price of O(1) rows.

**Rejected — true sliding window / timestamp log.** Unbounded rows per subject; needs a `DELETE` per request or a
retention job; no user-visible difference at these rates.
**Rejected — token bucket.** Needs a read-modify-write or float refill state, or a `blocked_until` column; the
fixed window already gives the "N per T" guarantee the roadmap asks for and is one statement.
**Rejected — leaky bucket in memory + periodic DB flush.** Two sources of truth, and the flush interval becomes the
real budget during an incident.

### D5 — Auth lockout: 10 attempts / 10 min per vault, counter cleared on success

Settled with the product owner. Consequences, stated plainly:

- Effective ceiling ≈ 1,440 guesses/day/target regardless of IP rotation.
- An attacker who knows the vault id can burn the budget and refuse the owner a **fresh password login for up to
  10 minutes at a time**, repeatedly. This is inherent to any per-target cap; the alternative below gives up the
  control entirely.
- Availability that is *not* affected: an already-unlocked vault (local-first, keys in `VaultState`), device unlock,
  the recovery file flow, and the extension's cached session. Only `/auth` is refused.
- The counter is **cleared on a successful login**, so an owner who mistypes a few times and then succeeds starts
  the next window with a full budget. This is not a bypass: only a correct verifier clears it, and once the cap is
  reached a correct attempt is refused like any other until the window ends.

**Rejected — no per-vault cap (per-IP only).** A botnet or a spoofed header defeats it; the item stays open.
**Rejected — permanent lockout / escalating hours.** Simultaneously a trivial remote DoS on the vault owner and
still only a linear improvement in guessing resistance; also incompatible with "the master password is the only
route back in when the session is gone" (`apps/client/src/lib/auth/flows.ts:149-160`).

### D6 — Denials are cached in memory as an optimization, never as the source of truth

After the store rejects a subject, the instance remembers `(key_hash → window_end)` in a bounded map and answers
further requests for that subject **without touching the database**. This keeps a flood from turning into a write
flood, and it is safe because the DB row remains authoritative: a lost/cleared cache only costs one extra DB read.

Bounded at 8,192 entries; on overflow, retain unexpired entries, then clear. Poisoned lock → fail open (same
reasoning as `recovery.rs:125-131`): a panic elsewhere must not turn the endpoint into a permanent outage.

### D7 — Response: `429` + `Retry-After` + a surface-specific code

```
HTTP/1.1 429 Too Many Requests
Retry-After: 542
Cache-Control: no-store
Content-Type: application/json

{"error_msg":"too many attempts, try again later","code":"RATE_LIMITED"}
```

- `error_msg` is identical everywhere; only `code` varies, and only to keep the two existing contracts
  (`RECOVERY_RATE_LIMITED` at `recovery.rs:512`, `PAIR_RATE_LIMITED` at `pair.rs:218`).
- `Retry-After` is integer seconds until the current window ends, clamped to `1..=window`.
- No new response fields, no `X-RateLimit-*` headers (nothing consumes them; they leak policy shape).
- `Cache-Control: no-store` arrives from the `/api` scope wrapper (`main.rs:314`), which also wraps extractor
  errors — no change needed there.

**Rejected — 403.** Conflates throttling with authorization; the client's `toUnlockError` already maps 401/403 to
"Incorrect password" (`flows.ts:273-275`), which would be a lie.
**Rejected — 503.** Implies server fault and invites client retry storms.
**Rejected — sleeping in the handler.** Holds a worker and a socket per refusal; that is a resource-exhaustion bug,
not a rate limit.
**Rejected — a generic `RATE_LIMITED` for every surface.** It would break the two codes already documented and
tested; the extra constants cost nothing.

### D8 — Abuse monitoring: structured denial logs + a queryable table, no metrics stack

- `warn` on the **first** denial of each window per subject (detected as `count == max + 1`). Later denials are
  `debug`. This is log-flood-proof by construction, without a second cache.
- Metadata: `policy`, `count`, `retry_after`, `subject_hash` (first 12 hex chars), `peer_ip`. Never the vault id,
  never the verifier, never a body.
- Startup `info`: active policies with budgets, trusted-proxy list, storage backend. An operator can see what is
  enforced.
- The `rate_limit` table is itself the ledger: `SELECT kind, count(*) FROM rate_limit GROUP BY kind` shows what is
  being hit right now.
- Store errors log at `error` at most once per 60 s (atomic timestamp), so a broken DB does not become a log flood.

**Rejected — a durable `abuse_event` audit table.** Duplicates the access log and grows without a retention policy;
a real audit trail belongs with the session/device inventory item (`ROADMAP:30`).
**Rejected — Prometheus/OpenTelemetry.** New dependency and an operational surface with no consumer.

### D9 — Budgets are compile-time constants, not environment variables

A security control that an operator can set to `0` or `unlimited` is a control that will be. The deployment shape
is known; changing a number is a code change with a review. Tests override via `RateLimiter::for_tests`, which is
`#[cfg(test)]`-only.

**Rejected — env-tunable budgets.** Configuration surface with no current user; invites silent disabling.

### D10 — `/lock`, `/logout`, `/session`, `/get_vault`, `/favicon`, and `/cloud/*` are deliberately not limited

- `/lock` is a **safety action** (`apps/client/src/lib/auth/lock.ts`): a lock that can be refused is a lock that
  cannot be relied on. Never rate-limit it.
- `/logout` and `/session` are session lifecycle, checked on focus/visibility (`use-session-sync.ts:158-164`) and by
  the extension's 1-minute alarm; a refusal here would strand the UI in a worse state than the abuse it prevents.
- `/get_vault` is authenticated, read-only, and pairs with every write in `sync()` (`sync/index.ts:119,170`), so a
  per-vault read cap would double-count legitimate sync.
- `/favicon` fans out up to 80 prefetches plus one per visible row (D2).
- `/cloud/*` is OAuth redirect plumbing and an authenticated operator surface; it has its own provider-side limits.

These are stated so their absence is not read as an oversight later.

### D11 — Pairing per-code attempts move from a process map to a column

`pair_code` gains `attempts INTEGER NOT NULL DEFAULT 0`, incremented atomically:
`UPDATE pair_code SET attempts = attempts + 1 WHERE code_hash = ? RETURNING attempts`.
The counter dies with the row, is shared across workers and instances, and cannot grow without bound. This is
strictly better than `pair.rs:111-130` and removes that leak.

---

## 4. Budgets

All windows are fixed, epoch-aligned, in seconds. "Subject" is what the key is derived from.

| Policy type | Route(s) | Subject | Budget | Why this number |
|---|---|---|---|---|
| `AuthIp` | `POST /auth` | client IP | **30 / 60 s** | A human needs ≤5 (typo + retry). 30 absorbs NAT and client retry loops while capping one host at ~43k/day. |
| `AuthTarget` | `POST /auth` | supplied vault id | **10 / 10 min** | D5. The only control that survives IP rotation. Cleared on success. |
| `RegisterIp` | `POST /register` | client IP | **5 / 60 min** | One human creates one vault; retries after a failed commit are covered (`registration.ts:137` surfaces the error, and `signup.tsx:91-95` reuses the committed result instead of re-registering). |
| `RegisterGlobal` | `POST /register` | constant | **30 / 60 min** | Disk-fill ceiling that does not depend on IP diversity. 30 new vaults/hour is absurd for a single-tenant server; the failure mode is "cannot register for an hour", not "disk full". |
| `CryptoParamsIp` | `GET /get_crypto_params` | client IP | **60 / 60 s** | One call per unlock attempt (`flows.ts:181`); 60 leaves room for a vault chooser and for manual retries while bounding enumeration. |
| `VaultWrite` | `POST /update_vault`, `POST /vaults`, `POST /vault/password` | session vault id | **60 / 60 s** | Sync coalesces (`sync-scheduler.ts:32-37`) and a human edits <10/min; 60/s·min protects the write path and the provider mirror without breaking a reconnect burst. |
| `VaultAdmin` | `POST /recovery/regenerate` | session vault id | **10 / 60 min** | Deliberate, rare, heavy (rotates the recovery key). |
| `PairStart` | `POST /pair/start` | session vault id | **10 / 60 s** | One code per pairing; preventing mint churn (each mint deletes the previous code, `pair.rs:161-164`). |
| `PairIp` | `POST /pair/consume` | client IP | **20 / 60 s** | Existing constant (`pair.rs:35-36`), preserved. |
| `RecoveryChallengeIp` | `POST /recovery/challenge` | client IP | **10 / 60 s** | Existing constant (`recovery.rs:89-90`), preserved. |
| `RecoveryPreauthIp` | `POST /recovery/unlock`, `POST /recovery/rewrap` | client IP | **20 / 60 s** | One recovery = challenge + unlock + rewrap; 20/min allows ~6 complete recoveries/min and bounds unauthenticated DB writes/HMAC work. |

Deliberately absent: a per-`(vault, day)` ceiling. Considered and rejected because keying a 24-hour row on a
*guessed* vault id lets an unauthenticated spray create ~43M rows/day (~4 GB) at 30 req/min/IP × 1,000 IPs, while
keying it only on *existing* vaults reintroduces an existence oracle via the 429. The 10/10-min target window
already bounds guessing to ~1,440/day; the daily ceiling bought a 6× tightening at the cost of a memory/DoS hole and
an oracle. Not worth it.

---

## 5. Data model

### 5.1 New table `rate_limit`

Migration `apps/server/migration/src/m20261028_000008_rate_limit.rs`, registered in `migration/src/lib.rs` after
`m20261027_000007`. This is a **new table**, not a compat migration: there is no old data to reshape and no version
field. (AGENTS.md's "no migrations" rule is about schema evolution; a new table still needs a migration because
that list is how tables exist.)

```
rate_limit
  kind         TEXT    NOT NULL   -- policy type name, e.g. "AuthIp"
  key_hash     TEXT    NOT NULL   -- hex SHA-256(kind || 0x1F || subject), 64 chars
  window_start INTEGER NOT NULL   -- unix seconds, epoch-aligned
  count        INTEGER NOT NULL
  expires_at   INTEGER NOT NULL   -- window_start + window_secs
  PRIMARY KEY (kind, key_hash)
  INDEX idx_rate_limit_expires_at (expires_at)
```

`sea_query` types: `string` for the two text columns, `big_integer` for the three integers
(`sea-orm-migration-2.0.0-rc.34/src/schema.rs:110,170`). Composite PK via
`.primary_key(Index::create().col(RateLimit::Kind).col(RateLimit::KeyHash))`.

Entity `apps/server/src/entity/rate_limit.rs`:

```rust
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "rate_limit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_hash: String,
    pub window_start: i64,
    pub count: i64,
    pub expires_at: i64,
}
```

No relations. Register it in `entity/mod.rs` and `entity/prelude.rs`.

### 5.2 `pair_code.attempts`

Same migration file: `alter_table(Table::alter().table(PairCode::Table).add_column(integer(PairCode::Attempts).not_null().default(0)))`,
and `pub attempts: i32` on `pair_code::Model`. Nothing reads it until M3, so the column can ship first and the
behaviour change later without an intermediate broken state.

### 5.3 Why `key_hash` and not the raw subject

The row is a **counter**, not an audit trail. Storing `ip|1.2.3.4` and `vault|<uuid>` plainly turns the table into a
targeting log that survives in backups, and lets a casual dump enumerate which vaults are being probed. Hashing is
cheap hygiene, not a secrecy claim: IPv4 is trivially enumerable, which is fine — the operator who needs the raw
value has the access log, and the counter has no need for it.

Hashing is domain-separated by `kind` so the same string under two policies cannot collide. `kind` is also in the
primary key, so a hash collision across policies is structurally impossible.

`subject` formats (before hashing): `ip:<canonical>` (IPv4-mapped IPv6 normalized to IPv4 via
`Ipv6Addr::to_ipv4_mapped`), `vault:<canonical lowercase uuid>`, `global`.

---

## 6. Module shape — `apps/server/src/rate_limit.rs`

New crate-root module (declared in `main.rs` next to `mod endpoints;`), because both `main.rs` and every endpoint
need it.

```rust
pub struct Budget { pub max: u32, pub window_secs: i64 }

/// Marker types. KEY names the policy; CODE is the wire code for a refusal.
pub trait Policy {
    const KEY: &'static str;
    const CODE: &'static str = "RATE_LIMITED";
}

pub enum Subject<'a> { Ip(IpAddr), Vault(&'a str), Global }

pub struct RateLimiter {
    pool: DbPool,
    budgets: HashMap<&'static str, Budget>,
    trusted_proxies: Vec<IpAddr>,
    denials: Mutex<HashMap<String, i64>>,   // key_hash -> window_end (D6)
    charges: AtomicU64,                     // drives the opportunistic sweep
    last_store_error: AtomicI64,            // log throttle (D8)
}

impl RateLimiter {
    /// Panics on an empty table or a duplicate policy key. A `#[test]` asserts
    /// that every marker type's `KEY` appears in `production_budgets()`, so a
    /// new policy cannot ship without a budget.
    pub fn new(pool: DbPool, budgets: Vec<(&'static str, Budget)>, trusted_proxies: Vec<IpAddr>) -> Self;

    #[cfg(test)]
    pub fn for_tests(pool: DbPool, overrides: &[(&'static str, Budget)]) -> Self;

    pub async fn charge<P: Policy>(&self, subject: &Subject<'_>) -> Result<Allowed, Rejected>;
    pub async fn reset<P: Policy>(&self, subject: &Subject<'_>);   // success path of /auth
    pub fn client_ip(&self, req: &HttpRequest) -> IpAddr;
    pub async fn sweep_expired(&self);                            // startup + every 256 charges
}

pub struct Allowed { pub remaining: u32 }
pub struct Rejected { pub retry_after_secs: u64, pub code: &'static str }

impl Rejected {
    pub fn into_response(self) -> HttpResponse;   // 429 + Retry-After + {error_msg, code}
}

/// FromRequest: charges the per-IP budget before the body extractor runs.
/// Missing `web::Data<RateLimiter>` in app_data is a hard error (500), never a bypass.
pub struct Limited<P: Policy>(PhantomData<P>);
impl<P: Policy + 'static> FromRequest for Limited<P> { type Error = Rejected; /* ... */ }
```

`Rejected` implements `actix_web::ResponseError` (`status_code = 429`, `error_response` delegates to
`into_response`), so the extractor path and the handler path produce byte-identical responses.

### 6.1 The charge statement

One statement: window rollover, increment, and read-back. SeaORM's `OnConflict` builder cannot express
`count = count + 1` with a CASE, so this is a parameterized `Statement` executed via
`ConnectionTrait::query_one` — bound values only, no interpolation.

```sql
INSERT INTO rate_limit (kind, key_hash, window_start, count, expires_at)
VALUES (
    ?, ?,                                  -- kind, key_hash
    (CAST(strftime('%s','now') AS INTEGER) / ?) * ?,   -- window_secs
    1,
    (CAST(strftime('%s','now') AS INTEGER) / ?) * ? + ?
)
ON CONFLICT (kind, key_hash) DO UPDATE SET
    count = CASE WHEN excluded.window_start > rate_limit.window_start
                 THEN 1 ELSE rate_limit.count + 1 END,
    window_start = CASE WHEN excluded.window_start > rate_limit.window_start
                        THEN excluded.window_start ELSE rate_limit.window_start END,
    expires_at = CASE WHEN excluded.window_start > rate_limit.window_start
                      THEN excluded.expires_at ELSE rate_limit.expires_at END
RETURNING count, expires_at;
```

- The statement binds `kind`, `key_hash`, and `window_secs` five times (once per `?`). sqlx-sqlite binds
  positionally, so push the same window value for every occurrence; do not rely on `?NNN` numbering.
- `strftime('%s','now')` is SQLite's UTC clock, so all instances agree on window boundaries even with skewed host
  clocks. Only `Retry-After` (computed from `expires_at` minus `chrono::Utc::now()`) is exposed to skew, clamped to
  `1..=window_secs`.
- `count <= max` → allowed. `count > max` → `Rejected { retry_after_secs: (expires_at - now).clamp(1, window) }`.
- The first denial of a window is exactly `count == max + 1`; that is the log trigger (D8).
- `RETURNING` requires SQLite ≥ 3.35; the bundle is 3.46 (`libsqlite3-sys 0.30.1`, `Cargo.lock:2046-2048`).

On any store error: log at `error` (throttled), return `Allowed` — **fail open**. Justified because every limited
route needs the same database to do anything at all: if the DB is down, `/auth` returns 500 at its `SELECT`
(`auth.rs:71-97`) and `/register` fails at `begin()` (`register.rs:127`). Failing open therefore cannot create an
unauthenticated bypass; it only skips counting during an outage that already denies service.

---

## 7. Endpoint wiring

### 7.1 `auth.rs`

```rust
pub async fn auth(
    pool: web::Data<DbPool>,
    limiter: web::Data<RateLimiter>,
    _limit: Limited<AuthIp>,       // MUST stay first: rejects before the body is parsed
    session: Session,
    payload: web::Json<AuthRequest>,
) -> HttpResponse
```

After `Uuid::parse_str` (`auth.rs:64-69`), before the vault `SELECT` (`:71`):

```rust
match limiter.charge::<AuthTarget>(&Subject::Vault(&vault_uuid.to_string())).await { ... }
```

Use the **canonicalized** id so `ABC…` and `abc…` share one budget. Charge before the lookup so unknown ids are
counted identically (no existence oracle). On success (`:107`), `limiter.reset::<AuthTarget>(...)` — only a
successful verifier can clear the budget. The verifier is never touched, never hashed, never keyed on.

### 7.2 `register.rs`

`_limit: Limited<RegisterIp>` first in the signature, plus an explicit `charge::<RegisterGlobal>(&Subject::Global)`
immediately after it (both before the UUID parse and the transaction at `:127`). No reset: a successful
registration is already bounded by both budgets.

### 7.3 `get_crypto_params.rs`

`_limit: Limited<CryptoParamsIp>` only. No per-vault budget: enumeration is capped per IP, and a per-vault budget
would make the 404 path (`:75-78`) behave differently from the 200 path in a way that is visible to a caller who
does not know whether the vault exists.

### 7.4 `update_vault.rs`

`_limit: Limited<VaultWrite>` is not usable here — the subject is the *session* vault, resolved inside the handler
(`:57-66`). So: no extractor; charge immediately after `session_vault_id`, before the `SELECT` at `:70`. Same for
`vaults.rs:52-57` (`create_vault`) and `update_vault_password.rs:24-31`. Key on the session id, never on anything in
the body.

### 7.5 `recovery.rs`

- `recovery_challenge`: replace the `throttle: web::Data<ChallengeThrottle>` argument and the manual check
  (`:497-514`) with `_limit: Limited<RecoveryChallengeIp>`.
- `recovery_unlock`, `recovery_rewrap`: add `_limit: Limited<RecoveryPreauthIp>`.
- `recovery_regenerate`: charge `VaultAdmin` after the session resolves.
- Delete `ChallengeThrottle`, `THROTTLE_SWEEP_THRESHOLD`, and `recovery::client_ip` (now unused in that file).
  Keep `MAX_LIVE_CHALLENGES_PER_VAULT` (`:66`) — it is a storage bound, not a rate limit.
- Preserve `RECOVERY_RATE_LIMITED` via `impl Policy for RecoveryChallengeIp { const CODE = "RECOVERY_RATE_LIMITED"; }`
  (shared by all three unauthenticated recovery routes).
- Do not change `auth_failed()` (`:164-170`) or any envelope code.

### 7.6 `pair.rs`

- `pair_consume`: `_limit: Limited<PairIp>` first; delete `CONSUME_THROTTLE`, `consume_throttle`,
  `check_consume_rate`, `client_ip` (`:81-107`).
- Replace the `CODE_ATTEMPTS` map (`:111-130`) with the `pair_code.attempts` column (D11): atomic increment +
  `RETURNING attempts`; `> MAX_CONSUME_ATTEMPTS_PER_CODE` deletes the row and returns `PAIR_INVALID` exactly as
  today (`:233-246`).
- `pair_start`: charge `PairStart` after the session resolves.

### 7.7 `main.rs`

```rust
// Built ONCE, outside the HttpServer::new closure — same reasoning as the
// recovery throttle comment above: the closure runs per worker.
let rate_limiter = web::Data::new(rate_limit::RateLimiter::new(
    db_data.get_ref().clone(),
    rate_limit::production_budgets(),
    config::trusted_proxies(),          // Vec<IpAddr>, empty unless TRUSTED_PROXY_IPS is set
));
rate_limiter.sweep_expired().await;     // next to recovery::prune_expired_challenges (main.rs:226)
```

`.app_data(rate_limiter.clone())` next to `db_data` (`:296`), and one startup `info` line with the active policies.
Nothing else in `main.rs` changes: no new middleware, so the COOP/COEP `DefaultHeaders` (`:302-306`), the access-log
wrapper (`:307`), session and CORS wrappers (`:308-309`) keep their order.

### 7.8 `config.rs` / `.env.example`

Add `pub const ENV_TRUSTED_PROXY_IPS: &str = "TRUSTED_PROXY_IPS";` and
`pub fn trusted_proxies() -> Vec<IpAddr>` (empty when unset; panic naming the bad value on a parse error). Document
it in the config table at `config.rs:12-21` and in `.env.example` next to the session/CORS block:

```sh
# Only set this when a reverse proxy terminates traffic in front of the server.
# Comma-separated exact IPs. Forwarded headers from any other peer are ignored,
# because they are client-controlled.
# TRUSTED_PROXY_IPS=127.0.0.1,::1
```

---

## 8. Client and extension behaviour

A 429 is a new server answer; two places would mishandle it today.

### 8.1 Client sync — a 429 must not strand intents

`sync()` already keeps intents on any unexpected error (`sync/index.ts:175-188` returns without marking them
synced), but the only mounted trigger is `intent-created` (`sync-scheduler.ts:16-38`, `use-sync-triggers.ts` is not
mounted), so a refused push would sit until the user edits again.

Minimal change:

- `sync/index.ts`: on `status === 429`, read `Retry-After`, log at `info`, and throw a typed
  `SyncRateLimited { retryAfterMs }` instead of `console.error(...)` + return.
- `sync-scheduler.ts`: handle that type in `syncOnce()` (which currently swallows every error at `:54-60`), arm one
  `setTimeout(() => this.requestSync("forced"), min(retryAfterMs, 60_000))` from `loop()`, keep `running = false`,
  and clear the timer on lock/session loss so a locked vault never schedules work.

Cap the wait at 60 s: the intent is to re-check, not to honour a long window exactly; the next attempt either
succeeds or gets a fresh `Retry-After`.

### 8.2 Client unlock — a 429 is not a wrong password

`toUnlockError` (`flows.ts:270-285`) maps 401/403/`/invalid/i` to "Incorrect password", 404 to "vault gone", and
falls through to `error_msg` for everything else — so a 429 already reads
"too many attempts, try again later". Add one explicit branch that reads `Retry-After` and says
"Too many attempts. Try again in 9 minutes." No behaviour change beyond the message. Same for the signup/register
path, which already surfaces `error_msg` (`lib/vault/registration.ts:137-140`).

### 8.3 Extension — a 429 during save is transient

`apps/extension/src/background/vault.ts:1429-1441` throws on anything that is not a network error or a version
conflict, which would surface "could not save" and drop the pending save. Add
`if (isRateLimited(e)) { await sleep(min(retryAfterMs, 2_000)); continue; }` inside the existing bounded attempt
loop, and return the existing `{ saved: false, offline: false }` shape when attempts are exhausted so the popup can
say "saving paused".

**Verification note:** the client and extension have no test runner (`AGENTS.md`), so this half is verified by hand
(§12, M4) — same caveat the project already records for other client work.

---

## 9. Files to touch

### New

| File | Purpose |
|---|---|
| `apps/server/src/rate_limit.rs` | limiter, policies, budgets, `Subject`, `Limited<P>`, `Rejected` |
| `apps/server/src/entity/rate_limit.rs` | SeaORM entity |
| `apps/server/migration/src/m20261028_000008_rate_limit.rs` | `rate_limit` table + `pair_code.attempts` |
| `plans/p0-auth-rate-limits.md` | this plan |

### Edit

| File | Change |
|---|---|
| `apps/server/src/main.rs` | `mod rate_limit;`, construct once, `app_data`, startup sweep + policy log |
| `apps/server/src/endpoints/auth.rs` | extractor + per-target charge/reset; tests |
| `apps/server/src/endpoints/register.rs` | extractor + global charge; test app wiring |
| `apps/server/src/endpoints/get_crypto_params.rs` | extractor; tests |
| `apps/server/src/endpoints/update_vault.rs` | session-keyed charge; test app wiring |
| `apps/server/src/endpoints/vaults.rs` | session-keyed charge |
| `apps/server/src/endpoints/update_vault_password.rs` | session-keyed charge |
| `apps/server/src/endpoints/recovery.rs` | replace bespoke throttle with the shared limiter; delete dead code; update 3 tests |
| `apps/server/src/endpoints/pair.rs` | extractor, `pair_code.attempts`, delete process maps |
| `apps/server/src/entity/mod.rs`, `entity/prelude.rs` | register the entity |
| `apps/server/src/entity/pair_code.rs` | `attempts: i32` |
| `apps/server/migration/src/lib.rs` | register the migration |
| `apps/server/src/config.rs` | `ENV_TRUSTED_PROXY_IPS`, `trusted_proxies()`, doc table |
| `apps/client/src/lib/sync/index.ts` | 429 → typed retryable error |
| `apps/client/src/lib/sync/sync-scheduler.ts` | one-shot retry timer |
| `apps/client/src/lib/auth/flows.ts` | 429 message with `Retry-After` |
| `apps/extension/src/background/vault.ts` | 429 transient in the save loop |
| `.env.example` | document `TRUSTED_PROXY_IPS` |
| `SECURITY_AND_FEATURE_ROADMAP.md` | update item 58 at the end of M4 |
| `AGENTS.md` | one gotcha line: limiter is DB-backed, constructed once, never key on a client-supplied id for authenticated routes |

### Do not touch (and why)

- `apps/server/src/endpoints/auth.rs:99` comparison semantics — the replayable-verifier P0 (`ROADMAP:57`). This plan
  only adds a limiter around the handler; do not "fix" constant-time comparison here.
- `packages/vault-core/src/crypto.ts` — the KDF P0 (`ROADMAP:56`). Nothing here changes derivations or iteration
  counts.
- `apps/server/src/session_auth.rs` — session semantics stay exactly as they are.
- `apps/client/src/lib/crypto/**`, `lib/sqlite/**`, `lib/state/**` — no client storage or key changes.
- `apps/server/src/endpoints/mod.rs` — `json_config()` body limits belong to the request-bounds P0 (`ROADMAP:61`).
- `apps/server/src/cloud/**` — the mirror is only *protected* by the write budget, not changed.
- COOP/COEP headers (`main.rs:302-306`, `apps/client/public/_headers`) — no new middleware, so no re-ordering.
- `apps/server/src/endpoints/lock.rs`, `logout.rs`, `session_status.rs`, `get_vault.rs`, `favicon.rs` — D10.

---

## 10. Trust boundaries and invariants

**Zero knowledge.** The limiter sees a method, a path, an IP, and (for `/auth`) a caller-supplied vault UUID. It
never reads or stores `vault_verifier`, the password, the vault key, either envelope, or any ciphertext. It does not
key on the verifier in any form — a hash of a credential is still a credential-shaped index and has no business in a
counter table. No new log line contains a vault id, verifier, proof, challenge, or body; the recovery flow's
existing `vault_id` log line (`recovery.rs:587-590`) is left alone (it belongs to the log-sanitization P0) and is not
copied.

**Session semantics.** A 429 is not a 401. `isSessionRequired` keys strictly on `status === 401 && code ===
SESSION_REQUIRED` (`http.ts:27-34`), so `teardownVaultSession` cannot fire from a refusal. A rejected `/auth` never
reaches `establish_vault_session` (`auth.rs:109`), so no session rotation, no fixation window, and no clearing of an
existing session. `/lock` is never limited (D10), so a throttled client can always lock.

**No new oracle.** `/auth` keeps one identical 401 for unknown-vault and bad-verifier, and the per-target counter is
keyed on the **supplied** id, so a known and an unknown vault consume budget identically and return the identical
429. `/recovery/*` keeps its uniform 401 (`recovery.rs:164-170`); a 429 is emitted on request volume only, never
conditioned on vault existence. `/get_crypto_params` keeps its existing 404 (a known P1, not worsened).

**Per-vault namespacing.** No client-side change: one OPFS file per vault, one IndexedDB record per vault, no new
key material, no new storage. `vault_write` is keyed by the **session** id, so a stolen cookie for vault A can never
spend vault B's budget, and no request body can influence an authenticated route's key.

**Recovery Rule R1.** Untouched. The only recovery change is where the per-IP check happens; `recovery_wrap`
direction, `recoveryAad`, and the two HMAC labels are untouched. A limiter refusal happens before any challenge,
proof, or envelope is read.

**COOP/COEP.** No new `wrap`. The limiter is an extractor and a handler call, so the header stack in `main.rs` is
byte-identical.

**CORS/CSRF.** Refusals are produced inside the service stack, so `Cors` and the `/api` `Cache-Control` wrapper still
apply; a 429 carries the same CORS headers as a 200. `OPTIONS` preflights are answered by the CORS middleware before
routing and are not charged.

**Data at rest.** The limiter adds counters only. A dump of `rate_limit` reveals how many attempts were made against
hashed subjects, not who or which vault, and `pair_code.attempts` is an integer on an already-existing row.

---

## 11. Failure modes and limits (what this does and does not buy)

| Situation | Behaviour |
|---|---|
| DB unavailable / store error | Fail open, `error` logged ≤1/60 s. Cannot create a bypass: the same DB is required by the endpoint itself. |
| Several instances, **separate** databases | N× budget. Not a bug — they are separate vault universes. Documented, not silent. |
| Several instances, **one** database file | One budget (the acceptance test proves this). Journal mode stays the default; do not change it here (unrelated DB hardening). |
| Host clock skew | Window boundaries come from SQLite, so counts agree. Only `Retry-After` can be off by the skew, and it is clamped. |
| Restart / crash | Budgets persist. An attacker cannot refill by crashing the server. |
| Contention with a vault write | The charge is a separate autocommit statement, never inside the handler's transaction, so it can only wait on SQLite's writer (≤5 s `busy_timeout`) and then fail open. Never wrap a charge and a vault write in one transaction. |
| Proxy behind an unset `TRUSTED_PROXY_IPS` | Every client collapses into one bucket — a self-DoS. Detected by the once-only "forwarded header from untrusted peer" warning. |
| Shared NAT / CGNAT | One budget per public IP. Budgets are sized for that (30 auth/min, 60 params/min). |
| Table growth | Expired rows swept at startup and every 256 charges. Steady-state rows ≈ distinct subjects × active policies, and no row outlives its window (the longest is 1 hour, `RegisterIp`/`VaultAdmin`). |
| Log volume under attack | One `warn` per subject per window (`count == max + 1`), rest at `debug`. |
| **Residual risk: weak master password** | 1,440 guesses/day/target is still enough for a top-10k password in a week. Rate limiting complements, and does not replace, the KDF P0 (`ROADMAP:56`). Say so in the release notes. |
| **Residual risk: targeted login DoS** | An attacker who knows the vault id can refuse fresh `/auth` for 10 min at a time (D5). Local unlock, device unlock, recovery, and `/lock` are unaffected. |
| **Residual risk: internal clients** | A local process can reach loopback directly and is indistinguishable from the app. Rate limiting is not a defence against a local attacker; file permissions and the OS boundary are. |

---

## 12. Phases

Each phase leaves the tree working. `cargo test` in `apps/server` must pass at the end of every phase.

### M0 — Primitive, schema, trust boundary (no route wired)

Scope:

- `migration/src/m20261028_000008_rate_limit.rs` + `lib.rs`; `entity/rate_limit.rs` + `mod.rs`/`prelude.rs`;
  `pair_code.attempts` column and entity field. Adding the field breaks the explicit `ActiveModel` literal at
  `pair.rs:169-175`, so that literal gains `attempts: Set(0)` in this phase (behaviour unchanged) to keep the tree
  compiling before M3 starts using it.
- `src/rate_limit.rs`: `Budget`, `Policy`, marker types, `Subject`, `RateLimiter::{new, for_tests, charge, reset,
  client_ip, sweep_expired}`, `Rejected` (+ `ResponseError`), `Limited<P>`, `production_budgets()`.
- `config.rs`: `ENV_TRUSTED_PROXY_IPS` + `trusted_proxies()`; `.env.example`.
- `main.rs`: module, construction outside the closure, `app_data`, startup sweep, startup `info`.
- Tests: allow-then-refuse; window rollover; two limiter instances over one pool share a budget; denial cache
  suppresses the DB write; hash domain separation; `client_ip` ignores a forwarded header from an untrusted peer and
  takes the rightmost untrusted hop from a trusted one; sweep deletes only expired rows.

Acceptance:

- `cargo test` passes; the new tests appear with names matching the list above.
- Behaviour is unchanged: `curl` 40× to `/api/get_crypto_params` returns its normal `200`/`404` every time and
  never `429` (no route uses the limiter yet).
- `sqlite3 <db> '.schema rate_limit'` shows the composite primary key and `idx_rate_limit_expires_at`.
- Start with `TRUSTED_PROXY_IPS=not-an-ip` → the process exits with a message naming the value.

### M1 — Pre-auth surface: `/register`, `/get_crypto_params`, `/auth`

Scope: extractors on the three routes; `RegisterGlobal`; `AuthTarget` charge + reset-on-success; add test modules
to `auth.rs` and `get_crypto_params.rs` (neither has one today) and update every test app that registers these
services (`register.rs:287-309` macro and any new tests) to include
`app_data(web::Data::new(RateLimiter::for_tests(...)))`.

Acceptance (one fixed window; a window straddle can show up to 2×):

- 6 registrations from one IP in a minute: 5 succeed (`201`), the 6th is `429` with
  `{"code":"RATE_LIMITED"}` and `Retry-After` between 1 and 3600.
- 11 `/auth` calls with a wrong verifier for one vault: 10× `401 AUTH_FAILED`, 11th `429`. A successful login
  *before* the cap clears the counter: 5 failures, 1 success (`200`), then 10 more failures are accepted before the
  next `429`. (A correct login after the cap is already spent is still refused — reset-on-success must not become a
  bypass; assert this in the integration test.)
- 11 `/auth` calls for an **unknown but well-formed** vault id: the 11th is also `429` (no existence oracle).
- 61 `/get_crypto_params` for the same id from one IP: 60× `200`, 61st `429`; adding
  `-H 'X-Forwarded-For: 9.9.9.9'` to each request does **not** reset the budget.
- With the limiter missing from `app_data`, a limited route returns `500` rather than silently running unlimited
  (`missing_limiter_fails_closed`).
- A malformed body may be answered by the JSON layer with `400` even when the budget is spent; that is expected
  (extractors are polled concurrently) and still never reaches the handler. Do not assert `429` for malformed bodies.

### M2 — Authenticated write surface

Scope: session-keyed `VaultWrite` on `/update_vault`, `/vaults`, `/vault/password`; `VaultAdmin` on
`/recovery/regenerate`. Update the `update_vault.rs` test app.

Acceptance:

- With one session, 61 `/update_vault` calls (any mix of `200`/`409`) → 61st is `429`; a second vault's session is
  unaffected.
- `/vault/password` consumes the same budget as `/update_vault` (they are the same policy).
- `/lock` still returns `200` after the write budget is exhausted — the safety action is never refused.
- `/get_vault` still returns `200` after the write budget is exhausted.

### M3 — Consolidate the existing ad-hoc throttles

Scope: recovery (`challenge`, `unlock`, `rewrap`) onto `Limited<...>`; delete `ChallengeThrottle`; pair consume/start
onto the limiter plus `pair_code.attempts`; delete `CONSUME_THROTTLE`/`CODE_ATTEMPTS`; update `recovery.rs` tests
(`throttle_*` unit tests are deleted; `challenge_is_rate_limited_per_ip` is rewritten against the limiter; every
test app gains the limiter); add a `pair.rs` test module (the endpoint has no tests today).

Acceptance:

- The full recovery flow (challenge → unlock → rewrap) still works end to end; `cargo test` green including
  `rewrap_establishes_a_session_for_the_recovered_vault` and the uniform-failure tests.
- 21 `/pair/consume` calls from one IP: 20 × `404 PAIR_INVALID`, 21st `429 PAIR_RATE_LIMITED` with `Retry-After`.
- One live code, 11 wrong attempts against it: `PAIR_INVALID` ten times, then the row is deleted and an 11th
  with the **correct** code also fails (`PAIR_INVALID`) — the burn is durable and shared.
- Two server instances over one DB: 10 attempts split 5 on A and 5 on B are all counted on the row; the 11th (on
  either instance) burns the code, and a following attempt with the **correct** code also fails. Proves the counter
  is the column, not a process map.
- `/recovery/challenge` still returns `RECOVERY_RATE_LIMITED` at the same 10/min budget, now with `Retry-After`.

### M4 — Client/extension behaviour, observability, release gate

Scope: the three client files + the extension file (§8); one `warn` per denial; startup policy log; roadmap and
AGENTS.md updates; the verification sheet below.

Acceptance:

- Burn the `VaultWrite` budget with `curl` using the browser's session cookie, then edit an item in the web UI.
  Console shows the retry message (not `console.error`), the item stays visible, and after the window the intent
  syncs without another edit. Reload before the retry → the item is still there (intent durable).
- Lock the vault while a retry timer is armed → no sync is attempted and the timer is gone.
- Wrong password 10× on the lock screen → 11th reads "Too many attempts. Try again in N minutes.", **not**
  "Incorrect password."
- Extension: with the write budget spent, saving a login from the popup shows "saving paused" and the pending save
  survives; it completes after the window.
- Server log during the above: exactly one `rate limit exhausted` line per policy per window, no vault id, no
  verifier, no body. `grep -c RATE` on the log is bounded by the number of policies × windows, not by requests.
- `cargo test` green; `npx tsc --noEmit` in `apps/client` and `apps/extension` green; `npm run build:web` succeeds.

---

## 13. Verification sheet (copy/paste)

```sh
# --- M0: schema + startup ---------------------------------------------------
sqlite3 "$HOME/Library/Application Support/Voult/voult.db" '.schema rate_limit'
TRUSTED_PROXY_IPS=not-an-ip cargo run          # must exit, naming the value

# --- M1: per-IP budget + no header bypass ----------------------------------
V=3f2504e0-4f89-41d3-9a0c-0305e82c3301
for i in $(seq 1 61); do
  curl -s -o /dev/null -w '%{http_code} ' \
    -H "X-Forwarded-For: 9.9.9.9" \
    "http://localhost:8080/api/get_crypto_params?vault_id=$V"
done; echo
# expect 60 normal responses (200, or 404 if that vault is not registered)
# then 429 — the spoofed header must not create new buckets.

# --- M1: targeted auth budget ---------------------------------------------
for i in $(seq 1 11); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST http://localhost:8080/api/auth \
    -H 'content-type: application/json' \
    -d "{\"vault_id\":\"$V\",\"vault_verifier\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"}"
done; echo
curl -si -X POST http://localhost:8080/api/auth -H 'content-type: application/json' \
  -d "{\"vault_id\":\"$V\",\"vault_verifier\":\"x\"}" | grep -iE 'HTTP/|retry-after|code'

# --- M2: write budget does not touch /lock ---------------------------------
# (use a real session cookie from the browser)
for i in $(seq 1 61); do curl -s -o /dev/null -b "$COOKIE" -X POST \
  http://localhost:8080/api/update_vault -H 'content-type: application/json' \
  -d "{\"vault\":\"AA==\",\"vaultiv\":\"AA==\",\"version\":$i}"; done
curl -s -o /dev/null -w '%{http_code}\n' -b "$COOKIE" -X POST http://localhost:8080/api/lock   # 200
curl -s -o /dev/null -w '%{http_code}\n' -b "$COOKIE" http://localhost:8080/api/get_vault        # 200

# --- M2: two instances, one database, one budget ---------------------------
# same DATABASE_URL and SESSION_COOKIE_KEY, different ports; start A, wait for
# migrations to finish, then B. Alternate registrations between :8080 and :8081:
# five succeed in total, the sixth is 429 on whichever port receives it.
```

Notes for the operator: a fixed window is epoch-aligned, so a run that straddles a boundary can legitimately show
up to 2× the budget; re-run inside one window. Two instances on one SQLite file must be started sequentially so
`Migrator::up` (main.rs:215-217) does not race.

---

## 14. Overlaps with other roadmap items (seams, not scope)

| Item | Relationship |
|---|---|
| `ROADMAP:56` — KDF strength | Complements this work; rate limits bound online guessing but do not make a weak password safe. Do not change iteration counts here. |
| `ROADMAP:57` — replayable verifier | Both control `/auth`. This plan adds a budget; that item changes the credential protocol. The limiter must not key on or hash the verifier, so the two can land in either order. |
| `ROADMAP:60` — log sanitization | The plan stops new logs from carrying vault ids/IPs beyond what the access log already prints, but it does not fix `%r` query-string logging. Do not couple them. |
| `ROADMAP:61` — request/protocol bounds | Owns body limits and field validation (`json_config()` in `endpoints/mod.rs`). This plan relies on the existing 2 MB cap; it does not add per-route limits. `RegisterGlobal` (30/h) is a ceiling, not a substitute for a body cap. |
| `ROADMAP:62` — security test suite | This plan adds a meaningful server test cluster (`rate_limit` unit + per-route HTTP tests). That partially serves the item; it is not the full suite and must not be marked as closing it. |
| `ROADMAP:70` — enumeration | The 429 is deliberately existence-independent; do not "improve" `/get_crypto_params` messaging here. (Origin/CSRF checks are a separate P1 at `ROADMAP:69`.) |
| `ROADMAP:30` — session/device inventory | A durable abuse-audit trail belongs there (D8 rejects it here). |
| `ROADMAP:68` — transport/proxy trust | This plan defines forwarded-header trust for the limiter only. The broader reverse-proxy/TLS policy stays with that item. |

---

## 15. Explicit non-goals

- No WAF, no fingerprinting, no CAPTCHA, no proof-of-work, no account suspension.
- No rate limit on `/lock`, `/logout`, `/session`, `/get_vault`, `/favicon`, `/cloud/*` (D10).
- No metrics endpoint, no exporter, no alerting pipeline (D8).
- No change to `json_config()` body limits or to per-field validation (owned by `ROADMAP:61`).
- No change to the verifier protocol, KDF parameters, session/cookie semantics, or any envelope.
- No client-side storage change; no new dependency.

---

## 16. As built

Implemented on `p0/auth-rate-limits` (2026-10-29).

- New: `apps/server/src/rate_limit.rs`, `apps/server/src/entity/rate_limit.rs`, migration
  `m20261028_000008_rate_limit.rs` (table + `pair_code.attempts`), a `RateLimit` logger context.
- Budgets are exactly §4. The marker types and `production_budgets()` are generated from one macro, so a policy
  cannot exist without a budget; `RateLimiter::new` rejects an empty or duplicate table.
- `charge` returns `Result<(), Rejected>`. The planned `Allowed { remaining }` was dropped: nothing consumes a
  remaining count, and `X-RateLimit-*` headers were rejected in D7.
- One 429 shape for both paths (extractor and handler): `Retry-After` in seconds, clamped to the window, plus the
  existing `{error_msg, code}` envelope. `RECOVERY_RATE_LIMITED` / `PAIR_RATE_LIMITED` are preserved; everything
  else is `RATE_LIMITED`.
- `ChallengeThrottle`, `CONSUME_THROTTLE`, and `CODE_ATTEMPTS` are deleted. Recovery
  challenge/unlock/rewrap and pair start/consume all use the shared limiter; `pair_code.attempts` is bumped with
  one `UPDATE … RETURNING`. M0 added the column and the `attempts: Set(0)` insert so the tree compiled before M3
  used it.
- **Correction to D2.** Actix polls a handler's extractor futures **concurrently**
  (`actix-web/src/extract.rs:327-380`), so `Limited<P>` guarantees the handler never runs but does not guarantee the
  body was never parsed. A malformed body can still receive the JSON layer's `400`; that request also never reaches
  the handler, and the existing 2 MB body cap bounds its cost. Tests assert the guarantee that exists (429 for a
  well-formed request after the budget is spent; 500 when the limiter is missing), not the one that does not.
- **Note on the per-code pair cap.** It is a retry bound on ONE live code, not a brute-force control: a wrong guess
  is a different hash and has no row, so the per-IP budget is what bounds guessing. That was already true of the
  in-memory map; the column makes it durable and bounded rather than a growing process map.

Verification:

- `cargo test` in `apps/server`: **126 passed**. New coverage: limiter unit tests (allow/refuse, window rollover, two
  instances over one pool sharing a budget, denial-cache write suppression, hash domain separation, IPv4-mapped
  normalization, trusted-proxy walk, forwarded-header spoof rejection, sweep) and HTTP tests (`/auth` per-vault +
  reset-on-success + unknown-vault parity + spoofed header + fail-closed extractor, `/register` per-IP + global
  ceiling, `/get_crypto_params` per-IP, `/update_vault` per-vault with `/lock` and `/get_vault` unaffected and
  `/vault/password` sharing the same budget, `/recovery/challenge` budget, `/recovery/unlock` pre-auth budget,
  `/pair/consume` budget + burn + single-use).
- `npx tsc --noEmit` passes in `apps/client` and `apps/extension`.
- Live smoke against the built binary on a temp DB: 61× `/get_crypto_params` → 60 × 404 + 1 × 429
  (`Retry-After: 50`, `Cache-Control: no-store`); 11× `/auth` → 10 × 401 + 429; 6× `/register` → 5 × 201 + 429;
  61× `/update_vault` → 1 × 200 + 59 × 409 + 429 with `/lock` and `/get_vault` still 200; 21× `/pair/consume` →
  20 × 404 + 429 `PAIR_RATE_LIMITED`; 11× `/recovery/challenge` → 10 × 200 + 429 `RECOVERY_RATE_LIMITED`; only 3
  live challenges retained; `rate_limit` contained only 64-char hashes (no raw IP or vault id);
  `TRUSTED_PROXY_IPS=not-an-ip` aborts startup naming the value.
- Not exercised: the browser-facing M4 flows (sync retry timer, lock-screen message, extension save pause). The
  client has no test runner, so those stay manual acceptance items.
