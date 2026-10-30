//! Application rate limits for authentication, pre-auth, and write endpoints.
//!
//! ## Why this exists
//!
//! `/auth` accepts a deterministic verifier derived from the master password,
//! and the salt/iteration count needed to compute it are served pre-auth by
//! `/get_crypto_params`. Without a budget the server is an online password
//! oracle: every guess costs the attacker one PBKDF2 and costs the server one
//! `SELECT`. `POST /register` can fill the disk, and `POST /update_vault` can
//! drive unbounded writes and provider uploads from one session.
//!
//! ## How it works
//!
//! A budget is `max` charges per `window_secs`. The window is aligned to the
//! epoch (`floor(now / window) * window`) and computed by SQLite, so every
//! instance sharing the database agrees on window boundaries even when host
//! clocks are skewed.
//!
//! The counter lives in the `rate_limit` table, not in process memory. That is
//! the whole point: a per-process map is multiplied by the worker count (Actix
//! defaults to `available_parallelism`, `actix-web/src/server.rs:131-133`) and
//! by the instance count. The DB is the only store this deployment shares, and
//! a single-process in-memory limiter is **not** a security boundary for a
//! multi-instance deployment.
//!
//! ## Identity
//!
//! Per-IP budgets use the socket peer, never `realip_remote_addr()`: Actix
//! resolves that from the client-supplied `Forwarded` / `X-Forwarded-For`
//! header (`actix-web/src/info.rs:142-146,168-173`), so trusting it by default
//! hands the attacker a fresh bucket per request. Forwarded headers are honoured
//! only when the immediate peer is in `TRUSTED_PROXY_IPS`; the rightmost
//! untrusted hop is then used.
//!
//! Per-vault budgets key on the **canonical** vault id. `/auth` uses the id the
//! caller supplied (so unknown and known vaults are counted identically and the
//! 429 cannot become an existence oracle); authenticated routes use the id from
//! the session, never one from the request body.
//!
//! ## Storage hygiene
//!
//! The row stores `SHA-256(kind || 0x1F || subject)`, never a raw IP or vault
//! id. It is a counter, not an audit trail: an operator who needs the raw value
//! has the access log.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use actix_web::dev::Payload;
use actix_web::http::StatusCode;
use actix_web::{FromRequest, HttpRequest, HttpResponse, ResponseError, error, web};
use chrono::Utc;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, DbErr, EntityTrait, QueryFilter, Statement, Value,
};
use sha2::{Digest, Sha256};

use crate::db::DbPool;
use crate::entity::rate_limit::{self, Entity as RateLimitEntity};

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::RateLimit);

/// Expired rows are swept every this many charges (plus once at startup), so
/// the table cannot grow with request volume — only with distinct subjects.
const SWEEP_EVERY: u64 = 256;

/// Upper bound on the in-memory denial cache. It only holds subjects whose
/// budget is already spent, so hitting this means an active flood from many
/// addresses; dropping the cache is safe because the DB stays authoritative.
const DENIAL_CACHE_CAP: usize = 8_192;

/// Store errors are logged at most once per this many seconds. A broken DB must
/// not turn into a log flood.
const STORE_ERROR_LOG_INTERVAL_SECS: i64 = 60;

// --- Policies --------------------------------------------------------------

/// One budget. Windows are fixed and epoch-aligned.
#[derive(Debug, Clone, Copy)]
pub struct Budget {
    pub max: u32,
    pub window_secs: i64,
}

impl Budget {
    pub const fn new(max: u32, window_secs: i64) -> Self {
        Self { max, window_secs }
    }
}

/// A named budget. Implementors are zero-sized marker types so a handler writes
/// `Limited<AuthIp>` or `charge::<AuthTarget>(..)` and cannot typo a string.
pub trait Policy {
    const KEY: &'static str;
    /// Wire code returned alongside the 429. Surface-specific only where an
    /// existing contract already had one (`PAIR_*`, `RECOVERY_*`).
    const CODE: &'static str;
}

/// Declares a marker type, its budget, and the production table in one place so
/// the two cannot drift. Duplicate keys are rejected by `RateLimiter::new`.
macro_rules! policies {
    ($($ty:ident => ($key:literal, $max:expr, $window:expr, $code:literal)),+ $(,)?) => {
        $(
            #[derive(Debug, Clone, Copy)]
            pub struct $ty;

            impl Policy for $ty {
                const KEY: &'static str = $key;
                const CODE: &'static str = $code;
            }
        )+

        /// Every policy with its budget, for `RateLimiter::new`.
        pub fn production_budgets() -> Vec<(&'static str, Budget)> {
            vec![
                $( ($key, Budget::new($max, $window)) ),+
            ]
        }
    };
}

// Rationale for each number is in plans/p0-auth-rate-limits.md §4.
//
// auth: 30/min/IP is generous for a human (typo + retry) and for NAT, while
// bounding one host. 10/10min per vault is the only control that survives IP
// rotation; a successful login clears it (see `reset`).
//
// register: 5/h/IP plus a 30/h global ceiling that does not depend on IP
// diversity, because every registration writes an attacker-sized row.
//
// vault writes: sync coalesces and a human edits <10/min; 60/min protects the
// write path and the provider mirror without breaking a reconnect burst.
policies! {
    AuthIp             => ("AuthIp", 30, 60, "RATE_LIMITED"),
    AuthTarget         => ("AuthTarget", 10, 10 * 60, "RATE_LIMITED"),
    RegisterIp         => ("RegisterIp", 5, 60 * 60, "RATE_LIMITED"),
    RegisterGlobal     => ("RegisterGlobal", 30, 60 * 60, "RATE_LIMITED"),
    CryptoParamsIp     => ("CryptoParamsIp", 60, 60, "RATE_LIMITED"),
    VaultWrite         => ("VaultWrite", 60, 60, "RATE_LIMITED"),
    VaultAdmin         => ("VaultAdmin", 10, 60 * 60, "RATE_LIMITED"),
    PairStart          => ("PairStart", 10, 60, "RATE_LIMITED"),
    PairIp             => ("PairIp", 20, 60, "PAIR_RATE_LIMITED"),
    RecoveryChallengeIp => ("RecoveryChallengeIp", 10, 60, "RECOVERY_RATE_LIMITED"),
    RecoveryPreauthIp  => ("RecoveryPreauthIp", 20, 60, "RECOVERY_RATE_LIMITED"),
}

// --- Subjects --------------------------------------------------------------

/// What a budget is spent against.
#[derive(Debug, Clone, Copy)]
pub enum Subject<'a> {
    /// A client address after proxy trust has been applied.
    Ip(IpAddr),
    /// A canonical lowercase vault UUID.
    Vault(&'a str),
    /// A single deployment-wide bucket (only `RegisterGlobal` today).
    Global,
}

impl Subject<'_> {
    /// The pre-hash subject string. Domain separation comes from the policy key
    /// being mixed into the hash as well.
    fn as_key(&self) -> String {
        match self {
            Subject::Ip(ip) => format!("ip:{}", canonical_ip(*ip)),
            Subject::Vault(id) => format!("vault:{id}"),
            Subject::Global => "global".to_string(),
        }
    }
}

/// ``::ffff:127.0.0.1`` and ``127.0.0.1`` are the same client; collapse them so
/// a dual-stack listener cannot hand out two budgets for one host.
fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

fn key_hash(kind: &str, subject: &Subject<'_>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(kind.as_bytes());
    hasher.update([0x1f]);
    hasher.update(subject.as_key().as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        // Writing to a String cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Never log a full hash; the first 12 hex chars are enough to correlate lines
/// for one subject within a window and useless for anything else.
fn short_hash(key_hash: &str) -> &str {
    key_hash.get(..12).unwrap_or(key_hash)
}

// --- Outcome ---------------------------------------------------------------

/// A refusal. Rendered identically by the extractor and by handler-level calls.
#[derive(Debug, Clone, Copy)]
pub struct Rejected {
    retry_after_secs: u64,
    code: &'static str,
}

impl Rejected {
    fn new(budget: Budget, expires_at: i64, now: i64, code: &'static str) -> Self {
        // `expires_at` comes from the DB clock; `now` from the app clock, so
        // this can be off by the host skew. Clamping keeps the header honest
        // enough (never 0, never beyond the window).
        let remaining = (expires_at - now).clamp(1, budget.window_secs);
        Self {
            retry_after_secs: remaining as u64,
            code,
        }
    }

    pub fn into_response(self) -> HttpResponse {
        HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
            .insert_header(("Retry-After", self.retry_after_secs.to_string()))
            .json(serde_json::json!({
                "error_msg": "too many attempts, try again later",
                "code": self.code,
            }))
    }
}

impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rate limited (code {}, retry after {}s)",
            self.code, self.retry_after_secs
        )
    }
}

impl ResponseError for Rejected {
    fn status_code(&self) -> StatusCode {
        StatusCode::TOO_MANY_REQUESTS
    }

    fn error_response(&self) -> HttpResponse {
        (*self).into_response()
    }
}

// --- Limiter ---------------------------------------------------------------

pub struct RateLimiter {
    pool: DbPool,
    budgets: HashMap<&'static str, Budget>,
    /// Exact peer addresses allowed to set `X-Forwarded-For`. Empty by default,
    /// because in the shipped topology there is no proxy and a forwarded header
    /// is either an attacker or a misconfiguration.
    trusted_proxies: Vec<IpAddr>,
    /// Deadline (unix seconds) per `key_hash` for subjects already refused.
    /// A pure optimization: it absorbs a flood without a DB write per request.
    denials: Mutex<HashMap<String, i64>>,
    /// Drives the opportunistic sweep.
    charges: AtomicU64,
    /// Unix seconds of the last store-error log.
    last_store_error: AtomicI64,
    /// One-shot warnings so a misconfigured/attacked deployment logs the clue
    /// once instead of once per request.
    warned_forwarded: AtomicBool,
    warned_no_peer: AtomicBool,
}

impl RateLimiter {
    /// Builds the limiter from an explicit budget table.
    ///
    /// Panics on an empty table or a duplicate key: those are programming
    /// errors, and starting with a policy silently missing would be worse than
    /// refusing to boot.
    pub fn new(
        pool: DbPool,
        budgets: Vec<(&'static str, Budget)>,
        trusted_proxies: Vec<IpAddr>,
    ) -> Self {
        assert!(
            !budgets.is_empty(),
            "rate limiter needs at least one policy budget"
        );
        let mut table = HashMap::with_capacity(budgets.len());
        for (key, budget) in budgets {
            assert!(
                table.insert(key, budget).is_none(),
                "duplicate rate limit policy key: {key}"
            );
        }
        Self {
            pool,
            budgets: table,
            trusted_proxies,
            denials: Mutex::new(HashMap::new()),
            charges: AtomicU64::new(0),
            last_store_error: AtomicI64::new(0),
            warned_forwarded: AtomicBool::new(false),
            warned_no_peer: AtomicBool::new(false),
        }
    }

    /// Test constructor: production budgets with per-policy overrides. Tests
    /// must never depend on the production numbers (they would become flaky the
    /// day a budget is tuned), and must not share process state.
    #[cfg(test)]
    pub fn for_tests(pool: DbPool, overrides: &[(&'static str, Budget)]) -> Self {
        let mut budgets = production_budgets();
        for (key, budget) in overrides {
            match budgets.iter_mut().find(|(existing, _)| existing == key) {
                Some(slot) => slot.1 = *budget,
                None => budgets.push((key, *budget)),
            }
        }
        Self::new(pool, budgets, Vec::new())
    }

    /// Every budget effectively unbounded, for test apps that exercise other
    /// behaviour. Tests about limits use `for_tests` with explicit small
    /// budgets so the production numbers can be tuned without rewriting them.
    #[cfg(test)]
    pub fn permissive(pool: DbPool) -> Self {
        let overrides: Vec<(&'static str, Budget)> = production_budgets()
            .into_iter()
            .map(|(key, _)| (key, Budget::new(1_000_000, 60)))
            .collect();
        Self::for_tests(pool, &overrides)
    }

    /// Charges one request to `subject` under policy `P`.
    ///
    /// Fails **open** on a store error. That cannot create a bypass: every
    /// limited route needs the same database to do anything at all, so an
    /// unavailable DB already denies the request at its own query.
    pub async fn charge<P: Policy>(&self, subject: &Subject<'_>) -> Result<(), Rejected> {
        let Some(budget) = self.budgets.get(P::KEY).copied() else {
            // Unreachable through `new` / `for_tests`; fail open rather than
            // take a route down if a future refactor desynchronises the table.
            LOG.error(
                format_args!("no budget registered for policy {}; allowing", P::KEY),
                logger::metadata! { "policy" => P::KEY },
            );
            return Ok(());
        };

        let key_hash = key_hash(P::KEY, subject);
        let now = Utc::now().timestamp();

        // A spent budget costs no DB work on this instance after the first
        // denial. The row remains authoritative; this only absorbs the flood.
        if let Some(until) = self.denied_until(&key_hash, now) {
            return Err(Rejected::new(budget, until, now, P::CODE));
        }

        let outcome = match self.store_charge(P::KEY, &key_hash, budget).await {
            Ok((count, expires_at)) => {
                if count <= budget.max as i64 {
                    Ok(())
                } else {
                    // `max + 1` is the first refusal of this window: one warn
                    // per subject per window, everything after is debug.
                    if count == budget.max as i64 + 1 {
                        LOG.warn(
                            format_args!(
                                "rate limit exhausted policy={} count={} retry_after={}s",
                                P::KEY,
                                count,
                                (expires_at - now).max(0)
                            ),
                            logger::metadata! {
                                "policy" => P::KEY,
                                "count" => count,
                                "subject" => subject.log_value(&key_hash),
                            },
                        );
                    } else {
                        LOG.debug(
                            format_args!("rate limit refused policy={} count={}", P::KEY, count),
                            logger::metadata! { "policy" => P::KEY },
                        );
                    }
                    self.remember_denial(&key_hash, expires_at);
                    Err(Rejected::new(budget, expires_at, now, P::CODE))
                }
            }
            Err(e) => {
                self.log_store_error(&e);
                Ok(())
            }
        };

        if self.charges.fetch_add(1, Ordering::Relaxed) % SWEEP_EVERY == 0 {
            self.sweep_expired().await;
        }

        outcome
    }

    /// Clears a subject's budget. Used only after a **successful** `/auth`, so a
    /// `429`-shaped DoS cannot be reset by the attacker and a legitimate owner
    /// who mistyped a few times starts fresh.
    pub async fn reset<P: Policy>(&self, subject: &Subject<'_>) {
        let key_hash = key_hash(P::KEY, subject);
        if let Ok(mut denials) = self.denials.lock() {
            denials.remove(&key_hash);
        }
        let result = RateLimitEntity::delete_many()
            .filter(rate_limit::Column::Kind.eq(P::KEY))
            .filter(rate_limit::Column::KeyHash.eq(key_hash))
            .exec(&self.pool)
            .await;
        if let Err(e) = result {
            LOG.warn(
                format_args!("failed to clear rate limit budget policy={}: {e}", P::KEY),
                logger::metadata! { "policy" => P::KEY },
            );
        }
    }

    /// Resolves the client address for a request.
    ///
    /// The socket peer is used unless it is an explicitly trusted proxy, in
    /// which case `X-Forwarded-For` is walked **right to left** and the first
    /// untrusted hop is taken. Leftmost values are attacker-supplied.
    pub fn client_ip(&self, req: &HttpRequest) -> IpAddr {
        let peer = match req.peer_addr() {
            Some(addr) => canonical_ip(addr.ip()),
            None => {
                // Non-TCP transports have no peer address. Treat it as local
                // and warn once: silently bucketing everyone together would be
                // a self-inflicted DoS if a future transport ever omits it.
                if !self.warned_no_peer.swap(true, Ordering::Relaxed) {
                    LOG.warn(
                        "request has no peer address; rate-limiting it as 127.0.0.1",
                        logger::Metadata::new(),
                    );
                }
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            }
        };

        if !self.trusted_proxies.contains(&peer) {
            if req.headers().contains_key("x-forwarded-for")
                && !self.warned_forwarded.swap(true, Ordering::Relaxed)
            {
                LOG.warn(
                    "ignoring X-Forwarded-For from an untrusted peer; set TRUSTED_PROXY_IPS if the server is behind a reverse proxy",
                    logger::Metadata::new(),
                );
            }
            return peer;
        }

        let Some(raw) = req
            .headers()
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
        else {
            return peer;
        };

        for hop in raw.rsplit(',') {
            if let Ok(ip) = hop.trim().parse::<IpAddr>() {
                let ip = canonical_ip(ip);
                if !self.trusted_proxies.contains(&ip) {
                    return ip;
                }
            }
        }
        peer
    }

    /// Deletes rows whose window has ended. Called once at startup and
    /// opportunistically from `charge`.
    pub async fn sweep_expired(&self) {
        let now = Utc::now().timestamp();
        let result = RateLimitEntity::delete_many()
            .filter(rate_limit::Column::ExpiresAt.lte(now))
            .exec(&self.pool)
            .await;
        match result {
            Ok(done) if done.rows_affected > 0 => {
                LOG.debug(
                    format_args!("swept {} expired rate limit rows", done.rows_affected),
                    logger::metadata! { "rows" => done.rows_affected },
                );
            }
            Ok(_) => {}
            Err(e) => LOG.warn(
                format_args!("failed to sweep expired rate limit rows: {e}"),
                logger::Metadata::new(),
            ),
        }
    }

    /// One startup line so an operator can see what is actually enforced.
    pub fn log_startup_summary(&self) {
        let mut policies: Vec<String> = self
            .budgets
            .iter()
            .map(|(key, budget)| format!("{key}={}/{}s", budget.max, budget.window_secs))
            .collect();
        policies.sort();
        LOG.log(
            format_args!(
                "rate limits active (sqlite): {}{}",
                policies.join(" "),
                if self.trusted_proxies.is_empty() {
                    String::new()
                } else {
                    format!(
                        " trusted_proxies={}",
                        self.trusted_proxies
                            .iter()
                            .map(|ip| ip.to_string())
                            .collect::<Vec<_>>()
                            .join(",")
                    )
                }
            ),
            logger::metadata! {
                "policies" => policies.len(),
                "trusted_proxies" => self.trusted_proxies.len(),
            },
        );
    }

    // --- internals ---------------------------------------------------------

    fn denied_until(&self, key_hash: &str, now: i64) -> Option<i64> {
        let cache = self.denials.lock().ok()?;
        cache.get(key_hash).copied().filter(|until| *until > now)
    }

    fn remember_denial(&self, key_hash: &str, until: i64) {
        let Ok(mut cache) = self.denials.lock() else {
            // Poisoned lock: the DB still enforces the budget, we only lose the
            // flood optimization.
            return;
        };
        if cache.len() >= DENIAL_CACHE_CAP {
            let now = Utc::now().timestamp();
            cache.retain(|_, deadline| *deadline > now);
            if cache.len() >= DENIAL_CACHE_CAP {
                cache.clear();
            }
        }
        cache.insert(key_hash.to_string(), until);
    }

    fn log_store_error(&self, error: &DbErr) {
        let now = Utc::now().timestamp();
        let last = self.last_store_error.load(Ordering::Relaxed);
        if now - last >= STORE_ERROR_LOG_INTERVAL_SECS
            && self
                .last_store_error
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            LOG.error(
                format_args!("rate limit store failed; allowing request: {error}"),
                logger::Metadata::new(),
            );
        }
    }

    /// One atomic statement: window rollover, increment, and read-back.
    ///
    /// SeaORM's `OnConflict` builder cannot express `count = count + 1` with a
    /// rollover CASE, so this is parameterized SQL with bound values only. The
    /// window arithmetic deliberately uses SQLite's clock so instances that
    /// share the file share window boundaries.
    async fn store_charge(
        &self,
        kind: &str,
        key_hash: &str,
        budget: Budget,
    ) -> Result<(i64, i64), DbErr> {
        // `window_secs` appears five times (two for the window start, three for
        // the expiry). sqlx-sqlite binds positionally, so it is passed once per
        // placeholder.
        const CHARGE_SQL: &str = r#"
INSERT INTO rate_limit (kind, key_hash, window_start, count, expires_at)
VALUES (
    ?, ?,
    (CAST(strftime('%s','now') AS INTEGER) / ?) * ?,
    1,
    (CAST(strftime('%s','now') AS INTEGER) / ?) * ? + ?
)
ON CONFLICT (kind, key_hash) DO UPDATE SET
    count = CASE
        WHEN excluded.window_start > rate_limit.window_start THEN 1
        ELSE rate_limit.count + 1
    END,
    window_start = CASE
        WHEN excluded.window_start > rate_limit.window_start THEN excluded.window_start
        ELSE rate_limit.window_start
    END,
    expires_at = CASE
        WHEN excluded.window_start > rate_limit.window_start THEN excluded.expires_at
        ELSE rate_limit.expires_at
    END
RETURNING count, expires_at
"#;
        let window = budget.window_secs;
        let statement = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            CHARGE_SQL,
            vec![
                Value::from(kind),
                Value::from(key_hash),
                Value::from(window),
                Value::from(window),
                Value::from(window),
                Value::from(window),
                Value::from(window),
            ],
        );
        let row = self
            .pool
            .query_one_raw(statement)
            .await?
            .ok_or_else(|| DbErr::RecordNotFound("rate_limit upsert returned no row".into()))?;
        let count: i64 = row.try_get("", "count")?;
        let expires_at: i64 = row.try_get("", "expires_at")?;
        Ok((count, expires_at))
    }
}

impl Subject<'_> {
    /// What a warn line may say about the subject. The IP is already in the
    /// access log and is what an operator needs to act; a vault id is not, so
    /// it is represented only by its hash prefix.
    fn log_value(&self, key_hash: &str) -> String {
        match self {
            Subject::Ip(ip) => canonical_ip(*ip).to_string(),
            Subject::Vault(_) => format!("#{}", short_hash(key_hash)),
            Subject::Global => "global".to_string(),
        }
    }
}

/// Per-IP budget extractor.
///
/// Extractors run before the handler, so a refusal means the handler never
/// executes. Actix polls the extractor futures of one handler **concurrently**
/// (`actix-web/src/extract.rs:327-380`), so a malformed body can still be
/// answered by `web::Json` with a 400; that request does not reach the handler
/// either, and the body-size cap bounds its cost. The budget therefore bounds
/// every request that would do work, not raw connection traffic — request-body
/// limits belong to the separate bounds item.
///
/// A missing `web::Data<RateLimiter>` is a hard error, never a silent bypass —
/// a forgotten `.app_data(...)` must break tests, not disable the control.
pub struct Limited<P: Policy>(std::marker::PhantomData<P>);

impl<P: Policy + 'static> FromRequest for Limited<P> {
    type Error = actix_web::Error;
    type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let limiter = req.app_data::<web::Data<RateLimiter>>().cloned();
        let ip = limiter.as_ref().map(|limiter| limiter.client_ip(req));

        Box::pin(async move {
            let Some(limiter) = limiter else {
                LOG.error(
                    format_args!(
                        "rate limiter missing from app_data for policy {}; refusing request",
                        P::KEY
                    ),
                    logger::metadata! { "policy" => P::KEY },
                );
                return Err(error::ErrorInternalServerError(serde_json::json!({
                    "error_msg": "rate limiter unavailable",
                    "code": "INTERNAL_ERROR",
                })));
            };
            // `ip` is Some whenever `limiter` is Some; the tuple is built above.
            let ip = ip.expect("client IP is resolved when the limiter exists");
            limiter.charge::<P>(&Subject::Ip(ip)).await?;
            Ok(Limited(std::marker::PhantomData))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use migration::MigratorTrait;
    use sea_orm::{ActiveModelTrait, Database, EntityTrait, Set};

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    fn budget(max: u32, window_secs: i64) -> Budget {
        Budget::new(max, window_secs)
    }

    async fn stored_count(pool: &DbPool, kind: &str, key_hash: &str) -> Option<i64> {
        RateLimitEntity::find_by_id((kind.to_string(), key_hash.to_string()))
            .one(pool)
            .await
            .expect("read counter")
            .map(|row| row.count)
    }

    #[actix_web::test]
    async fn allows_up_to_the_budget_then_refuses() {
        let pool = test_pool().await;
        let limiter = RateLimiter::for_tests(pool.clone(), &[("AuthIp", budget(3, 60))]);

        assert!(
            limiter
                .charge::<AuthIp>(&Subject::Ip("1.2.3.4".parse().unwrap()))
                .await
                .is_ok()
        );
        assert!(
            limiter
                .charge::<AuthIp>(&Subject::Ip("1.2.3.4".parse().unwrap()))
                .await
                .is_ok()
        );
        assert!(
            limiter
                .charge::<AuthIp>(&Subject::Ip("1.2.3.4".parse().unwrap()))
                .await
                .is_ok()
        );

        let rejected = limiter
            .charge::<AuthIp>(&Subject::Ip("1.2.3.4".parse().unwrap()))
            .await
            .expect_err("budget is spent");
        assert_eq!(rejected.code, "RATE_LIMITED");
        assert!(rejected.retry_after_secs >= 1 && rejected.retry_after_secs <= 60);

        // ...but only for that address.
        assert!(
            limiter
                .charge::<AuthIp>(&Subject::Ip("5.6.7.8".parse().unwrap()))
                .await
                .is_ok()
        );
    }

    /// The reason the store is the database: two limiter instances stand in for
    /// two server processes over one file. If this fails, the control is
    /// per-instance and the roadmap item is not actually closed.
    #[actix_web::test]
    async fn two_limiter_instances_share_one_budget() {
        let pool = test_pool().await;
        let a = RateLimiter::for_tests(pool.clone(), &[("RegisterIp", budget(2, 60))]);
        let b = RateLimiter::for_tests(pool.clone(), &[("RegisterIp", budget(2, 60))]);

        assert!(
            a.charge::<RegisterIp>(&Subject::Ip("9.9.9.9".parse().unwrap()))
                .await
                .is_ok()
        );
        assert!(
            b.charge::<RegisterIp>(&Subject::Ip("9.9.9.9".parse().unwrap()))
                .await
                .is_ok()
        );
        assert!(
            a.charge::<RegisterIp>(&Subject::Ip("9.9.9.9".parse().unwrap()))
                .await
                .is_err(),
            "the second instance must see the first instance's spend"
        );
    }

    #[actix_web::test]
    async fn window_rolls_over() {
        let pool = test_pool().await;
        let limiter = RateLimiter::for_tests(pool.clone(), &[("AuthIp", budget(1, 1))]);
        let ip = Subject::Ip("7.7.7.7".parse().unwrap());

        assert!(limiter.charge::<AuthIp>(&ip).await.is_ok());
        assert!(limiter.charge::<AuthIp>(&ip).await.is_err());

        // Epoch-aligned one-second windows: sleeping past a boundary is enough.
        actix_web::rt::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(limiter.charge::<AuthIp>(&ip).await.is_ok());
    }

    /// A denial is cached so a flood costs one DB write per window, not one per
    /// request. The stored count proves the extra calls never reached SQLite.
    #[actix_web::test]
    async fn denied_subject_is_cached_without_more_writes() {
        let pool = test_pool().await;
        let limiter = RateLimiter::for_tests(pool.clone(), &[("CryptoParamsIp", budget(2, 60))]);
        let ip = Subject::Ip("8.8.8.8".parse().unwrap());

        assert!(limiter.charge::<CryptoParamsIp>(&ip).await.is_ok());
        assert!(limiter.charge::<CryptoParamsIp>(&ip).await.is_ok());
        assert!(limiter.charge::<CryptoParamsIp>(&ip).await.is_err());

        // The first refusal is decided by the DB and increments the count to
        // max + 1; everything after it must be served from the denial cache.
        let hash = key_hash("CryptoParamsIp", &ip);
        assert_eq!(stored_count(&pool, "CryptoParamsIp", &hash).await, Some(3));

        for _ in 0..5 {
            assert!(limiter.charge::<CryptoParamsIp>(&ip).await.is_err());
        }
        assert_eq!(
            stored_count(&pool, "CryptoParamsIp", &hash).await,
            Some(3),
            "cached denials must not increment the DB counter"
        );
    }

    #[actix_web::test]
    async fn reset_clears_the_budget() {
        let pool = test_pool().await;
        let limiter = RateLimiter::for_tests(pool.clone(), &[("AuthTarget", budget(1, 60))]);
        let vault = Subject::Vault("3f2504e0-4f89-41d3-9a0c-0305e82c3301");

        assert!(limiter.charge::<AuthTarget>(&vault).await.is_ok());
        assert!(limiter.charge::<AuthTarget>(&vault).await.is_err());

        limiter.reset::<AuthTarget>(&vault).await;

        assert!(
            limiter.charge::<AuthTarget>(&vault).await.is_ok(),
            "a successful login clears the target budget"
        );
    }

    /// The stored key must be a hash, and the same subject under two policies
    /// must not share a row (domain separation).
    #[actix_web::test]
    async fn subjects_are_hashed_and_domain_separated() {
        let pool = test_pool().await;
        let vault_id = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
        let limiter = RateLimiter::for_tests(
            pool.clone(),
            &[("VaultWrite", budget(1, 60)), ("VaultAdmin", budget(1, 60))],
        );

        limiter
            .charge::<VaultWrite>(&Subject::Vault(vault_id))
            .await
            .expect("first charge");
        limiter
            .charge::<VaultAdmin>(&Subject::Vault(vault_id))
            .await
            .expect("a different policy is a different budget");

        let rows = RateLimitEntity::find().all(&pool).await.expect("rows");
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row.key_hash.len(), 64);
            assert!(row.key_hash.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(!row.key_hash.contains(vault_id));
        }
    }

    #[actix_web::test]
    async fn sweep_removes_only_expired_rows() {
        let pool = test_pool().await;
        let now = Utc::now().timestamp();
        for (kind, expires_at) in [("AuthIp", now - 10), ("AuthIp", now + 600)] {
            rate_limit::ActiveModel {
                kind: Set(kind.to_string()),
                key_hash: Set(format!("{expires_at:x}")),
                window_start: Set(now),
                count: Set(1),
                expires_at: Set(expires_at),
            }
            .insert(&pool)
            .await
            .expect("insert");
        }

        let limiter = RateLimiter::for_tests(pool.clone(), &[]);
        limiter.sweep_expired().await;

        let rows = RateLimitEntity::find().all(&pool).await.expect("rows");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].expires_at > now);
    }

    #[actix_web::test]
    async fn client_ip_ignores_spoofed_header_without_a_trusted_proxy() {
        let pool = test_pool().await;
        let limiter = RateLimiter::for_tests(pool.clone(), &[]);
        let req = TestRequest::default()
            .peer_addr("1.2.3.4:5000".parse().unwrap())
            .insert_header(("x-forwarded-for", "9.9.9.9"))
            .to_http_request();

        assert_eq!(
            limiter.client_ip(&req),
            "1.2.3.4".parse::<IpAddr>().unwrap(),
            "a forwarded header from an untrusted peer must be ignored"
        );
    }

    #[actix_web::test]
    async fn client_ip_uses_rightmost_untrusted_hop_behind_a_trusted_proxy() {
        let pool = test_pool().await;
        let mut limiter = RateLimiter::for_tests(pool.clone(), &[]);
        limiter.trusted_proxies = vec!["127.0.0.1".parse().unwrap()];

        // Leftmost entries are attacker-controlled; our proxy appended 9.9.9.9.
        let req = TestRequest::default()
            .peer_addr("127.0.0.1:5000".parse().unwrap())
            .insert_header(("x-forwarded-for", "1.1.1.1, 9.9.9.9"))
            .to_http_request();
        assert_eq!(
            limiter.client_ip(&req),
            "9.9.9.9".parse::<IpAddr>().unwrap()
        );

        // A chain of trusted proxies walks left until an untrusted hop.
        let req = TestRequest::default()
            .peer_addr("127.0.0.1:5000".parse().unwrap())
            .insert_header(("x-forwarded-for", "1.1.1.1, 127.0.0.1"))
            .to_http_request();
        assert_eq!(
            limiter.client_ip(&req),
            "1.1.1.1".parse::<IpAddr>().unwrap()
        );
    }

    #[actix_web::test]
    async fn ipv4_mapped_addresses_share_one_bucket() {
        let pool = test_pool().await;
        let limiter = RateLimiter::for_tests(pool.clone(), &[("AuthIp", budget(1, 60))]);
        let v4: IpAddr = "1.2.3.4".parse().unwrap();
        let mapped: IpAddr = "::ffff:1.2.3.4".parse().unwrap();

        assert!(limiter.charge::<AuthIp>(&Subject::Ip(v4)).await.is_ok());
        assert!(
            limiter
                .charge::<AuthIp>(&Subject::Ip(mapped))
                .await
                .is_err(),
            "a dual-stack listener must not hand out two budgets for one host"
        );
    }

    #[test]
    fn every_policy_has_a_budget() {
        let keys: Vec<&'static str> = production_budgets().into_iter().map(|(k, _)| k).collect();
        for key in [
            AuthIp::KEY,
            AuthTarget::KEY,
            RegisterIp::KEY,
            RegisterGlobal::KEY,
            CryptoParamsIp::KEY,
            VaultWrite::KEY,
            VaultAdmin::KEY,
            PairStart::KEY,
            PairIp::KEY,
            RecoveryChallengeIp::KEY,
            RecoveryPreauthIp::KEY,
        ] {
            assert!(keys.contains(&key), "policy {key} has no budget");
        }
    }
}
