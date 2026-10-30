use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use chrono::Utc;
use rand::Rng;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, QueryFilter, Set,
    Statement, Value,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::DbPool;
use crate::entity::pair_code::{self, Entity as PairCode};
use crate::error::{error_response, session_required};
use crate::rate_limit::{Limited, PairIp, PairStart, RateLimiter, Subject};
use crate::session_auth::session_vault_id;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Pair);

// One-time extension-pairing codes (plans/extension-signin-flow.md §4b).
//
// The web app (authenticated) mints a short code; the extension (which shares
// no storage with the web origin) redeems it for the vault identity only.
// The vault still requires the master password (or the extension's own
// device key) — the code is not an auth credential, just a substitute for
// typing a UUID. Records carry only `vault_id`, never verifier/wraps/plaintext.

// Unambiguous alphabet: no 0/O, 1/I/L. 32^6 ≈ 1B combos.
const CODE_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const CODE_LEN: usize = 6;
const DEFAULT_TTL_SECS: i64 = 5 * 60;
// Attempts allowed against ONE live code. This is a retry bound, not a
// brute-force control: a wrong guess is a different hash and has no row, so the
// per-IP budget is what bounds guessing. The counter lives on the row (atomic,
// shared by every worker and instance) and dies with it.
const MAX_CONSUME_ATTEMPTS_PER_CODE: i32 = 10;

fn pair_ttl_secs() -> i64 {
    std::env::var("PAIR_CODE_TTL_SECS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_TTL_SECS)
}

fn code_hash_hex(code_normalized: &str) -> String {
    // Pepper binds the hash to this install's session key when configured;
    // falls back to a static domain string so dev installs without env work.
    let pepper = std::env::var("SESSION_COOKIE_KEY").unwrap_or_else(|_| "voult-pair".to_string());
    let mut h = Sha256::new();
    h.update(pepper.as_bytes());
    h.update(b"|pair|");
    h.update(code_normalized.as_bytes());
    hex_of(h.finalize())
}

fn hex_of(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

fn new_code() -> String {
    let mut rng = rand::thread_rng();
    (0..CODE_LEN)
        .map(|_| {
            let i = rng.gen_range(0..CODE_ALPHABET.len());
            CODE_ALPHABET[i] as char
        })
        .collect()
}

/// Canonical form: trim, strip spaces/dashes, uppercase. Users type `ab12 cd`
/// or `ab12-cd` from the web app; all forms redeem the same record.
fn normalize_code(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The single failure shape for the consume path: an unknown code, an expired
/// code, a malformed code, and a burned code are indistinguishable.
fn pair_invalid() -> HttpResponse {
    error_response(
        StatusCode::NOT_FOUND,
        "invalid or expired code",
        "PAIR_INVALID",
    )
}

/// Atomically increments and reads the per-code attempt counter.
///
/// One statement, so two workers (or two instances over one database) cannot
/// both read 9 and write 10. `None` means no row carries this hash — the caller
/// answers exactly like an expired code.
async fn bump_attempts(pool: &DbPool, hash: &str) -> Result<Option<i32>, sea_orm::DbErr> {
    const SQL: &str =
        "UPDATE pair_code SET attempts = attempts + 1 WHERE code_hash = ? RETURNING attempts";
    let statement = Statement::from_sql_and_values(DbBackend::Sqlite, SQL, vec![Value::from(hash)]);
    let row = pool.query_one_raw(statement).await?;
    row.map(|row| row.try_get::<i32>("", "attempts"))
        .transpose()
}

async fn sweep_expired(pool: &DbPool) {
    // Best-effort: a stale row only wastes space until its TTL passes; a
    // failed sweep must never fail the request.
    let now = Utc::now();
    let _ = PairCode::delete_many()
        .filter(pair_code::Column::ExpiresAt.lt(now))
        .exec(pool)
        .await;
}

#[derive(Serialize)]
pub struct PairStartResponse {
    pub code: String,
    pub expires_at: String,
}

/// Mint a one-time pairing code for the session's vault. Requires auth; the
/// response goes to the already-authenticated web app, which shows the code
/// to the user. The code itself is shown once and stored hashed.
#[post("/pair/start")]
pub async fn pair_start(
    pool: web::Data<DbPool>,
    limiter: web::Data<RateLimiter>,
    session: Session,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => return session_required(),
    };
    // One code per pairing; this only prevents mint churn (each mint deletes the
    // previous code, so a loop would invalidate the code the user is reading).
    if let Err(rejected) = limiter
        .charge::<PairStart>(&Subject::Vault(&vault_id))
        .await
    {
        return rejected.into_response();
    }
    sweep_expired(pool.get_ref()).await;

    // One live code per vault: minting replaces any previous code so only
    // the newest display is valid (prevents "which code?" confusion).
    let _ = PairCode::delete_many()
        .filter(pair_code::Column::VaultId.eq(&vault_id))
        .exec(pool.get_ref())
        .await;

    let code = new_code();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(pair_ttl_secs());
    let am = pair_code::ActiveModel {
        selector: Set(uuid::Uuid::new_v4().to_string()),
        vault_id: Set(vault_id),
        code_hash: Set(code_hash_hex(&code)),
        // Starts at zero; M3 makes the consume path increment it atomically.
        attempts: Set(0),
        created_at: Set(now),
        expires_at: Set(expires_at),
    };
    if let Err(e) = am.insert(pool.get_ref()).await {
        LOG.error(
            format_args!("failed to create pair code: {:?}", e),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create pairing code",
            "DB_ERROR",
        );
    }
    LOG.log(format_args!("pairing code minted"), logger::Metadata::new());
    HttpResponse::Ok().json(PairStartResponse {
        code,
        expires_at: expires_at.to_rfc3339(),
    })
}

#[derive(Deserialize)]
pub struct PairConsumeRequest {
    pub code: String,
}

#[derive(Serialize)]
pub struct PairConsumeResponse {
    pub vault_id: String,
}

/// Redeem a pairing code for the vault identity. Unauthenticated by design
/// (the extension has no session yet) — throttled per IP, single-use, and
/// generic errors so a guesser learns nothing about vault existence.
#[post("/pair/consume")]
pub async fn pair_consume(
    pool: web::Data<DbPool>,
    // Per-IP budget for the unauthenticated path. This is what bounds guessing:
    // a wrong guess is a different code hash and therefore a different key, so
    // the per-code counter below cannot see it.
    _limit: Limited<PairIp>,
    payload: web::Json<PairConsumeRequest>,
) -> HttpResponse {
    let normalized = normalize_code(&payload.code);
    if normalized.len() != CODE_LEN || !normalized.bytes().all(|b| CODE_ALPHABET.contains(&b)) {
        // Same generic error as unknown/expired: no oracle for code shape.
        return pair_invalid();
    }
    sweep_expired(pool.get_ref()).await;

    let hash = code_hash_hex(&normalized);

    // Atomic increment + read-back. The counter lives on the row, so it is
    // shared by every worker and instance and dies with the code.
    let attempts = match bump_attempts(pool.get_ref(), &hash).await {
        Ok(Some(attempts)) => attempts,
        // No row carries this hash: unknown and expired (swept) codes answer
        // identically.
        Ok(None) => return pair_invalid(),
        Err(e) => {
            LOG.error(
                format_args!("failed to bump pair code attempts: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to redeem pairing code",
                "DB_ERROR",
            );
        }
    };

    if attempts > MAX_CONSUME_ATTEMPTS_PER_CODE {
        // Burn the record so a stuck client cannot keep retrying one code.
        let _ = PairCode::delete_many()
            .filter(pair_code::Column::CodeHash.eq(&hash))
            .exec(pool.get_ref())
            .await;
        return pair_invalid();
    }

    let record = match PairCode::find()
        .filter(pair_code::Column::CodeHash.eq(&hash))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return pair_invalid(),
        Err(e) => {
            LOG.error(
                format_args!("failed to look up pair code: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to redeem pairing code",
                "DB_ERROR",
            );
        }
    };

    if record.expires_at < Utc::now() {
        let _ = PairCode::delete_many()
            .filter(pair_code::Column::CodeHash.eq(&hash))
            .exec(pool.get_ref())
            .await;
        return pair_invalid();
    }

    // Single-use burn before responding: the code can never be replayed,
    // even if the response is lost. The attempt counter dies with the row.
    let _ = PairCode::delete_many()
        .filter(pair_code::Column::CodeHash.eq(&hash))
        .exec(pool.get_ref())
        .await;
    LOG.log(
        format_args!("pairing code redeemed"),
        logger::Metadata::new(),
    );
    HttpResponse::Ok().json(PairConsumeResponse {
        vault_id: record.vault_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::vault;
    use crate::rate_limit::{Budget, RateLimiter};
    use actix_web::App;
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::{ActiveModelTrait, Database, EntityTrait};

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const CODE: &str = "ABC234";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    async fn seed_vault(pool: &DbPool) {
        vault::ActiveModel {
            id: Set(VAULT_ID.to_string()),
            vault: Set("Y2lwaGVydGV4dA==".to_string()),
            salt: Set("c2FsdA==".to_string()),
            iterations: Set(60_000),
            vaultiv: Set("aXY=".to_string()),
            vault_verifier: Set("dmVyaWZpZXI=".to_string()),
            version: Set(1),
            crypto_version: Set(2),
            vault_key_wrap: Set(Some("d3JhcA==".to_string())),
            vault_key_wrap_iv: Set(Some("d2l2".to_string())),
            ..Default::default()
        }
        .insert(pool)
        .await
        .expect("seed vault");
    }

    async fn seed_code(pool: &DbPool, code: &str, attempts: i32) {
        pair_code::ActiveModel {
            selector: Set(uuid::Uuid::new_v4().to_string()),
            vault_id: Set(VAULT_ID.to_string()),
            code_hash: Set(code_hash_hex(&normalize_code(code))),
            attempts: Set(attempts),
            created_at: Set(Utc::now()),
            expires_at: Set(Utc::now() + chrono::Duration::seconds(300)),
        }
        .insert(pool)
        .await
        .expect("seed code");
    }

    macro_rules! test_app {
        ($pool:expr, $limiter:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(web::Data::new($limiter))
                    .app_data(crate::endpoints::json_config())
                    .service(super::pair_consume),
            )
            .await
        };
    }

    fn consume_request(code: &str, peer: &str) -> test::TestRequest {
        test::TestRequest::post()
            .uri("/pair/consume")
            .peer_addr(peer.parse().expect("peer"))
            .set_json(serde_json::json!({ "code": code }))
    }

    /// The unauthenticated consume path is bounded per IP. A wrong guess is a
    /// different hash, so this is the control that matters — the per-code
    /// counter cannot see distinct guesses.
    #[actix_web::test]
    async fn consume_is_limited_per_ip() {
        let pool = test_pool().await;
        let limiter = RateLimiter::for_tests(pool.clone(), &[("PairIp", Budget::new(2, 60))]);
        let app = test_app!(&pool, limiter);

        for code in ["AAAAAA", "BBBBBB"] {
            let resp =
                test::call_service(&app, consume_request(code, "1.1.1.1:1000").to_request()).await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(body["code"], "PAIR_INVALID");
        }

        let resp =
            test::call_service(&app, consume_request("CCCCCC", "1.1.1.1:1000").to_request()).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().get("retry-after").is_some());
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "PAIR_RATE_LIMITED");

        // A different address keeps its own budget.
        let resp =
            test::call_service(&app, consume_request("DDDDDD", "2.2.2.2:1000").to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// An unknown code must not create a row — otherwise the per-code counter
    /// would become an unbounded, attacker-controlled table.
    #[actix_web::test]
    async fn unknown_code_writes_nothing() {
        let pool = test_pool().await;
        let limiter = RateLimiter::permissive(pool.clone());
        let app = test_app!(&pool, limiter);

        let resp =
            test::call_service(&app, consume_request("ZZZZZZ", "1.1.1.1:1000").to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(PairCode::find().all(&pool).await.expect("rows").len(), 0);
    }

    /// A code that has spent its attempt allowance is burned, and the answer is
    /// byte-identical to "unknown" (no oracle for the burn state).
    #[actix_web::test]
    async fn exhausted_code_is_burned_and_answers_generically() {
        let pool = test_pool().await;
        seed_vault(&pool).await;
        seed_code(&pool, CODE, MAX_CONSUME_ATTEMPTS_PER_CODE).await;
        let limiter = RateLimiter::permissive(pool.clone());
        let app = test_app!(&pool, limiter);

        let resp =
            test::call_service(&app, consume_request(CODE, "1.1.1.1:1000").to_request()).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "PAIR_INVALID");
        assert_eq!(
            PairCode::find().all(&pool).await.expect("rows").len(),
            0,
            "the burned code must not survive"
        );
    }

    /// A successful redemption is single-use: the row is gone before the
    /// response, so a lost response cannot be replayed.
    #[actix_web::test]
    async fn redemption_is_single_use() {
        let pool = test_pool().await;
        seed_vault(&pool).await;
        seed_code(&pool, CODE, 0).await;
        let limiter = RateLimiter::permissive(pool.clone());
        let app = test_app!(&pool, limiter);

        let resp =
            test::call_service(&app, consume_request(CODE, "1.1.1.1:1000").to_request()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["vault_id"], VAULT_ID);
        assert_eq!(PairCode::find().all(&pool).await.expect("rows").len(), 0);

        let replay =
            test::call_service(&app, consume_request(CODE, "1.1.1.1:1000").to_request()).await;
        assert_eq!(replay.status(), StatusCode::NOT_FOUND);
    }
}
