use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use chrono::Utc;
use rand::Rng;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::db::DbPool;
use crate::entity::pair_code::{self, Entity as PairCode};
use crate::error::{error_response, session_required};
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
// Burned on success and on terminal failure; expired rows swept opportunistically.
const MAX_CONSUME_ATTEMPTS_PER_CODE: u32 = 10;
// Per-IP throttle on the unauthenticated consume path (localhost-first dev
// still benefits; production should add a reverse-proxy limit too).
const CONSUME_WINDOW_SECS: u64 = 60;
const CONSUME_MAX_PER_WINDOW: u32 = 20;

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

fn client_ip(req: &actix_web::HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string()
}

// --- In-memory consume throttle (per IP, sliding window) -------------------

static CONSUME_THROTTLE: OnceLock<Mutex<HashMap<String, (u32, Instant)>>> = OnceLock::new();

fn consume_throttle() -> &'static Mutex<HashMap<String, (u32, Instant)>> {
    CONSUME_THROTTLE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn check_consume_rate(ip: &str) -> bool {
    let Ok(mut map) = consume_throttle().lock() else {
        return true;
    };
    let now = Instant::now();
    let entry = map.entry(ip.to_string()).or_insert((0, now));
    if now.duration_since(entry.1).as_secs() >= CONSUME_WINDOW_SECS {
        *entry = (0, now);
    }
    entry.0 += 1;
    entry.0 <= CONSUME_MAX_PER_WINDOW
}

// --- In-memory per-code attempt counter (avoids a DB column) ---------------

static CODE_ATTEMPTS: OnceLock<Mutex<HashMap<String, u32>>> = OnceLock::new();

fn code_attempts() -> &'static Mutex<HashMap<String, u32>> {
    CODE_ATTEMPTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn bump_code_attempts(key: &str) -> u32 {
    let Ok(mut map) = code_attempts().lock() else {
        return 1;
    };
    let n = map.get(key).copied().unwrap_or(0) + 1;
    map.insert(key.to_string(), n);
    n
}

fn clear_code_attempts(key: &str) {
    if let Ok(mut map) = code_attempts().lock() {
        map.remove(key);
    }
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
pub async fn pair_start(pool: web::Data<DbPool>, session: Session) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        Ok(None) | Err(_) => return session_required(),
    };
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
    req: actix_web::HttpRequest,
    payload: web::Json<PairConsumeRequest>,
) -> HttpResponse {
    let ip = client_ip(&req);
    if !check_consume_rate(&ip) {
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts, try again later",
            "PAIR_RATE_LIMITED",
        );
    }
    let normalized = normalize_code(&payload.code);
    if normalized.len() != CODE_LEN || !normalized.bytes().all(|b| CODE_ALPHABET.contains(&b)) {
        // Same generic error as unknown/expired: no oracle for code shape.
        return error_response(
            StatusCode::NOT_FOUND,
            "invalid or expired code",
            "PAIR_INVALID",
        );
    }
    sweep_expired(pool.get_ref()).await;

    let hash = code_hash_hex(&normalized);
    let attempts = bump_code_attempts(&hash);
    if attempts > MAX_CONSUME_ATTEMPTS_PER_CODE {
        // Burn the record (if any) so brute force can't continue offline.
        let _ = PairCode::delete_many()
            .filter(pair_code::Column::CodeHash.eq(&hash))
            .exec(pool.get_ref())
            .await;
        clear_code_attempts(&hash);
        return error_response(
            StatusCode::NOT_FOUND,
            "invalid or expired code",
            "PAIR_INVALID",
        );
    }

    let record = match PairCode::find()
        .filter(pair_code::Column::CodeHash.eq(&hash))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            return error_response(
                StatusCode::NOT_FOUND,
                "invalid or expired code",
                "PAIR_INVALID",
            );
        }
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
        clear_code_attempts(&hash);
        return error_response(
            StatusCode::NOT_FOUND,
            "invalid or expired code",
            "PAIR_INVALID",
        );
    }

    // Single-use burn before responding: the code can never be replayed,
    // even if the response is lost.
    let _ = PairCode::delete_many()
        .filter(pair_code::Column::CodeHash.eq(&hash))
        .exec(pool.get_ref())
        .await;
    clear_code_attempts(&hash);
    LOG.log(
        format_args!("pairing code redeemed"),
        logger::Metadata::new(),
    );
    HttpResponse::Ok().json(PairConsumeResponse {
        vault_id: record.vault_id,
    })
}
