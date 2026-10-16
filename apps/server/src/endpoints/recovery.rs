//! Vault recovery, case 3 (recovery secret, no device key, password forgotten).
//!
//! Three steps, three round-trips, and exactly one irreversible write:
//!
//!   1. `POST /recovery/challenge` — unauthenticated. Mints a fresh random
//!      challenge for a vault that has recovery configured.
//!   2. `POST /recovery/unlock` — unauthenticated, **no state change**. Proves
//!      knowledge of the recovery secret and releases the opaque recovery
//!      envelope so the client can unwrap `vaultKeyRaw` locally.
//!   3. `POST /recovery/rewrap` — the only write. Consumes the challenge
//!      (single-use) and rotates the *password* credential to a new one,
//!      establishing a session for the caller.
//!
//! Every abort path leaves the vault byte-identical, so a wrong recovery key,
//! an expired challenge, or a lost response is always safely re-doable.
//!
//! Zero-knowledge: the server stores `recovery_verifier` (a 256-bit HMAC output,
//! non-invertible) and the `recovery_wrap` ciphertext, and never holds the
//! recovery secret, K_rec, or the vault key. The server's whole decision here is
//! "does this proof match what I would compute from `recovery_verifier` and this
//! vault's fresh challenge?".

use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use base64::Engine as _;
use chrono::Utc;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DatabaseTransaction, EntityTrait, ExprTrait,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::db::DbPool;
// Aliased: the module is `recovery_challenge`, which would otherwise collide with
// this file's `recovery_challenge` handler.
use crate::entity::recovery_challenge::{self as rc, Entity as Challenges};
use crate::entity::vault::{self, Entity as Vaults};
use crate::error::error_response;
use crate::session_auth::establish_vault_session;

type HmacSha256 = Hmac<Sha256>;

/// HMAC label for the recovery proof. MUST match `RECOVERY_PROOF_LABEL` in
/// packages/vault-core/src/crypto.ts — it is the wire contract between the two.
/// The client pins both labels with known-answer tests precisely so a rename
/// here cannot silently strand every existing vault.
const RECOVERY_PROOF_LABEL: &str = "recovery-proof-v1";

/// Challenge lifetime. Long enough to type a recovery key and a new master
/// password by hand, short enough that a stolen challenge is near-useless.
const CHALLENGE_TTL_SECS: i64 = 10 * 60;

/// Live challenges retained per vault. Bounds the table against unauthenticated
/// spam (§13): a caller can make at most this many live challenges per vault.
const MAX_LIVE_CHALLENGES_PER_VAULT: u64 = 3;

/// PBKDF2 iteration floor for the credential the rewrap installs. Mirrors the
/// client's PBKDF2_ITERATIONS; anything lower is rejected rather than stored.
const MIN_NEW_ITERATIONS: i32 = 60_000;
/// Upper bound so a hostile or buggy client cannot pin the server into an
/// absurd KDF cost that later makes every password login slow.
const MAX_NEW_ITERATIONS: i32 = 2_000_000;

/// Exact byte lengths the client is required to produce. Validated before any
/// DB work so a malformed body cannot reach the vault row.
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
/// 32-byte vault key + 16-byte GCM tag.
const WRAP_LEN: usize = 48;
const VERIFIER_LEN: usize = 32;
const PROOF_LEN: usize = 32;
const CHALLENGE_LEN: usize = 32;

// --- Per-IP throttle for the unauthenticated challenge endpoint -------------

/// Default budget: enough for one recovery plus a retry or two, far below
/// anything a person actually needs.
const CHALLENGE_MAX_PER_WINDOW: u32 = 10;
const CHALLENGE_WINDOW_SECS: u64 = 60;

/// Entries beyond this are swept on the next call, so a flood from many
/// addresses cannot grow the map without bound.
const THROTTLE_SWEEP_THRESHOLD: usize = 256;

/// Sliding-window throttle for `POST /recovery/challenge`, keyed by client IP.
///
/// App-scoped rather than a process global: the eight Actix workers share one
/// instance through the same `app_data`, so a single caller cannot get a fresh
/// budget per worker — while a test still gets its own clean instance instead of
/// contaminating every other test through shared process state.
pub struct ChallengeThrottle {
    entries: Mutex<HashMap<String, (u32, Instant)>>,
    max_per_window: u32,
    window_secs: u64,
}

impl Default for ChallengeThrottle {
    fn default() -> Self {
        Self::new(CHALLENGE_MAX_PER_WINDOW, CHALLENGE_WINDOW_SECS)
    }
}

impl ChallengeThrottle {
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            max_per_window,
            window_secs,
        }
    }

    /// Charges one request to `key`. Returns false when the budget is spent.
    ///
    /// Fails OPEN on a poisoned lock: a panic elsewhere must not turn this
    /// endpoint into a permanent outage, and the per-vault live cap plus the
    /// challenge TTL already bound the real cost.
    pub fn allow(&self, key: &str) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return true;
        };
        if entries.len() > THROTTLE_SWEEP_THRESHOLD {
            let window = Duration::from_secs(self.window_secs);
            entries.retain(|_, (_, started)| started.elapsed() < window);
        }

        let now = Instant::now();
        let window = Duration::from_secs(self.window_secs);
        let entry = entries.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            *entry = (0, now);
        }
        entry.0 = entry.0.saturating_add(1);
        entry.0 <= self.max_per_window
    }
}

fn client_ip(req: &actix_web::HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string()
}

// --- Shared helpers --------------------------------------------------------

/// The single failure shape for every recovery-proof path.
///
/// Deliberately identical for an unknown selector, an expired challenge, a
/// wrong proof, a wrong vault, and a vault with no recovery configured. If these
/// diverged, any of them would become an oracle — most importantly, telling a
/// caller "this vault has no recovery" would turn the endpoint back into a
/// vault-existence probe.
fn auth_failed() -> HttpResponse {
    error_response(
        StatusCode::UNAUTHORIZED,
        "Recovery failed. Check the recovery key.",
        "AUTH_FAILED",
    )
}

/// Constant-time equality. Not defence-in-depth paranoia: the proof is a
/// 32-byte MAC and a timing-variable comparison would leak how many leading
/// bytes of a guessed value matched. The length check short-circuits, which is
/// safe because every proof is exactly `PROOF_LEN`.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Recomputes what the client's proof must be:
/// `HMAC-SHA256(recovery_verifier, "recovery-proof-v1|" + vault_id + "|" + challenge)`.
///
/// The server can do this because it holds `recovery_verifier`, without ever
/// holding the recovery secret or K_rec.
fn expected_proof(verifier_b64: &str, vault_id: &str, challenge_b64: &str) -> Option<Vec<u8>> {
    let key = decode_exact(verifier_b64, VERIFIER_LEN)?;
    let mut mac = HmacSha256::new_from_slice(&key).ok()?;
    mac.update(RECOVERY_PROOF_LABEL.as_bytes());
    mac.update(b"|");
    mac.update(vault_id.as_bytes());
    mac.update(b"|");
    mac.update(challenge_b64.as_bytes());
    Some(mac.finalize().into_bytes().to_vec())
}

/// `SHA256(vault_id || challenge)`, hex. An integrity check over the stored row,
/// not a secrecy boundary — the challenge sits next to it in the clear. Catches
/// a row whose `challenge` was altered without its hash being updated, which
/// would otherwise make a valid proof silently fail for no visible reason.
fn challenge_hash(vault_id: &str, challenge_b64: &str) -> String {
    let mut h = Sha256::new();
    h.update(vault_id.as_bytes());
    h.update(challenge_b64.as_bytes());
    hex_of(h.finalize())
}

fn hex_of(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Base64-decodes to exactly `len` bytes, or `None`.
fn decode_exact(s: &str, len: usize) -> Option<Vec<u8>> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .ok()?;
    if bytes.len() != len {
        return None;
    }
    Some(bytes)
}

/// Parses a canonical (lowercase, hyphenated) UUID. Rejects the uppercase and
/// braced forms so a caller cannot produce two distinct rows for one vault by
/// varying the spelling of the same id.
fn canonical_uuid(raw: &str) -> Option<String> {
    let parsed = Uuid::parse_str(raw.trim()).ok()?;
    let canonical = parsed.to_string();
    (canonical == raw.trim()).then_some(canonical)
}

/// Deletes every expired challenge row, everywhere.
///
/// Run on each challenge insert (the table is tiny — at most
/// `MAX_LIVE_CHALLENGES_PER_VAULT` rows per vault) and once at startup, so rows
/// orphaned by a crash mid-flow do not linger for the rest of the process's
/// life. Best-effort by design: a stale row only wastes space until its TTL
/// passes, and a failed sweep must never fail the request that triggered it.
pub async fn prune_expired_challenges(pool: &DatabaseConnection) {
    if let Err(e) = Challenges::delete_many()
        .filter(rc::Column::ExpiresAt.lt(Utc::now()))
        .exec(pool)
        .await
    {
        log::warn!("recovery challenge sweep failed: {:?}", e);
    }
}

/// Removes expired challenges for one vault, then enforces the live cap.
async fn prune_and_cap(pool: &DatabaseConnection, vault_id: &str) {
    let now = Utc::now();
    let _ = Challenges::delete_many()
        .filter(rc::Column::ExpiresAt.lt(now))
        .exec(pool)
        .await;

    let live = match Challenges::find()
        .filter(rc::Column::VaultId.eq(vault_id))
        .filter(rc::Column::ExpiresAt.gte(now))
        .order_by_asc(rc::Column::CreatedAt)
        .all(pool)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            log::error!("failed to count live recovery challenges: {:?}", e);
            return;
        }
    };

    let excess = live.len() as u64 + 1;
    if excess <= MAX_LIVE_CHALLENGES_PER_VAULT {
        return;
    }
    let to_drop = (excess - MAX_LIVE_CHALLENGES_PER_VAULT) as usize;
    let selectors: Vec<String> = live.iter().take(to_drop).map(|c| c.selector.clone()).collect();
    if let Err(e) = Challenges::delete_many()
        .filter(rc::Column::Selector.is_in(selectors))
        .exec(pool)
        .await
    {
        log::error!("failed to evict stale recovery challenges: {:?}", e);
    } else {
        log::warn!("recovery challenge cap enforced; evicted {to_drop} oldest challenge(s)");
    }
}

/// Loads a challenge row and checks it is live, addressed to this vault, and
/// internally consistent. Returns `None` for every failure so callers cannot
/// distinguish the reasons.
async fn load_live_challenge(
    pool: &DbPool,
    selector: &str,
    vault_id: &str,
) -> Option<rc::Model> {
    let row = Challenges::find()
        .filter(rc::Column::Selector.eq(selector))
        .one(pool)
        .await
        .ok()??;

    if row.vault_id != vault_id {
        return None;
    }
    if row.expires_at < Utc::now() {
        return None;
    }
    if row.challenge_hash != challenge_hash(vault_id, &row.challenge) {
        return None;
    }
    Some(row)
}

/// Full proof check against a vault's stored `recovery_verifier`.
fn proof_is_valid(vault: &vault::Model, vault_id: &str, challenge_b64: &str, proof: &[u8]) -> bool {
    let Some(verifier) = vault.recovery_verifier.as_deref() else {
        return false;
    };
    let Some(expected) = expected_proof(verifier, vault_id, challenge_b64) else {
        return false;
    };
    constant_time_eq(&expected, proof)
}

/// Consumes the challenge addressed by `selector` and verifies `proof` against
/// `vault_id`'s stored `recovery_verifier`, all inside the caller's transaction.
///
/// Shared verbatim by `rewrap` and `regenerate` so the challenge lifecycle and
/// the proof check cannot drift between them — and so a future
/// session-authenticated password-change endpoint reuses the same routine rather
/// than copying it.
///
/// On success returns the vault row. On any failure it returns the uniform
/// `auth_failed()` (or a DB error) for the caller to propagate, and the CALLER
/// must roll the transaction back — `rollback()` consumes the transaction, so
/// this helper cannot do it. Rolling back also undoes the challenge burn, which
/// is deliberate: a user who mistyped their recovery key can simply retry
/// against the same challenge. Callers only ever see "verified" or "identical
/// failure response", never a reason.
async fn verify_recovery_proof(
    tx: &DatabaseTransaction,
    selector: &str,
    vault_id: &str,
    proof: &[u8],
    context: &str,
) -> Result<vault::Model, HttpResponse> {
    let challenge = match Challenges::find()
        .filter(rc::Column::Selector.eq(selector))
        .one(&*tx)
        .await
    {
        Ok(Some(c)) => c,
        Ok(None) => {
            log::warn!("{context} rejected: unknown selector vault_id={vault_id}");
            return Err(auth_failed());
        }
        Err(e) => {
            log::error!("failed to load recovery challenge: {:?}", e);
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "recovery failed",
                "DB_ERROR",
            ));
        }
    };

    if challenge.vault_id != vault_id || challenge.expires_at < Utc::now() {
        log::warn!("{context} rejected: challenge not usable vault_id={vault_id}");
        return Err(auth_failed());
    }
    if challenge.challenge_hash != challenge_hash(vault_id, &challenge.challenge) {
        log::warn!("{context} rejected: challenge integrity mismatch vault_id={vault_id}");
        return Err(auth_failed());
    }

    // Burn it inside the transaction: single-use is guaranteed on the success
    // path, and rolled back with everything else on any failure.
    if Challenges::delete_by_id(&challenge.selector)
        .exec(&*tx)
        .await
        .is_err()
    {
        log::error!("failed to consume recovery challenge");
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "recovery failed",
            "DB_ERROR",
        ));
    }

    let vault = match Vaults::find()
        .filter(vault::Column::Id.eq(vault_id))
        .one(&*tx)
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            log::warn!("{context} rejected: vault not found vault_id={vault_id}");
            return Err(auth_failed());
        }
        Err(e) => {
            log::error!("failed to load vault for {context}: {:?}", e);
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "recovery failed",
                "DB_ERROR",
            ));
        }
    };

    if vault.recovery_verifier.is_none() {
        log::warn!("{context} rejected: vault has no recovery configured vault_id={vault_id}");
        return Err(auth_failed());
    }
    if !proof_is_valid(&vault, vault_id, &challenge.challenge, proof) {
        log::warn!("{context} rejected: proof mismatch vault_id={vault_id}");
        return Err(auth_failed());
    }

    Ok(vault)
}

// --- POST /recovery/challenge ----------------------------------------------

#[derive(Deserialize)]
pub struct ChallengeRequest {
    pub vault_id: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub selector: String,
    pub challenge: String,
    pub expires_at: String,
}

/// Mints a fresh recovery challenge. Unauthenticated by design: the recovering
/// user has a paper recovery key and nothing else.
///
/// Returns 404 VAULT_NO_RECOVERY for both "no such vault" and "vault has no
/// recovery". That is safe — existence and `has_recovery` are already public
/// via GET /get_crypto_params — and it gives the client something actionable to
/// say instead of a bare auth failure.
///
/// Throttled per client IP. This endpoint is unauthenticated and writes a row on
/// every call, so without a budget a single address could fill the table (and the
/// server's write path) on its own. The per-vault live cap below is the second
/// layer: it bounds the table even against a spray across many addresses.
#[post("/recovery/challenge")]
pub async fn recovery_challenge(
    pool: web::Data<DbPool>,
    req: actix_web::HttpRequest,
    throttle: web::Data<ChallengeThrottle>,
    payload: web::Json<ChallengeRequest>,
) -> HttpResponse {
    let ip = client_ip(&req);
    if !throttle.allow(&ip) {
        log::warn!("recovery challenge refused: rate limited");
        return error_response(
            StatusCode::TOO_MANY_REQUESTS,
            "too many attempts, try again later",
            "RECOVERY_RATE_LIMITED",
        );
    }

    let request = payload.into_inner();
    let Some(vault_id) = canonical_uuid(&request.vault_id) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT");
    };

    let vault = match Vaults::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            log::warn!("recovery challenge refused: vault not found");
            return no_recovery();
        }
        Err(e) => {
            log::error!("failed to fetch vault for recovery challenge: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to create recovery challenge",
                "DB_ERROR",
            );
        }
    };

    if vault.recovery_verifier.is_none() {
        log::warn!("recovery challenge refused: vault has no recovery configured");
        return no_recovery();
    }

    prune_and_cap(pool.get_ref(), &vault_id).await;

    // 256 bits of CSPRNG. Reusing a challenge across vaults would let one
    // proof be replayed, so this is always freshly drawn per request.
    let mut raw = [0u8; CHALLENGE_LEN];
    rand::thread_rng().fill_bytes(&mut raw);
    let challenge = base64::engine::general_purpose::STANDARD.encode(raw);
    let selector = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(CHALLENGE_TTL_SECS);

    let am = rc::ActiveModel {
        selector: Set(selector.clone()),
        vault_id: Set(vault_id.clone()),
        challenge_hash: Set(challenge_hash(&vault_id, &challenge)),
        challenge: Set(challenge.clone()),
        created_at: Set(now),
        expires_at: Set(expires_at),
    };
    if let Err(e) = am.insert(pool.get_ref()).await {
        log::error!("failed to create recovery challenge: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed to create recovery challenge",
            "DB_ERROR",
        );
    }

    // vault_id only — never the challenge, proof, verifier, or wrap.
    log::warn!("recovery challenge issued vault_id={vault_id}");
    HttpResponse::Ok().json(ChallengeResponse {
        selector,
        challenge,
        expires_at: expires_at.to_rfc3339(),
    })
}

fn no_recovery() -> HttpResponse {
    error_response(
        StatusCode::NOT_FOUND,
        "vault not found or has no recovery",
        "VAULT_NO_RECOVERY",
    )
}

// --- POST /recovery/unlock --------------------------------------------------

#[derive(Deserialize)]
pub struct UnlockRequest {
    pub vault_id: String,
    pub selector: String,
    pub proof: String,
}

#[derive(Serialize)]
pub struct UnlockResponse {
    pub recovery_wrap: String,
    pub recovery_wrap_iv: String,
    pub credential_version: i32,
}

/// Releases the recovery envelope to a caller that has proven knowledge of the
/// recovery secret.
///
/// This establishes **no session** and modifies **no vault row**. The challenge
/// is deliberately not consumed here, so the same `(selector, proof)` pair stays
/// usable at the rewrap step within its TTL: it only ever releases an opaque
/// ciphertext, which a successful prover could decrypt anyway. The challenge is
/// consumed exactly once, at the rewrap — the operation that actually changes
/// something.
#[post("/recovery/unlock")]
pub async fn recovery_unlock(
    pool: web::Data<DbPool>,
    payload: web::Json<UnlockRequest>,
) -> HttpResponse {
    let request = payload.into_inner();
    let Some(vault_id) = canonical_uuid(&request.vault_id) else {
        return auth_failed();
    };
    let Some(proof) = decode_exact(&request.proof, PROOF_LEN) else {
        return auth_failed();
    };

    let Some(challenge) =
        load_live_challenge(pool.get_ref(), request.selector.trim(), &vault_id).await
    else {
        log::warn!("recovery unlock rejected: no live challenge vault_id={vault_id}");
        return auth_failed();
    };

    let vault = match Vaults::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => {
            log::warn!("recovery unlock rejected: vault not found vault_id={vault_id}");
            return auth_failed();
        }
        Err(e) => {
            log::error!("failed to fetch vault for recovery unlock: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "recovery failed",
                "DB_ERROR",
            );
        }
    };

    if !proof_is_valid(&vault, &vault_id, &challenge.challenge, &proof) {
        log::warn!("recovery unlock rejected: proof mismatch vault_id={vault_id}");
        return auth_failed();
    }

    let (Some(wrap), Some(wrap_iv)) =
        (vault.recovery_wrap.clone(), vault.recovery_wrap_iv.clone())
    else {
        // recovery_verifier present but no envelope: a corrupt row. Reported as
        // a plain auth failure rather than a distinct code, to keep the failure
        // surface uniform.
        log::error!("recovery unlock: vault has a verifier but no recovery envelope");
        return auth_failed();
    };

    log::warn!("recovery unlock succeeded vault_id={vault_id}");
    HttpResponse::Ok().json(UnlockResponse {
        recovery_wrap: wrap,
        recovery_wrap_iv: wrap_iv,
        credential_version: vault.credential_version,
    })
}

// --- POST /recovery/rewrap --------------------------------------------------

#[derive(Deserialize)]
pub struct RewrapRequest {
    pub vault_id: String,
    pub selector: String,
    pub proof: String,
    pub credential_version: i32,
    pub new_salt: String,
    pub new_iterations: i32,
    pub new_vault_verifier: String,
    pub new_vault_key_wrap: String,
    pub new_vault_key_wrap_iv: String,
}

#[derive(Serialize)]
pub struct RewrapResponse {
    pub vault_id: String,
    pub crypto_version: i32,
    pub lock_epoch: i32,
}

/// The only irreversible write in recovery: rotates the password credential
/// (salt / iterations / verifier / password envelope) and establishes a session.
///
/// Column discipline — this write must NOT touch:
///   * `vault`, `vaultiv` — the vault key is unchanged, so the ciphertext is too.
///   * `version`         — the *document* CAS counter. Bumping it would
///                          invalidate every pending sync intent's base_version
///                          and force a needless conflict cycle.
///   * `recovery_*`      — Rule R1: the recovery wrap holds `vaultKeyRaw`
///                          directly, so rotating the password leaves the
///                          recovery path intact, and a vault must stay
///                          recoverable by the very key that just recovered it.
///   * `lock_epoch`      — no lock event occurred.
#[post("/recovery/rewrap")]
pub async fn recovery_rewrap(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<RewrapRequest>,
) -> HttpResponse {
    let request = payload.into_inner();

    // --- Validate every input before touching the database. ---
    let Some(vault_id) = canonical_uuid(&request.vault_id) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT");
    };
    let Some(proof) = decode_exact(&request.proof, PROOF_LEN) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid proof", "INVALID_INPUT");
    };
    if decode_exact(&request.new_salt, SALT_LEN).is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_salt must be 16 bytes of base64",
            "INVALID_INPUT",
        );
    }
    if decode_exact(&request.new_vault_verifier, VERIFIER_LEN).is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_vault_verifier must be 32 bytes of base64",
            "INVALID_INPUT",
        );
    }
    // Paired or not at all: a half-written password envelope would leave the
    // vault unwrappable by any password.
    if decode_exact(&request.new_vault_key_wrap, WRAP_LEN).is_none()
        || decode_exact(&request.new_vault_key_wrap_iv, IV_LEN).is_none()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_vault_key_wrap must be 48 bytes and new_vault_key_wrap_iv 12 bytes of base64",
            "INVALID_INPUT",
        );
    }
    if !(MIN_NEW_ITERATIONS..=MAX_NEW_ITERATIONS).contains(&request.new_iterations) {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_iterations out of range",
            "INVALID_INPUT",
        );
    }
    if request.credential_version < 0 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid credential_version",
            "INVALID_INPUT",
        );
    }

    let tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("failed to create transaction: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "recovery failed",
                "DB_ERROR",
            );
        }
    };

    // 1-3. Consume the challenge and verify the proof. Shared with regenerate.
    let vault = match verify_recovery_proof(
        &tx,
        request.selector.trim(),
        &vault_id,
        &proof,
        "recovery rewrap",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => {
            let _ = tx.rollback().await;
            return resp;
        }
    };

    // The rewrap installs a v2-shaped credential (bounded KDF + wrapped vault
    // key), so it is only meaningful for a vault already on v2.
    if vault.crypto_version != 2 {
        let _ = tx.rollback().await;
        log::warn!("recovery rewrap rejected: unsupported crypto_version");
        return error_response(
            StatusCode::CONFLICT,
            "vault is not on crypto version 2",
            "UNSUPPORTED_CRYPTO_VERSION",
        );
    }

    // 4. Compare-and-swap on credential_version. Exactly one of N concurrent
    //    recoveries can win; the losers see rows_affected == 0 and get 409.
    let update = Vaults::update_many()
        .col_expr(vault::Column::Salt, Expr::value(request.new_salt.clone()))
        .col_expr(
            vault::Column::Iterations,
            Expr::value(request.new_iterations),
        )
        .col_expr(
            vault::Column::VaultVerifier,
            Expr::value(request.new_vault_verifier.clone()),
        )
        .col_expr(
            vault::Column::VaultKeyWrap,
            Expr::value(request.new_vault_key_wrap.clone()),
        )
        .col_expr(
            vault::Column::VaultKeyWrapIv,
            Expr::value(request.new_vault_key_wrap_iv.clone()),
        )
        .col_expr(
            vault::Column::CredentialVersion,
            Expr::col(vault::Column::CredentialVersion).add(1),
        )
        .filter(vault::Column::Id.eq(&vault_id))
        .filter(
            vault::Column::CredentialVersion
                .eq(request.credential_version),
        )
        .exec(&tx)
        .await;

    let rows_affected = match update {
        Ok(r) => r.rows_affected,
        Err(e) => {
            let _ = tx.rollback().await;
            log::error!("failed to rotate vault credential: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "recovery failed",
                "DB_ERROR",
            );
        }
    };

    if rows_affected == 0 {
        let _ = tx.rollback().await;
        log::warn!("recovery rewrap rejected: stale credential_version");
        return error_response(
            StatusCode::CONFLICT,
            "recovery was already completed; start over",
            "CREDENTIAL_STALE",
        );
    }

    // `lock_epoch` is read from the pre-update snapshot, and the rewrap does not
    // touch that column, so it is still accurate to answer with.
    let crypto_version = vault.crypto_version;
    let lock_epoch = vault.lock_epoch;

    if let Err(e) = tx.commit().await {
        log::error!("failed to commit recovery transaction: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "recovery failed",
            "DB_ERROR",
        );
    }

    // 5. Establish the session — after the commit, so a failure here never
    //    leaves an authenticated caller without a rotated credential.
    if let Err(e) = establish_vault_session(&session, &vault_id) {
        log::error!("failed to establish session after recovery: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "recovery completed but session could not be established",
            "SESSION_ERROR",
        );
    }

    // The challenge is now spent, the password credential is rotated, and the
    // recovery path is untouched — so this vault can be recovered again with
    // the same recovery key (Rule R1).
    log::warn!("recovery succeeded; password credential rotated vault_id={vault_id}");
    HttpResponse::Ok().json(RewrapResponse {
        vault_id,
        crypto_version,
        lock_epoch,
    })
}

// --- POST /recovery/regenerate ---------------------------------------------

#[derive(Deserialize)]
pub struct RegenerateRequest {
    pub vault_id: String,
    pub selector: String,
    /// Proof made with the CURRENT recovery key — proving it is what the caller
    /// is replacing (e.g. the paper copy was lost or stolen).
    pub proof: String,
    pub new_recovery_verifier: String,
    pub new_recovery_salt: String,
    pub new_recovery_wrap: String,
    pub new_recovery_wrap_iv: String,
}

/// Rotates the recovery key. Session-required, because it is a deliberate change
/// to a live vault's recovery material made from inside the app — unlike the
/// three unauthenticated endpoints, which exist precisely because the caller has
/// no session.
///
/// This does NOT touch `salt`, `iterations`, `vault_verifier`, `vault_key_wrap*`,
/// `version`, `lock_epoch`, or the `vault`/`vaultiv` ciphertext: the password
/// credential is entirely unaffected, so a user rotating a stolen paper key does
/// not have to change their master password. It also does not bump
/// `credential_version` — that counter tracks the *password* credential, which
/// this endpoint leaves alone.
#[post("/recovery/regenerate")]
pub async fn recovery_regenerate(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<RegenerateRequest>,
) -> HttpResponse {
    let request = payload.into_inner();

    // The session, not the body, decides which vault is being changed. A body
    // naming a different vault is refused rather than silently ignored.
    let session_vault = match crate::session_auth::session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => {
            return crate::error::session_required();
        }
    };
    let Some(vault_id) = canonical_uuid(&request.vault_id) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid vault_id", "INVALID_INPUT");
    };
    if vault_id != session_vault {
        log::warn!("recovery regenerate refused: vault does not match session");
        return error_response(
            StatusCode::FORBIDDEN,
            "vault does not match session",
            "VAULT_MISMATCH",
        );
    }

    let Some(proof) = decode_exact(&request.proof, PROOF_LEN) else {
        return error_response(StatusCode::BAD_REQUEST, "invalid proof", "INVALID_INPUT");
    };
    if decode_exact(&request.new_recovery_verifier, VERIFIER_LEN).is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_recovery_verifier must be 32 bytes of base64",
            "INVALID_INPUT",
        );
    }
    if decode_exact(&request.new_recovery_salt, SALT_LEN).is_none() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_recovery_salt must be 16 bytes of base64",
            "INVALID_INPUT",
        );
    }
    // Paired or not at all, exactly as for the rewrap.
    if decode_exact(&request.new_recovery_wrap, WRAP_LEN).is_none()
        || decode_exact(&request.new_recovery_wrap_iv, IV_LEN).is_none()
    {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_recovery_wrap must be 48 bytes and new_recovery_wrap_iv 12 bytes of base64",
            "INVALID_INPUT",
        );
    }

    let tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            log::error!("failed to create transaction: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "recovery rotation failed",
                "DB_ERROR",
            );
        }
    };

    let vault = match verify_recovery_proof(
        &tx,
        request.selector.trim(),
        &vault_id,
        &proof,
        "recovery regenerate",
    )
    .await
    {
        Ok(v) => v,
        Err(resp) => {
            let _ = tx.rollback().await;
            return resp;
        }
    };

    // Compare-and-swap on the recovery material itself. The caller proved it
    // holds the CURRENT key, so the stored verifier it was proved against is
    // exactly the value to guard on — two concurrent rotations cannot both win,
    // and this needs no extra field in the body.
    let Some(current_verifier) = vault.recovery_verifier.as_deref() else {
        let _ = tx.rollback().await;
        return auth_failed();
    };
    let current_verifier = current_verifier.to_string();

    let update = Vaults::update_many()
        .col_expr(
            vault::Column::RecoveryVerifier,
            Expr::value(request.new_recovery_verifier.clone()),
        )
        .col_expr(
            vault::Column::RecoverySalt,
            Expr::value(request.new_recovery_salt.clone()),
        )
        .col_expr(
            vault::Column::RecoveryWrap,
            Expr::value(request.new_recovery_wrap.clone()),
        )
        .col_expr(
            vault::Column::RecoveryWrapIv,
            Expr::value(request.new_recovery_wrap_iv.clone()),
        )
        .filter(vault::Column::Id.eq(&vault_id))
        .filter(vault::Column::RecoveryVerifier.eq(&current_verifier))
        .exec(&tx)
        .await;

    match update {
        Ok(r) if r.rows_affected == 0 => {
            let _ = tx.rollback().await;
            log::warn!("recovery regenerate rejected: stale recovery verifier");
            return error_response(
                StatusCode::CONFLICT,
                "recovery key was already rotated; reload and try again",
                "RECOVERY_STALE",
            );
        }
        Ok(_) => {}
        Err(e) => {
            let _ = tx.rollback().await;
            log::error!("failed to rotate recovery material: {:?}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "recovery rotation failed",
                "DB_ERROR",
            );
        }
    }

    if let Err(e) = tx.commit().await {
        log::error!("failed to commit recovery rotation: {:?}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "recovery rotation failed",
            "DB_ERROR",
        );
    }

    log::warn!("recovery key rotated vault_id={vault_id}");
    HttpResponse::Ok().json(serde_json::json!({ "rotated": true }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::App;
    use actix_web::cookie::Key;
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::Database;

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const OTHER_VAULT_ID: &str = "00000000-0000-4000-8000-000000000000";

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    macro_rules! test_app {
        ($pool:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(crate::endpoints::json_config())
                    // Per-app instance, so one test's budget cannot consume
                    // another's. Tests that exercise the limit install their own
                    // tight throttle instead.
                    .app_data(web::Data::new(super::ChallengeThrottle::new(
                        10_000,
                        60,
                    )))
                    .wrap(
                        actix_session::SessionMiddleware::builder(
                            actix_session::storage::CookieSessionStore::default(),
                            Key::from(
                                b"test-key-for-session-middleware-must-be-at-least-64-bytes-long!!",
                            ),
                        )
                        .cookie_name("voult_session".to_string())
                        .build(),
                    )
                    .service(super::recovery_challenge)
                    .service(super::recovery_unlock)
                    .service(super::recovery_rewrap)
                    .service(super::recovery_regenerate)
                    .service(crate::endpoints::register::register)
                    .service(crate::endpoints::session_status::get_session),
            )
            .await
        };
    }

    /// Issues a challenge over HTTP and returns (selector, challenge). A macro
    /// rather than a helper fn because naming the service's request type would
    /// require depending on actix-service directly.
    macro_rules! issue_challenge {
        ($app:expr, $vault_id:expr) => {{
            let resp = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/recovery/challenge")
                    .set_json(serde_json::json!({ "vault_id": $vault_id }))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
            let body: serde_json::Value = test::read_body_json(resp).await;
            (
                body["selector"].as_str().expect("selector").to_string(),
                body["challenge"].as_str().expect("challenge").to_string(),
            )
        }};
    }

    /// Deterministic base64 of an exact byte length, with a recognisable fill so
    /// an unintended write is obvious in a diff.
    fn b64_of(len: usize, fill: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode(vec![fill; len])
    }

    /// Seeds a recoverable vault with distinctive sentinels in every column, so
    /// a test can assert precisely which ones the rewrap touched.
    async fn seed_vault(pool: &DbPool, vault_id: &str) -> vault::Model {
        let am = vault::ActiveModel {
            id: Set(vault_id.to_string()),
            vault: Set(b64_of(16, 0xA1)),
            vaultiv: Set(b64_of(12, 0xA2)),
            salt: Set(b64_of(16, 0xA3)),
            iterations: Set(60_000),
            vault_verifier: Set(b64_of(32, 0xA4)),
            vault_key_wrap: Set(Some(b64_of(48, 0xA5))),
            vault_key_wrap_iv: Set(Some(b64_of(12, 0xA6))),
            recovery_verifier: Set(Some(b64_of(32, 0xB1))),
            recovery_salt: Set(Some(b64_of(16, 0xB2))),
            recovery_wrap: Set(Some(b64_of(48, 0xB3))),
            recovery_wrap_iv: Set(Some(b64_of(12, 0xB4))),
            recovery_created_at: Set(Some(Utc::now())),
            credential_version: Set(0),
            version: Set(7),
            crypto_version: Set(2),
            lock_epoch: Set(3),
            created_at: Set(Utc::now()),
            ..Default::default()
        };
        am.insert(pool).await.expect("seed vault")
    }

    async fn load_vault(pool: &DbPool, vault_id: &str) -> vault::Model {
        Vaults::find()
            .filter(vault::Column::Id.eq(vault_id))
            .one(pool)
            .await
            .expect("load")
            .expect("vault exists")
    }

    fn proof_for(verifier_b64: impl AsRef<str>, vault_id: &str, challenge: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(
            expected_proof(verifier_b64.as_ref(), vault_id, challenge).expect("proof"),
        )
    }

    fn unlock_body(vault_id: &str, selector: &str, proof: &str) -> serde_json::Value {
        serde_json::json!({
            "vault_id": vault_id,
            "selector": selector,
            "proof": proof,
        })
    }

    /// A valid rewrap body, with the challenge-specific parts filled per test.
    fn rewrap_body(
        vault_id: &str,
        selector: &str,
        proof: &str,
        credential_version: i32,
    ) -> serde_json::Value {
        serde_json::json!({
            "vault_id": vault_id,
            "selector": selector,
            "proof": proof,
            "credential_version": credential_version,
            "new_salt": b64_of(16, 0xC1),
            "new_iterations": 60000,
            "new_vault_verifier": b64_of(32, 0xC2),
            "new_vault_key_wrap": b64_of(48, 0xC3),
            "new_vault_key_wrap_iv": b64_of(12, 0xC4),
        })
    }

    // --- challenge ---------------------------------------------------------

    #[actix_web::test]
    async fn challenge_issues_a_usable_challenge() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;

        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);

        assert!(
            Uuid::parse_str(&selector).is_ok(),
            "selector must be a UUID"
        );
        assert!(
            decode_exact(&challenge, CHALLENGE_LEN).is_some(),
            "challenge must be 32 bytes of base64"
        );

        let row = load_live_challenge(&pool, &selector, VAULT_ID)
            .await
            .expect("row stored");
        assert_eq!(row.vault_id, VAULT_ID);
        assert_eq!(row.challenge, challenge);
        assert_eq!(
            row.challenge_hash,
            challenge_hash(VAULT_ID, &challenge),
            "integrity hash must match"
        );
    }

    #[actix_web::test]
    async fn challenge_refuses_unknown_and_unrecoverable_vaults_identically() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        // A vault whose recovery columns are explicitly NULL.
        let am = vault::ActiveModel {
            id: Set(OTHER_VAULT_ID.to_string()),
            vault: Set(b64_of(16, 0xA1)),
            vaultiv: Set(b64_of(12, 0xA2)),
            salt: Set(b64_of(16, 0xA3)),
            iterations: Set(60_000),
            vault_verifier: Set(b64_of(32, 0xA4)),
            version: Set(1),
            ..Default::default()
        };
        am.insert(&pool).await.expect("seed no-recovery vault");

        for id in [OTHER_VAULT_ID, "11111111-2222-4333-8444-555555555555"] {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/recovery/challenge")
                    .set_json(serde_json::json!({ "vault_id": id }))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::NOT_FOUND);
            let body: serde_json::Value = test::read_body_json(resp).await;
            assert_eq!(body["code"], "VAULT_NO_RECOVERY");
        }
    }

    #[actix_web::test]
    async fn challenge_caps_live_challenges_per_vault() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;

        // Mint well past the cap; the table must stay bounded against spam.
        for _ in 0..(MAX_LIVE_CHALLENGES_PER_VAULT as usize + 3) {
            issue_challenge!(&app, VAULT_ID);
        }

        let live = Challenges::find()
            .filter(rc::Column::VaultId.eq(VAULT_ID))
            .filter(rc::Column::ExpiresAt.gte(Utc::now()))
            .all(&pool)
            .await
            .expect("count");
        assert_eq!(live.len() as u64, MAX_LIVE_CHALLENGES_PER_VAULT);
    }

    #[actix_web::test]
    async fn challenge_rejects_non_canonical_vault_id() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;

        // Uppercase names the same UUID but not the canonical form stored, so it
        // must not be allowed to address the row.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/challenge")
                .set_json(serde_json::json!({ "vault_id": VAULT_ID.to_uppercase() }))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // --- unlock ------------------------------------------------------------

    #[actix_web::test]
    async fn unlock_releases_the_envelope_and_changes_nothing() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let before = seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/unlock")
                .set_json(unlock_body(VAULT_ID, &selector, &proof))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["recovery_wrap"], b64_of(48, 0xB3));
        assert_eq!(body["recovery_wrap_iv"], b64_of(12, 0xB4));
        assert_eq!(body["credential_version"], 0);

        // No vault row may move, and no session may be established.
        let after = load_vault(&pool, VAULT_ID).await;
        assert_eq!(before, after, "unlock must not modify the vault row");
    }

    #[actix_web::test]
    async fn unlock_does_not_consume_the_challenge() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        // The same (selector, proof) must work repeatedly: the rewrap needs it
        // after unlock already used it.
        for _ in 0..2 {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/recovery/unlock")
                    .set_json(unlock_body(VAULT_ID, &selector, &proof))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[actix_web::test]
    async fn unlock_failures_are_byte_identical() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let good = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);
        let bad = proof_for(&b64_of(32, 0xFF), VAULT_ID, &challenge);

        let cases = [
            // wrong proof
            unlock_body(VAULT_ID, &selector, &bad),
            // unknown selector
            unlock_body(
                VAULT_ID,
                "99999999-9999-4999-8999-999999999999",
                &good,
            ),
            // selector issued for a different vault
            unlock_body(OTHER_VAULT_ID, &selector, &good),
            // proof computed for a different vault id
            unlock_body(
                VAULT_ID,
                &selector,
                &proof_for(&b64_of(32, 0xB1), OTHER_VAULT_ID, &challenge),
            ),
            // proof computed for a different challenge
            unlock_body(
                VAULT_ID,
                &selector,
                &proof_for(&b64_of(32, 0xB1), VAULT_ID, "b3RoZXI="),
            ),
            // malformed proof (wrong length)
            unlock_body(VAULT_ID, &selector, "AAAA"),
        ];

        let mut bodies = Vec::new();
        for case in cases {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/recovery/unlock")
                    .set_json(case)
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
            bodies.push(test::read_body(resp).await);
        }

        // A caller must not be able to tell these apart — otherwise each one is
        // an oracle for vault existence, challenge liveness, or key correctness.
        for b in &bodies[1..] {
            assert_eq!(
                &bodies[0], b,
                "recovery failures must be indistinguishable"
            );
        }
        let parsed: serde_json::Value = serde_json::from_slice(&bodies[0]).unwrap();
        assert_eq!(parsed["code"], "AUTH_FAILED");
        assert_eq!(parsed["error_msg"], "Recovery failed. Check the recovery key.");
    }

    // --- rewrap ------------------------------------------------------------

    /// The central contract: the rewrap rotates the password credential and
    /// nothing else.
    #[actix_web::test]
    async fn rewrap_rotates_only_the_password_credential() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let before = seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &selector, &proof, 0))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["vault_id"], VAULT_ID);
        assert_eq!(body["crypto_version"], 2);
        assert_eq!(body["lock_epoch"], before.lock_epoch);

        let after = load_vault(&pool, VAULT_ID).await;

        // --- must change: the password credential -------------------------
        assert_eq!(after.salt, b64_of(16, 0xC1));
        assert_eq!(after.vault_verifier, b64_of(32, 0xC2));
        assert_eq!(after.vault_key_wrap.as_deref(), Some(&b64_of(48, 0xC3)[..]));
        assert_eq!(after.vault_key_wrap_iv.as_deref(), Some(&b64_of(12, 0xC4)[..]));
        assert_eq!(after.iterations, 60_000);
        assert_eq!(after.credential_version, 1);

        // --- must NOT change ----------------------------------------------
        // The vault key is unchanged, so the ciphertext is too.
        assert_eq!(after.vault, before.vault, "ciphertext must not change");
        assert_eq!(after.vaultiv, before.vaultiv, "ciphertext IV must not change");
        // `version` is the document CAS counter; bumping it would invalidate
        // every pending sync intent's base_version for no reason.
        assert_eq!(
            after.version, before.version,
            "document version must not change"
        );
        // No lock event occurred.
        assert_eq!(after.lock_epoch, before.lock_epoch);
        // Rule R1: the recovery path survives its own use.
        assert_eq!(after.recovery_verifier, before.recovery_verifier);
        assert_eq!(after.recovery_salt, before.recovery_salt);
        assert_eq!(after.recovery_wrap, before.recovery_wrap);
        assert_eq!(after.recovery_wrap_iv, before.recovery_wrap_iv);
        assert_eq!(after.recovery_created_at, before.recovery_created_at);
    }

    /// Rule R1, end to end: after a recovery has rotated the password, the
    /// *same* recovery key must still authenticate. If this fails the design is
    /// broken rather than merely buggy — recovery would destroy itself.
    #[actix_web::test]
    async fn recovery_still_works_after_a_recovery() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;

        for round in 0..2i32 {
            let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
            let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/recovery/rewrap")
                    .set_json(rewrap_body(VAULT_ID, &selector, &proof, round))
                    .to_request(),
            )
            .await;
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "round {round}: the same recovery key must keep working"
            );
            assert_eq!(
                load_vault(&pool, VAULT_ID).await.credential_version,
                round + 1
            );
        }
    }

    #[actix_web::test]
    async fn rewrap_consumes_the_challenge_exactly_once() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        let first = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &selector, &proof, 0))
                .to_request(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        // Replay the identical request. Sending credential_version 0 again
        // isolates this from the CAS check, so the only thing that can reject it
        // is the consumed selector.
        let second = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &selector, &proof, 0))
                .to_request(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(second).await;
        assert_eq!(body["code"], "AUTH_FAILED");
        assert_eq!(load_vault(&pool, VAULT_ID).await.credential_version, 1);
    }

    #[actix_web::test]
    async fn rewrap_rejects_an_expired_challenge() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let before = seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        // Age the row past its TTL rather than sleeping through it.
        let expired = Utc::now() - chrono::Duration::seconds(CHALLENGE_TTL_SECS + 60);
        Challenges::update_many()
            .col_expr(rc::Column::ExpiresAt, Expr::value(expired))
            .filter(rc::Column::Selector.eq(&selector))
            .exec(&pool)
            .await
            .expect("age challenge");

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &selector, &proof, 0))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(load_vault(&pool, VAULT_ID).await, before);
    }

    /// Two devices racing a recovery: each holds its own challenge, both were
    /// issued against credential_version 0. Exactly one may win.
    #[actix_web::test]
    async fn rewrap_rejects_a_stale_credential_version() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let before = seed_vault(&pool, VAULT_ID).await;

        let (sel_a, ch_a) = issue_challenge!(&app, VAULT_ID);
        let (sel_b, ch_b) = issue_challenge!(&app, VAULT_ID);
        let proof_a = proof_for(&b64_of(32, 0xB1), VAULT_ID, &ch_a);
        let proof_b = proof_for(&b64_of(32, 0xB1), VAULT_ID, &ch_b);

        let first = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &sel_a, &proof_a, 0))
                .to_request(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        let second = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &sel_b, &proof_b, 0))
                .to_request(),
        )
        .await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = test::read_body_json(second).await;
        assert_eq!(body["code"], "CREDENTIAL_STALE");

        // The loser overwrote nothing.
        let after = load_vault(&pool, VAULT_ID).await;
        assert_eq!(after.credential_version, 1);
        assert_ne!(after.salt, before.salt);
        assert_eq!(after.salt, b64_of(16, 0xC1));
        assert_eq!(after.vault, before.vault);
    }

    #[actix_web::test]
    async fn rewrap_rejects_malformed_bodies_before_mutating() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let before = seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        let mut cases: Vec<(&str, serde_json::Value)> = Vec::new();

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["new_salt"] = serde_json::Value::String(b64_of(8, 0xC1));
        cases.push(("new_salt wrong length", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["new_vault_key_wrap_iv"] = serde_json::Value::String(b64_of(8, 0xC4));
        cases.push(("wrap iv wrong length", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["new_vault_key_wrap"] = serde_json::Value::String(b64_of(32, 0xC3));
        cases.push(("wrap wrong length", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["new_vault_verifier"] = serde_json::Value::String(b64_of(16, 0xC2));
        cases.push(("verifier wrong length", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["new_salt"] = serde_json::Value::String("not base64!!".to_string());
        cases.push(("new_salt not base64", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["new_iterations"] = serde_json::Value::from(1_000);
        cases.push(("iterations below floor", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["new_iterations"] = serde_json::Value::from(50_000_000);
        cases.push(("iterations above ceiling", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["credential_version"] = serde_json::Value::from(-1);
        cases.push(("negative credential_version", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["vault_id"] = serde_json::Value::String("not-a-uuid".to_string());
        cases.push(("malformed vault_id", c));

        let mut c = rewrap_body(VAULT_ID, &selector, &proof, 0);
        c["proof"] = serde_json::Value::String(b64_of(32, 0xEE));
        cases.push(("wrong proof", c));

        for (name, body) in cases {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/recovery/rewrap")
                    .set_json(body)
                    .to_request(),
            )
            .await;
            assert!(
                resp.status().is_client_error(),
                "{name} must be rejected, got {}",
                resp.status()
            );
            assert_eq!(
                load_vault(&pool, VAULT_ID).await,
                before,
                "{name} mutated the vault"
            );
        }

        // Every one of those rolled back — including the wrong-proof case — so
        // the challenge is still live and a corrected request still succeeds.
        // Undoing the burn on failure is deliberate: the proof is a 256-bit MAC,
        // so unlimited attempts against one challenge are not a brute-force
        // surface, and it lets a user who mistyped their recovery key simply
        // try again instead of re-requesting a challenge.
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &selector, &proof, 0))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[actix_web::test]
    async fn rewrap_establishes_a_session_for_the_recovered_vault() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &selector, &proof, 0))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let cookie = resp
            .response()
            .cookies()
            .next()
            .expect("session cookie")
            .clone();

        let req = test::TestRequest::get()
            .uri("/session")
            .cookie(cookie)
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["vault_id"], VAULT_ID);
    }

    /// The rewrap installs a v2-shaped credential, so a vault still on v1 is
    /// refused rather than half-migrated.
    ///
    /// ASSUMPTION (§5.6 lists "enforce a crypto_version of exactly 2" among the
    /// *input* bounds, but the request body carries no crypto_version): the
    /// constraint is read as applying to the stored vault, and the row is left
    /// untouched so a v1 vault can still be migrated by its normal path.
    #[actix_web::test]
    async fn rewrap_rejects_a_vault_on_a_non_v2_crypto_version() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;
        Vaults::update_many()
            .col_expr(vault::Column::CryptoVersion, Expr::value(1))
            .filter(vault::Column::Id.eq(VAULT_ID))
            .exec(&pool)
            .await
            .expect("downgrade");
        let before = load_vault(&pool, VAULT_ID).await;

        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/rewrap")
                .set_json(rewrap_body(VAULT_ID, &selector, &proof, 0))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "UNSUPPORTED_CRYPTO_VERSION");
        assert_eq!(load_vault(&pool, VAULT_ID).await, before);
    }

    /// A challenge issued for one vault must not open another, even with a proof
    /// correctly computed for that other vault. The vault id is inside the MAC,
    /// but the stored row is checked too — defence in depth on the binding.
    #[actix_web::test]
    async fn a_challenge_cannot_be_replayed_against_another_vault() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;
        seed_vault(&pool, OTHER_VAULT_ID).await;

        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof_for_other = proof_for(&b64_of(32, 0xB1), OTHER_VAULT_ID, &challenge);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/unlock")
                .set_json(unlock_body(OTHER_VAULT_ID, &selector, &proof_for_other))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let other = load_vault(&pool, OTHER_VAULT_ID).await;
        assert_eq!(other.recovery_wrap, Some(b64_of(48, 0xB3)));
    }

    #[actix_web::test]
    async fn constant_time_eq_matches_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        // Length mismatch is a mismatch, not a prefix match.
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }

    // --- hardening: throttle + sweeping -----------------------------------

    // `#[test]` is shadowed in this module by `use actix_web::test`, so these
    // use the same async test attribute as the rest of the suite.
    #[actix_web::test]
    async fn throttle_spends_a_budget_then_refuses() {
        let t = ChallengeThrottle::new(3, 60);
        assert!(t.allow("1.2.3.4"));
        assert!(t.allow("1.2.3.4"));
        assert!(t.allow("1.2.3.4"));
        // Budget spent for this address.
        assert!(!t.allow("1.2.3.4"));
        assert!(!t.allow("1.2.3.4"));
        // ...but only for this address.
        assert!(t.allow("5.6.7.8"));
    }

    #[actix_web::test]
    async fn throttle_window_resets_the_budget() {
        let t = ChallengeThrottle::new(2, 0);
        // A zero-second window is already elapsed on the first call, so it resets
        // every time and the budget can never be exhausted.
        for _ in 0..5 {
            assert!(t.allow("1.2.3.4"));
        }

        // With a real window the budget is spent...
        let t = ChallengeThrottle::new(2, 1);
        assert!(t.allow("9.9.9.9"));
        assert!(t.allow("9.9.9.9"));
        assert!(!t.allow("9.9.9.9"));
        // ...and recovers once the window has passed.
        actix_web::rt::time::sleep(std::time::Duration::from_millis(1_100)).await;
        assert!(t.allow("9.9.9.9"));
    }

    #[actix_web::test]
    async fn challenge_is_rate_limited_per_ip() {
        let pool = test_pool().await;
        // Budget of 2 for this test's own app instance.
        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .app_data(crate::endpoints::json_config())
                .app_data(web::Data::new(ChallengeThrottle::new(2, 60)))
                .service(super::recovery_challenge),
        )
        .await;
        seed_vault(&pool, VAULT_ID).await;

        let mut statuses = Vec::new();
        for _ in 0..4 {
            let resp = test::call_service(
                &app,
                test::TestRequest::post()
                    .uri("/recovery/challenge")
                    .set_json(serde_json::json!({ "vault_id": VAULT_ID }))
                    .to_request(),
            )
            .await;
            statuses.push(resp.status());
        }

        assert_eq!(
            statuses,
            vec![
                StatusCode::OK,
                StatusCode::OK,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::TOO_MANY_REQUESTS
            ]
        );

        // The rate limit must not have written rows beyond the budget.
        let rows = Challenges::find()
            .filter(rc::Column::VaultId.eq(VAULT_ID))
            .all(&pool)
            .await
            .expect("count");
        assert_eq!(rows.len(), 2);
    }

    #[actix_web::test]
    async fn expired_challenges_are_swept_on_insert() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;

        // Plant a stale row directly.
        let am = rc::ActiveModel {
            selector: Set("11111111-1111-4111-8111-111111111111".to_string()),
            vault_id: Set(VAULT_ID.to_string()),
            challenge: Set(b64_of(CHALLENGE_LEN, 0x01)),
            challenge_hash: Set("00".to_string()),
            created_at: Set(Utc::now() - chrono::Duration::hours(2)),
            expires_at: Set(Utc::now() - chrono::Duration::hours(1)),
        };
        am.insert(&pool).await.expect("plant stale row");

        issue_challenge!(&app, VAULT_ID);

        let rows = Challenges::find()
            .filter(rc::Column::VaultId.eq(VAULT_ID))
            .all(&pool)
            .await
            .expect("count");
        assert_eq!(rows.len(), 1, "the expired row must be gone");
    }

    #[actix_web::test]
    async fn startup_prune_clears_expired_rows_across_all_vaults() {
        let pool = test_pool().await;
        seed_vault(&pool, VAULT_ID).await;
        seed_vault(&pool, OTHER_VAULT_ID).await;

        for (i, vid) in [VAULT_ID, OTHER_VAULT_ID].iter().enumerate() {
            let am = rc::ActiveModel {
                selector: Set(format!("2222{i}2222-2222-4222-8222-222222222222")),
                vault_id: Set(vid.to_string()),
                challenge: Set(b64_of(CHALLENGE_LEN, 0x02)),
                challenge_hash: Set("00".to_string()),
                created_at: Set(Utc::now() - chrono::Duration::hours(2)),
                expires_at: Set(Utc::now() - chrono::Duration::hours(1)),
            };
            am.insert(&pool).await.expect("plant stale row");
        }

        super::prune_expired_challenges(&pool).await;

        let rows = Challenges::find().all(&pool).await.expect("count");
        assert_eq!(rows.len(), 0, "startup prune must clear every vault");
    }

    // --- regenerate -------------------------------------------------------

    /// Registers through the real endpoint so the test holds a session cookie to
    /// replay — regenerate is the one recovery endpoint that requires one.
    /// Evaluates to the cookie. A macro rather than a helper fn because naming
    /// the service's request type would require depending on actix-service.
    macro_rules! seed_with_session {
        ($app:expr) => {{
            let resp = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/register")
                    .set_json(serde_json::json!({
                        "vault_id": VAULT_ID,
                        "vault_verifier": b64_of(32, 0xA4),
                        "salt": b64_of(16, 0xA3),
                        "iterations": 60000,
                        "vaultiv": b64_of(12, 0xA2),
                        "vault": b64_of(16, 0xA1),
                        "crypto_version": 2,
                        "vault_key_wrap": b64_of(48, 0xA5),
                        "vault_key_wrap_iv": b64_of(12, 0xA6),
                        "recovery_verifier": b64_of(32, 0xB1),
                        "recovery_salt": b64_of(16, 0xB2),
                        "recovery_wrap": b64_of(48, 0xB3),
                        "recovery_wrap_iv": b64_of(12, 0xB4),
                    }))
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            resp.response()
                .cookies()
                .find(|c| c.name() == "voult_session")
                .expect("session cookie")
                .clone()
                .into_owned()
        }};
    }

    fn regenerate_body(vault_id: &str, selector: &str, proof: &str) -> serde_json::Value {
        serde_json::json!({
            "vault_id": vault_id,
            "selector": selector,
            "proof": proof,
            "new_recovery_verifier": b64_of(32, 0xD1),
            "new_recovery_salt": b64_of(16, 0xD2),
            "new_recovery_wrap": b64_of(48, 0xD3),
            "new_recovery_wrap_iv": b64_of(12, 0xD4),
        })
    }

    #[actix_web::test]
    async fn regenerate_rotates_only_the_recovery_material() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed_with_session!(&app);
        let before = load_vault(&pool, VAULT_ID).await;

        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/regenerate")
                .cookie(cookie.clone())
                .set_json(regenerate_body(VAULT_ID, &selector, &proof))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let after = load_vault(&pool, VAULT_ID).await;

        // Changed: only the recovery material.
        assert_eq!(after.recovery_verifier.as_deref(), Some(&b64_of(32, 0xD1)[..]));
        assert_eq!(after.recovery_salt.as_deref(), Some(&b64_of(16, 0xD2)[..]));
        assert_eq!(after.recovery_wrap.as_deref(), Some(&b64_of(48, 0xD3)[..]));
        assert_eq!(after.recovery_wrap_iv.as_deref(), Some(&b64_of(12, 0xD4)[..]));

        // Untouched: the password credential, the document, and the counter.
        // `credential_version` tracks the *password* credential, which a
        // recovery rotation does not touch.
        assert_eq!(after.salt, before.salt);
        assert_eq!(after.iterations, before.iterations);
        assert_eq!(after.vault_verifier, before.vault_verifier);
        assert_eq!(after.vault_key_wrap, before.vault_key_wrap);
        assert_eq!(after.vault_key_wrap_iv, before.vault_key_wrap_iv);
        assert_eq!(after.credential_version, before.credential_version);
        assert_eq!(after.vault, before.vault);
        assert_eq!(after.vaultiv, before.vaultiv);
        assert_eq!(after.version, before.version);
        assert_eq!(after.lock_epoch, before.lock_epoch);
    }

    #[actix_web::test]
    async fn regenerate_requires_a_session() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        seed_vault(&pool, VAULT_ID).await;
        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/regenerate")
                .set_json(regenerate_body(VAULT_ID, &selector, &proof))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "SESSION_REQUIRED");
        assert_eq!(
            load_vault(&pool, VAULT_ID).await.recovery_verifier,
            Some(b64_of(32, 0xB1))
        );
    }

    /// The session decides which vault is rotated, not the body.
    #[actix_web::test]
    async fn regenerate_refuses_a_vault_other_than_the_sessions() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed_with_session!(&app);
        seed_vault(&pool, OTHER_VAULT_ID).await;
        let before = load_vault(&pool, OTHER_VAULT_ID).await;

        let (selector, challenge) = issue_challenge!(&app, OTHER_VAULT_ID);
        let proof = proof_for(b64_of(32, 0xB1), OTHER_VAULT_ID, &challenge);

        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/regenerate")
                .cookie(cookie)
                .set_json(regenerate_body(OTHER_VAULT_ID, &selector, &proof))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "VAULT_MISMATCH");
        assert_eq!(load_vault(&pool, OTHER_VAULT_ID).await, before);
    }

    /// After a rotation the OLD key must stop working and the NEW one must take
    /// over — otherwise rotation would not actually revoke a stolen paper copy.
    #[actix_web::test]
    async fn after_rotation_the_old_key_is_rejected_and_the_new_one_works() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed_with_session!(&app);

        let (selector, challenge) = issue_challenge!(&app, VAULT_ID);
        let old_proof = proof_for(&b64_of(32, 0xB1), VAULT_ID, &challenge);
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/regenerate")
                .cookie(cookie.clone())
                .set_json(regenerate_body(VAULT_ID, &selector, &old_proof))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // The old key can no longer open anything.
        let (sel2, ch2) = issue_challenge!(&app, VAULT_ID);
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/unlock")
                .set_json(unlock_body(VAULT_ID, &sel2, &old_proof))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // The new key can.
        let new_proof = proof_for(b64_of(32, 0xD1), VAULT_ID, &ch2);
        let resp = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/unlock")
                .set_json(unlock_body(VAULT_ID, &sel2, &new_proof))
                .to_request(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["recovery_wrap"], b64_of(48, 0xD3));
    }

    /// Two rotations racing: the CAS is on the recovery verifier the caller
    /// proved against, so exactly one can win.
    #[actix_web::test]
    async fn a_second_rotation_with_the_superseded_key_conflicts() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed_with_session!(&app);

        let (sel_a, ch_a) = issue_challenge!(&app, VAULT_ID);
        let proof_a = proof_for(b64_of(32, 0xB1), VAULT_ID, &ch_a);
        let first = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/regenerate")
                .cookie(cookie.clone())
                .set_json(regenerate_body(VAULT_ID, &sel_a, &proof_a))
                .to_request(),
        )
        .await;
        assert_eq!(first.status(), StatusCode::OK);

        // The second was proved against the now-superseded verifier, so it
        // cannot even verify — and must certainly not overwrite.
        let (sel_b, ch_b) = issue_challenge!(&app, VAULT_ID);
        let proof_b = proof_for(b64_of(32, 0xB1), VAULT_ID, &ch_b);
        let second = test::call_service(
            &app,
            test::TestRequest::post()
                .uri("/recovery/regenerate")
                .cookie(cookie)
                .set_json(regenerate_body(VAULT_ID, &sel_b, &proof_b))
                .to_request(),
        )
        .await;
        assert!(
            second.status().is_client_error(),
            "a superseded key must not rotate again, got {}",
            second.status()
        );
        assert_eq!(
            load_vault(&pool, VAULT_ID).await.recovery_verifier,
            Some(b64_of(32, 0xD1)),
            "the winning rotation must stand"
        );
    }
}