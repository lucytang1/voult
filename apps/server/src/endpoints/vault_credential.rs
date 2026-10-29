//! `POST /api/vault/credential` — the only write that changes a password
//! credential.
//!
//! The client derives the new credential entirely locally: a fresh salt, a new
//! KDF profile, the verifier and a fresh AES-GCM wrap of the SAME `vaultKeyRaw`.
//! It sends only those public/ciphertext values — never the password, the vault
//! key, or any derived key.
//!
//! Three guards:
//!   * the vault id comes from the session, never the body;
//!   * `current_vault_verifier` proves the caller knows the existing password
//!     credential, so a stolen cookie alone cannot replace it;
//!   * `credential_version` is a compare-and-swap counter, so two concurrent
//!     rotations (or a recovery) cannot both win.
//!
//! The write must NOT touch `vault`, `vaultiv`, `version`, `recovery_*` or
//! `lock_epoch`. Rule R1: the recovery envelope wraps `vaultKeyRaw` directly, so
//! rotating the password leaves recovery intact.

use actix_session::Session;
use actix_web::{HttpResponse, http::StatusCode, post, web};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, ExprTrait, QueryFilter};
use serde::{Deserialize, Serialize};

use crate::db::DbPool;
use crate::entity::vault::{self, Entity as Vaults};
use crate::error::{error_response, session_required};
use crate::kdf::KdfParams;
use crate::session_auth::session_vault_id;

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Auth);

/// Exact byte lengths the client is required to produce. Validated before any
/// DB work so a malformed body cannot reach the vault row.
const SALT_LEN: usize = 16;
const IV_LEN: usize = 12;
/// 32-byte vault key + 16-byte GCM tag.
const WRAP_LEN: usize = 48;
const VERIFIER_LEN: usize = 32;

#[derive(Deserialize)]
pub struct RotateCredentialRequest {
    /// The current `vault_verifier`, base64. A reauthentication proof, not an
    /// identity: it proves the caller can derive the existing credential.
    pub current_vault_verifier: String,
    /// The `credential_version` the client observed. CAS guard.
    pub credential_version: i32,
    pub new_salt: String,
    pub new_kdf: KdfParams,
    pub new_vault_verifier: String,
    pub new_vault_key_wrap: String,
    pub new_vault_key_wrap_iv: String,
}

#[derive(Serialize)]
pub struct RotateCredentialResponse {
    pub vault_id: String,
    /// The value after this write (observed + 1).
    pub credential_version: i32,
    pub kdf: KdfParams,
    pub lock_epoch: i32,
}

/// Decodes a base64 field and requires an exact byte length.
fn decode_exact(value: &str, expected: usize) -> Option<Vec<u8>> {
    let bytes = BASE64.decode(value.trim()).ok()?;
    (bytes.len() == expected).then_some(bytes)
}

/// Length-independent comparison for two fixed-size credential values.
/// XOR-accumulate with no early exit; mirrors the client's `bytesEqual`.
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

#[post("/vault/credential")]
pub async fn rotate_credential(
    pool: web::Data<DbPool>,
    session: Session,
    payload: web::Json<RotateCredentialRequest>,
) -> HttpResponse {
    let vault_id = match session_vault_id(&session) {
        Ok(Some(id)) => id,
        _ => return session_required(),
    };
    let request = payload.into_inner();

    // --- Validate every input before touching the database. ---
    let Some(current_verifier) = decode_exact(&request.current_vault_verifier, VERIFIER_LEN) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "current_vault_verifier must be 32 bytes of base64",
            "INVALID_INPUT",
        );
    };
    let Some(new_salt) = decode_exact(&request.new_salt, SALT_LEN) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_salt must be 16 bytes of base64",
            "INVALID_INPUT",
        );
    };
    let Some(new_verifier) = decode_exact(&request.new_vault_verifier, VERIFIER_LEN) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_vault_verifier must be 32 bytes of base64",
            "INVALID_INPUT",
        );
    };
    // Paired or not at all: a half-written password envelope would leave the
    // vault unwrappable by any password.
    let Some(new_wrap) = decode_exact(&request.new_vault_key_wrap, WRAP_LEN) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_vault_key_wrap must be 48 bytes of base64",
            "INVALID_INPUT",
        );
    };
    let Some(new_wrap_iv) = decode_exact(&request.new_vault_key_wrap_iv, IV_LEN) else {
        return error_response(
            StatusCode::BAD_REQUEST,
            "new_vault_key_wrap_iv must be 12 bytes of base64",
            "INVALID_INPUT",
        );
    };
    if request.new_kdf.validate_for_write().is_err() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "unknown KDF profile",
            "KDF_UNKNOWN",
        );
    }
    if request.credential_version < 0 {
        return error_response(
            StatusCode::BAD_REQUEST,
            "invalid credential_version",
            "INVALID_INPUT",
        );
    }

    let vault = match Vaults::find()
        .filter(vault::Column::Id.eq(&vault_id))
        .one(pool.get_ref())
        .await
    {
        Ok(Some(vault)) => vault,
        Ok(None) => return session_required(),
        Err(e) => {
            LOG.error(
                format_args!("failed to fetch vault: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to fetch vault",
                "DB_ERROR",
            );
        }
    };

    // The rotation installs a v2-shaped credential (bounded KDF + wrapped vault
    // key), so it is only meaningful for a vault already on v2.
    if vault.crypto_version != 2 {
        return error_response(
            StatusCode::CONFLICT,
            "vault is not on crypto version 2",
            "UNSUPPORTED_CRYPTO_VERSION",
        );
    }

    // Stored metadata that does not parse is a server integrity bug. Compare it
    // as bytes so the verifier check is constant-time.
    let stored_kdf = match KdfParams::parse_stored(&vault.kdf) {
        Ok(kdf) => kdf,
        Err(_) => {
            LOG.error(
                format_args!("vault has an unparsable kdf column: {:?}", vault.id),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid vault metadata",
                "DATA_INTEGRITY_ERROR",
            );
        }
    };
    let Some(stored_verifier) = decode_exact(&vault.vault_verifier, VERIFIER_LEN) else {
        LOG.error(
            format_args!("vault has an invalid verifier: {:?}", vault.id),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid vault metadata",
            "DATA_INTEGRITY_ERROR",
        );
    };

    // Reauth proof. A cookie alone is not enough to replace the credential.
    if !constant_time_eq(&current_verifier, &stored_verifier) {
        LOG.warn(
            format_args!("credential rotation rejected: verifier mismatch vault_id={vault_id}"),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::UNAUTHORIZED,
            "invalid vault credential",
            "AUTH_FAILED",
        );
    }

    // No downgrades. Rank is a policy order over the published ladder.
    if request.new_kdf.rank() < stored_kdf.rank() {
        LOG.warn(
            format_args!(
                "credential rotation rejected: KDF downgrade {} -> {} vault_id={vault_id}",
                stored_kdf.describe(),
                request.new_kdf.describe()
            ),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::BAD_REQUEST,
            "KDF profile downgrade is not allowed",
            "KDF_DOWNGRADE",
        );
    }

    // Canonical base64, so the row cannot acquire a second spelling of the same
    // bytes (and the recovery/credential comparisons stay exact).
    let new_salt_b64 = BASE64.encode(&new_salt);
    let new_verifier_b64 = BASE64.encode(&new_verifier);
    let new_wrap_b64 = BASE64.encode(&new_wrap);
    let new_wrap_iv_b64 = BASE64.encode(&new_wrap_iv);
    let new_kdf_stored = request.new_kdf.to_stored();

    let update = Vaults::update_many()
        .col_expr(vault::Column::Salt, Expr::value(new_salt_b64))
        .col_expr(vault::Column::Kdf, Expr::value(new_kdf_stored))
        .col_expr(vault::Column::VaultVerifier, Expr::value(new_verifier_b64))
        .col_expr(vault::Column::VaultKeyWrap, Expr::value(new_wrap_b64))
        .col_expr(vault::Column::VaultKeyWrapIv, Expr::value(new_wrap_iv_b64))
        .col_expr(
            vault::Column::CredentialVersion,
            Expr::col(vault::Column::CredentialVersion).add(1),
        )
        .filter(vault::Column::Id.eq(&vault_id))
        .filter(vault::Column::CredentialVersion.eq(request.credential_version))
        .exec(pool.get_ref())
        .await;

    let rows_affected = match update {
        Ok(result) => result.rows_affected,
        Err(e) => {
            LOG.error(
                format_args!("failed to rotate vault credential: {:?}", e),
                logger::Metadata::new(),
            );
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "failed to rotate credential",
                "DB_ERROR",
            );
        }
    };

    if rows_affected == 0 {
        LOG.warn(
            format_args!("credential rotation rejected: stale version vault_id={vault_id}"),
            logger::Metadata::new(),
        );
        return error_response(
            StatusCode::CONFLICT,
            "credential was rotated elsewhere; refresh and retry",
            "CREDENTIAL_STALE",
        );
    }

    let new_credential_version = request.credential_version + 1;
    LOG.log(
        format_args!(
            "password credential rotated vault_id={vault_id} kdf={} credential_version={new_credential_version}",
            request.new_kdf.describe()
        ),
        logger::Metadata::new(),
    );

    HttpResponse::Ok().json(RotateCredentialResponse {
        vault_id,
        credential_version: new_credential_version,
        kdf: request.new_kdf,
        lock_epoch: vault.lock_epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::App;
    use actix_web::cookie::Key;
    use actix_web::http::header::SET_COOKIE;
    use actix_web::test;
    use migration::MigratorTrait;
    use sea_orm::{Database, EntityTrait};
    use serde_json::json;

    const VAULT_ID: &str = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";

    fn b64_of(len: usize, byte: u8) -> String {
        BASE64.encode(vec![byte; len])
    }

    async fn test_pool() -> DbPool {
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    /// Builds the app with the session middleware, the registration route (so a
    /// test can create a vault + session) and the rotation route.
    macro_rules! test_app {
        ($pool:expr) => {
            test::init_service(
                App::new()
                    .app_data(web::Data::new($pool.clone()))
                    .app_data(crate::endpoints::json_config())
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
                    .service(crate::endpoints::register::register)
                    .service(rotate_credential),
            )
            .await
        };
    }

    /// Registers a vault, asserts it succeeded, and returns the session cookie
    /// (`name=value`) so the following calls carry it. `test::call_service`
    /// does not maintain a cookie jar.
    macro_rules! seed {
        ($app:expr) => {{
            let resp = test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/register")
                    .set_json(register_body())
                    .to_request(),
            )
            .await;
            assert_eq!(resp.status(), StatusCode::CREATED);
            resp.headers()
                .get(SET_COOKIE)
                .expect("register sets a session cookie")
                .to_str()
                .expect("cookie is ascii")
                .split(';')
                .next()
                .expect("cookie pair")
                .to_string()
        }};
    }

    /// POSTs a rotation body with the session cookie attached.
    macro_rules! rotate {
        ($app:expr, $cookie:expr, $body:expr) => {
            test::call_service(
                &$app,
                test::TestRequest::post()
                    .uri("/vault/credential")
                    .insert_header(("Cookie", $cookie))
                    .set_json($body)
                    .to_request(),
            )
            .await
        };
    }

    fn register_body() -> serde_json::Value {
        json!({
            "vault_id": VAULT_ID,
            "vault_verifier": b64_of(32, 0xAA),
            "salt": b64_of(16, 0x01),
            "kdf": { "algorithm": "argon2id", "memory_kib": 19456, "time_cost": 2, "parallelism": 1 },
            "vaultiv": b64_of(12, 0x02),
            "vault": b64_of(64, 0x03),
            "crypto_version": 2,
            "vault_key_wrap": b64_of(48, 0x04),
            "vault_key_wrap_iv": b64_of(12, 0x05),
            "recovery_verifier": b64_of(32, 0x06),
            "recovery_salt": b64_of(16, 0x07),
            "recovery_wrap": b64_of(48, 0x08),
            "recovery_wrap_iv": b64_of(12, 0x09),
        })
    }

    fn rotate_body(credential_version: i32) -> serde_json::Value {
        json!({
            "current_vault_verifier": b64_of(32, 0xAA),
            "credential_version": credential_version,
            "new_salt": b64_of(16, 0x11),
            "new_kdf": { "algorithm": "argon2id", "memory_kib": 65536, "time_cost": 3, "parallelism": 1 },
            "new_vault_verifier": b64_of(32, 0x12),
            "new_vault_key_wrap": b64_of(48, 0x13),
            "new_vault_key_wrap_iv": b64_of(12, 0x14),
        })
    }

    async fn load(pool: &DbPool) -> vault::Model {
        Vaults::find()
            .filter(vault::Column::Id.eq(VAULT_ID))
            .one(pool)
            .await
            .expect("query")
            .expect("vault exists")
    }

    #[actix_web::test]
    async fn rotates_only_the_password_credential() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed!(app);
        let before = load(&pool).await;

        let resp = rotate!(app, cookie, rotate_body(0));
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["credential_version"], 1);
        assert_eq!(body["kdf"]["memory_kib"], 65_536);

        let after = load(&pool).await;
        // Changed: salt, profile, verifier, envelope, counter.
        assert_eq!(after.salt, b64_of(16, 0x11));
        assert_eq!(
            KdfParams::parse_stored(&after.kdf).expect("kdf parses"),
            KdfParams::ladder()[2]
        );
        assert_eq!(after.vault_verifier, b64_of(32, 0x12));
        assert_eq!(after.vault_key_wrap.as_deref(), Some(&b64_of(48, 0x13)[..]));
        assert_eq!(
            after.vault_key_wrap_iv.as_deref(),
            Some(&b64_of(12, 0x14)[..])
        );
        assert_eq!(after.credential_version, 1);

        // Untouched: the vault key, the document, recovery (Rule R1), epoch.
        assert_eq!(after.vault, before.vault);
        assert_eq!(after.vaultiv, before.vaultiv);
        assert_eq!(after.version, before.version);
        assert_eq!(after.recovery_verifier, before.recovery_verifier);
        assert_eq!(after.recovery_salt, before.recovery_salt);
        assert_eq!(after.recovery_wrap, before.recovery_wrap);
        assert_eq!(after.recovery_wrap_iv, before.recovery_wrap_iv);
        assert_eq!(after.lock_epoch, before.lock_epoch);
    }

    #[actix_web::test]
    async fn wrong_verifier_is_rejected_without_a_write() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed!(app);
        let before = load(&pool).await;

        let mut body = rotate_body(0);
        body["current_vault_verifier"] = json!(b64_of(32, 0xEE));
        let resp = rotate!(app, cookie, body);
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "AUTH_FAILED");

        let after = load(&pool).await;
        assert_eq!(after.kdf, before.kdf);
        assert_eq!(after.credential_version, before.credential_version);
        assert_eq!(after.vault_verifier, before.vault_verifier);
    }

    #[actix_web::test]
    async fn stale_version_is_a_conflict() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed!(app);

        let first = rotate!(app, cookie.clone(), rotate_body(0));
        assert_eq!(first.status(), StatusCode::OK);

        // Same observed version, same old verifier: the second attempt loses.
        // (The stored verifier already moved, so the reauth check fires first;
        // either 401 or 409 is a correct convergence signal for the client.)
        let second = rotate!(app, cookie, rotate_body(0));
        assert!(
            second.status() == StatusCode::UNAUTHORIZED || second.status() == StatusCode::CONFLICT,
            "unexpected status {}",
            second.status()
        );
        assert_eq!(load(&pool).await.credential_version, 1);
    }

    #[actix_web::test]
    async fn stale_credential_version_is_a_conflict() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed!(app);

        // Simulate another writer bumping the counter while the verifier stays
        // the same. The reauth proof still matches, so the CAS is the guard that
        // rejects this request.
        Vaults::update_many()
            .col_expr(vault::Column::CredentialVersion, Expr::value(1))
            .filter(vault::Column::Id.eq(VAULT_ID))
            .exec(&pool)
            .await
            .expect("bump version");

        let resp = rotate!(app, cookie, rotate_body(0));
        assert_eq!(resp.status(), StatusCode::CONFLICT);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "CREDENTIAL_STALE");

        let after = load(&pool).await;
        assert_eq!(after.credential_version, 1);
        assert_eq!(
            after.salt,
            b64_of(16, 0x01),
            "the losing write changed nothing"
        );
    }

    #[actix_web::test]
    async fn downgrade_is_rejected() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed!(app);

        // Move to the top rung first.
        let first = rotate!(app, cookie.clone(), rotate_body(0));
        assert_eq!(first.status(), StatusCode::OK);
        let before = load(&pool).await;

        // Try to install the floor with the *new* verifier as the reauth proof.
        let mut body = rotate_body(1);
        body["current_vault_verifier"] = json!(b64_of(32, 0x12));
        body["new_kdf"] = json!({
            "algorithm": "argon2id",
            "memory_kib": 19456,
            "time_cost": 2,
            "parallelism": 1
        });
        let resp = rotate!(app, cookie, body);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "KDF_DOWNGRADE");

        let after = load(&pool).await;
        assert_eq!(after.kdf, before.kdf);
        assert_eq!(after.credential_version, before.credential_version);
    }

    #[actix_web::test]
    async fn off_ladder_kdf_is_rejected() {
        let pool = test_pool().await;
        let app = test_app!(&pool);
        let cookie = seed!(app);

        let mut body = rotate_body(0);
        body["new_kdf"] = json!({
            "algorithm": "argon2id",
            "memory_kib": 19_457,
            "time_cost": 2,
            "parallelism": 1
        });
        let resp = rotate!(app, cookie, body);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "KDF_UNKNOWN");
    }
}
