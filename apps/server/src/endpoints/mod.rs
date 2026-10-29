pub mod auth;
pub mod cloud_endpoints;
pub mod favicon;
pub mod get_crypto_params;
pub mod get_vault;
pub mod lock;
pub mod logout;
pub mod pair;
pub mod recovery;
pub mod register;
pub mod session_status;
pub mod update_vault;
pub mod vault_credential;
pub mod vaults;

use actix_web::error::JsonPayloadError;
use actix_web::{HttpResponse, http::StatusCode, web};

/// Shared `Json` extractor config.
///
/// By default Actix answers a body that fails to deserialize — a missing field,
/// a wrong type, malformed JSON — with a plain-text 400 that never reaches the
/// handler. That is inconsistent with every other error this API returns, all of
/// which are `{"error_msg", "code"}`, and it silently breaks clients that read
/// `error_msg` (the Expo client does, in `signup.tsx` and the recovery flow).
///
/// It matters most for the now-required recovery fields on vault creation:
/// without this, omitting `recovery_wrap` yields a 400 that carries no
/// `INVALID_INPUT` code, so the documented contract does not hold for the exact
/// case the contract is written about.
///
/// The extractor error text is derived from serde and names only request fields,
/// so it is safe to surface; it never contains submitted values.
pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default().error_handler(|err, _req| {
        let (status, code, msg): (StatusCode, &str, String) = match &err {
            // Distinguish "too large" from "malformed" so body-size limits stay
            // distinguishable from validation failures.
            JsonPayloadError::OverflowKnownLength { .. } | JsonPayloadError::Overflow { .. } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "PAYLOAD_TOO_LARGE",
                "request body too large".to_string(),
            ),
            _ => (StatusCode::BAD_REQUEST, "INVALID_INPUT", err.to_string()),
        };
        actix_web::error::InternalError::from_response(
            err,
            HttpResponse::build(status).json(serde_json::json!({
                "error_msg": msg,
                "code": code,
            })),
        )
        .into()
    })
}
