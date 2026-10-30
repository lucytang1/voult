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
pub mod update_vault_password;
pub mod validate;
pub mod vaults;

use actix_web::error::JsonPayloadError;
use actix_web::{HttpResponse, http::StatusCode, web};

use validate::MAX_JSON_BODY_BYTES;

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
///
/// The body limit is explicit here rather than inherited from Actix's 2 MiB
/// default: `MAX_JSON_BODY_BYTES` is sized from the largest legitimate request
/// (a maximum-size backup package, base64-encoded for upload), and an implicit
/// transport default is what silently capped vaults at ~1.5 MiB before.
pub fn json_config() -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(MAX_JSON_BODY_BYTES)
        .error_handler(|err, _req| {
            let (status, code, msg): (StatusCode, &str, String) = match &err {
                // Distinguish "too large" from "malformed" so body-size limits stay
                // distinguishable from validation failures.
                JsonPayloadError::OverflowKnownLength { .. }
                | JsonPayloadError::Overflow { .. } => (
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{App, post, test};

    /// A service that only exists to prove the extractor accepted the body.
    #[post("/echo")]
    async fn echo(body: web::Json<serde_json::Value>) -> HttpResponse {
        HttpResponse::Ok().json(body.into_inner())
    }

    fn app_config(cfg: &mut web::ServiceConfig) {
        cfg.app_data(json_config()).service(echo);
    }

    fn body_of(size: usize) -> String {
        // `size` counts body bytes. `{"blob":"` is 9 bytes and `"}` is 2, so
        // the padding is `size - 11` — the test must be exact, or it proves
        // nothing about the cap.
        format!("{{\"blob\":\"{}\"}}", "x".repeat(size - 11))
    }

    #[actix_web::test]
    async fn body_limit_is_explicit_and_uses_the_documented_envelope() {
        let app = test::init_service(App::new().configure(app_config)).await;

        let over = test::TestRequest::post()
            .uri("/echo")
            .insert_header(("content-type", "application/json"))
            .set_payload(body_of(MAX_JSON_BODY_BYTES + 1))
            .to_request();
        let resp = test::call_service(&app, over).await;
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body: serde_json::Value = test::read_body_json(resp).await;
        assert_eq!(body["code"], "PAYLOAD_TOO_LARGE");

        // One byte under the cap must still reach the handler: the limit is a
        // backstop for absurd bodies, not a second field cap.
        let under = test::TestRequest::post()
            .uri("/echo")
            .insert_header(("content-type", "application/json"))
            .set_payload(body_of(MAX_JSON_BODY_BYTES - 1))
            .to_request();
        let resp = test::call_service(&app, under).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
