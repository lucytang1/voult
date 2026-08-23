use actix_web::{HttpResponse, http::StatusCode};
use serde::Serialize;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error_msg: String,
    pub code: &'static str,
}

pub fn error_response(status: StatusCode, error_msg: &str, code: &'static str) -> HttpResponse {
    HttpResponse::build(status).json(ErrorResponse {
        error_msg: error_msg.to_string(),
        code,
    })
}

pub fn session_required() -> HttpResponse {
    error_response(
        StatusCode::UNAUTHORIZED,
        "session required",
        "SESSION_REQUIRED",
    )
}
