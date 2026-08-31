use serde::Serialize;

/// Provider-neutral error categories per spec §4.3
#[derive(Debug, Clone, Serialize)]
pub enum ProviderErrorKind {
    #[serde(rename = "PROVIDER_AUTH_REQUIRED")]
    AuthRequired,
    #[serde(rename = "PROVIDER_WRONG_ACCOUNT")]
    WrongAccount,
    #[serde(rename = "PROVIDER_PERMISSION_DENIED")]
    PermissionDenied,
    #[serde(rename = "REMOTE_CONFLICT")]
    RemoteConflict,
    #[serde(rename = "REMOTE_UNAVAILABLE")]
    RemoteUnavailable,
    #[serde(rename = "REMOTE_DELETED")]
    RemoteDeleted,
    #[serde(rename = "VAULT_NOT_FOUND")]
    VaultNotFound,
    #[serde(rename = "PACKAGE_INVALID")]
    PackageInvalid,
    #[serde(rename = "PROVIDER_RATE_LIMITED")]
    RateLimited,
    #[serde(rename = "UNKNOWN")]
    Unknown,
}

impl ProviderErrorKind {
    pub fn http_status(&self) -> actix_web::http::StatusCode {
        match self {
            ProviderErrorKind::AuthRequired => actix_web::http::StatusCode::UNAUTHORIZED,
            ProviderErrorKind::WrongAccount => actix_web::http::StatusCode::FORBIDDEN,
            ProviderErrorKind::PermissionDenied => actix_web::http::StatusCode::FORBIDDEN,
            ProviderErrorKind::RemoteConflict => actix_web::http::StatusCode::CONFLICT,
            ProviderErrorKind::RemoteUnavailable => actix_web::http::StatusCode::BAD_GATEWAY,
            ProviderErrorKind::RemoteDeleted => actix_web::http::StatusCode::NOT_FOUND,
            ProviderErrorKind::VaultNotFound => actix_web::http::StatusCode::NOT_FOUND,
            ProviderErrorKind::PackageInvalid => actix_web::http::StatusCode::UNPROCESSABLE_ENTITY,
            ProviderErrorKind::RateLimited => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
            ProviderErrorKind::Unknown => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    pub fn code(&self) -> &'static str {
        match self {
            ProviderErrorKind::AuthRequired => "PROVIDER_AUTH_REQUIRED",
            ProviderErrorKind::WrongAccount => "PROVIDER_WRONG_ACCOUNT",
            ProviderErrorKind::PermissionDenied => "PROVIDER_PERMISSION_DENIED",
            ProviderErrorKind::RemoteConflict => "REMOTE_CONFLICT",
            ProviderErrorKind::RemoteUnavailable => "REMOTE_UNAVAILABLE",
            ProviderErrorKind::RemoteDeleted => "REMOTE_DELETED",
            ProviderErrorKind::VaultNotFound => "VAULT_NOT_FOUND",
            ProviderErrorKind::PackageInvalid => "PACKAGE_INVALID",
            ProviderErrorKind::RateLimited => "PROVIDER_RATE_LIMITED",
            ProviderErrorKind::Unknown => "UNKNOWN",
        }
    }
}

pub fn map_google_http_error(status: reqwest::StatusCode, body: &str) -> ProviderErrorKind {
    match status.as_u16() {
        401 => ProviderErrorKind::AuthRequired,
        403 => {
            if body.contains("rateLimitExceeded") || body.contains("userRateLimitExceeded") {
                ProviderErrorKind::RateLimited
            } else if body.contains("insufficientPermissions") || body.contains("accessNotConfigured") {
                ProviderErrorKind::PermissionDenied
            } else {
                ProviderErrorKind::PermissionDenied
            }
        }
        404 => ProviderErrorKind::RemoteDeleted,
        409 => ProviderErrorKind::RemoteConflict,
        412 => ProviderErrorKind::RemoteConflict, // precondition failed
        429 => ProviderErrorKind::RateLimited,
        500..=599 => ProviderErrorKind::RemoteUnavailable,
        _ => ProviderErrorKind::Unknown,
    }
}

#[derive(Serialize)]
pub struct ProviderErrorResponse {
    pub error_msg: String,
    pub code: &'static str,
}

pub fn provider_error_response(kind: ProviderErrorKind, msg: &str) -> actix_web::HttpResponse {
    let status = kind.http_status();
    let code = kind.code();
    actix_web::HttpResponse::build(status).json(ProviderErrorResponse {
        error_msg: msg.to_string(),
        code,
    })
}
