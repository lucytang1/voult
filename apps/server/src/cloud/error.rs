use serde::Serialize;

/// Provider-neutral error categories per spec §4.3
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum ProviderErrorKind {
    #[serde(rename = "PROVIDER_AUTH_REQUIRED")]
    AuthRequired,
    /// Reserved for a provider that can tell "this file belongs to a different
    /// account" from a generic permission failure. Never constructed yet;
    /// removing it would change the wire vocabulary, so it stays.
    #[allow(dead_code)]
    #[serde(rename = "PROVIDER_WRONG_ACCOUNT")]
    WrongAccount,
    #[serde(rename = "PROVIDER_PERMISSION_DENIED")]
    PermissionDenied,
    #[serde(rename = "REMOTE_CONFLICT")]
    RemoteConflict,
    /// The provider reported no usable revision token for the file, so there is
    /// nothing safe to condition a conditional write on. Distinct from
    /// `RemoteConflict`: nothing *changed*, we simply cannot prove what is there.
    /// Treated as "refuse", never as "matches anything".
    #[serde(rename = "REMOTE_REVISION_UNAVAILABLE")]
    RemoteRevisionUnavailable,
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
            // Only ever produced inside the mirror, never by a route, so this arm
            // exists to keep the mapping total rather than to be reached.
            ProviderErrorKind::RemoteRevisionUnavailable => actix_web::http::StatusCode::CONFLICT,
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
            ProviderErrorKind::RemoteRevisionUnavailable => "REMOTE_REVISION_UNAVAILABLE",
            ProviderErrorKind::RemoteUnavailable => "REMOTE_UNAVAILABLE",
            ProviderErrorKind::RemoteDeleted => "REMOTE_DELETED",
            ProviderErrorKind::VaultNotFound => "VAULT_NOT_FOUND",
            ProviderErrorKind::PackageInvalid => "PACKAGE_INVALID",
            ProviderErrorKind::RateLimited => "PROVIDER_RATE_LIMITED",
            ProviderErrorKind::Unknown => "UNKNOWN",
        }
    }
}

/// A provider failure: a neutral category plus a provider-specific detail.
///
/// The *kind* is what callers branch on; the *message* is for logs and
/// diagnostics only. Callers must not switch on the message, and it must never
/// be echoed verbatim to a client, because provider error bodies can carry
/// account or file metadata.
///
/// Invariant for the message: it contains only first-party text — fixed
/// strings, HTTP statuses, and database errors — never a provider response
/// body. That is what makes `Display`/`detail()` safe to write to a server log.
/// It still must never be put in a browser-visible redirect or response body;
/// use [`ProviderError::redacted_detail`] for that.
#[derive(Debug, Clone)]
pub struct ProviderError {
    pub kind: ProviderErrorKind,
    message: String,
}

impl ProviderError {
    /// Build from a neutral kind plus a diagnostic message.
    pub fn new(kind: ProviderErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// The message, for server logs. Never send this to a client.
    pub fn detail(&self) -> &str {
        &self.message
    }

    /// A client-safe replacement for the message. Every provider gets the same
    /// generic text so the response cannot leak provider internals — the kind
    /// already tells the client everything it needs to act on.
    pub fn redacted_detail(&self) -> &str {
        "provider request failed"
    }

    /// The stable machine code, persisted in `cloud_binding.last_mirror_error`
    /// and surfaced to the client as `code`.
    pub fn code(&self) -> &'static str {
        self.kind.code()
    }
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.kind.code(), self.message)
    }
}

impl std::error::Error for ProviderError {}

impl From<ProviderErrorKind> for ProviderError {
    fn from(kind: ProviderErrorKind) -> Self {
        let code = kind.code();
        Self::new(kind, code)
    }
}

impl ProviderError {
    /// Render as an HTTP response.
    ///
    /// Takes `self` so the kind can be moved into the response while the message
    /// is reduced to the generic text, which also guarantees the
    /// provider-specific detail is dropped rather than accidentally forwarded.
    pub fn into_response(self) -> actix_web::HttpResponse {
        let detail = self.redacted_detail().to_string();
        provider_error_response(self.kind, &detail)
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
