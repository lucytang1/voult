//! Google HTTP status → neutral `ProviderErrorKind`.
//!
//! Private to the Drive implementation: no caller outside
//! `providers/google_drive/` may map a Google status code, so a second
//! provider cannot accidentally inherit Drive's 403 sub-cases.

use crate::cloud::error::ProviderErrorKind;

pub(super) fn map_google_http_error(status: reqwest::StatusCode, body: &str) -> ProviderErrorKind {
    match status.as_u16() {
        401 => ProviderErrorKind::AuthRequired,
        403 => {
            if body.contains("rateLimitExceeded") || body.contains("userRateLimitExceeded") {
                ProviderErrorKind::RateLimited
            } else if body.contains("insufficientPermissions")
                || body.contains("accessNotConfigured")
            {
                ProviderErrorKind::PermissionDenied
            } else {
                ProviderErrorKind::PermissionDenied
            }
        }
        404 => ProviderErrorKind::RemoteDeleted,
        409 => ProviderErrorKind::RemoteConflict,
        // 412 precondition failed is the same refusal as 409 for our purposes:
        // the file is not where we left it.
        412 => ProviderErrorKind::RemoteConflict,
        429 => ProviderErrorKind::RateLimited,
        500..=599 => ProviderErrorKind::RemoteUnavailable,
        _ => ProviderErrorKind::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_and_deletion_are_distinguished() {
        // 401 means "reconnect", 404 means "the backup file is gone". Collapsing
        // them would send the user to the wrong fix.
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::UNAUTHORIZED, ""),
            ProviderErrorKind::AuthRequired
        );
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::NOT_FOUND, ""),
            ProviderErrorKind::RemoteDeleted
        );
    }

    /// A refusal must map to Conflict so the mirror records `conflict` and
    /// leaves the backup watermark untouched.
    #[test]
    fn precondition_failures_map_to_conflict() {
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::CONFLICT, ""),
            ProviderErrorKind::RemoteConflict
        );
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::PRECONDITION_FAILED, ""),
            ProviderErrorKind::RemoteConflict
        );
    }

    /// Rate limiting is distinguished from permission denial so the mirror can
    /// treat one as retryable and the other as a user action.
    #[test]
    fn rate_limits_are_not_permission_failures() {
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::FORBIDDEN, "rateLimitExceeded"),
            ProviderErrorKind::RateLimited
        );
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::FORBIDDEN, "insufficientPermissions"),
            ProviderErrorKind::PermissionDenied
        );
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::TOO_MANY_REQUESTS, ""),
            ProviderErrorKind::RateLimited
        );
    }

    #[test]
    fn server_errors_are_retryable_and_others_are_unknown() {
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::INTERNAL_SERVER_ERROR, ""),
            ProviderErrorKind::RemoteUnavailable
        );
        assert_eq!(
            map_google_http_error(reqwest::StatusCode::IM_A_TEAPOT, ""),
            ProviderErrorKind::Unknown
        );
    }
}
