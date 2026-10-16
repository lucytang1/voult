use std::env;

/// Returns Google OAuth config from env, or None if not configured (Phase 3 local-only fallback).
#[derive(Clone, Debug)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
}

impl GoogleConfig {
    pub fn from_env() -> Option<Self> {
        let client_id = env::var("GOOGLE_CLIENT_ID").ok()?;
        let client_secret = env::var("GOOGLE_CLIENT_SECRET").ok()?;
        // Prefer explicit GOOGLE_OAUTH_REDIRECT_URI, fallback to GOOGLE_REDIRECT_URI (legacy), then default
        let redirect_uri = env::var("GOOGLE_OAUTH_REDIRECT_URI")
            .or_else(|_| env::var("GOOGLE_REDIRECT_URI"))
            .unwrap_or_else(|_| {
                "http://localhost:8080/api/cloud/oauth/callback?provider=google_drive".to_string()
            });
        let scope = env::var("GOOGLE_DRIVE_SCOPE")
            .unwrap_or_else(|_| "https://www.googleapis.com/auth/drive.appdata".to_string());
        Some(Self {
            client_id,
            client_secret,
            redirect_uri,
            scope,
        })
    }

    /// Optional operator override for where the browser lands after consent.
    ///
    /// The bundled-vs-dev default lives on `CloudProvider::post_auth_redirect`,
    /// because that branch is a property of how the app is served rather than of
    /// Google — a second provider must not have to reimplement it.
    pub fn post_auth_redirect_override() -> Option<String> {
        env::var("GOOGLE_POST_AUTH_REDIRECT").ok().and_then(|v| {
            let t = v.trim().to_string();
            if t.is_empty() { None } else { Some(t) }
        })
    }
}
