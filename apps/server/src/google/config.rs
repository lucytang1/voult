use std::env;

/// Returns Google OAuth config from env, or None if not configured (Phase 3 local-only fallback).
#[derive(Clone, Debug)]
pub struct GoogleConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub scope: String,
    pub post_auth_redirect: String,
}

impl GoogleConfig {
    pub fn from_env() -> Option<Self> {
        let client_id = env::var("GOOGLE_CLIENT_ID").ok()?;
        let client_secret = env::var("GOOGLE_CLIENT_SECRET").ok()?;
        // Prefer explicit GOOGLE_OAUTH_REDIRECT_URI, fallback to GOOGLE_REDIRECT_URI (legacy), then default
        let redirect_uri = env::var("GOOGLE_OAUTH_REDIRECT_URI")
            .or_else(|_| env::var("GOOGLE_REDIRECT_URI"))
            .unwrap_or_else(|_| "http://localhost:8080/api/google/oauth/callback".to_string());
        let scope = env::var("GOOGLE_DRIVE_SCOPE")
            .unwrap_or_else(|_| "https://www.googleapis.com/auth/drive.appdata".to_string());
        let post_auth_redirect = env::var("GOOGLE_POST_AUTH_REDIRECT").unwrap_or_else(|_| {
            // In bundled mode the frontend is served from :8080 same-origin;
            // :8081 is only the Expo dev server. Prefer :8080 when not overridden.
            // If STATIC_DIR resolves to a bundle, use :8080, otherwise keep dev default.
            // We infer via env presence: if running bundled, STATIC_DIR will be Resources/dist
            let is_bundled = env::var("STATIC_DIR")
                .map(|v| v.contains("Resources/dist"))
                .unwrap_or_else(|_| {
                    // No explicit STATIC_DIR → check if bundled Resources/dist exists relative to exe
                    if let Ok(exe) = env::current_exe() {
                        if let Some(dir) = exe.parent() {
                            return dir.join("../Resources/dist/index.html").exists()
                                || dir.join("../../Resources/dist/index.html").exists();
                        }
                    }
                    false
                });
            if is_bundled {
                "http://localhost:8080/vault".to_string()
            } else {
                "http://localhost:8081/vault".to_string()
            }
        });
        Some(Self {
            client_id,
            client_secret,
            redirect_uri,
            scope,
            post_auth_redirect,
        })
    }

    pub fn is_configured(&self) -> bool {
        !self.client_id.is_empty() && !self.client_secret.is_empty()
    }
}
