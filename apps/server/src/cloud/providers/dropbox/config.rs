use std::env;
#[derive(Clone, Debug)]
pub struct DropboxConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}
impl DropboxConfig {
    pub fn from_env() -> Option<Self> {
        Some(Self {
            client_id: env::var("DROPBOX_CLIENT_ID").ok()?,
            client_secret: env::var("DROPBOX_CLIENT_SECRET").ok()?,
            redirect_uri: env::var("DROPBOX_OAUTH_REDIRECT_URI").unwrap_or_else(|_| {
                "http://localhost:8080/api/cloud/oauth/callback?provider=dropbox".into()
            }),
        })
    }
    pub fn post_auth_redirect(&self) -> Option<String> {
        env::var("DROPBOX_POST_AUTH_REDIRECT")
            .ok()
            .filter(|s| !s.trim().is_empty())
    }
}
