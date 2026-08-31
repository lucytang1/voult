use actix_session::Session;

// Session cookie key holding the authenticated vault identity. The cookie
// stores only this ID plus framework-managed session state — never vault keys,
// envelopes, or vault data.
pub const SESSION_VAULT_ID_KEY: &str = "vault_id";

/// Reads the authenticated vault ID from the session, if present.
pub fn session_vault_id(session: &Session) -> Result<Option<String>, actix_session::SessionGetError> {
    session.get::<String>(SESSION_VAULT_ID_KEY)
}

/// Establishes an authenticated session scoped to a vault, rotating any existing
/// session first to prevent session fixation. The cookie stores only the vault
/// ID — never vault keys, envelopes, or vault data.
pub fn establish_vault_session(
    session: &Session,
    vault_id: &str,
) -> Result<(), actix_session::SessionInsertError> {
    if session.contains_key(SESSION_VAULT_ID_KEY) {
        session.purge();
    }
    session.insert(SESSION_VAULT_ID_KEY, vault_id.to_string())
}
