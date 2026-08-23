use actix_session::Session;

pub const SESSION_USER_ID_KEY: &str = "user_id";

/// Reads the authenticated user ID from the session, if present.
pub fn session_user_id(session: &Session) -> Result<Option<String>, actix_session::SessionGetError> {
    session.get::<String>(SESSION_USER_ID_KEY)
}

/// Establishes an authenticated session, rotating any existing session to
/// prevent session fixation. The cookie stores only the user ID — never vault
/// keys, envelopes, or vault data.
pub fn establish_session(session: &Session, user_id: &str) -> Result<(), actix_session::SessionInsertError> {
    if session.contains_key(SESSION_USER_ID_KEY) {
        session.purge();
    }
    session.insert(SESSION_USER_ID_KEY, user_id.to_string())
}
