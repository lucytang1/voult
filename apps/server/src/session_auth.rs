use actix_session::Session;

// Session cookie key holding the authenticated vault identity. The cookie
// stores only this ID plus framework-managed session state — never vault keys,
// envelopes, or vault data.
pub const SESSION_VAULT_ID_KEY: &str = "vault_id";

/// Reads the authenticated vault ID from the session, if present.
pub fn session_vault_id(
    session: &Session,
) -> Result<Option<String>, actix_session::SessionGetError> {
    session.get::<String>(SESSION_VAULT_ID_KEY)
}

/// Destroys the current vault session, if any. Idempotent: purging an empty
/// session is a no-op success so logout converges even under races
/// (e.g. web + extension logging out near-simultaneously).
pub fn clear_vault_session(session: &Session) {
    session.purge();
}

/// Establishes an authenticated session scoped to a vault, rotating any existing
/// session first to prevent session fixation. The cookie stores only the vault
/// ID — never vault keys, envelopes, or vault data.
///
/// Rotation uses `renew()`, NOT `purge()` + `insert()`: in actix-session 0.11
/// `insert()` after `purge()` is a silent no-op (status stays `Purged`, the
/// entry is dropped, `Ok` is still returned) and the middleware then sends a
/// cookie *deletion* — so a login issued while a session cookie was present
/// returned 200 yet left the caller logged out (next call 401). `renew()`
/// deletes the old key server-side and re-saves state into a fresh cookie.
pub fn establish_vault_session(
    session: &Session,
    vault_id: &str,
) -> Result<(), actix_session::SessionInsertError> {
    session.renew();
    session.insert(SESSION_VAULT_ID_KEY, vault_id.to_string())
}
