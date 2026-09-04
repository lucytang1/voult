use actix_session::Session;
use actix_web::{HttpResponse, post};
use serde::Serialize;

use crate::session_auth::clear_vault_session;

#[derive(Serialize)]
pub struct LogoutResponse {
    pub ok: bool,
}

/// Destroys the caller's vault session cookie. Idempotent: succeeds even with
/// no session so web + extension logout races converge. Note this clears only
/// the caller's cookie jar view — a holder in another browser profile keeps a
/// valid stateless cookie until TTL (see plans/session-consistency.md M3 for
/// the DB-backed revocation follow-up). It does NOT touch vault data or the
/// global lock epoch: use POST /api/lock when the intent is "lock everywhere".
#[post("/logout")]
pub async fn logout(session: Session) -> HttpResponse {
    clear_vault_session(&session);
    HttpResponse::Ok().json(LogoutResponse { ok: true })
}
