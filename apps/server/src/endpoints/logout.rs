use actix_session::Session;
use actix_web::{post, HttpResponse};
use serde::Serialize;

#[derive(Serialize)]
struct LogoutResponse {
    ok: bool,
}

/// Purges the current session (client and server side).
#[post("/logout")]
pub async fn logout(session: Session) -> HttpResponse {
    session.purge();
    HttpResponse::Ok().json(LogoutResponse { ok: true })
}
