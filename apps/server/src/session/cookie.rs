use crate::session::interface::SessionStore;

pub struct CookieSessionStore;

impl SessionStore for CookieSessionStore {
    fn save_session(&self, request: &SaveSessionRequest) -> impl Future<Output = Result<(), SaveSessionError>> {
        
    }
}
