// interface for the session store
// pub Trait SessionStore {
// fn delete_session(&self, DeleteSessionRequest) -> Result<(), DeleteSessionError>
// fn save_session(&self, SaveSessionRequest) -> Result<(), SaveSessionError> {
//  seaorm insert query
//  returns the session_id which is to be used for the Cookie
// }
// fn update_session(&self, UpdateSessionRequest) -> Result<(), UpdateSessionError>
// }
// 
use std::future::Future;
use crate::entity::session::Model as SessionModel;
pub trait SessionStore {
    fn save_session(&self, request: &SaveSessionRequest) -> impl Future<Output = Result<SessionModel, SaveSessionError>>;
    // fn delete_session(&self, request: &DeleteSessionRequest) -> impl Future<Output = Result<(), DeleteSessionError>>;
    //fn update_session(&self, request: &UpdateSessionRequest) -> impl Future<Output = Result<(), UpdateSessionError>>;
}

pub struct SaveSessionRequest {
    pub session_id: String,
    pub used_id: String
}

pub struct SaveSessionError;
// pub struct DeleteSessionRequest {
//     pub session_id: String
// }
// pub struct DeleteSessionError;
