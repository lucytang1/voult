//! Target-specific formatting for noisy dependency records.
//!
//! The generic renderer prints whatever a dependency puts in `record.args()`.
//! A few dependencies use structured or space-separated payloads that are much
//! easier to read after a small translation. Each submodule handles one target
//! and returns a message plus normal [`Metadata`]; anything unrecognised falls
//! back to the raw message.

mod actix_web;
mod sqlx;

use crate::Metadata;

pub(crate) struct FormattedEvent {
    pub message: String,
    pub metadata: Metadata,
}

/// Format a dependency record, or return `None` to use the raw message.
pub(crate) fn format(target: &str, message: &str) -> Option<FormattedEvent> {
    if target.starts_with("sqlx::query") {
        sqlx::parse(message)
    } else if target.starts_with("actix_web::middleware::logger") {
        actix_web::parse(message)
    } else {
        None
    }
}
