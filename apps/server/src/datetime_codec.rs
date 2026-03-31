use chrono::{DateTime, ParseError, SecondsFormat, Utc};
use sea_orm::entity::prelude::DateTimeUtc;

#[allow(dead_code)]
pub fn parse_iso_utc(raw: &str) -> Result<DateTimeUtc, ParseError> {
    let dt = DateTime::parse_from_rfc3339(raw)?;
    Ok(dt.with_timezone(&Utc))
}

#[allow(dead_code)]
pub fn format_iso_utc(dt: &DateTimeUtc) -> String {
    dt.to_rfc3339_opts(SecondsFormat::Millis, true)
}
