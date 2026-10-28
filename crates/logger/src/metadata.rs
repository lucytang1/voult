//! Metadata values attached to a log call.
//!
//! Bluesky's metadata type is shaped partly around Sentry. This logger only
//! needs the key/value part: a value may be serializable, an error, or a value
//! that has no serializable representation and is rendered with `Debug`.

use std::fmt;

use serde::Serialize;

/// An ordered list of metadata entries.
///
/// Insertion order is preserved so log lines stay stable and easy to read.
/// Keys are `&'static str` because every current call site uses a literal.
#[derive(Debug, Clone, Default)]
pub struct Metadata {
    entries: Vec<(&'static str, MetaValue)>,
}

impl Metadata {
    /// Create an empty metadata map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or append one key/value pair.
    pub fn insert(&mut self, key: &'static str, value: impl Into<MetaValue>) -> &mut Self {
        self.entries.push((key, value.into()));
        self
    }

    /// Iterate over the entries in insertion order.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'static str, &MetaValue)> {
        self.entries.iter().map(|(key, value)| (*key, value))
    }
}

/// One metadata value.
///
/// This mirrors the useful subset of Bluesky's
/// `[key: string]: Serializable | Error | unknown`:
///
/// - `Json` holds anything that serializes to JSON.
/// - `Error` holds an error's `Display` text.
/// - `Unknown` holds a `Debug` representation for values with no useful
///   serializable form.
#[derive(Debug, Clone)]
pub enum MetaValue {
    /// Any JSON-serializable value.
    Json(serde_json::Value),

    /// An error (or any displayable value), stored as text.
    Error(String),

    /// A value with no serializable representation, stored as `Debug` text.
    Unknown(String),
}

impl MetaValue {
    /// Convert any `Serialize` value into JSON metadata.
    ///
    /// Serialization errors are kept visible as `MetaValue::Error` rather than
    /// silently dropping the field.
    pub fn json(value: impl Serialize) -> Self {
        match serde_json::to_value(value) {
            Ok(value) => Self::Json(value),
            Err(error) => Self::Error(error.to_string()),
        }
    }

    /// Store an error (or any displayable value) as the error arm.
    pub fn error(error: impl fmt::Display) -> Self {
        Self::Error(error.to_string())
    }

    /// Store a non-serializable value using its `Debug` representation.
    pub fn unknown(value: impl fmt::Debug) -> Self {
        Self::Unknown(format!("{value:?}"))
    }
}

impl From<serde_json::Value> for MetaValue {
    fn from(value: serde_json::Value) -> Self {
        Self::Json(value)
    }
}

impl From<&str> for MetaValue {
    fn from(value: &str) -> Self {
        Self::Json(serde_json::Value::String(value.to_string()))
    }
}

impl From<String> for MetaValue {
    fn from(value: String) -> Self {
        Self::Json(serde_json::Value::String(value))
    }
}

impl From<&String> for MetaValue {
    fn from(value: &String) -> Self {
        Self::Json(serde_json::Value::String(value.clone()))
    }
}

impl From<bool> for MetaValue {
    fn from(value: bool) -> Self {
        Self::Json(serde_json::Value::Bool(value))
    }
}

macro_rules! impl_signed_meta {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for MetaValue {
                fn from(value: $ty) -> Self {
                    Self::Json(serde_json::Value::from(value as i64))
                }
            }
        )*
    };
}

macro_rules! impl_unsigned_meta {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for MetaValue {
                fn from(value: $ty) -> Self {
                    Self::Json(serde_json::Value::from(value as u64))
                }
            }
        )*
    };
}

macro_rules! impl_float_meta {
    ($($ty:ty),* $(,)?) => {
        $(
            impl From<$ty> for MetaValue {
                fn from(value: $ty) -> Self {
                    Self::Json(serde_json::Value::from(value as f64))
                }
            }
        )*
    };
}

impl_signed_meta!(i8, i16, i32, i64, isize);
impl_unsigned_meta!(u8, u16, u32, u64, usize);
impl_float_meta!(f32, f64);

/// Construct a [`Metadata`] map with object-literal syntax.
///
/// This is a metadata constructor, not a logging macro. Logging stays on the
/// two-argument `Logger` methods.
///
/// ```ignore
/// let meta = logger::metadata! {
///     "vault_id" => vault_id.to_string(),
///     "status" => 409,
///     "retryable" => false,
/// };
/// ```
#[macro_export]
macro_rules! metadata {
    ($($key:literal => $value:expr),* $(,)?) => {{
        // `mut` is unused only for the zero-field expansion; keeping one arm
        // avoids duplicating the macro body just for `metadata! {}`.
        #[allow(unused_mut)]
        let mut metadata = $crate::Metadata::new();
        $(metadata.insert($key, $value);)*
        metadata
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_keeps_insertion_order() {
        let metadata = metadata! {
            "first" => "one",
            "second" => 2,
            "third" => true,
        };

        let keys: Vec<_> = metadata.iter().map(|(key, _)| key).collect();
        assert_eq!(keys, ["first", "second", "third"]);
    }

    #[test]
    fn empty_metadata_macro_is_empty() {
        let metadata = metadata! {};
        assert!(metadata.iter().next().is_none());
    }

    #[test]
    fn scalar_values_convert() {
        assert!(matches!(
            MetaValue::from("hello"),
            MetaValue::Json(serde_json::Value::String(value)) if value == "hello"
        ));
        assert!(matches!(
            MetaValue::from(42_i64),
            MetaValue::Json(serde_json::Value::Number(value)) if value.as_i64() == Some(42)
        ));
        assert!(matches!(
            MetaValue::from(false),
            MetaValue::Json(serde_json::Value::Bool(false))
        ));
    }

    #[test]
    fn json_helper_accepts_serializable_values() {
        let value = MetaValue::json(vec![1, 2, 3]);
        assert!(matches!(
            value,
            MetaValue::Json(serde_json::Value::Array(items)) if items.len() == 3
        ));
    }

    #[test]
    fn error_and_unknown_keep_text() {
        let error = MetaValue::error("connection refused");
        assert!(matches!(error, MetaValue::Error(value) if value == "connection refused"));

        let unknown = MetaValue::unknown(&Some(7));
        assert!(matches!(unknown, MetaValue::Unknown(value) if value == "Some(7)"));
    }
}
