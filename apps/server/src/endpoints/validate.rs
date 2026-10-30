//! Protocol bounds and the single validation dialect for every write boundary.
//!
//! # Why this module exists
//!
//! The write handlers used to enforce "the field is present" and leave shape to
//! the client. That is not a contract: a 3-byte IV, a 1-character verifier, or
//! an arbitrary `crypto_version` was stored happily, while every reader in the
//! system (recovery, the backup package, every client's `atob`) assumes the
//! exact shapes produced by `packages/vault-core/src/crypto.ts`. A row that
//! violates them is not merely unusual, it is unopenable — and for a
//! half-written password envelope, unrepairable.
//!
//! So every write boundary validates here, before any DB work. This module is
//! the only place allowed to contain a length, an iteration bound, or a
//! supported crypto version; endpoint modules never compare against a literal.
//! The KDF-profile item moves `KDF_ITERATIONS_*` here and nowhere else.
//!
//! The client mirror is `packages/vault-core/src/bounds.ts`. The two are a wire
//! contract, pinned by tests on both sides and documented in
//! `docs/request-bounds.md`.
//!
//! # The three rules
//!
//! * **Canonical UUID.** Trimmed, lowercase, hyphenated, and version 4. Every
//!   producer is a CSPRNG v4 (`crypto.randomUUID()` or `uuidv4()`), so any other
//!   spelling names the same vault under a different string and is refused.
//! * **Canonical base64.** Standard alphabet, padded to a multiple of 4,
//!   canonical trailing bits, no interior whitespace; outer whitespace is
//!   trimmed. This is exactly what `base64`'s `STANDARD` engine accepts and what
//!   the client's `btoa` produces.
//! * **Bounded KDF.** The iteration count is a *write-time* policy: reads must
//!   keep honouring rows written under an older profile, so the floor moves only
//!   in lockstep with the clients. The client's `deriveRootKey` has its own
//!   absolute read floor.

use actix_web::HttpResponse;
use actix_web::http::StatusCode;
use base64::Engine as _;
use uuid::Uuid;

use crate::error::error_response;

// --- Exact byte lengths ------------------------------------------------------
//
// Every value below is a property of the v2 hierarchy in
// `packages/vault-core/src/crypto.ts`, not a preference. Changing one without
// changing the matching client code makes every new row unreadable.

/// PBKDF2 salt. `generateSalt()` allocates 16 bytes.
pub const SALT_LEN: usize = 16;
/// AES-GCM nonce. Every `encrypt`/`wrapKeyBytes` call uses a 96-bit IV.
pub const IV_LEN: usize = 12;
/// HMAC-SHA256 output used as `vault_verifier` and `recovery_verifier`.
pub const VERIFIER_LEN: usize = 32;
/// Wrapped 256-bit key (32 bytes) plus the 16-byte GCM tag. Applies to both the
/// password and the recovery envelope.
pub const KEY_WRAP_LEN: usize = 48;
/// HMAC-SHA256 recovery proof.
pub const PROOF_LEN: usize = 32;
/// Server-minted 256-bit recovery challenge.
pub const CHALLENGE_LEN: usize = 32;

// --- Vault ciphertext --------------------------------------------------------

/// A GCM tag (16 bytes) plus at least one byte of payload. The real minimum
/// document is ~40 bytes of JSON; this is a sanity floor, not a document check
/// (the server cannot inspect the plaintext).
pub const MIN_CIPHERTEXT_LEN: usize = 17;

/// Chosen ceiling for the single-blob vault document.
///
/// This is a product decision, not a measurement: ≈6,000 average items, and it
/// keeps one full-document CAS rewrite plus the post-commit mirror bounded. If
/// real vaults approach it, the long-term answer is per-item sync, not a bigger
/// blob. The client refuses to push above it (`MAX_VAULT_CIPHERTEXT_BYTES` in
/// `vault-core`'s bounds module).
pub const MAX_CIPHERTEXT_LEN: usize = 4 * 1024 * 1024;

/// Largest backup package the server will accept or produce: the ciphertext as
/// base64 plus the envelopes and metadata (`cloud/package.rs`).
pub const MAX_PACKAGE_LEN: usize = 6 * 1024 * 1024;

/// Provider file ids and revisions. Opaque, but they end up in provider URLs,
/// so they get a hard ceiling far above anything a provider issues.
pub const MAX_REMOTE_ID_LEN: usize = 512;

// --- KDF and crypto version --------------------------------------------------

/// Write-time iteration floor. This is the value every client writes today
/// (`PBKDF2_ITERATIONS` in `vault-core`), and the same floor recovery already
/// enforced. It is a *policy on writes*: a row written under an older profile
/// must still open, so this number moves only when the clients do.
pub const KDF_ITERATIONS_MIN: i32 = 60_000;

/// Write-time ceiling. The client runs PBKDF2 with the server-supplied count on
/// every unlock, so an absurd count makes the vault unopenable on every device.
/// 2,000,000 is the largest cost that still completes in seconds on the slowest
/// supported hardware; moving it is the KDF-profile item's job.
pub const KDF_ITERATIONS_MAX: i32 = 2_000_000;

/// The only crypto version any producer emits. A v1 row has no password
/// envelope, cannot be backed up (`cloud/package.rs` refuses it as legacy) and
/// cannot be rewrapped (`recovery.rs` refuses it), so it is not a supported
/// state — not even as a read-only legacy shape.
pub const SUPPORTED_CRYPTO_VERSION: i32 = 2;

// --- Transport ---------------------------------------------------------------

/// Explicit JSON body cap, replacing Actix's unowned 2 MiB default.
///
/// Sized from the largest legitimate request: `base64(MAX_PACKAGE_LEN)` plus
/// JSON framing covers the double-encoded cloud-upload path with ~4 MiB of
/// headroom. This is a *transport* bound; storage is bounded by the field caps
/// and, for request counts, by the rate-limiting item.
pub const MAX_JSON_BODY_BYTES: usize = 12 * 1024 * 1024;

/// Canonical base64 length for `bytes` bytes.
pub const fn b64_encoded_len(bytes: usize) -> usize {
    // `(n + 2) / 3 * 4` rather than `div_ceil`: the latter's const stability
    // has changed across toolchains, and this form is trivially auditable.
    (bytes + 2) / 3 * 4
}

/// The encoded form of a maximum-size ciphertext.
pub const MAX_CIPHERTEXT_B64_LEN: usize = b64_encoded_len(MAX_CIPHERTEXT_LEN);
/// The encoded form of a maximum-size package (the cloud-upload field).
pub const MAX_PACKAGE_B64_LEN: usize = b64_encoded_len(MAX_PACKAGE_LEN);

// Compile-time guards: the caps must nest. A ciphertext lives inside a package
// as base64; a package is uploaded as base64 inside a JSON body. If one of the
// three numbers moves without the others, these fail the build rather than
// producing a cap that rejects a legal maximum-size vault.
const _: () = assert!(MAX_CIPHERTEXT_B64_LEN < MAX_PACKAGE_LEN);
const _: () = assert!(MAX_PACKAGE_B64_LEN < MAX_JSON_BODY_BYTES);

// --- Error shape -------------------------------------------------------------

/// One field that failed its shape check, rendered in the same dialect as every
/// other API error: `{"error_msg": "<field> must be <expected>", "code":
/// "INVALID_INPUT"}`.
///
/// The message names only the request field and the expected shape. It never
/// echoes the submitted value, and callers never log the value either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldError {
    pub field: &'static str,
    pub expected: String,
}

impl FieldError {
    pub fn new(field: &'static str, expected: impl Into<String>) -> Self {
        Self {
            field,
            expected: expected.into(),
        }
    }

    /// 400 with the documented envelope. Shape failures are 400, never 413:
    /// 413 is reserved for "the transport refused to read the body".
    pub fn response(&self) -> HttpResponse {
        error_response(
            StatusCode::BAD_REQUEST,
            &format!("{} must be {}", self.field, self.expected),
            "INVALID_INPUT",
        )
    }
}

// --- Primitives --------------------------------------------------------------

/// Canonical standard base64 as bytes, for the small fixed-length fields.
///
/// Returns the decoded bytes because several callers need them (the recovery
/// proof and the verifier are HMAC inputs).
pub fn decode_exact(raw: &str, len: usize) -> Option<Vec<u8>> {
    let s = raw.trim();
    if decoded_len(s)? != len {
        return None;
    }
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

/// Validates a variable-length base64 field without allocating its plaintext:
/// the ciphertext can be 4 MiB and the handler only needs the string.
pub fn b64_length_in(raw: &str, min: usize, max: usize) -> Option<usize> {
    let len = decoded_len(raw.trim())?;
    (min..=max).contains(&len).then_some(len)
}

/// A canonical UUID v4, as a `Uuid`.
///
/// The canonical-form comparison rejects uppercase, braced, and unhyphenated
/// spellings — they address the same row under a different string, which is
/// exactly how two code paths end up disagreeing about identity.
pub fn canonical_uuid(raw: &str) -> Option<Uuid> {
    let trimmed = raw.trim();
    let parsed = Uuid::parse_str(trimmed).ok()?;
    (parsed.to_string() == trimmed && parsed.get_version_num() == 4).then_some(parsed)
}

/// The string form used where a vault id is compared with the session value.
pub fn canonical_uuid_string(raw: &str) -> Option<String> {
    canonical_uuid(raw).map(|u| u.to_string())
}

/// Write-time KDF policy. Reads deliberately do not call this: a row written
/// under an older profile must still open (the client's `deriveRootKey` has the
/// absolute read floor).
pub fn kdf_ok(iterations: i32) -> bool {
    (KDF_ITERATIONS_MIN..=KDF_ITERATIONS_MAX).contains(&iterations)
}

/// The only supported crypto version.
pub fn crypto_version_ok(version: i32) -> bool {
    version == SUPPORTED_CRYPTO_VERSION
}

// --- Field wrappers ----------------------------------------------------------
//
// These exist so an endpoint never has to build an error message itself. Keep
// the `expected` phrasing in the second person of the field, not the check.

pub fn require_uuid(field: &'static str, raw: &str) -> Result<Uuid, FieldError> {
    canonical_uuid(raw).ok_or_else(|| FieldError::new(field, "a canonical UUID v4"))
}

pub fn require_b64_exact(field: &'static str, raw: &str, len: usize) -> Result<(), FieldError> {
    decode_exact(raw, len)
        .map(|_| ())
        .ok_or_else(|| FieldError::new(field, format!("{len} bytes of base64")))
}

pub fn require_b64_in_range(
    field: &'static str,
    raw: &str,
    min: usize,
    max: usize,
) -> Result<(), FieldError> {
    b64_length_in(raw, min, max).map(|_| ()).ok_or_else(|| {
        FieldError::new(
            field,
            format!("between {min} and {max} decoded bytes of base64"),
        )
    })
}

pub fn require_kdf(field: &'static str, iterations: i32) -> Result<(), FieldError> {
    kdf_ok(iterations).then_some(()).ok_or_else(|| {
        FieldError::new(
            field,
            format!("between {KDF_ITERATIONS_MIN} and {KDF_ITERATIONS_MAX}"),
        )
    })
}

pub fn require_crypto_version(field: &'static str, version: i32) -> Result<(), FieldError> {
    crypto_version_ok(version)
        .then_some(())
        .ok_or_else(|| FieldError::new(field, format!("{SUPPORTED_CRYPTO_VERSION}")))
}

/// Provider identifiers (file ids, revisions). Non-empty and bounded; no
/// alphabet requirement, because providers define their own.
pub fn require_remote_id(field: &'static str, raw: &str) -> Result<(), FieldError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().count() > MAX_REMOTE_ID_LEN {
        return Err(FieldError::new(
            field,
            format!("between 1 and {MAX_REMOTE_ID_LEN} characters"),
        ));
    }
    Ok(())
}

// --- The complete vault row --------------------------------------------------

/// Every crypto field both creation endpoints write, in one place.
///
/// `POST /register` and `POST /vaults` insert exactly the same row shape. Two
/// copies of these twelve checks is how the two endpoints drifted apart before
/// (one defaulted `crypto_version` to 1, the other to 2).
pub struct VaultMaterial<'a> {
    pub vault_verifier: &'a str,
    pub salt: &'a str,
    pub iterations: i32,
    pub vault_iv: &'a str,
    pub vault: &'a str,
    pub crypto_version: i32,
    pub vault_key_wrap: &'a str,
    pub vault_key_wrap_iv: &'a str,
    pub recovery_verifier: &'a str,
    pub recovery_salt: &'a str,
    pub recovery_wrap: &'a str,
    pub recovery_wrap_iv: &'a str,
}

/// Validates all twelve fields, paired-or-not-at-all.
pub fn validate_vault_material(m: &VaultMaterial<'_>) -> Result<(), FieldError> {
    require_b64_exact("vault_verifier", m.vault_verifier, VERIFIER_LEN)?;
    require_b64_exact("salt", m.salt, SALT_LEN)?;
    require_kdf("iterations", m.iterations)?;
    require_b64_exact("vaultiv", m.vault_iv, IV_LEN)?;
    require_b64_in_range("vault", m.vault, MIN_CIPHERTEXT_LEN, MAX_CIPHERTEXT_LEN)?;
    require_crypto_version("crypto_version", m.crypto_version)?;
    require_b64_exact("vault_key_wrap", m.vault_key_wrap, KEY_WRAP_LEN)?;
    require_b64_exact("vault_key_wrap_iv", m.vault_key_wrap_iv, IV_LEN)?;
    require_b64_exact("recovery_verifier", m.recovery_verifier, VERIFIER_LEN)?;
    require_b64_exact("recovery_salt", m.recovery_salt, SALT_LEN)?;
    require_b64_exact("recovery_wrap", m.recovery_wrap, KEY_WRAP_LEN)?;
    require_b64_exact("recovery_wrap_iv", m.recovery_wrap_iv, IV_LEN)?;
    Ok(())
}

// --- Internals ---------------------------------------------------------------

const B64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(byte: u8) -> u8 {
    // Only called after the alphabet check, so the position always exists.
    B64_ALPHABET
        .iter()
        .position(|c| *c == byte)
        .expect("b64_value called on a non-alphabet byte") as u8
}

/// True for canonical standard base64: padded to a multiple of 4, padding only
/// at the end, and zero trailing bits in the final quantum.
///
/// Hand-rolled instead of "decode and re-encode" because the largest field is
/// 4 MiB and `btoa(atob(...))`-style checks either allocate twice or overflow
/// the stack when spread into `String::from_char`. The unit tests pin this
/// against the `base64` engine's `STANDARD` behaviour so the two cannot drift.
fn is_canonical_b64(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() % 4 != 0 {
        return false;
    }
    let pad = if b.ends_with(b"==") {
        2
    } else if b.ends_with(b"=") {
        1
    } else {
        0
    };
    let data_len = b.len() - pad;
    if b[..data_len].contains(&b'=') {
        return false;
    }
    if !b[..data_len].iter().all(|c| B64_ALPHABET.contains(c)) {
        return false;
    }
    match pad {
        // One byte in the final quantum: the low four bits of the last symbol
        // are padding bits and must be zero.
        2 => b64_value(b[data_len - 1]) & 0x0f == 0,
        // Two bytes in the final quantum: the low two bits must be zero.
        1 => b64_value(b[data_len - 1]) & 0x03 == 0,
        _ => true,
    }
}

/// Decoded byte length of canonical base64, or `None` if it is not canonical.
fn decoded_len(s: &str) -> Option<usize> {
    if !is_canonical_b64(s) {
        return None;
    }
    let pad = if s.ends_with("==") {
        2
    } else if s.ends_with('=') {
        1
    } else {
        0
    };
    Some(s.len() / 4 * 3 - pad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    #[test]
    fn canonical_base64_matches_the_engine() {
        let cases = [
            "", "A", "AA", "AAA", "AAAA", "AA==", "AAA=", "A===", "====",
            "AB==", // non-zero trailing bits in a 1-byte quantum
            "AAB=", // non-zero trailing bits in a 2-byte quantum
            "AA=A", "AA-_", // URL-safe alphabet
            "AA+/", "AA==AA==", " AA==", // outer whitespace is trimmed by the public API
            "AA==\n",
        ];
        for case in cases {
            let engine_ok = base64::engine::general_purpose::STANDARD
                .decode(case.trim())
                .is_ok();
            hex_dump_on_mismatch(case, engine_ok);
            assert_eq!(
                is_canonical_b64(case.trim()),
                engine_ok,
                "canonicality disagrees with the base64 engine for {case:?}"
            );
        }
    }

    /// Prints the offending input before an assertion fires; useful when the
    /// engine and the hand-rolled check disagree after a dependency bump.
    fn hex_dump_on_mismatch(case: &str, engine_ok: bool) {
        if is_canonical_b64(case.trim()) != engine_ok {
            eprintln!("mismatch: {:?} bytes={:?}", case, case.as_bytes());
        }
    }

    #[test]
    fn decode_exact_accepts_only_the_exact_length() {
        assert!(decode_exact(&b64(&[0u8; 32]), 32).is_some());
        assert!(decode_exact(&b64(&[0u8; 31]), 32).is_none());
        assert!(decode_exact(&b64(&[0u8; 33]), 32).is_none());
        // Outer whitespace is tolerated; interior whitespace is not.
        assert!(decode_exact(&format!("  {}  ", b64(&[0u8; 32])), 32).is_some());
        assert!(decode_exact("AA A=", 2).is_none());
    }

    #[test]
    fn bounded_length_checks_the_decoded_size() {
        assert_eq!(
            b64_length_in(&b64(&[0u8; 17]), 17, 4 * 1024 * 1024),
            Some(17)
        );
        assert_eq!(b64_length_in(&b64(&[0u8; 16]), 17, 4 * 1024 * 1024), None);
        assert_eq!(
            b64_length_in(
                &b64(&vec![0u8; MAX_CIPHERTEXT_LEN + 1]),
                17,
                MAX_CIPHERTEXT_LEN
            ),
            None
        );
    }

    #[test]
    fn uuid_must_be_canonical_and_v4() {
        let v4 = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
        assert_eq!(
            canonical_uuid(v4).map(|u| u.to_string()),
            Some(v4.to_string())
        );
        assert!(canonical_uuid(&v4.to_uppercase()).is_none(), "uppercase");
        assert!(canonical_uuid(&format!("{{{v4}}}")).is_none(), "braced");
        assert!(
            canonical_uuid(&v4.replace('-', "")).is_none(),
            "unhyphenated"
        );
        assert!(
            canonical_uuid("00000000-0000-0000-0000-000000000000").is_none(),
            "nil is v0"
        );
        assert!(
            canonical_uuid("3f2504e0-4f89-11d3-9a0c-0305e82c3301").is_none(),
            "v1"
        );
    }

    #[test]
    fn kdf_bounds_are_inclusive() {
        assert!(!kdf_ok(KDF_ITERATIONS_MIN - 1));
        assert!(kdf_ok(KDF_ITERATIONS_MIN));
        assert!(kdf_ok(KDF_ITERATIONS_MAX));
        assert!(!kdf_ok(KDF_ITERATIONS_MAX + 1));
        assert!(!kdf_ok(0));
        assert!(!kdf_ok(-1));
    }

    #[test]
    fn only_version_2_is_supported() {
        assert!(crypto_version_ok(2));
        assert!(!crypto_version_ok(1));
        assert!(!crypto_version_ok(3));
    }

    #[test]
    fn caps_nest() {
        assert!(MAX_CIPHERTEXT_B64_LEN < MAX_PACKAGE_LEN);
        assert!(MAX_PACKAGE_B64_LEN < MAX_JSON_BODY_BYTES);
        assert!(MIN_CIPHERTEXT_LEN <= MAX_CIPHERTEXT_LEN);
    }

    #[test]
    fn field_errors_never_echo_the_value() {
        let err = require_b64_exact("salt", "super-secret-value", SALT_LEN).unwrap_err();
        let body = err.response();
        assert_eq!(body.status(), StatusCode::BAD_REQUEST);
        // The message is built from the field name and the expected shape only.
        assert_eq!(err.field, "salt");
        assert!(!err.expected.contains("super-secret-value"));
    }
}
