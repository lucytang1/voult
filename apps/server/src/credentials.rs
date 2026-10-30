//! Password-credential at rest.
//!
//! The client proves knowledge of `vault_verifier` on every password login.
//! That value is derived from the master password, so **storing it verbatim
//! makes the database row a replayable login credential**: anyone who can read
//! one row could present it to `POST /api/auth` and receive a session without
//! knowing the password. This module is the only place that knows how the
//! credential is stored, and it stores a keyed hash of what the client sent.
//!
//! The wire value is still the preimage:
//!
//! ```text
//! client:  presented  = HMAC(authKey, "auth-v1||static")       (32 bytes, base64)
//! server:  stored     = HMAC(verifier_salt, label || presented) (32 bytes, base64)
//! check :  HMAC(verifier_salt, label || presented) == stored     (constant time)
//! ```
//!
//! **Never add a path that accepts the stored value as input.** That would turn
//! this into pass-the-hash: the column would become presentable again and the
//! entire point of the module would be lost. The client always sends the
//! preimage; the server always hashes on arrival.
//!
//! What this does and does not buy, stated so it is not misread:
//!
//! - It **does** remove the zero-work replay. A dumped row yields a hash whose
//!   preimage is the verifier, and the verifier is only recoverable by guessing
//!   the master password.
//! - It **does not** make a database dump harmless. The same row holds
//!   `vault_key_wrap`, derived from the same PBKDF2 root with the same salt and
//!   iterations, so one PBKDF2 evaluation per candidate password tests both
//!   targets. Offline cracking cost is unchanged and belongs to the KDF item.
//! - It **does not** make the verifier safe in transit. It is still a bearer
//!   credential on the wire; only a PAKE removes that. See
//!   `plans/p0-verifier-replay.md` §4.2 for the recorded re-open triggers.
//!
//! The salt is public and non-sensitive. Neither the salt nor the hash may be
//! logged, and the hash must never gain a `Debug` impl that prints it.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Bytes of per-write random salt. Base64-encodes to 24 characters.
pub const VERIFIER_SALT_LEN: usize = 16;

/// Bytes in the stored hash (HMAC-SHA256). Base64-encodes to 44 characters.
pub const VERIFIER_HASH_LEN: usize = 32;

/// The real verifier is 32 bytes, i.e. 44 base64 characters. This cap exists
/// only so an unbounded string can never reach the HMAC; canonical base64
/// validation of the verifier is the request-bounds item's job, not this one.
pub const MAX_VERIFIER_LEN: usize = 256;

/// Domain separation for the stored hash. This string is part of the at-rest
/// credential format: changing it invalidates every stored credential, so it is
/// fixed for the lifetime of the schema and pinned by a known-answer test.
const VERIFIER_HASH_LABEL: &str = "voult-verifier-v1|";

/// What gets written to `vault.verifier_salt` / `vault.verifier_hash`.
pub struct StoredCredential {
    pub salt_b64: String,
    pub hash_b64: String,
}

/// Mints a fresh salt and the matching hash for a presented verifier.
///
/// `None` when the presented value is empty, whitespace-only, or oversized —
/// callers answer `INVALID_INPUT`. The salt is fresh on every write so two rows
/// (or the same row across a password rotation) never share a stored value.
pub fn new_credential(presented: &str) -> Option<StoredCredential> {
    if !acceptable(presented) {
        return None;
    }

    let mut salt = [0u8; VERIFIER_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);

    let mac = mac_for(&salt, presented)?;
    let hash = mac.finalize().into_bytes();
    debug_assert_eq!(hash.len(), VERIFIER_HASH_LEN);

    Some(StoredCredential {
        salt_b64: BASE64.encode(salt),
        hash_b64: BASE64.encode(hash),
    })
}

/// True only when `presented` hashes to the stored value under the stored salt.
///
/// The comparison is constant-time (`Mac::verify_slice`). Every malformed input
/// — empty columns, wrong decoded lengths, invalid base64 — returns `false`
/// rather than an error, so a row written before this format existed fails
/// closed as an ordinary `AUTH_FAILED` instead of surfacing a 500 that would
/// distinguish it from a wrong password.
pub fn accepts(salt_b64: &str, hash_b64: &str, presented: &str) -> bool {
    if !acceptable(presented) {
        return false;
    }

    let Some(salt) = decode_exact(salt_b64, VERIFIER_SALT_LEN) else {
        return false;
    };
    let Some(expected) = decode_exact(hash_b64, VERIFIER_HASH_LEN) else {
        return false;
    };
    let Some(mac) = mac_for(&salt, presented) else {
        return false;
    };

    mac.verify_slice(&expected).is_ok()
}

/// Length and emptiness guard shared by `/auth` and every credential writer.
///
/// This is deliberately narrower than full validation: it does not require the
/// value to be canonical 32-byte base64. Hashing whatever the client sent keeps
/// the credential pinned to one exact byte sequence (a different spelling
/// produces a different hash), so no aliasing is introduced, and it leaves
/// canonical-form validation to the request-bounds item.
pub fn acceptable(presented: &str) -> bool {
    !presented.trim().is_empty() && presented.len() <= MAX_VERIFIER_LEN
}

/// Builds the HMAC over `label || presented` keyed by the salt. Shared by both
/// directions so the stored format cannot drift between minting and checking.
fn mac_for(salt: &[u8], presented: &str) -> Option<HmacSha256> {
    let mut mac = HmacSha256::new_from_slice(salt).ok()?;
    mac.update(VERIFIER_HASH_LABEL.as_bytes());
    mac.update(presented.as_bytes());
    Some(mac)
}

/// Base64-decodes to exactly `len` bytes, or `None`.
fn decode_exact(s: &str, len: usize) -> Option<Vec<u8>> {
    let bytes = BASE64.decode(s.trim()).ok()?;
    (bytes.len() == len).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Pins the at-rest format. The vectors were generated independently with
    /// `printf '<msg>' | openssl dgst -sha256 -mac HMAC -macopt hexkey:<key>`,
    /// so a change to the label, the key, or the message layout fails here
    /// instead of silently invalidating every vault's stored credential.
    #[test]
    fn known_answer_vectors() {
        let key_a = [0u8; VERIFIER_SALT_LEN];
        let digest_a = mac_for(&key_a, "abc").unwrap().finalize().into_bytes();
        assert_eq!(
            hex(&digest_a),
            "4bbf2b1efd6fbf32c088164d9de86725c1f0580ba03843716dc45665629b0946"
        );

        let key_b: Vec<u8> = (1u8..=16).collect();
        let digest_b = mac_for(&key_b, "Zm9vYmFy").unwrap().finalize().into_bytes();
        assert_eq!(
            hex(&digest_b),
            "98173a776cc512f8a100b22eb30e227f723d3b29732a18678cfbdf69ae764461"
        );
    }

    #[test]
    fn round_trip_accepts_the_same_value() {
        let presented = "Zm9vYmFy";
        let cred = new_credential(presented).expect("credential");
        assert!(accepts(&cred.salt_b64, &cred.hash_b64, presented));
    }

    #[test]
    fn stored_shape_is_the_documented_size() {
        let cred = new_credential("Zm9vYmFy").expect("credential");
        assert_eq!(
            BASE64.decode(&cred.salt_b64).unwrap().len(),
            VERIFIER_SALT_LEN
        );
        assert_eq!(
            BASE64.decode(&cred.hash_b64).unwrap().len(),
            VERIFIER_HASH_LEN
        );
    }

    #[test]
    fn rejects_a_different_value() {
        let cred = new_credential("Zm9vYmFy").expect("credential");
        // One-base64-character change is a completely different credential.
        assert!(!accepts(&cred.salt_b64, &cred.hash_b64, "Zm9vYmF6"));
        // And the stored hash cannot be presented as the credential; that would
        // be pass-the-hash and would defeat the whole module.
        assert!(!accepts(&cred.salt_b64, &cred.hash_b64, &cred.hash_b64));
    }

    #[test]
    fn fresh_salt_per_write() {
        let a = new_credential("Zm9vYmFy").expect("a");
        let b = new_credential("Zm9vYmFy").expect("b");
        assert_ne!(a.salt_b64, b.salt_b64);
        assert_ne!(a.hash_b64, b.hash_b64);
        // Both still verify: the salt is stored beside the hash.
        assert!(accepts(&a.salt_b64, &a.hash_b64, "Zm9vYmFy"));
        assert!(accepts(&b.salt_b64, &b.hash_b64, "Zm9vYmFy"));
    }

    #[test]
    fn rejects_empty_and_malformed_columns() {
        let cred = new_credential("Zm9vYmFy").expect("credential");
        let value = "Zm9vYmFy";
        // The fail-closed state left behind by the schema migration.
        assert!(!accepts("", "", value));
        assert!(!accepts(&cred.salt_b64, "", value));
        assert!(!accepts("", &cred.hash_b64, value));
        // Right lengths, wrong bytes.
        assert!(!accepts(
            &BASE64.encode([9u8; VERIFIER_SALT_LEN]),
            &cred.hash_b64,
            value
        ));
        // Wrong decoded lengths.
        assert!(!accepts("AAAA", &cred.hash_b64, value));
        assert!(!accepts(&cred.salt_b64, "AAAA", value));
        // Not base64 at all.
        assert!(!accepts("not base64!!", &cred.hash_b64, value));
    }

    #[test]
    fn acceptable_bounds() {
        assert!(!acceptable(""));
        assert!(!acceptable("   "));
        assert!(acceptable("Zm9vYmFy"));
        assert!(acceptable(&"A".repeat(MAX_VERIFIER_LEN)));
        assert!(!acceptable(&"A".repeat(MAX_VERIFIER_LEN + 1)));
        assert!(new_credential("   ").is_none());
        assert!(new_credential(&"A".repeat(MAX_VERIFIER_LEN + 1)).is_none());
    }
}
