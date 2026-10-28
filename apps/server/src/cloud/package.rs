//! Server-side construction of the encrypted Voult package that a provider
//! stores. Provider-neutral: the byte layout is a Voult contract, not a Drive
//! one, which is what lets a vault backed up to one provider be restored by
//! any client regardless of which provider it went to.
//!
//! The server is the write authority for vault ciphertext but never holds a key
//! and never sees plaintext. It can therefore re-emit the package *exactly*
//! because every field is ciphertext or public crypto metadata the server
//! already stores: `vault.vault` (AES-GCM ciphertext), `vault.vaultiv`,
//! `salt`, `iterations`, `crypto_version`, the password-wrapped vault-key
//! envelope, and the recovery envelope. Building a backup is a re-serialization,
//! never a decryption.
//!
//! The recovery envelope is part of the *vault*, not of whichever server row
//! happens to exist. Shipping it is what makes one recovery file work on every
//! instance of a vault id: import registers these exact values instead of
//! minting a fresh secret, so the file the user saved at creation keeps working
//! after a restore onto another server.
//!
//! The JSON shape must stay byte-compatible with the client's
//! `createVoultPackage` (`apps/client/src/lib/crypto/vault.ts`) and
//! `VoultPackage` (`apps/client/src/lib/state/type.ts`), because
//! the client's restore path parses this document to recover a vault on a new
//! device. The unit tests below pin that contract.

use serde::Serialize;

use crate::entity::vault;

/// Bump only in lockstep with `PACKAGE_FORMAT_VERSION` in
/// `apps/client/src/lib/crypto/vault.ts`. Version 2 added `recoveryEnvelope`.
const PACKAGE_FORMAT_VERSION: u32 = 2;

/// Why a package could not be produced. These are surfaced verbatim to the
/// client as `sync_status`/`last_mirror_error`, so they stay short, stable, and
/// free of provider detail, ciphertext, or key material.
pub const ERR_MISSING_ENVELOPE: &str = "MISSING_KEY_ENVELOPE";
pub const ERR_LEGACY_CRYPTO: &str = "LEGACY_CRYPTO_VERSION";
/// The row has no recovery material, so a package built from it could not
/// reproduce the vault's recovery path. Every row created through the API
/// carries recovery, so this is a defensive guard rather than a real state.
pub const ERR_MISSING_RECOVERY: &str = "MISSING_RECOVERY";

#[derive(Serialize)]
struct CryptoParameters {
    salt: String,
    iterations: i32,
}

#[derive(Serialize)]
struct Snapshot {
    ciphertext: String,
    iv: String,
}

#[derive(Serialize)]
struct PasswordKeyEnvelope {
    #[serde(rename = "wrappedVaultKey")]
    wrapped_vault_key: String,
    iv: String,
}

/// The recovery material, carried so the vault's recovery key is portable.
///
/// Every field is already public-ish metadata the server stores for the vault:
/// the HKDF salt, the non-invertible HMAC verifier, and the AES-GCM envelope
/// holding `vaultKeyRaw` under `K_rec`. None of it is a secret the server holds
/// alone, and none of it can be opened without the recovery file the user kept.
#[derive(Serialize)]
struct RecoveryEnvelope {
    /// HKDF salt (base64) for `K_rec`. Served pre-auth by
    /// `GET /get_crypto_params`; carried here so a restore keeps the same salt.
    salt: String,
    /// `HMAC-SHA256(K_rec, "recovery-verify-v1")`, base64. The server's second
    /// authentication path, which it validates without holding the secret.
    verifier: String,
    /// AES-GCM envelope of `vaultKeyRaw` under `K_rec` (Rule R1: raw key, not a
    /// password-derived key), AAD-bound to the vault id.
    #[serde(rename = "wrappedVaultKey")]
    wrapped_vault_key: String,
    iv: String,
}

#[derive(Serialize)]
struct VoultPackage {
    #[serde(rename = "packageFormatVersion")]
    package_format_version: u32,
    #[serde(rename = "vaultId")]
    vault_id: String,
    #[serde(rename = "logicalRevision")]
    logical_revision: i32,
    #[serde(rename = "cryptoVersion")]
    crypto_version: i32,
    #[serde(rename = "cryptoParameters")]
    crypto_parameters: CryptoParameters,
    snapshot: Snapshot,
    #[serde(rename = "passwordKeyEnvelope")]
    password_key_envelope: PasswordKeyEnvelope,
    #[serde(rename = "recoveryEnvelope")]
    recovery_envelope: RecoveryEnvelope,
}

/// Metadata the server can read out of a package document without decrypting
/// anything. The outer envelope is plaintext by design — the *contents* are the
/// ciphertext. Used to (a) verify a client-uploaded package belongs to the vault
/// being enrolled and (b) learn which logical revision a provider copy holds.
#[derive(serde::Deserialize, Debug, PartialEq)]
pub struct PackageHeader {
    #[serde(rename = "packageFormatVersion")]
    pub package_format_version: u32,
    #[serde(rename = "vaultId")]
    pub vault_id: String,
    #[serde(rename = "logicalRevision")]
    pub logical_revision: i32,
}

/// Parses only the outer envelope of a package document. Rejects any document
/// whose `vaultId` does not match `expected_vault_id`, so a package can never
/// be attributed to the wrong vault.
pub fn parse_header(bytes: &[u8], expected_vault_id: &str) -> Result<PackageHeader, &'static str> {
    let header: PackageHeader =
        serde_json::from_slice(bytes).map_err(|_| "PACKAGE_INVALID_JSON")?;
    if header.package_format_version != PACKAGE_FORMAT_VERSION {
        return Err("PACKAGE_UNSUPPORTED_VERSION");
    }
    if header.vault_id != expected_vault_id {
        return Err("PACKAGE_VAULT_MISMATCH");
    }
    Ok(header)
}

/// Serializes the committed server-side vault state as an encrypted package.
///
/// Fails when the password-wrapped envelope is absent: without it the package
/// is unrestorable on a new device, so writing it to a provider would be a
/// backup in name only. That is the case for legacy `crypto_version = 1` vaults, which the
/// client migrates to v2 on first password login.
///
/// Also fails when recovery material is absent, so a restored vault always keeps
/// its original recovery file rather than silently acquiring a new one.
pub fn build(vault: &vault::Model) -> Result<Vec<u8>, &'static str> {
    let (Some(wrapped_vault_key), Some(wrap_iv)) = (
        vault.vault_key_wrap.as_ref(),
        vault.vault_key_wrap_iv.as_ref(),
    ) else {
        return Err(if vault.crypto_version < 2 {
            ERR_LEGACY_CRYPTO
        } else {
            ERR_MISSING_ENVELOPE
        });
    };

    let (Some(recovery_salt), Some(recovery_verifier), Some(recovery_wrap), Some(recovery_wrap_iv)) = (
        vault.recovery_salt.as_ref(),
        vault.recovery_verifier.as_ref(),
        vault.recovery_wrap.as_ref(),
        vault.recovery_wrap_iv.as_ref(),
    ) else {
        return Err(ERR_MISSING_RECOVERY);
    };

    let pkg = VoultPackage {
        package_format_version: PACKAGE_FORMAT_VERSION,
        vault_id: vault.id.clone(),
        logical_revision: vault.version,
        crypto_version: vault.crypto_version,
        crypto_parameters: CryptoParameters {
            salt: vault.salt.clone(),
            iterations: vault.iterations,
        },
        snapshot: Snapshot {
            ciphertext: vault.vault.clone(),
            iv: vault.vaultiv.clone(),
        },
        password_key_envelope: PasswordKeyEnvelope {
            wrapped_vault_key: wrapped_vault_key.clone(),
            iv: wrap_iv.clone(),
        },
        recovery_envelope: RecoveryEnvelope {
            salt: recovery_salt.clone(),
            verifier: recovery_verifier.clone(),
            wrapped_vault_key: recovery_wrap.clone(),
            iv: recovery_wrap_iv.clone(),
        },
    };

    serde_json::to_vec(&pkg).map_err(|_| "PACKAGE_SERIALIZE_FAILED")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_vault() -> vault::Model {
        vault::Model {
            id: "11111111-2222-4333-8444-555555555555".to_string(),
            vault: "Y2lwaGVydGV4dA==".to_string(),
            salt: "c2FsdA==".to_string(),
            iterations: 60_000,
            vaultiv: "aXY=".to_string(),
            vault_verifier: "dmVyaWZpZXI=".to_string(),
            created_at: chrono::Utc::now(),
            version: 7,
            crypto_version: 2,
            vault_key_wrap: Some("d3JhcA==".to_string()),
            vault_key_wrap_iv: Some("d2l2".to_string()),
            recovery_verifier: Some("cmVjb3ZlcnktdmVyaWZpZXI=".to_string()),
            recovery_salt: Some("cmVjb3Zlcnktc2FsdA==".to_string()),
            recovery_wrap: Some("cmVjb3Zlcnktd3JhcA==".to_string()),
            recovery_wrap_iv: Some("cmVjdml2".to_string()),
            recovery_created_at: Some(chrono::Utc::now()),
            credential_version: 0,
            lock_epoch: 0,
        }
    }

    #[test]
    fn package_matches_client_shape() {
        let bytes = build(&sample_vault()).expect("package builds");
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Field names are the client's camelCase contract; a rename here would
        // silently break provider-side restore on another device.
        assert_eq!(json["packageFormatVersion"], 2);
        assert_eq!(json["vaultId"], "11111111-2222-4333-8444-555555555555");
        assert_eq!(json["logicalRevision"], 7);
        assert_eq!(json["cryptoVersion"], 2);
        assert_eq!(json["cryptoParameters"]["salt"], "c2FsdA==");
        assert_eq!(json["cryptoParameters"]["iterations"], 60_000);
        assert_eq!(json["snapshot"]["ciphertext"], "Y2lwaGVydGV4dA==");
        assert_eq!(json["snapshot"]["iv"], "aXY=");
        assert_eq!(json["passwordKeyEnvelope"]["wrappedVaultKey"], "d3JhcA==");
        assert_eq!(json["passwordKeyEnvelope"]["iv"], "d2l2");
        assert_eq!(json["recoveryEnvelope"]["salt"], "cmVjb3Zlcnktc2FsdA==");
        assert_eq!(
            json["recoveryEnvelope"]["verifier"],
            "cmVjb3ZlcnktdmVyaWZpZXI="
        );
        assert_eq!(
            json["recoveryEnvelope"]["wrappedVaultKey"],
            "cmVjb3Zlcnktd3JhcA=="
        );
        assert_eq!(json["recoveryEnvelope"]["iv"], "cmVjdml2");
    }

    #[test]
    fn header_round_trips_and_binds_vault_id() {
        let bytes = build(&sample_vault()).unwrap();
        let header = parse_header(&bytes, "11111111-2222-4333-8444-555555555555").unwrap();
        assert_eq!(header.logical_revision, 7);

        // A package for another vault must never be attributed to this one.
        assert_eq!(
            parse_header(&bytes, "99999999-2222-4333-8444-555555555555"),
            Err("PACKAGE_VAULT_MISMATCH")
        );
    }

    #[test]
    fn missing_envelope_is_rejected() {
        let mut v = sample_vault();
        v.vault_key_wrap = None;
        assert_eq!(build(&v), Err(ERR_MISSING_ENVELOPE));

        // Legacy v1 vaults report the distinct reason so Settings can explain it.
        let mut legacy = sample_vault();
        legacy.crypto_version = 1;
        legacy.vault_key_wrap = None;
        legacy.vault_key_wrap_iv = None;
        assert_eq!(build(&legacy), Err(ERR_LEGACY_CRYPTO));
    }

    /// A package without recovery material could restore a vault that no longer
    /// answers to the user's original recovery file, so it is refused rather
    /// than written.
    #[test]
    fn missing_recovery_is_rejected() {
        let mut v = sample_vault();
        v.recovery_wrap = None;
        assert_eq!(build(&v), Err(ERR_MISSING_RECOVERY));

        let mut no_verifier = sample_vault();
        no_verifier.recovery_verifier = None;
        assert_eq!(build(&no_verifier), Err(ERR_MISSING_RECOVERY));
    }

    /// A package mirrored after POST /recovery/rewrap must carry the NEW
    /// password envelope. That is correct, not a bug: recovery rotates the
    /// password credential, so restoring this backup needs the new password and
    /// must reject the old one. Pins that `build` reads the row's current
    /// envelope rather than anything cached from before the rewrap.
    #[test]
    fn package_after_rewrap_carries_the_new_password_envelope() {
        let mut post = sample_vault();
        // What rewrap writes: new salt/iterations/verifier + new envelope.
        post.salt = "bmV3LXNhbHQ=".to_string();
        post.iterations = 120_000;
        post.vault_verifier = "bmV3LXZlcmlmaWVy".to_string();
        post.vault_key_wrap = Some("bmV3LWdyYXA=".to_string());
        post.vault_key_wrap_iv = Some("bmV3LWl2".to_string());
        // ...and what it must NOT touch.
        post.vault = "Y2lwaGVydGV4dA==".to_string();
        post.vaultiv = "aXY=".to_string();
        post.version = 7;
        post.lock_epoch = 0;
        post.credential_version = 1;

        let json: serde_json::Value =
            serde_json::from_slice(&build(&post).expect("package builds")).unwrap();

        assert_eq!(json["cryptoParameters"]["salt"], "bmV3LXNhbHQ=");
        assert_eq!(json["cryptoParameters"]["iterations"], 120_000);
        assert_eq!(
            json["passwordKeyEnvelope"]["wrappedVaultKey"],
            "bmV3LWdyYXA="
        );
        assert_eq!(json["passwordKeyEnvelope"]["iv"], "bmV3LWl2");
        // Ciphertext and revision are untouched by a credential rotation.
        assert_eq!(json["snapshot"]["ciphertext"], "Y2lwaGVydGV4dA==");
        assert_eq!(json["logicalRevision"], 7);
    }

    /// Recovery material travels WITH the backup. A package is a portable
    /// recovery kit: restoring it must reproduce the vault's recovery key, not
    /// mint a fresh one, or the same vault id would answer to a different
    /// recovery file on every server it is restored to.
    #[test]
    fn package_carries_recovery_material() {
        let bytes = build(&sample_vault()).expect("package builds");
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        let envelope = json
            .get("recoveryEnvelope")
            .expect("package must carry the recovery envelope");
        assert_eq!(envelope["salt"], "cmVjb3Zlcnktc2FsdA==");
        assert_eq!(envelope["verifier"], "cmVjb3ZlcnktdmVyaWZpZXI=");
        assert_eq!(envelope["wrappedVaultKey"], "cmVjb3Zlcnktd3JhcA==");
        assert_eq!(envelope["iv"], "cmVjdml2");
    }
}
