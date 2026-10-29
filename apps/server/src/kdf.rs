//! Password KDF profiles — the server-side mirror of
//! `packages/vault-core/src/kdf.ts`.
//!
//! The server never runs the KDF. It stores the descriptor, validates that it is
//! a published profile, and enforces that a credential rotation cannot move to a
//! weaker one. The ladder must stay in lockstep with the TypeScript registry:
//! an unknown tuple is rejected with `KDF_UNKNOWN`, never interpreted.
//!
//! There is no legacy algorithm. PBKDF2 was removed with the clean-start schema
//! change; every vault row carries an Argon2id descriptor.

use serde::{Deserialize, Serialize};

/// The password KDF parameters stored in `vault.kdf` and returned on the wire.
///
/// Serialized with the algorithm as an internal tag:
/// `{"algorithm":"argon2id","memory_kib":65536,"time_cost":3,"parallelism":1}`.
/// Field order is the declaration order, so `to_stored` is canonical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "algorithm")]
pub enum KdfParams {
    #[serde(rename = "argon2id")]
    Argon2id {
        memory_kib: u32,
        time_cost: u32,
        parallelism: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// A well-formed descriptor that is not one of the published rungs.
    Unknown,
    /// The stored column is missing/corrupt JSON. A server bug, not caller input.
    InvalidStored,
}

const LADDER: [KdfParams; 3] = [
    // 19 MiB / t=2 — OWASP minimum, the hard floor.
    KdfParams::Argon2id {
        memory_kib: 19_456,
        time_cost: 2,
        parallelism: 1,
    },
    // 32 MiB / t=3 — default before calibration.
    KdfParams::Argon2id {
        memory_kib: 32_768,
        time_cost: 3,
        parallelism: 1,
    },
    // 64 MiB / t=3 — RFC 9106 low-memory shape, p reduced to 1.
    KdfParams::Argon2id {
        memory_kib: 65_536,
        time_cost: 3,
        parallelism: 1,
    },
];

impl KdfParams {
    /// The published ladder, cheapest first. Append-only.
    pub fn ladder() -> &'static [KdfParams] {
        &LADDER
    }

    /// The lowest acceptable profile. Test fixtures use it; production code
    /// never needs to construct it (the client always sends a concrete rung).
    #[allow(dead_code)]
    pub fn floor() -> Self {
        LADDER[0].clone()
    }

    /// Parses the canonical JSON stored in `vault.kdf`.
    ///
    /// An off-ladder tuple is treated as corrupt storage, not as a valid
    /// descriptor the caller may interpret: every write path validates first,
    /// so a row that does not match the ladder is a server integrity bug.
    pub fn parse_stored(raw: &str) -> Result<Self, KdfError> {
        let kdf: Self = serde_json::from_str(raw).map_err(|_| KdfError::InvalidStored)?;
        if kdf.is_known() {
            Ok(kdf)
        } else {
            Err(KdfError::InvalidStored)
        }
    }

    /// Canonical storage form. Used for every write so the column cannot drift.
    pub fn to_stored(&self) -> String {
        serde_json::to_string(self).expect("KdfParams is always serializable")
    }

    pub fn is_known(&self) -> bool {
        LADDER.contains(self)
    }

    /// Rejects anything that is not an exact published rung.
    pub fn validate_for_write(&self) -> Result<(), KdfError> {
        if self.is_known() {
            Ok(())
        } else {
            Err(KdfError::Unknown)
        }
    }

    /// 1-based ladder position, or 0 for anything unknown.
    ///
    /// Policy order over published profiles, not a measured comparison between
    /// parameter sets. A rotation may move to an equal or higher rank only.
    pub fn rank(&self) -> u8 {
        Self::ladder()
            .iter()
            .position(|rung| rung == self)
            .map(|index| (index + 1) as u8)
            .unwrap_or(0)
    }

    /// Short, non-secret label for logs and error messages.
    pub fn describe(&self) -> String {
        match self {
            KdfParams::Argon2id {
                memory_kib,
                time_cost,
                parallelism,
            } => format!(
                "argon2id m={}KiB t={} p={}",
                memory_kib, time_cost, parallelism
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ladder_is_monotonic_and_pinned() {
        // Pinned so the Rust allowlist cannot drift from the TypeScript registry
        // without a test failing. The three tuples are the contract.
        assert_eq!(KdfParams::ladder().len(), 3);
        assert_eq!(
            KdfParams::ladder()[0],
            KdfParams::Argon2id {
                memory_kib: 19_456,
                time_cost: 2,
                parallelism: 1
            }
        );
        assert_eq!(
            KdfParams::ladder()[1],
            KdfParams::Argon2id {
                memory_kib: 32_768,
                time_cost: 3,
                parallelism: 1
            }
        );
        assert_eq!(
            KdfParams::ladder()[2],
            KdfParams::Argon2id {
                memory_kib: 65_536,
                time_cost: 3,
                parallelism: 1
            }
        );

        let mut previous = 0;
        for rung in KdfParams::ladder() {
            let KdfParams::Argon2id {
                memory_kib,
                time_cost,
                ..
            } = rung;
            let cost = memory_kib * time_cost;
            assert!(cost > previous, "ladder must be monotonic in cost");
            previous = cost;
        }
    }

    #[test]
    fn storage_round_trips_canonically() {
        let raw = r#"{"algorithm":"argon2id","memory_kib":65536,"time_cost":3,"parallelism":1}"#;
        let parsed = KdfParams::parse_stored(raw).expect("parses");
        assert_eq!(parsed.to_stored(), raw);
    }

    #[test]
    fn rejects_off_ladder_and_malformed_descriptors() {
        let cases = [
            r#"{"algorithm":"pbkdf2-sha256","iterations":60000}"#,
            r#"{"algorithm":"argon2id","memory_kib":19457,"time_cost":2,"parallelism":1}"#,
            r#"{"algorithm":"argon2id","memory_kib":65536,"time_cost":3,"parallelism":4}"#,
            r#"{"algorithm":"argon2id","memory_kib":0,"time_cost":3,"parallelism":1}"#,
            r#"{}"#,
        ];
        for raw in cases {
            assert_eq!(
                KdfParams::parse_stored(raw),
                Err(KdfError::InvalidStored),
                "{raw}"
            );
        }
        assert_eq!(
            KdfParams::parse_stored("not json"),
            Err(KdfError::InvalidStored)
        );
    }

    #[test]
    fn ranks_and_floor() {
        assert_eq!(KdfParams::floor().rank(), 1);
        assert_eq!(KdfParams::ladder()[1].rank(), 2);
        assert_eq!(KdfParams::ladder()[2].rank(), 3);
        let off = KdfParams::Argon2id {
            memory_kib: 19_457,
            time_cost: 2,
            parallelism: 1,
        };
        assert_eq!(off.rank(), 0);
        assert_eq!(off.validate_for_write(), Err(KdfError::Unknown));
    }
}
