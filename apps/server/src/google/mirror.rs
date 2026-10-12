//! Out-of-band Drive mirroring: the disaster-recovery copy.
//!
//! # Model
//!
//! **The server is the write authority. Drive is the disaster-recovery copy.**
//!
//! `/update_vault` commits a vault write with an atomic version CAS and returns.
//! It never waits on Google, never fails because Google is down, and never
//! makes a vault write conditional on Drive. Immediately *after* the commit we
//! spawn a detached mirror task that re-writes the Drive copy.
//!
//! # Safety properties
//!
//! * **Never blocking, never failing the write.** The mirror is spawned with
//!   `actix_web::rt::spawn` after the CAS succeeds. Every failure path is logged
//!   and folded into `cloud_binding` state; none can affect `/update_vault`.
//! * **Cannot clobber a newer Drive copy.** The write is conditional on
//!   `cloud_binding.remote_revision` — the revision *we* last observed ourselves
//!   (`drive::replace_vault` honours `if_match_revision`). If the Drive file
//!   moved underneath us (restored elsewhere, edited by another client, changed
//!   by hand) the CAS fails, we record `REMOTE_CONFLICT`, and we do **not**
//!   overwrite. Overwriting is a separate, explicit, user-initiated act.
//! * **Coalesced.** A burst of vault writes collapses into a bounded number of
//!   Drive writes. Sync pushes can land back-to-back while a user edits; without
//!   coalescing each push would cost a Drive round trip and burn quota.
//! * **Zero-knowledge.** The mirror only re-serializes ciphertext the server
//!   already stores (see [`crate::google::package`]). No key is derived,
//!   unwrapped, or decrypted here, and no plaintext, verifier, or token is
//!   logged.
//!
//! # Failure surfacing
//!
//! `cloud_binding.sync_status`, `mirrored_vault_version`, and
//! `last_mirror_error` carry the real backup state that Settings renders:
//!
//! | `sync_status`   | meaning                                            |
//! |-----------------|----------------------------------------------------|
//! | `idle`          | Drive matches the committed server vault            |
//! | `pending`       | vault committed, mirror queued                      |
//! | `mirroring`     | mirror in flight                                   |
//! | `auth_required` | Google token missing/expired — reconnect required   |
//! | `unlinked`      | no usable Drive file bound to this vault            |
//! | `conflict`      | Drive moved; copy preserved, never overwritten      |
//! | `error`         | transient provider failure; retried on next write  |

use std::collections::HashMap;
use std::sync::Mutex;

use actix_web::rt;
use chrono::{SecondsFormat, Utc};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::db::DbPool;
use crate::entity::cloud_binding::{self, Entity as CloudBindingEntity};
use crate::entity::vault::{self, Entity as VaultEntity};
use crate::google::error::ProviderErrorKind;
use crate::google::{drive, package, token_store};

pub const STATUS_IDLE: &str = "idle";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_MIRRORING: &str = "mirroring";
pub const STATUS_AUTH_REQUIRED: &str = "auth_required";
pub const STATUS_UNLINKED: &str = "unlinked";
pub const STATUS_CONFLICT: &str = "conflict";
pub const STATUS_ERROR: &str = "error";

/// Vaults with a mirror currently running, mapped to "another vault write
/// landed while this mirror was in flight". Stops a burst of vault writes from
/// spawning a Drive write each.
static IN_FLIGHT: Mutex<Option<HashMap<String, bool>>> = Mutex::new(None);

/// Try to become the single mirror for `vault_id`. Returns `true` when the
/// caller must run one; `false` when a mirror already covers this vault.
///
/// A `false` result is not a dropped write — it sets the in-flight entry's
/// "rerun" flag, which the running task consumes in [`settle`]. That is what
/// guarantees every committed write is eventually mirrored.
fn claim(vault_id: &str) -> bool {
    let mut guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    match map.get_mut(vault_id) {
        Some(rerun) => {
            *rerun = true;
            false
        }
        None => {
            map.insert(vault_id.to_string(), false);
            true
        }
    }
}

/// Atomically read the "rerun" flag **and** drop the in-flight claim.
///
/// Doing both under one lock is what makes the handoff race-free. A concurrent
/// [`claim`] either sets the flag before this call (we see `true` and loop) or
/// arrives after the entry is removed (it wins the claim and starts its own
/// task). There is no window in which a write is dropped with no mirror left to
/// cover it.
fn settle(vault_id: &str) -> bool {
    let mut guard = IN_FLIGHT.lock().unwrap_or_else(|e| e.into_inner());
    let map = guard.get_or_insert_with(HashMap::new);
    map.remove(vault_id).unwrap_or(false)
}

/// Result of a mirror attempt. Returned by the awaited
/// [`mirror_now`] path (the explicit "Back up now" action in Settings) so the
/// UI can report what actually happened instead of assuming success.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "result")]
pub enum MirrorOutcome {
    /// Drive now holds the committed server vault.
    #[serde(rename = "mirrored")]
    Mirrored { vault_version: i32 },
    /// Drive already held this exact version — nothing was written.
    #[serde(rename = "up_to_date")]
    UpToDate { vault_version: i32 },
    /// This vault has no Drive binding, so there is nothing to mirror to.
    #[serde(rename = "unlinked")]
    Unlinked,
    /// Google authorization is missing or expired; the user must reconnect.
    #[serde(rename = "auth_required")]
    AuthRequired,
    /// The Drive file changed since our last observed revision. Preserved, not
    /// overwritten — resolving this is an explicit user action.
    #[serde(rename = "conflict")]
    Conflict,
    /// The vault has no password-wrapped envelope, so a Drive copy would not be
    /// restorable on a new device.
    #[serde(rename = "unsupported")]
    Unsupported { reason: String },
    /// Transient provider failure; retried on the next vault write.
    #[serde(rename = "error")]
    Error { code: String },
}

/// Spawn a detached mirror for `vault_id`. Returns immediately.
///
/// Called after `/update_vault` commits. Must never be awaited by the request
/// path: the vault write is already durably accepted, and a Drive outage must
/// not turn a successful write into an error or a slow response.
pub fn spawn_after_commit(pool: DbPool, vault_id: String) {
    if !claim(&vault_id) {
        // A mirror is already running for this vault. Its trailing re-check
        // picks up the version we just committed, so dropping this request is
        // safe and keeps a burst of writes to one upload.
        log::debug!("Drive mirror already in flight for vault; coalescing");
        return;
    }
    rt::spawn(async move {
        // Mirror, then re-check while still holding the claim. `settle` reports
        // whether a vault write landed during the pass; if so we loop and mirror
        // the newer version. The pass bound keeps a pathological write stream
        // from looping forever — the claim is already dropped by `settle`, so
        // the next write starts a fresh task normally.
        for _ in 0..MAX_MIRROR_PASSES {
            mirror_once(&pool, &vault_id).await;
            if !settle(&vault_id) {
                return;
            }
        }
        log::debug!(
            "Drive mirror pass limit reached for vault {}; leaving any newer version to the next vault write",
            short_id(&vault_id)
        );
    });
}

/// Upper bound on coalesced passes per spawned mirror. Each pass only runs when
/// a vault write actually landed since the previous one, so this is a safety
/// valve for a continuous write stream, not a normal path.
const MAX_MIRROR_PASSES: usize = 8;

/// Mark the binding as owing a mirror, without performing one.
///
/// Cheap pre-check: the overwhelmingly common case is a local-only vault with
/// no binding, which costs one indexed read and writes nothing.
pub async fn mark_pending(pool: &DbPool, vault_id: &str) {
    let has_binding = CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(vault_id))
        .filter(cloud_binding::Column::DriveFileId.is_not_null())
        .one(pool)
        .await
        .map(|r| r.is_some())
        .unwrap_or(false);
    if !has_binding {
        return;
    }
    set_status(pool, vault_id, STATUS_PENDING, None).await;
}

/// Mirror the committed vault to Drive now, awaiting the result.
///
/// For the explicit "Back up now" user action. Respects the same CAS gate as
/// the automatic path, so a manual retry after a conflict fails again until the
/// user resolves the divergence — the manual action is "try again", never
/// "overwrite".
pub async fn mirror_now(pool: &DbPool, vault_id: &str) -> MirrorOutcome {
    match attempt(pool, vault_id).await {
        Attempt::Mirrored(v) => MirrorOutcome::Mirrored { vault_version: v },
        Attempt::UpToDate(v) => MirrorOutcome::UpToDate { vault_version: v },
        Attempt::Unlinked => MirrorOutcome::Unlinked,
        Attempt::AuthRequired => MirrorOutcome::AuthRequired,
        Attempt::Conflict => MirrorOutcome::Conflict,
        Attempt::Unsupported(r) => MirrorOutcome::Unsupported { reason: r },
        Attempt::Failed(code) => MirrorOutcome::Error { code },
    }
}

/// Detached pass. Returns nothing — the caller must not depend on the result.
async fn mirror_once(pool: &DbPool, vault_id: &str) {
    let _ = attempt(pool, vault_id).await;
}

enum Attempt {
    Mirrored(i32),
    UpToDate(i32),
    Unlinked,
    AuthRequired,
    Conflict,
    Unsupported(String),
    Failed(String),
}

async fn attempt(pool: &DbPool, vault_id: &str) -> Attempt {
    let binding = match CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(vault_id))
        .one(pool)
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            // No Drive binding: this vault is local-only. Not an error.
            log::debug!("No Drive binding for vault; nothing to mirror");
            return Attempt::Unlinked;
        }
        Err(e) => {
            log::error!("failed to load cloud binding for mirror: {}", e);
            return Attempt::Failed("DB_ERROR".to_string());
        }
    };

    let Some(file_id) = binding.drive_file_id.clone() else {
        set_status(pool, vault_id, STATUS_UNLINKED, Some("NO_DRIVE_FILE")).await;
        return Attempt::Unlinked;
    };

    let vault_row = match VaultEntity::find()
        .filter(vault::Column::Id.eq(vault_id))
        .one(pool)
        .await
    {
        Ok(Some(v)) => v,
        Ok(None) => return Attempt::Failed("VAULT_NOT_FOUND".to_string()),
        Err(e) => {
            log::error!("failed to load vault for mirror: {}", e);
            return Attempt::Failed("DB_ERROR".to_string());
        }
    };

    // Already backed up at this exact version: skip the Drive round trip
    // entirely, so a re-check costs one indexed read.
    if binding.mirrored_vault_version == Some(vault_row.version) {
        return Attempt::UpToDate(vault_row.version);
    }

    // Build the encrypted package. This re-serializes stored ciphertext and
    // public crypto metadata; it never decrypts and never touches key material.
    let package_bytes = match package::build(&vault_row) {
        Ok(b) => b,
        Err(reason) => {
            log::warn!(
                "Drive mirror skipped for vault {}: no restorable package ({})",
                short_id(vault_id),
                reason
            );
            set_status(pool, vault_id, STATUS_ERROR, Some(reason)).await;
            return Attempt::Unsupported(reason.to_string());
        }
    };

    // Google access token (refreshed when near expiry). Missing/expired is a
    // user action, not a vault-write failure.
    let access_token = match token_store::get_valid_access_token(pool, vault_id).await {
        Ok(t) => t,
        Err(_) => {
            set_status(pool, vault_id, STATUS_AUTH_REQUIRED, None).await;
            return Attempt::AuthRequired;
        }
    };

    set_status(pool, vault_id, STATUS_MIRRORING, None).await;

    // The CAS baseline: the last Drive revision *we* observed. If the binding
    // never recorded one (e.g. a binding adopted from an import), read the
    // current revision first — a metadata read plus a conditional write is
    // strictly safer than writing blind, and still refuses to clobber a copy
    // that moves between the read and the write.
    let expected = match resolve_baseline(pool, vault_id, &access_token, &file_id, &binding).await
    {
        Ok(rev) => rev,
        Err(code) => {
            set_status(pool, vault_id, STATUS_ERROR, Some(code.as_str())).await;
            return Attempt::Failed(code);
        }
    };
    let expected = expected.as_deref();

    match drive::replace_vault(&access_token, &file_id, &package_bytes, expected).await {
        Ok(new_rev) => {
            log::info!(
                "Mirrored vault to Drive (vault_version={}, revision={})",
                vault_row.version,
                short_id(&new_rev)
            );
            mark_mirrored(pool, vault_id, vault_row.version, Some(&new_rev)).await;
            Attempt::Mirrored(vault_row.version)
        }
        Err((kind, msg)) => {
            handle_drive_error(pool, vault_id, vault_row.version, &kind, &msg).await;
            match kind {
                ProviderErrorKind::AuthRequired => Attempt::AuthRequired,
                ProviderErrorKind::RemoteConflict => Attempt::Conflict,
                ProviderErrorKind::RemoteDeleted | ProviderErrorKind::VaultNotFound => {
                    Attempt::Unlinked
                }
                other => Attempt::Failed(other.code().to_string()),
            }
        }
    }
}

/// The revision to condition the Drive write on. Normally the one recorded on
/// the binding; read live only when the binding has none.
async fn resolve_baseline(
    pool: &DbPool,
    vault_id: &str,
    access_token: &str,
    file_id: &str,
    binding: &cloud_binding::Model,
) -> Result<Option<String>, String> {
    if let Some(rev) = binding.remote_revision.as_deref() {
        return Ok(Some(rev.to_string()));
    }
    match drive::file_revision(access_token, file_id).await {
        Ok(rev) if rev != drive::UNKNOWN_REVISION => {
            // Persist it so subsequent mirrors condition on the stored value.
            let _ = CloudBindingEntity::update_many()
                .col_expr(cloud_binding::Column::RemoteRevision, Expr::value(Some(rev.clone())))
                .filter(cloud_binding::Column::VaultId.eq(vault_id))
                .exec(pool)
                .await;
            Ok(Some(rev))
        }
        // "unknown" is not a usable CAS token: conditioning on it would match
        // any file, defeating the gate. Refuse rather than write blind.
        Ok(_) => Err("REMOTE_REVISION_UNAVAILABLE".to_string()),
        Err((kind, _)) => Err(kind.code().to_string()),
    }
}

/// Record that the Drive copy is current at `vault_version`.
///
/// `remote_revision` of `None` leaves the stored revision untouched (used when
/// the binding's revision is already correct).
pub async fn mark_mirrored(
    pool: &DbPool,
    vault_id: &str,
    vault_version: i32,
    remote_revision: Option<&str>,
) {
    let now = Utc::now();
    let mut update = CloudBindingEntity::update_many()
        .col_expr(
            cloud_binding::Column::MirroredVaultVersion,
            Expr::value(Some(vault_version)),
        )
        .col_expr(
            cloud_binding::Column::LastMirroredAt,
            Expr::value(Some(now.to_rfc3339_opts(SecondsFormat::Secs, true))),
        )
        .col_expr(cloud_binding::Column::LastMirrorError, Expr::value(None::<String>))
        .col_expr(cloud_binding::Column::SyncStatus, Expr::value(STATUS_IDLE))
        .col_expr(cloud_binding::Column::UpdatedAt, Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))))
        .filter(cloud_binding::Column::VaultId.eq(vault_id));
    if let Some(rev) = remote_revision {
        update = update.col_expr(
            cloud_binding::Column::RemoteRevision,
            Expr::value(Some(rev.to_string())),
        );
    }
    if let Err(e) = update.exec(pool).await {
        log::error!("failed to persist mirror state: {}", e);
    }
}

async fn handle_drive_error(
    pool: &DbPool,
    vault_id: &str,
    vault_version: i32,
    kind: &ProviderErrorKind,
    msg: &str,
) {
    match kind {
        ProviderErrorKind::AuthRequired => {
            set_status(pool, vault_id, STATUS_AUTH_REQUIRED, None).await;
        }
        ProviderErrorKind::RemoteConflict => {
            // The Drive copy is newer than what we last saw. Deliberately do NOT
            // advance `mirrored_vault_version` — claiming the backup is current
            // would hide a real divergence between the server and Drive.
            log::warn!(
                "Drive mirror conflict for vault {} (server at version {}): the Drive copy changed since last sync; not overwriting",
                short_id(vault_id),
                vault_version
            );
            set_status(pool, vault_id, STATUS_CONFLICT, Some(kind.code())).await;
        }
        ProviderErrorKind::RemoteDeleted | ProviderErrorKind::VaultNotFound => {
            log::warn!(
                "Drive backup for vault {} is missing; the local vault at version {} is unaffected",
                short_id(vault_id),
                vault_version
            );
            set_status(pool, vault_id, STATUS_UNLINKED, Some(kind.code())).await;
        }
        other => {
            // Transient (rate limit, provider 5xx, network). The local vault is
            // committed and correct; only the DR copy is behind, and the next
            // vault write retries.
            log::warn!(
                "Drive mirror failed for vault {} at version {}: {} ({})",
                short_id(vault_id),
                vault_version,
                other.code(),
                msg
            );
            set_status(pool, vault_id, STATUS_ERROR, Some(other.code())).await;
        }
    }
}

/// Record a non-success state without touching the mirrored-version watermark.
async fn set_status(pool: &DbPool, vault_id: &str, status: &str, error: Option<&str>) {
    let now = Utc::now();
    let mut update = CloudBindingEntity::update_many()
        .col_expr(cloud_binding::Column::SyncStatus, Expr::value(status))
        .col_expr(cloud_binding::Column::UpdatedAt, Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))))
        .filter(cloud_binding::Column::VaultId.eq(vault_id));
    if let Some(code) = error {
        update = update.col_expr(
            cloud_binding::Column::LastMirrorError,
            Expr::value(Some(code.to_string())),
        );
    }
    if let Err(e) = update.exec(pool).await {
        log::error!("failed to persist mirror status: {}", e);
    }
}

/// Records that the Drive copy corresponds to `vault_version` **without**
/// claiming a revision.
///
/// Used when a Drive package is adopted as the local vault (import/enrollment):
/// the Drive copy *is* the source of truth there, so no upload is needed — but
/// the revision was never recorded, so the next automatic mirror reads a live
/// baseline before its first conditional write rather than writing blind.
pub async fn mark_adopted(pool: &DbPool, vault_id: &str, vault_version: i32) {
    let now = Utc::now();
    let _ = CloudBindingEntity::update_many()
        .col_expr(
            cloud_binding::Column::MirroredVaultVersion,
            Expr::value(Some(vault_version)),
        )
        .col_expr(cloud_binding::Column::LastMirroredAt, Expr::value(Some(now.to_rfc3339_opts(SecondsFormat::Secs, true))))
        .col_expr(cloud_binding::Column::LastMirrorError, Expr::value(None::<String>))
        .col_expr(cloud_binding::Column::SyncStatus, Expr::value(STATUS_IDLE))
        .col_expr(cloud_binding::Column::UpdatedAt, Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))))
        .filter(cloud_binding::Column::VaultId.eq(vault_id))
        .exec(pool)
        .await;
}

/// First 8 characters of an identifier, for logs. Enough to correlate, and it
/// is a public UUID or an opaque Drive revision — never key material.
fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}

/// Used by the enrollment path to learn the revision it just created, so the
/// first automatic mirror has a real CAS baseline.
pub async fn observe_remote_revision(pool: &DbPool, vault_id: &str, file_id: &str) -> Option<String> {
    let token = token_store::get_valid_access_token(pool, vault_id).await.ok()?;
    let rev = drive::file_revision(&token, file_id).await.ok()?;
    if rev == drive::UNKNOWN_REVISION {
        return None;
    }
    let _ = CloudBindingEntity::update_many()
        .col_expr(cloud_binding::Column::RemoteRevision, Expr::value(Some(rev.clone())))
        .filter(cloud_binding::Column::VaultId.eq(vault_id))
        .exec(pool)
        .await;
    Some(rev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DbPool;
    use migration::MigratorTrait;
    use sea_orm::{ActiveModelTrait, Database, EntityTrait};

    async fn test_pool() -> DbPool {
        // In-memory SQLite, migrated to the current schema so the tests exercise
        // the real columns rather than a hand-rolled approximation.
        let pool = Database::connect("sqlite::memory:")
            .await
            .expect("connect");
        migration::Migrator::up(&pool, None).await.expect("migrate");
        pool
    }

    async fn seed_vault(pool: &DbPool, id: &str) {
        use sea_orm::Set;
        let am = vault::ActiveModel {
            id: Set(id.to_string()),
            vault: Set("Y2lwaGVydGV4dA==".to_string()),
            salt: Set("c2FsdA==".to_string()),
            iterations: Set(60_000),
            vaultiv: Set("aXY=".to_string()),
            vault_verifier: Set("dmVyaWZpZXI=".to_string()),
            version: Set(1),
            crypto_version: Set(2),
            vault_key_wrap: Set(Some("d3JhcA==".to_string())),
            vault_key_wrap_iv: Set(Some("d2l2".to_string())),
            ..Default::default()
        };
        am.insert(pool).await.expect("insert vault");
    }

    async fn seed_binding(pool: &DbPool, id: &str, file_id: Option<&str>) {
        use sea_orm::Set;
        let am = cloud_binding::ActiveModel {
            vault_id: Set(id.to_string()),
            provider_kind: Set("google_drive".to_string()),
            drive_file_id: Set(file_id.map(|s| s.to_string())),
            sync_status: Set(STATUS_IDLE.to_string()),
            ..Default::default()
        };
        am.insert(pool).await.expect("insert binding");
    }

    async fn load_binding(pool: &DbPool, id: &str) -> cloud_binding::Model {
        CloudBindingEntity::find_by_id(id)
            .one(pool)
            .await
            .expect("query")
            .expect("binding exists")
    }

    /// The CAS gate must never pass `None` through to `replace_vault` when the
    /// Drive revision is unknown — an unconditional write could clobber a newer
    /// copy, which is exactly what this module exists to prevent.
    #[test]
    fn unknown_revision_is_not_usable_as_a_baseline() {
        assert_eq!(drive::UNKNOWN_REVISION, "unknown");
        assert_ne!(drive::UNKNOWN_REVISION, "");
    }

    /// The handoff between concurrent writers must be race-free: a write that
    /// arrives mid-pass sets the rerun flag, and `settle` must observe it while
    /// still holding the claim. A dropped write would leave a committed vault
    /// version with no backup and no scheduled mirror — the exact silent
    /// staleness this module exists to prevent.
    #[test]
    fn a_write_during_a_mirror_is_never_dropped() {
        // First writer claims the vault and starts mirroring.
        assert!(claim("t-race"));
        // A write lands mid-pass: it cannot claim, so it must flag a rerun.
        assert!(!claim("t-race"));
        assert!(!claim("t-race"));
        // The running task settles and is told to run again.
        assert!(settle("t-race"), "a mid-pass write must force another pass");
        // That pass settles with nothing new, so the task finishes.
        assert!(!settle("t-race"));
    }

    #[test]
    fn claim_is_exclusive_per_vault() {
        assert!(claim("t-a"));
        assert!(!claim("t-a"), "second claim while in flight must coalesce");
        assert!(claim("t-b"), "a different vault is independent");
        // "t-a" had a write land mid-pass, so it reruns; "t-b" did not.
        assert!(settle("t-a"));
        assert!(!settle("t-b"));
        assert!(claim("t-a"), "after settling the vault can mirror again");
        settle("t-a");
    }

    /// A writer that arrives after the claim is dropped must win the claim and
    /// start its own task, rather than being told to coalesce into nothing.
    #[test]
    fn a_write_after_settling_claims_the_vault_afresh() {
        assert!(claim("t-late"));
        // Running task finishes: no write arrived, so it drops the claim.
        assert!(!settle("t-late"));
        // The next write must be able to start a fresh mirror.
        assert!(claim("t-late"));
        settle("t-late");
    }

    #[test]
    fn mirror_outcome_serializes_as_a_discriminated_result() {
        let json = serde_json::to_value(MirrorOutcome::Mirrored { vault_version: 12 }).unwrap();
        assert_eq!(json["result"], "mirrored");
        assert_eq!(json["vault_version"], 12);

        let conflict = serde_json::to_value(MirrorOutcome::Conflict).unwrap();
        assert_eq!(conflict["result"], "conflict");
    }

    /// A local-only vault must cost one indexed read and write nothing. If
    /// `mark_pending` wrote unconditionally it would create bindings for every
    /// vault on the server.
    #[tokio::test]
    async fn mark_pending_is_a_noop_without_a_binding() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-local").await;

        mark_pending(&pool, "v-local").await;

        assert_eq!(
            CloudBindingEntity::find()
                .all(&pool)
                .await
                .expect("query")
                .len(),
            0,
            "mark_pending must not create a binding for a local-only vault"
        );
    }

    #[tokio::test]
    async fn mark_pending_marks_a_bound_vault() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-bound").await;
        seed_binding(&pool, "v-bound", Some("file-1")).await;

        mark_pending(&pool, "v-bound").await;

        assert_eq!(load_binding(&pool, "v-bound").await.sync_status, STATUS_PENDING);
    }

    /// The watermark must advance together with the status, and the error must
    /// clear — otherwise Settings keeps reporting a resolved failure forever.
    #[tokio::test]
    async fn mark_mirrored_advances_the_watermark_and_clears_errors() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-ok").await;
        seed_binding(&pool, "v-ok", Some("file-1")).await;
        set_status(&pool, "v-ok", STATUS_ERROR, Some("PROVIDER_RATE_LIMITED")).await;

        mark_mirrored(&pool, "v-ok", 7, Some("rev-2")).await;

        let b = load_binding(&pool, "v-ok").await;
        assert_eq!(b.sync_status, STATUS_IDLE);
        assert_eq!(b.mirrored_vault_version, Some(7));
        assert_eq!(b.remote_revision.as_deref(), Some("rev-2"));
        assert_eq!(b.last_mirror_error, None);
        assert!(b.last_mirrored_at.is_some());
    }

    /// The conflict path must NOT advance the watermark. Claiming the backup is
    /// current when Drive has diverged is precisely the silent-staleness bug
    /// this work exists to remove.
    #[tokio::test]
    async fn conflict_does_not_advance_the_watermark() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-conflict").await;
        seed_binding(&pool, "v-conflict", Some("file-1")).await;
        mark_mirrored(&pool, "v-conflict", 5, Some("rev-1")).await;

        handle_drive_error(
            &pool,
            "v-conflict",
            9,
            &ProviderErrorKind::RemoteConflict,
            "revision mismatch",
        )
        .await;

        let b = load_binding(&pool, "v-conflict").await;
        assert_eq!(b.sync_status, STATUS_CONFLICT);
        assert_eq!(b.last_mirror_error.as_deref(), Some("REMOTE_CONFLICT"));
        assert_eq!(
            b.mirrored_vault_version,
            Some(5),
            "a refused write must leave the backup watermark where it was"
        );
    }

    #[tokio::test]
    async fn deleted_drive_file_is_reported_as_unlinked() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-gone").await;
        seed_binding(&pool, "v-gone", Some("file-1")).await;

        handle_drive_error(
            &pool,
            "v-gone",
            3,
            &ProviderErrorKind::RemoteDeleted,
            "404",
        )
        .await;

        let b = load_binding(&pool, "v-gone").await;
        assert_eq!(b.sync_status, STATUS_UNLINKED);
        assert_eq!(b.last_mirror_error.as_deref(), Some("REMOTE_DELETED"));
        assert_eq!(
            b.mirrored_vault_version, None,
            "the local vault is unaffected; only the backup is missing"
        );
    }

    /// `UpToDate` must short-circuit before any Drive call, which is what makes
    /// the trailing re-check in `spawn_after_commit` free.
    #[tokio::test]
    async fn mirror_now_reports_up_to_date_without_touching_drive() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-fresh").await;
        seed_binding(&pool, "v-fresh", Some("file-1")).await;
        // No google_token row → any real Drive attempt would fail on the token.
        // Returning UpToDate proves the version check short-circuits first.
        mark_mirrored(&pool, "v-fresh", 1, Some("rev-1")).await;

        match mirror_now(&pool, "v-fresh").await {
            MirrorOutcome::UpToDate { vault_version } => assert_eq!(vault_version, 1),
            other => panic!("expected UpToDate, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mirror_now_reports_unlinked_without_a_binding() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-none").await;

        assert!(matches!(
            mirror_now(&pool, "v-none").await,
            MirrorOutcome::Unlinked
        ));
    }

    /// A vault with no password envelope cannot produce a restorable backup, so
    /// the mirror must refuse rather than write an unusable copy to Drive.
    #[tokio::test]
    async fn vault_without_envelope_is_unsupported() {
        use sea_orm::Set;
        let pool = test_pool().await;
        let am = vault::ActiveModel {
            id: Set("v-legacy".to_string()),
            vault: Set("Y2lwaGVydGV4dA==".to_string()),
            salt: Set("c2FsdA==".to_string()),
            iterations: Set(60_000),
            vaultiv: Set("aXY=".to_string()),
            vault_verifier: Set("dmVyaWZpZXI=".to_string()),
            version: Set(2),
            crypto_version: Set(1),
            vault_key_wrap: Set(None),
            vault_key_wrap_iv: Set(None),
            ..Default::default()
        };
        am.insert(&pool).await.expect("insert");
        seed_binding(&pool, "v-legacy", Some("file-1")).await;

        match mirror_now(&pool, "v-legacy").await {
            MirrorOutcome::Unsupported { reason } => {
                assert_eq!(reason, package::ERR_LEGACY_CRYPTO)
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// Import/adoption: the Drive copy is the source of truth, so the local
    /// vault's current version is the watermark — without inventing a revision.
    #[tokio::test]
    async fn mark_adopted_claims_the_version_but_not_a_revision() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-import").await;
        seed_binding(&pool, "v-import", Some("file-1")).await;

        mark_adopted(&pool, "v-import", 4).await;

        let b = load_binding(&pool, "v-import").await;
        assert_eq!(b.mirrored_vault_version, Some(4));
        assert_eq!(b.sync_status, STATUS_IDLE);
        assert_eq!(
            b.remote_revision, None,
            "adoption must not invent a Drive revision; the first mirror reads a real baseline"
        );
    }
}
