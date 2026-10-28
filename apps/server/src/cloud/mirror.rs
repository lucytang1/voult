//! Out-of-band provider mirroring: the disaster-recovery copy.
//!
//! This module is provider-neutral. It knows the vault's version, the binding's
//! watermark, and the rules for refusing to clobber; it does not know what a
//! Drive is. Everything provider-specific goes through
//! [`crate::cloud::provider::CloudProvider`].
//!
//! # Model
//!
//! **The server is the write authority. A provider is the disaster-recovery
//! copy.**
//!
//! `/update_vault` commits a vault write with an atomic version CAS and returns.
//! It never waits on a provider, never fails because one is down, and never
//! makes a vault write conditional on one. Immediately *after* the commit we
//! spawn a detached mirror task that re-writes the provider copy.
//!
//! # Safety properties
//!
//! * **Never blocking, never failing the write.** The mirror is spawned with
//!   `actix_web::rt::spawn` after the CAS succeeds. Every failure path is logged
//!   and folded into `cloud_binding` state; none can affect `/update_vault`.
//! * **Cannot clobber a newer provider copy.** The write is conditional on
//!   `cloud_binding.remote_revision` — the revision *we* last observed ourselves,
//!   passed as `if_match` to [`crate::cloud::provider::CloudProvider::conditional_write`].
//!   If the remote file moved underneath us (restored elsewhere, edited by another
//!   client, changed by hand) the CAS fails, we record `REMOTE_CONFLICT`, and we
//!   do **not** overwrite. Overwriting is a separate, explicit, user-initiated act.
//! * **Coalesced.** A burst of vault writes collapses into a bounded number of
//!   provider writes. Sync pushes can land back-to-back while a user edits;
//!   without coalescing each push would cost a round trip and burn quota.
//! * **Zero-knowledge.** The mirror only re-serializes ciphertext the server
//!   already stores (see [`crate::cloud::package`]). No key is derived,
//!   unwrapped, or decrypted here, and no plaintext, verifier, or token is
//!   logged.
//!
//! # Failure surfacing
//!
//! `cloud_binding.sync_status`, `mirrored_vault_version`, and
//! `last_mirror_error` carry the real backup state that Settings renders:
//!
//! | `sync_status`   | meaning                                                     |
//! |-----------------|-------------------------------------------------------------|
//! | `idle`          | the provider copy matches the committed server vault        |
//! | `pending`       | vault committed, mirror queued                              |
//! | `mirroring`     | mirror in flight                                            |
//! | `auth_required` | credential missing/expired, or provider unconfigured        |
//! | `unlinked`      | no usable remote file bound to this vault                   |
//! | `conflict`      | remote copy moved; preserved, never overwritten             |
//! | `error`         | transient provider failure; retried on next write           |
//!
//! # One binding incarnation at a time
//!
//! `cloud_binding` is keyed by `vault_id`, so a provider switch, a re-enroll, an
//! import and a disconnect all rewrite the row a detached pass may still be
//! working against. Every pass therefore captures
//! [`BindingGuard`] — the `binding_generation` it observed — and every state
//! write it makes is conditional on that value still matching. A pass that loses
//! the binding drops its write silently: the new incarnation owns the row, and
//! the old pass's revision and watermark describe a provider this vault no longer
//! backs up to. Only the writers in this module may move `binding_generation`,
//! and only the three callers that replace what the binding points at
//! (`POST /cloud/binding`, import-adoption, `POST /cloud/disconnect`) bump it.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use actix_web::rt;
use chrono::{SecondsFormat, Utc};
use sea_orm::sea_query::Expr;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::cloud::error::{ProviderError, ProviderErrorKind};
use crate::cloud::provider::{self, CloudProvider, ProviderKind};
use crate::cloud::{package, token_store};
use crate::db::DbPool;
use crate::entity::cloud_binding::{self, Entity as CloudBindingEntity};
use crate::entity::vault::{self, Entity as VaultEntity};

const LOG: logger::ServerLogger = logger::Logger::create(logger::ServerContext::Cloud);

pub const STATUS_IDLE: &str = "idle";
pub const STATUS_PENDING: &str = "pending";
pub const STATUS_MIRRORING: &str = "mirroring";
pub const STATUS_AUTH_REQUIRED: &str = "auth_required";
pub const STATUS_UNLINKED: &str = "unlinked";
pub const STATUS_CONFLICT: &str = "conflict";
pub const STATUS_ERROR: &str = "error";

/// A binding with no provider file id. Provider-neutral: the id is opaque, and
/// only the provider that issued it can interpret it.
const ERR_NO_REMOTE_FILE: &str = "NO_REMOTE_FILE";
/// The `cloud_binding.provider_kind` column names a provider this build does
/// not implement. Never fall back to a default provider here.
const ERR_UNKNOWN_PROVIDER: &str = "UNKNOWN_PROVIDER";
/// The user removed this vault's credential for its provider.
const ERR_DISCONNECTED: &str = "DISCONNECTED";

/// The provider binding a mirror pass is allowed to write state against.
///
/// Captured once, from the row the pass read at its start. Every status,
/// watermark and revision write is conditional on the generation still matching,
/// so a pass that began before a provider switch — or before a disconnect — can
/// never stamp its result onto the row that now describes a different binding.
#[derive(Debug, Clone)]
pub(crate) struct BindingGuard {
    vault_id: String,
    generation: i32,
}

impl BindingGuard {
    /// Capture the incarnation a pass is allowed to write against.
    pub(crate) fn of(binding: &cloud_binding::Model) -> Self {
        Self {
            vault_id: binding.vault_id.clone(),
            generation: binding.binding_generation,
        }
    }
}

/// Vaults with a mirror currently running, mapped to "another vault write
/// landed while this mirror was in flight". Stops a burst of vault writes from
/// spawning a provider write each.
static IN_FLIGHT: Mutex<Option<HashMap<String, bool>>> = Mutex::new(None);

/// Holds the in-flight claim for as long as it is alive.
///
/// A leaked claim is a silent outage: every later write for the vault would
/// coalesce into a pass that no longer exists, so no write would ever be
/// mirrored again. A panic inside a detached task must not be able to cause that,
/// hence RAII rather than a manual `settle` on each return path.
pub(crate) struct Claim {
    vault_id: String,
}

impl Claim {
    /// Become the single mirror for `vault_id`, or `None` when one is running.
    fn try_acquire(vault_id: &str) -> Option<Self> {
        claim(vault_id).then(|| Claim {
            vault_id: vault_id.to_string(),
        })
    }

    /// Read-and-clear the "rerun" flag. `true` means a vault write landed during
    /// this pass and the caller must mirror again before dropping the claim.
    fn settled_rerun(&self) -> bool {
        settle(&self.vault_id)
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        // `settle` removes the entry. If it reports a rerun the claim is already
        // gone, which is correct: the caller is exiting, and the write that set
        // the flag can start its own pass.
        let _ = settle(&self.vault_id);
    }
}

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
    /// The provider now holds the committed server vault.
    #[serde(rename = "mirrored")]
    Mirrored { vault_version: i32 },
    /// The provider already held this exact version — nothing was written.
    #[serde(rename = "up_to_date")]
    UpToDate { vault_version: i32 },
    /// This vault has no provider binding, so there is nothing to mirror to.
    #[serde(rename = "unlinked")]
    Unlinked,
    /// The credential is missing or expired, or the provider is not configured
    /// on this server. Either way the user must reconnect.
    #[serde(rename = "auth_required")]
    AuthRequired,
    /// The remote file changed since our last observed revision. Preserved, not
    /// overwritten — resolving this is an explicit user action.
    #[serde(rename = "conflict")]
    Conflict,
    /// The vault has no password-wrapped envelope, so a provider copy would not
    /// be restorable on a new device.
    #[serde(rename = "unsupported")]
    Unsupported { reason: String },
    /// Transient provider failure; retried on the next vault write.
    #[serde(rename = "error")]
    Error { code: String },
}

/// Spawn a detached mirror for `vault_id`. Returns immediately.
///
/// Called after `/update_vault` commits. Must never be awaited by the request
/// path: the vault write is already durably accepted, and a provider outage must
/// not turn a successful write into an error or a slow response.
pub fn spawn_after_commit(pool: DbPool, vault_id: String) {
    let Some(claim) = Claim::try_acquire(&vault_id) else {
        // A mirror is already running for this vault. Its trailing re-check
        // picks up the version we just committed, so dropping this request is
        // safe and keeps a burst of writes to one upload.
        LOG.debug(
            format_args!("Mirror already in flight for vault; coalescing"),
            logger::Metadata::new(),
        );
        return;
    };
    rt::spawn(async move {
        // The guard is the claim: dropping it (including on panic) releases the
        // vault, so a dead task can never wedge every future mirror into
        // coalescing against a pass that no longer exists.
        mirror_loop(&pool, claim, MirrorMode::Auto).await;
    });
}

/// Mirror passes until no write landed mid-pass, staying claimed throughout.
///
/// After a rerun the claim is re-acquired rather than simply continuing: `settle`
/// removed it, so continuing blind would let a second task mirror the same vault
/// concurrently and produce a false `REMOTE_CONFLICT` from two conditional
/// writes racing on one revision. Either we win the claim again, or the task that
/// beat us covers the newer version.
async fn mirror_loop(pool: &DbPool, mut claim: Claim, mode: MirrorMode) -> Attempt {
    let vault_id = claim.vault_id.clone();
    let mut outcome = attempt(pool, &vault_id, mode).await;
    let mut passes = 1;
    while claim.settled_rerun() {
        if passes >= MAX_MIRROR_PASSES {
            // `settled_rerun` already released the claim; the write that set the
            // flag is left to the next commit or the sweeper.
            LOG.debug(format_args!(
                "Mirror pass limit reached for vault {}; leaving any newer version to the next vault write",
                short_id(&vault_id)
            ), logger::Metadata::new());
            return outcome;
        }
        claim = match Claim::try_acquire(&vault_id) {
            Some(next) => next,
            None => return outcome,
        };
        outcome = attempt(pool, &vault_id, mode).await;
        passes += 1;
    }
    outcome
}

/// Recover level-triggered mirror work after a crash and retry provider
/// failures periodically even if the vault receives no further writes.
pub fn start_sweeper(pool: DbPool) {
    rt::spawn(async move {
        let mut tick = rt::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            sweep_pending(&pool).await;
        }
    });
}

/// A binding is owed a mirror exactly while its watermark trails the server
/// vault version. No retry queue or extra durable state is needed.
pub async fn sweep_pending(pool: &DbPool) {
    let bindings = match CloudBindingEntity::find()
        .filter(cloud_binding::Column::RemoteFileId.is_not_null())
        .all(pool)
        .await
    {
        Ok(bindings) => bindings,
        Err(err) => {
            LOG.error(
                format_args!("cloud mirror sweeper could not load bindings: {err}"),
                logger::Metadata::new(),
            );
            return;
        }
    };
    for binding in bindings {
        let vault = match VaultEntity::find_by_id(binding.vault_id.clone())
            .one(pool)
            .await
        {
            Ok(Some(vault)) => vault,
            Ok(None) => continue,
            Err(err) => {
                LOG.warn(
                    format_args!("cloud mirror sweeper could not read vault version: {err}"),
                    logger::Metadata::new(),
                );
                continue;
            }
        };
        if binding.mirrored_vault_version != Some(vault.version) {
            spawn_after_commit(pool.clone(), binding.vault_id);
        } else if binding.sync_status == STATUS_PENDING || binding.sync_status == STATUS_MIRRORING {
            // Nothing is owed, but the status still says work is in flight: a
            // concurrent commit re-opened `pending` after the pass that mirrored
            // this version had already finished. No vault write would ever clear
            // it, so the sweeper settles it directly.
            settle_current(pool, &BindingGuard::of(&binding), vault.version).await;
        }
    }
}

/// Upper bound on coalesced passes per spawned mirror. Each pass only runs when
/// a vault write actually landed since the previous one, so this is a safety
/// valve for a continuous write stream, not a normal path.
const MAX_MIRROR_PASSES: usize = 8;

/// How long "Back up now" waits for a running pass to finish before telling the
/// user to try again. A provider round trip is normally well under a second.
#[cfg(not(test))]
const MANUAL_CLAIM_WAIT: Duration = Duration::from_secs(5);
/// Test builds use a short wait so the busy path does not cost the suite five
/// seconds per run. The production value is the one above.
#[cfg(test)]
const MANUAL_CLAIM_WAIT: Duration = Duration::from_millis(20);

/// How long a provider switch waits for a running pass. Longer than the manual
/// wait because the switch is the only path that must not leave a half-applied
/// binding behind, and it refuses *before* creating anything at the target.
#[cfg(not(test))]
pub(crate) const SWITCH_CLAIM_WAIT: Duration = Duration::from_secs(10);
/// Test builds refuse almost immediately so the suite does not spend ten seconds
/// per switch-refusal case. Production uses the value above.
#[cfg(test)]
pub(crate) const SWITCH_CLAIM_WAIT: Duration = Duration::from_millis(20);

/// Poll interval while waiting for the claim.
const CLAIM_POLL: Duration = Duration::from_millis(50);

/// A provider switch or "Back up now" could not get the claim in time. Nothing
/// was written; the caller should retry once the current pass settles.
pub const ERR_MIRROR_BUSY: &str = "MIRROR_BUSY";

/// Mark the binding as owing a mirror, without performing one.
///
/// Cheap pre-check: the overwhelmingly common case is a local-only vault with
/// no binding, which costs one indexed read and writes nothing.
pub async fn mark_pending(pool: &DbPool, vault_id: &str) {
    let binding = match CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(vault_id))
        .filter(cloud_binding::Column::RemoteFileId.is_not_null())
        .one(pool)
        .await
    {
        Ok(binding) => binding,
        Err(err) => {
            LOG.warn(
                format_args!("could not read cloud binding before marking pending: {err}"),
                logger::Metadata::new(),
            );
            return;
        }
    };
    let Some(binding) = binding else {
        return;
    };
    // Conditional on the generation read above. A switch that landed between the
    // commit and this write owns the row, and re-opening its just-settled status
    // would leave the UI reporting "saving" forever.
    set_status(pool, &BindingGuard::of(&binding), STATUS_PENDING, None).await;
}

/// Record that the vault no longer has a credential for its provider.
///
/// Disconnecting is a safety action, so it never waits behind a provider write:
/// the generation is bumped in the same statement as the status, which makes any
/// upload still in flight unable to stamp its result onto this row. The binding
/// itself — file id, revision, watermark — is preserved, because the provider
/// copy still exists and becomes current again the moment the user reconnects.
pub async fn mark_disconnected(pool: &DbPool, vault_id: &str) {
    // Scoped to this function: `ExprTrait` also defines `min`, which would
    // otherwise shadow `Ord::min` in `short_id`.
    use sea_orm::sea_query::ExprTrait as _;
    let now = Utc::now();
    match CloudBindingEntity::update_many()
        .col_expr(
            cloud_binding::Column::SyncStatus,
            Expr::value(STATUS_AUTH_REQUIRED),
        )
        .col_expr(
            cloud_binding::Column::LastMirrorError,
            Expr::value(Some(ERR_DISCONNECTED.to_string())),
        )
        .col_expr(
            cloud_binding::Column::BindingGeneration,
            Expr::col(cloud_binding::Column::BindingGeneration).add(1),
        )
        .col_expr(
            cloud_binding::Column::UpdatedAt,
            Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))),
        )
        .filter(cloud_binding::Column::VaultId.eq(vault_id))
        .exec(pool)
        .await
    {
        Ok(result) if result.rows_affected > 0 => LOG.log(
            format_args!(
                "cloud backup paused for vault {}: credential removed",
                short_id(vault_id)
            ),
            logger::Metadata::new(),
        ),
        Ok(_) => {}
        Err(e) => LOG.error(
            format_args!("failed to record cloud disconnect: {}", e),
            logger::Metadata::new(),
        ),
    }
}

/// Mirror the committed vault to the provider now, awaiting the result.
///
/// For the explicit "Back up now" user action, which means *verify and re-upload*
/// rather than "maybe do nothing": the pass reads the live provider revision
/// first, so a deleted or externally replaced copy is reported instead of being
/// hidden behind a current watermark. It still refuses to write over a copy that
/// moved — "Back up now" is "try again", never "overwrite".
///
/// Waits for a detached pass to finish rather than racing it: two concurrent
/// conditional writes on one revision would produce a false `REMOTE_CONFLICT`.
pub async fn mirror_now(pool: &DbPool, vault_id: &str) -> MirrorOutcome {
    let Some(claim) = claim_waiting(vault_id, MANUAL_CLAIM_WAIT).await else {
        return MirrorOutcome::Error {
            code: ERR_MIRROR_BUSY.to_string(),
        };
    };
    mirror_loop(pool, claim, MirrorMode::Manual)
        .await
        .into_outcome()
}

/// Run a mirror while the caller already holds the claim, and release it.
///
/// Used by the provider switch, which must hold the claim across enrollment so a
/// vault write cannot start a second pass against a half-written binding.
pub(crate) async fn mirror_held(pool: &DbPool, claim: Claim, mode: MirrorMode) {
    let _ = mirror_loop(pool, claim, mode).await;
}

/// Wait for the single-mirror claim, up to `timeout`.
///
/// Returns `None` when another pass is still running. Callers must treat that as
/// "refuse and change nothing", never as "run it too".
pub(crate) async fn claim_waiting(vault_id: &str, timeout: Duration) -> Option<Claim> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(claim) = Claim::try_acquire(vault_id) {
            return Some(claim);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        rt::time::sleep(CLAIM_POLL).await;
    }
}

/// How a pass may treat the provider copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MirrorMode {
    /// Post-commit / sweeper pass. Skips the provider entirely when the
    /// watermark already matches the committed vault version.
    Auto,
    /// Explicit user action. Verifies the live revision and uploads even when the
    /// watermark says the copy is current.
    Manual,
}

#[derive(Debug)]
enum Attempt {
    Mirrored(i32),
    UpToDate(i32),
    Unlinked,
    AuthRequired,
    Conflict,
    Unsupported(String),
    Failed(String),
}

impl Attempt {
    fn into_outcome(self) -> MirrorOutcome {
        match self {
            Attempt::Mirrored(v) => MirrorOutcome::Mirrored { vault_version: v },
            Attempt::UpToDate(v) => MirrorOutcome::UpToDate { vault_version: v },
            Attempt::Unlinked => MirrorOutcome::Unlinked,
            Attempt::AuthRequired => MirrorOutcome::AuthRequired,
            Attempt::Conflict => MirrorOutcome::Conflict,
            Attempt::Unsupported(reason) => MirrorOutcome::Unsupported { reason },
            Attempt::Failed(code) => MirrorOutcome::Error { code },
        }
    }
}

async fn attempt(pool: &DbPool, vault_id: &str, mode: MirrorMode) -> Attempt {
    let binding = match CloudBindingEntity::find()
        .filter(cloud_binding::Column::VaultId.eq(vault_id))
        .one(pool)
        .await
    {
        Ok(Some(b)) => b,
        Ok(None) => {
            // No provider binding: this vault is local-only. Not an error.
            LOG.debug(
                format_args!("No provider binding for vault; nothing to mirror"),
                logger::Metadata::new(),
            );
            return Attempt::Unlinked;
        }
        Err(e) => {
            LOG.error(
                format_args!("failed to load cloud binding for mirror: {}", e),
                logger::Metadata::new(),
            );
            return Attempt::Failed("DB_ERROR".to_string());
        }
    };

    // Everything below may only write state while the row still describes the
    // binding we just read. A switch or disconnect bumps the generation, and this
    // pass's revision then belongs to a provider the vault no longer backs up to.
    let guard = BindingGuard::of(&binding);

    // Resolve which provider this vault is bound to. A value we cannot parse is
    // a real fault (the database holds a provider this build does not know), and
    // it must NOT silently fall back to a default: mirroring to the wrong
    // account would copy a vault to a provider the user never chose.
    let kind = match ProviderKind::parse(&binding.provider_kind) {
        Ok(k) => k,
        Err(e) => {
            LOG.error(
                format_args!("unrecognized provider in cloud binding: {}", e.0),
                logger::Metadata::new(),
            );
            set_status(pool, &guard, STATUS_ERROR, Some(ERR_UNKNOWN_PROVIDER)).await;
            return Attempt::Failed(ERR_UNKNOWN_PROVIDER.to_string());
        }
    };

    let Some(file_id) = binding.remote_file_id.clone() else {
        set_status(pool, &guard, STATUS_UNLINKED, Some(ERR_NO_REMOTE_FILE)).await;
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
            LOG.error(
                format_args!("failed to load vault for mirror: {}", e),
                logger::Metadata::new(),
            );
            return Attempt::Failed("DB_ERROR".to_string());
        }
    };

    // A current watermark does not prove a usable credential still exists:
    // disconnect deliberately preserves the binding. Check the indexed token
    // row first so Settings cannot report "up to date" after credentials were
    // removed. This performs no provider request unless refresh is due.
    let access_token = match token_store::get_valid_access_token(pool, kind, vault_id).await {
        Ok(t) => t,
        Err(_) => {
            set_status(pool, &guard, STATUS_AUTH_REQUIRED, None).await;
            return Attempt::AuthRequired;
        }
    };

    // Already backed up at this exact version: no package serialization or
    // provider file request is needed once the credential is known to exist.
    //
    // Automatic passes stop here, but must still *settle* the status. A
    // concurrent commit can re-open `pending` after this pass's own
    // `mark_mirrored`, and nothing else ever clears it — the sweeper only acts
    // when the watermark differs, so a `pending` status with a current watermark
    // would otherwise be permanent and Settings would say "Backing up…" forever.
    //
    // A manual pass skips this branch entirely: "Back up now" means verify and
    // re-upload, never "maybe do nothing".
    if mode == MirrorMode::Auto && binding.mirrored_vault_version == Some(vault_row.version) {
        settle_current(pool, &guard, vault_row.version).await;
        return Attempt::UpToDate(vault_row.version);
    }

    // Build the encrypted package. This re-serializes stored ciphertext and
    // public crypto metadata; it never decrypts and never touches key material.
    let package_bytes = match package::build(&vault_row) {
        Ok(b) => b,
        Err(reason) => {
            LOG.warn(
                format_args!(
                    "Mirror skipped for vault {}: no restorable package ({})",
                    short_id(vault_id),
                    reason
                ),
                logger::Metadata::new(),
            );
            set_status(pool, &guard, STATUS_ERROR, Some(reason)).await;
            return Attempt::Unsupported(reason.to_string());
        }
    };

    set_status(pool, &guard, STATUS_MIRRORING, None).await;

    // Resolve the provider implementation. A binding can name a provider this
    // build knows but cannot configure (missing credentials) — that is
    // `auth_required`, not a mirror bug.
    let impl_ = match provider::provider(kind) {
        Some(p) => p,
        None => {
            LOG.warn(
                format_args!(
                    "vault {} is bound to {}, which is not configured on this server",
                    short_id(vault_id),
                    kind
                ),
                logger::Metadata::new(),
            );
            set_status(pool, &guard, STATUS_AUTH_REQUIRED, None).await;
            return Attempt::AuthRequired;
        }
    };

    // The CAS baseline. Automatic passes condition on the last revision *we*
    // observed, reading it live only when the binding never recorded one. A
    // manual pass always reads it live, because proving that the copy about to be
    // replaced is still the copy we think it is is the whole point of the action.
    let baseline = match mode {
        MirrorMode::Auto => {
            resolve_baseline(&impl_, pool, &guard, &access_token, &file_id, &binding).await
        }
        MirrorMode::Manual => {
            verify_baseline(&impl_, pool, &guard, &access_token, &file_id, &binding).await
        }
    };
    let expected = match baseline {
        Baseline::Revision(rev) => rev,
        Baseline::Done(outcome) => return outcome,
    };
    let expected = expected.as_deref();

    match impl_
        .conditional_write(&access_token, &file_id, &package_bytes, expected)
        .await
    {
        Ok(new_rev) => {
            LOG.log(
                format_args!(
                    "Mirrored vault to {} (vault_version={}, revision={})",
                    kind,
                    vault_row.version,
                    short_id(&new_rev)
                ),
                logger::Metadata::new(),
            );
            mark_mirrored(pool, &guard, vault_row.version, Some(&new_rev)).await;
            Attempt::Mirrored(vault_row.version)
        }
        Err(err) => {
            handle_provider_error(pool, &guard, &err).await;
            attempt_from_error(&err)
        }
    }
}

/// What a pass may condition its write on, or the outcome that ends it.
enum Baseline {
    /// The `if_match` token, or `None` when the provider offers no revision (the
    /// provider implementation then refuses rather than writing blind).
    Revision(Option<String>),
    /// The pass already recorded a terminal state; return this without writing.
    Done(Attempt),
}

/// The revision to condition the write on. Normally the one recorded on the
/// binding; read live only when the binding has none.
async fn resolve_baseline(
    impl_: &provider::AnyProvider,
    pool: &DbPool,
    guard: &BindingGuard,
    access_token: &str,
    file_id: &str,
    binding: &cloud_binding::Model,
) -> Baseline {
    if let Some(rev) = binding.remote_revision.as_deref() {
        return Baseline::Revision(Some(rev.to_string()));
    }
    // Read the provider's revision. Three distinct outcomes:
    //   Err(..)      → the read failed (network, auth, file gone)
    //   Ok(Err(..))  → the file exists but reports no usable revision: refuse
    //   Ok(Ok(rev))  → a real revision we can condition on
    match impl_.file_revision(access_token, file_id).await {
        Ok(Ok(rev)) => {
            // Persist it so subsequent mirrors condition on the stored value.
            let _ = CloudBindingEntity::update_many()
                .col_expr(
                    cloud_binding::Column::RemoteRevision,
                    Expr::value(Some(rev.clone())),
                )
                .filter(cloud_binding::Column::VaultId.eq(&guard.vault_id))
                .filter(cloud_binding::Column::BindingGeneration.eq(guard.generation))
                .exec(pool)
                .await;
            Baseline::Revision(Some(rev))
        }
        // An absent revision is not a usable CAS token: conditioning on it would
        // match any file, defeating the gate. Refuse rather than write blind.
        Ok(Err(_no_revision)) => {
            let code = ProviderErrorKind::RemoteRevisionUnavailable
                .code()
                .to_string();
            set_status(pool, guard, STATUS_ERROR, Some(&code)).await;
            Baseline::Done(Attempt::Failed(code))
        }
        Err(err) => {
            handle_provider_error(pool, guard, &err).await;
            Baseline::Done(attempt_from_error(&err))
        }
    }
}

/// Manual baseline: prove the remote copy is still the one we last wrote.
///
/// Reads the live revision instead of trusting the stored one, so "Back up now"
/// can report a deleted or externally replaced copy instead of hiding it behind a
/// current watermark. It still refuses to overwrite a copy that moved.
async fn verify_baseline(
    impl_: &provider::AnyProvider,
    pool: &DbPool,
    guard: &BindingGuard,
    access_token: &str,
    file_id: &str,
    binding: &cloud_binding::Model,
) -> Baseline {
    let live = match impl_.file_revision(access_token, file_id).await {
        Ok(Ok(rev)) => rev,
        Ok(Err(_no_revision)) => {
            let code = ProviderErrorKind::RemoteRevisionUnavailable
                .code()
                .to_string();
            set_status(pool, guard, STATUS_ERROR, Some(&code)).await;
            return Baseline::Done(Attempt::Failed(code));
        }
        Err(err) => {
            handle_provider_error(pool, guard, &err).await;
            return Baseline::Done(attempt_from_error(&err));
        }
    };

    match binding.remote_revision.as_deref() {
        // Never mirrored under this incarnation: the live revision is a real CAS
        // token, so condition the write on it rather than writing blind.
        None => Baseline::Revision(Some(live)),
        Some(stored) if stored == live => Baseline::Revision(Some(live)),
        Some(_) => {
            // The copy changed since we last wrote it. Preserved, not replaced —
            // resolving this is the explicit "Start a new backup" action.
            LOG.warn(
                format_args!(
                    "Backup refused for vault {}: the provider copy moved since the last backup",
                    short_id(&guard.vault_id)
                ),
                logger::Metadata::new(),
            );
            set_status(
                pool,
                guard,
                STATUS_CONFLICT,
                Some(ProviderErrorKind::RemoteConflict.code()),
            )
            .await;
            Baseline::Done(Attempt::Conflict)
        }
    }
}

/// Map a provider failure onto the pass outcome. Status recording is separate
/// ([`handle_provider_error`]) so both the writer and the reader paths agree.
fn attempt_from_error(err: &ProviderError) -> Attempt {
    match &err.kind {
        ProviderErrorKind::AuthRequired => Attempt::AuthRequired,
        ProviderErrorKind::RemoteConflict => Attempt::Conflict,
        ProviderErrorKind::RemoteDeleted | ProviderErrorKind::VaultNotFound => Attempt::Unlinked,
        other => Attempt::Failed(other.code().to_string()),
    }
}

/// Record that the provider copy is current at `vault_version`.
///
/// `remote_revision` of `None` leaves the stored revision untouched (used when
/// the binding's revision is already correct).
///
/// Conditional on the generation: a pass that lost the binding to a provider
/// switch must not claim the *new* provider's copy is current at a version the
/// new provider never received.
pub(crate) async fn mark_mirrored(
    pool: &DbPool,
    guard: &BindingGuard,
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
        .col_expr(
            cloud_binding::Column::LastMirrorError,
            Expr::value(None::<String>),
        )
        .col_expr(cloud_binding::Column::SyncStatus, Expr::value(STATUS_IDLE))
        .col_expr(
            cloud_binding::Column::UpdatedAt,
            Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))),
        )
        .filter(cloud_binding::Column::VaultId.eq(&guard.vault_id))
        .filter(cloud_binding::Column::BindingGeneration.eq(guard.generation));
    if let Some(rev) = remote_revision {
        update = update.col_expr(
            cloud_binding::Column::RemoteRevision,
            Expr::value(Some(rev.to_string())),
        );
    }
    match update.exec(pool).await {
        Ok(result) if result.rows_affected == 0 => LOG.debug(
            format_args!(
                "dropped stale mirror state write for vault {}",
                short_id(&guard.vault_id)
            ),
            logger::Metadata::new(),
        ),
        Ok(_) => {}
        Err(e) => LOG.error(
            format_args!("failed to persist mirror state: {}", e),
            logger::Metadata::new(),
        ),
    }
}

/// Clear a transient status when the watermark already matches the vault.
///
/// The high-water mark only moves in [`mark_mirrored`], so "watermark equals the
/// vault version" is proof the copy is current even if the status still says
/// `pending`/`mirroring` — which happens when a concurrent commit re-opens
/// `pending` after a successful pass. Deliberately limited to those two states:
/// `conflict`, `auth_required`, `unlinked` and `error` describe the *remote*, not
/// staleness, and clearing them here would erase a real problem. Nothing is
/// advanced and `last_mirrored_at` is untouched, because nothing was written.
async fn settle_current(pool: &DbPool, guard: &BindingGuard, vault_version: i32) {
    let now = Utc::now();
    match CloudBindingEntity::update_many()
        .col_expr(cloud_binding::Column::SyncStatus, Expr::value(STATUS_IDLE))
        .col_expr(
            cloud_binding::Column::LastMirrorError,
            Expr::value(None::<String>),
        )
        .col_expr(
            cloud_binding::Column::UpdatedAt,
            Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))),
        )
        .filter(cloud_binding::Column::VaultId.eq(&guard.vault_id))
        .filter(cloud_binding::Column::BindingGeneration.eq(guard.generation))
        .filter(cloud_binding::Column::MirroredVaultVersion.eq(vault_version))
        .filter(cloud_binding::Column::SyncStatus.is_in([STATUS_PENDING, STATUS_MIRRORING]))
        .exec(pool)
        .await
    {
        Ok(result) if result.rows_affected > 0 => {
            LOG.debug(
                format_args!(
                    "settled stale transient backup status for vault {}",
                    short_id(&guard.vault_id)
                ),
                logger::Metadata::new(),
            );
        }
        Ok(_) => {}
        Err(e) => LOG.error(
            format_args!("failed to settle mirror status: {}", e),
            logger::Metadata::new(),
        ),
    }
}

async fn handle_provider_error(pool: &DbPool, guard: &BindingGuard, err: &ProviderError) {
    match &err.kind {
        ProviderErrorKind::AuthRequired => {
            set_status(pool, guard, STATUS_AUTH_REQUIRED, None).await;
        }
        ProviderErrorKind::RemoteConflict => {
            // The remote copy is newer than what we last saw. Deliberately do NOT
            // advance `mirrored_vault_version` — claiming the backup is current
            // would hide a real divergence between the server and the provider.
            LOG.warn(format_args!(
                "Mirror conflict for vault {}: the remote copy changed since last sync; not overwriting",
                short_id(&guard.vault_id)
            ), logger::Metadata::new());
            set_status(pool, guard, STATUS_CONFLICT, Some(err.code())).await;
        }
        ProviderErrorKind::RemoteDeleted | ProviderErrorKind::VaultNotFound => {
            LOG.warn(
                format_args!(
                    "Remote backup for vault {} is missing; the local vault is unaffected",
                    short_id(&guard.vault_id)
                ),
                logger::Metadata::new(),
            );
            set_status(pool, guard, STATUS_UNLINKED, Some(err.code())).await;
        }
        other => {
            // Transient (rate limit, provider 5xx, network). The local vault is
            // committed and correct; only the DR copy is behind, and the next
            // vault write retries.
            LOG.warn(
                format_args!(
                    "Mirror failed for vault {}: {} ({})",
                    short_id(&guard.vault_id),
                    other.code(),
                    err.detail()
                ),
                logger::Metadata::new(),
            );
            set_status(pool, guard, STATUS_ERROR, Some(other.code())).await;
        }
    }
}

/// Record a non-success state without touching the mirrored-version watermark.
///
/// Conditional on the generation for the same reason as [`mark_mirrored`]: the
/// status describes the binding the pass started with, and after a switch it no
/// longer applies.
async fn set_status(pool: &DbPool, guard: &BindingGuard, status: &str, error: Option<&str>) {
    let now = Utc::now();
    let mut update = CloudBindingEntity::update_many()
        .col_expr(cloud_binding::Column::SyncStatus, Expr::value(status))
        .col_expr(
            cloud_binding::Column::UpdatedAt,
            Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))),
        )
        .filter(cloud_binding::Column::VaultId.eq(&guard.vault_id))
        .filter(cloud_binding::Column::BindingGeneration.eq(guard.generation));
    if let Some(code) = error {
        update = update.col_expr(
            cloud_binding::Column::LastMirrorError,
            Expr::value(Some(code.to_string())),
        );
    }
    match update.exec(pool).await {
        Ok(result) if result.rows_affected == 0 => LOG.debug(
            format_args!(
                "dropped stale mirror status write for vault {}",
                short_id(&guard.vault_id)
            ),
            logger::Metadata::new(),
        ),
        Ok(_) => {}
        Err(e) => LOG.error(
            format_args!("failed to persist mirror status: {}", e),
            logger::Metadata::new(),
        ),
    }
}

/// Records that the provider copy corresponds to `vault_version` **without**
/// claiming a revision.
///
/// Used when a provider package is adopted as the local vault (import): the
/// remote copy *is* the source of truth there, so no upload is needed — but no
/// revision was recorded either, so the next automatic mirror reads a live
/// baseline before its first conditional write rather than writing blind.
///
/// Currently unreferenced: the import path records adoption through
/// `POST /cloud/binding`. Kept because it is the correct primitive for that
/// path, and deleting it would only defer the same reasoning to the next change.
#[allow(dead_code)]
pub async fn mark_adopted(pool: &DbPool, guard: &BindingGuard, vault_version: i32) {
    let now = Utc::now();
    let _ = CloudBindingEntity::update_many()
        .col_expr(
            cloud_binding::Column::MirroredVaultVersion,
            Expr::value(Some(vault_version)),
        )
        .col_expr(
            cloud_binding::Column::LastMirroredAt,
            Expr::value(Some(now.to_rfc3339_opts(SecondsFormat::Secs, true))),
        )
        .col_expr(
            cloud_binding::Column::LastMirrorError,
            Expr::value(None::<String>),
        )
        .col_expr(cloud_binding::Column::SyncStatus, Expr::value(STATUS_IDLE))
        .col_expr(
            cloud_binding::Column::UpdatedAt,
            Expr::value(sea_orm::Value::ChronoDateTimeUtc(Some(now))),
        )
        .filter(cloud_binding::Column::VaultId.eq(&guard.vault_id))
        .filter(cloud_binding::Column::BindingGeneration.eq(guard.generation))
        .exec(pool)
        .await;
}

/// First 8 characters of an identifier, for logs. Enough to correlate, and it
/// is a public UUID or an opaque provider revision — never key material.
fn short_id(id: &str) -> &str {
    &id[..8.min(id.len())]
}

/// Used by the enrollment path to learn the revision it just created, so the
/// first automatic mirror has a real CAS baseline.
///
/// Unreferenced today: enrollment records the returned revision directly on the
/// binding. Retained because it is the only way to establish a baseline when a
/// provider's create call does not report one.
#[allow(dead_code)]
pub async fn observe_remote_revision(
    pool: &DbPool,
    guard: &BindingGuard,
    kind: ProviderKind,
    file_id: &str,
) -> Option<String> {
    let token = token_store::get_valid_access_token(pool, kind, &guard.vault_id)
        .await
        .ok()?;
    let impl_ = provider::provider(kind)?;
    // `None` for either "the read failed" or "no usable revision": in both cases
    // there is no baseline to record, and recording a placeholder would let a
    // later conditional write match nothing.
    let rev = impl_.file_revision(&token, file_id).await.ok()?.ok()?;
    let _ = CloudBindingEntity::update_many()
        .col_expr(
            cloud_binding::Column::RemoteRevision,
            Expr::value(Some(rev.clone())),
        )
        .filter(cloud_binding::Column::VaultId.eq(&guard.vault_id))
        .filter(cloud_binding::Column::BindingGeneration.eq(guard.generation))
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
        let pool = Database::connect("sqlite::memory:").await.expect("connect");
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
            recovery_verifier: Set(Some("cmVjb3ZlcnktdmVyaWZpZXI=".to_string())),
            recovery_salt: Set(Some("cmVjb3Zlcnktc2FsdA==".to_string())),
            recovery_wrap: Set(Some("cmVjb3Zlcnktd3JhcA==".to_string())),
            recovery_wrap_iv: Set(Some("cmVjdml2".to_string())),
            ..Default::default()
        };
        am.insert(pool).await.expect("insert vault");
    }

    async fn seed_binding(pool: &DbPool, id: &str, file_id: Option<&str>) {
        use sea_orm::Set;
        let am = cloud_binding::ActiveModel {
            vault_id: Set(id.to_string()),
            provider_kind: Set("google_drive".to_string()),
            remote_file_id: Set(file_id.map(|s| s.to_string())),
            sync_status: Set(STATUS_IDLE.to_string()),
            ..Default::default()
        };
        am.insert(pool).await.expect("insert binding");
    }

    async fn seed_usable_token(pool: &DbPool, id: &str) {
        use crate::entity::cloud_token;
        use sea_orm::Set;
        let am = cloud_token::ActiveModel {
            vault_id: Set(id.to_string()),
            provider_kind: Set("google_drive".to_string()),
            access_token: Set("test-access-token".to_string()),
            refresh_token: Set(None),
            token_type: Set("Bearer".to_string()),
            expires_at: Set(chrono::Utc::now().timestamp() + 3600),
            scope: Set(None),
            provider_account_id: Set(None),
            provider_email: Set(None),
            ..Default::default()
        };
        am.insert(pool).await.expect("insert token");
    }

    async fn load_binding(pool: &DbPool, id: &str) -> cloud_binding::Model {
        CloudBindingEntity::find_by_id(id)
            .one(pool)
            .await
            .expect("query")
            .expect("binding exists")
    }

    /// The guard a pass starting now would capture.
    async fn guard_of(pool: &DbPool, id: &str) -> BindingGuard {
        BindingGuard::of(&load_binding(pool, id).await)
    }

    /// The mirror must refuse to mirror when the provider cannot produce a
    /// revision token. The sentinel's *value* is Drive's business and is pinned
    /// in its own implementation; what this module must guarantee is that it
    /// never turns "no revision" into "any revision matches".
    #[test]
    fn no_revision_is_not_a_usable_baseline() {
        use crate::cloud::provider::NoRevision;
        // Distinct from a real revision, so `resolve_baseline` can tell them
        // apart and refuse instead of writing blind.
        assert_ne!(
            NoRevision.to_string(),
            "rev-1",
            "an absent revision must never compare equal to a real one"
        );
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

        assert_eq!(
            load_binding(&pool, "v-bound").await.sync_status,
            STATUS_PENDING
        );
    }

    /// The watermark must advance together with the status, and the error must
    /// clear — otherwise Settings keeps reporting a resolved failure forever.
    #[tokio::test]
    async fn mark_mirrored_advances_the_watermark_and_clears_errors() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-ok").await;
        seed_binding(&pool, "v-ok", Some("file-1")).await;
        let guard = guard_of(&pool, "v-ok").await;
        set_status(&pool, &guard, STATUS_ERROR, Some("PROVIDER_RATE_LIMITED")).await;

        mark_mirrored(&pool, &guard, 7, Some("rev-2")).await;

        let b = load_binding(&pool, "v-ok").await;
        assert_eq!(b.sync_status, STATUS_IDLE);
        assert_eq!(b.mirrored_vault_version, Some(7));
        assert_eq!(b.remote_revision.as_deref(), Some("rev-2"));
        assert_eq!(b.last_mirror_error, None);
        assert!(b.last_mirrored_at.is_some());
    }

    /// The conflict path must NOT advance the watermark. Claiming the backup is
    /// current when the provider has diverged is precisely the silent-staleness bug
    /// this work exists to remove.
    #[tokio::test]
    async fn conflict_does_not_advance_the_watermark() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-conflict").await;
        seed_binding(&pool, "v-conflict", Some("file-1")).await;
        let guard = guard_of(&pool, "v-conflict").await;
        mark_mirrored(&pool, &guard, 5, Some("rev-1")).await;

        let err = ProviderError::new(ProviderErrorKind::RemoteConflict, "revision mismatch");
        handle_provider_error(&pool, &guard, &err).await;

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

        let err = ProviderError::new(ProviderErrorKind::RemoteDeleted, "404");
        handle_provider_error(&pool, &guard_of(&pool, "v-gone").await, &err).await;

        let b = load_binding(&pool, "v-gone").await;
        assert_eq!(b.sync_status, STATUS_UNLINKED);
        assert_eq!(b.last_mirror_error.as_deref(), Some("REMOTE_DELETED"));
        assert_eq!(
            b.mirrored_vault_version, None,
            "the local vault is unaffected; only the backup is missing"
        );
    }

    /// A current watermark still requires a credential row; this catches
    /// disconnects while avoiding any Drive file request for a healthy binding.
    #[tokio::test]
    async fn mirror_now_requires_credentials_even_when_watermark_matches() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-fresh").await;
        seed_binding(&pool, "v-fresh", Some("file-1")).await;
        // Simulate disconnect: the binding remains, but its provider token is gone.
        mark_mirrored(&pool, &guard_of(&pool, "v-fresh").await, 1, Some("rev-1")).await;

        match mirror_now(&pool, "v-fresh").await {
            MirrorOutcome::AuthRequired => {}
            other => panic!("expected AuthRequired, got {other:?}"),
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
    /// the mirror must refuse rather than write an unusable copy.
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
        seed_usable_token(&pool, "v-legacy").await;

        match mirror_now(&pool, "v-legacy").await {
            MirrorOutcome::Unsupported { reason } => {
                assert_eq!(reason, package::ERR_LEGACY_CRYPTO)
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    /// Import/adoption: the provider copy is the source of truth, so the local
    /// vault's current version is the watermark — without inventing a revision.
    #[tokio::test]
    async fn mark_adopted_claims_the_version_but_not_a_revision() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-import").await;
        seed_binding(&pool, "v-import", Some("file-1")).await;

        mark_adopted(&pool, &guard_of(&pool, "v-import").await, 4).await;

        let b = load_binding(&pool, "v-import").await;
        assert_eq!(b.mirrored_vault_version, Some(4));
        assert_eq!(b.sync_status, STATUS_IDLE);
        assert_eq!(
            b.remote_revision, None,
            "adoption must not invent a revision; the first mirror reads a real baseline"
        );
    }

    // --- Binding generations -------------------------------------------------

    /// The bug this column exists for: a pass that started under one binding
    /// incarnation must not stamp its revision, watermark or status onto the row
    /// that now describes a different provider.
    #[tokio::test]
    async fn switch_generation_bump_rejects_an_inflight_pass() {
        use sea_orm::Set;

        let pool = test_pool().await;
        seed_vault(&pool, "v-switch").await;
        seed_binding(&pool, "v-switch", Some("drive-file")).await;
        let inflight = guard_of(&pool, "v-switch").await;
        assert_eq!(inflight.generation, 0);

        // What `POST /cloud/binding` does: point the row at Dropbox and bump the
        // generation in the same write.
        let existing = load_binding(&pool, "v-switch").await;
        let mut am: cloud_binding::ActiveModel = existing.into();
        am.provider_kind = Set("dropbox".to_string());
        am.remote_file_id = Set(Some("dropbox-file".to_string()));
        am.remote_revision = Set(Some("dropbox-rev-1".to_string()));
        am.mirrored_vault_version = Set(None);
        am.sync_status = Set(STATUS_PENDING.to_string());
        am.binding_generation = Set(1);
        am.update(&pool).await.expect("switch write");

        // The Drive pass finishes late.
        mark_mirrored(&pool, &inflight, 9, Some("drive-rev-9")).await;
        set_status(&pool, &inflight, STATUS_CONFLICT, Some("REMOTE_CONFLICT")).await;

        let b = load_binding(&pool, "v-switch").await;
        assert_eq!(b.provider_kind, "dropbox");
        assert_eq!(b.remote_file_id.as_deref(), Some("dropbox-file"));
        assert_eq!(
            b.remote_revision.as_deref(),
            Some("dropbox-rev-1"),
            "a stale pass must not replace the new provider's revision"
        );
        assert_eq!(
            b.mirrored_vault_version, None,
            "the new provider holds nothing yet; the stale pass must not claim it does"
        );
        assert_eq!(
            b.sync_status, STATUS_PENDING,
            "a stale pass must not overwrite the new binding's status either"
        );
        assert_eq!(b.binding_generation, 1);
    }

    #[tokio::test]
    async fn stale_generation_state_writes_are_dropped() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-stale").await;
        seed_binding(&pool, "v-stale", Some("file-1")).await;

        let stale = BindingGuard {
            vault_id: "v-stale".to_string(),
            generation: 7,
        };
        set_status(&pool, &stale, STATUS_ERROR, Some("PROVIDER_RATE_LIMITED")).await;
        mark_mirrored(&pool, &stale, 4, Some("rev-stale")).await;

        let b = load_binding(&pool, "v-stale").await;
        assert_eq!(b.sync_status, STATUS_IDLE);
        assert_eq!(b.mirrored_vault_version, None);
        assert_eq!(b.remote_revision, None);
        assert_eq!(b.last_mirror_error, None);
    }

    // --- Honest status -------------------------------------------------------

    /// A transient status left behind by a racing commit must settle instead of
    /// spinning "Backing up…" forever. Nothing was uploaded, so the recorded
    /// last-backup time must not move.
    #[tokio::test]
    async fn up_to_date_clears_a_stuck_transient_status() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-stuck").await;
        seed_binding(&pool, "v-stuck", Some("file-1")).await;
        seed_usable_token(&pool, "v-stuck").await;
        let guard = guard_of(&pool, "v-stuck").await;
        mark_mirrored(&pool, &guard, 1, Some("rev-1")).await;
        set_status(&pool, &guard, STATUS_PENDING, None).await;
        let last_mirrored_at = load_binding(&pool, "v-stuck").await.last_mirrored_at;

        match attempt(&pool, "v-stuck", MirrorMode::Auto).await {
            Attempt::UpToDate(1) => {}
            other => panic!("expected UpToDate, got {other:?}"),
        }

        let b = load_binding(&pool, "v-stuck").await;
        assert_eq!(b.sync_status, STATUS_IDLE);
        assert_eq!(
            b.last_mirrored_at, last_mirrored_at,
            "settling must not claim a new upload happened"
        );
        assert_eq!(b.mirrored_vault_version, Some(1));
    }

    /// The sweeper has to fix the same stuck state on its own: if it only looked
    /// at the watermark, a `pending`/`idle` mismatch would never be repaired
    /// without another vault write.
    #[tokio::test]
    async fn sweeper_settles_a_stuck_binding_without_a_vault_write() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-sweep").await;
        seed_binding(&pool, "v-sweep", Some("file-1")).await;
        let guard = guard_of(&pool, "v-sweep").await;
        mark_mirrored(&pool, &guard, 1, Some("rev-1")).await;
        set_status(&pool, &guard, STATUS_PENDING, None).await;

        sweep_pending(&pool).await;

        assert_eq!(
            load_binding(&pool, "v-sweep").await.sync_status,
            STATUS_IDLE
        );
    }

    /// `settle_current` must never erase a state that describes the remote.
    #[tokio::test]
    async fn settle_current_leaves_a_real_conflict_alone() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-keep").await;
        seed_binding(&pool, "v-keep", Some("file-1")).await;
        let guard = guard_of(&pool, "v-keep").await;
        mark_mirrored(&pool, &guard, 1, Some("rev-1")).await;
        set_status(&pool, &guard, STATUS_CONFLICT, Some("REMOTE_CONFLICT")).await;

        settle_current(&pool, &guard, 1).await;

        let b = load_binding(&pool, "v-keep").await;
        assert_eq!(b.sync_status, STATUS_CONFLICT);
        assert_eq!(b.last_mirror_error.as_deref(), Some("REMOTE_CONFLICT"));
    }

    // --- Claims --------------------------------------------------------------

    #[tokio::test]
    async fn manual_backup_reports_busy_instead_of_racing_a_running_pass() {
        let pool = test_pool().await;
        seed_vault(&pool, "v-busy").await;
        seed_binding(&pool, "v-busy", Some("file-1")).await;
        seed_usable_token(&pool, "v-busy").await;

        // Stand in for a detached pass that is still uploading.
        let held = Claim::try_acquire("v-busy").expect("claim");

        match mirror_now(&pool, "v-busy").await {
            MirrorOutcome::Error { code } => assert_eq!(code, ERR_MIRROR_BUSY),
            other => panic!("expected MIRROR_BUSY, got {other:?}"),
        }
        assert!(
            !claim("v-busy"),
            "the running pass must still own the claim after a refused manual backup"
        );
        drop(held);
    }

    /// A leaked claim would stop every future mirror for the vault, so dropping
    /// the guard must always release it.
    #[tokio::test]
    async fn claim_is_released_when_the_guard_drops() {
        let held = Claim::try_acquire("t-guard").expect("claim");
        assert!(!claim("t-guard"), "second claim must coalesce");
        drop(held);

        let again = claim_waiting("t-guard", Duration::from_millis(1)).await;
        assert!(again.is_some(), "dropping the guard must release the vault");
        drop(again);
    }
}
