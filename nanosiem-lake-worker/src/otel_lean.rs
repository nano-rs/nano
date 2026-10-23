// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean-lake OTLP traces and metrics (NAN-3243).
//!
//! A lean tenant has no Iceberg catalog, no gen1 hot-tail ledger and no owner
//! writer, so the gen1 drain (`otel_handoff`: handoff -> staged hot tail ->
//! Iceberg) cannot run for it. The edge half is shared: the tenant Worker's
//! `otel.internal` outbound host lands every Vector `otlp_lake_*` batch as one
//! immutable object under `otel-handoff-v1/tenant_uuid=<T>/` in the tenant's
//! own bucket `nano-shared-r2-<T>`, exactly as on gen1.
//!
//! The lean drain is `lake_otel_ingest` with `NANO_OTEL_LAKE_MODE=lean`:
//!
//! * **Durable store = the handoff objects.** They stay in R2 for the
//!   tenant's retention window and are deleted by [`expire_handoff_objects`]
//!   once their receipt hour is older than it, and never while the tenant has
//!   ANY active or ambiguous legal hold (the lean coordinator policy, 9003440:
//!   OTLP event times are client-supplied, so a receipt hour bounds nothing
//!   about which held hours an object's rows fall in). There is no second durable copy to keep in
//!   step, so no ledger rows, no owner-plane writes and no control-DB growth.
//! * **Query store = the local mirror** (`OtelHandoffDrain::lean`): rows are
//!   normalized and encoded into the same native OTLP Parquet shape the gen1
//!   query planners read, one directory per event hour, and
//!   [`compact_mirror`] folds each hour into one file so the query source glob
//!   stays bounded. The mirror is a cache: an empty mirror (a rescheduled pod)
//!   re-drains every handoff object inside the mirror window.
//! * **Restart resumes** (NAN-3886): on a persistent mirror volume a new
//!   process keeps the resident Parquet, the drain markers and the listing
//!   state ([`load_lean_scan_state`]: live-window watermark + backfill sweep
//!   cursor), so it drains only what arrived since, and never re-lists the
//!   whole prefix to find out.
//! * **Exactly-once per mirror** through local drain markers
//!   ([`LeanOtelHandoffLedger`]) written after the Parquet lands. A cycle's
//!   Parquet files and markers are written under a drain journal
//!   ([`begin_drain_journal`]): a crash between the first file and the last
//!   marker is rolled back ([`recover_drain_journal`]) and the objects are
//!   re-drained, so no row is ever mirrored twice.
//! * **Presence** is the existing `otel_publish` heartbeat definer (9000760),
//!   so `/api/observability/telemetry` turns `available` without any lean
//!   special case; the retention window and legal holds come from
//!   `nano_shared.read_lake_purge_policy()` on the same session.
//! * **R2 credential**: a short-lived key scoped to exactly
//!   `otel-handoff-v1/tenant_uuid=<T>/` in `nano-shared-r2-<T>` (the lean
//!   per-tenant credential shape, `S3Location` JSON), re-read every
//!   `NANO_OTEL_LEAN_CREDENTIAL_RELOAD_SECONDS`; endpoint, bucket, region and
//!   prefix are pinned at boot. Every key this module touches is checked
//!   against the same prefix.

use crate::otel_handoff::{
    handoff_prefix, mirror_objects, parse_handoff_key, receipt_epoch_hour, write_mirror_object,
    write_mirror_object_synced, DrainAcknowledgement, LeanScanState, LedgerTailObject,
    OtelHandoffLedger, OtelHandoffSource, OTEL_HANDOFF_PREFIX,
};
use crate::otel_iceberg::{otel_arrow_schema, OtelDataset};
use crate::part_ingest::s3_store::S3Location;
use chrono::{DateTime, Utc};
use anyhow::{bail, ensure, Context, Result};
use arc_swap::ArcSwap;
use opendal::layers::RetryLayer;
use opendal::services::S3;
use opendal::Operator;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;

pub use nanosiem_core::observability::slo_repository::{OTEL_MIN_RETENTION_DAYS, SLO_WINDOW_DAYS_MAX};

/// NAN-3894: the OTLP retention actually applied for a tenant whose own
/// retention is `tenant_days`: never below [`OTEL_MIN_RETENTION_DAYS`] (so
/// the longest SLO window stays attestable), never shorter than the tenant's
/// own setting. Legal holds are unaffected (they only pause deletes).
pub fn otel_retention_days(tenant_days: u32) -> u32 {
    tenant_days.max(OTEL_MIN_RETENTION_DAYS)
}

fn with_otel_retention_floor(policy: Option<LeanPurgePolicy>) -> Option<LeanPurgePolicy> {
    policy.map(|policy| LeanPurgePolicy { retention_days: otel_retention_days(policy.retention_days), ..policy })
}

/// Directory (under the mirror root) holding the local drain markers.
pub const DRAIN_MARKER_DIR: &str = ".drained";
/// An event hour with more files than this is compacted even while open.
pub const OPEN_HOUR_COMPACT_FILES: usize = 32;
/// How long a read of the purge policy is reused.
const POLICY_TTL: Duration = Duration::from_secs(300);
/// An idle drain (nothing drained) heartbeats at most this often. The
/// presence row is one upsert per tenant either way; this keeps an idle
/// tenant's control-DB write rate at one per minute instead of one per drain
/// cycle and dataset (the console's liveness window is 15 minutes).
pub const IDLE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
const MAX_CREDENTIAL_FILE_BYTES: usize = 16 * 1024;

/// The one prefix the lean drain's R2 credential is scoped to.
pub fn lean_handoff_credential_prefix(tenant: Uuid) -> String {
    format!("{OTEL_HANDOFF_PREFIX}tenant_uuid={tenant}/")
}

/// `nano-shared-r2-<T>`, the tenant's own bucket.
pub fn lean_tenant_bucket(tenant: Uuid) -> String {
    format!("nano-shared-r2-{tenant}")
}

/// The location the presence heartbeat records for one dataset: the handoff
/// prefix the rows are drained from (the 9000760 CHECK admits any location in
/// the tenant bucket; there is no table on lean).
pub fn lean_dataset_location(tenant: Uuid, dataset: OtelDataset) -> String {
    format!(
        "s3://{}/{}",
        lean_tenant_bucket(tenant),
        handoff_prefix(tenant, dataset).trim_end_matches('/')
    )
}

// ---------------------------------------------------------------------------
// R2 source (prefix-scoped, reloadable credential)
// ---------------------------------------------------------------------------

fn read_lean_location(path: &Path, tenant: Uuid) -> Result<(S3Location, Vec<u8>)> {
    let bytes = std::fs::read(path).context("lean OTLP R2 credential file")?;
    ensure!(
        bytes.len() <= MAX_CREDENTIAL_FILE_BYTES,
        "lean OTLP R2 credential file is too large"
    );
    let location: S3Location =
        serde_json::from_slice(&bytes).context("lean OTLP R2 credential file")?;
    if location.prefix != lean_handoff_credential_prefix(tenant) {
        bail!("lean OTLP R2 credential prefix is not this tenant's handoff prefix");
    }
    if location.bucket != lean_tenant_bucket(tenant) {
        bail!("lean OTLP R2 credential names another bucket than the tenant's own");
    }
    if location.access_key_id.is_empty() || location.secret_access_key.is_empty() {
        bail!("lean OTLP R2 credential is empty");
    }
    Ok((location, bytes))
}

fn lean_operator(location: &S3Location) -> Result<Operator> {
    // Rooted at the bucket: handoff keys are absolute (`otel-handoff-v1/...`),
    // the prefix scope is enforced by the credential and by `guard`.
    let mut builder = S3::default()
        .bucket(&location.bucket)
        .region(&location.region)
        .endpoint(&location.endpoint)
        .access_key_id(&location.access_key_id)
        .secret_access_key(&location.secret_access_key)
        .disable_config_load()
        .disable_ec2_metadata();
    if let Some(token) = &location.session_token {
        builder = builder.session_token(token);
    }
    let retry = RetryLayer::new()
        .with_min_delay(Duration::from_millis(200))
        .with_max_delay(Duration::from_secs(5))
        .with_max_times(5)
        .with_jitter();
    let timeout = opendal::layers::TimeoutLayer::new()
        .with_timeout(Duration::from_secs(60))
        .with_io_timeout(Duration::from_secs(30));
    Ok(Operator::new(builder)?
        .layer(crate::r2_ops::layer())
        .layer(timeout)
        .layer(retry)
        .finish())
}

/// The tenant's handoff prefix in R2, through a reloadable credential.
pub struct LeanOtelR2Source {
    tenant: Uuid,
    prefix: String,
    path: PathBuf,
    boot: (String, String, String),
    operator: ArcSwap<Operator>,
    last: Mutex<Vec<u8>>,
}

impl LeanOtelR2Source {
    pub fn open(path: &Path, tenant: Uuid) -> Result<Self> {
        let (location, bytes) = read_lean_location(path, tenant)?;
        Ok(Self {
            tenant,
            prefix: lean_handoff_credential_prefix(tenant),
            path: path.to_path_buf(),
            boot: (
                location.endpoint.clone(),
                location.bucket.clone(),
                location.region.clone(),
            ),
            operator: ArcSwap::from_pointee(lean_operator(&location)?),
            last: Mutex::new(bytes),
        })
    }

    /// Re-read the credential file; swap the operator in when it changed.
    /// Endpoint, bucket, region and prefix are pinned to the boot values.
    pub fn reload(&self) -> Result<bool> {
        let (location, bytes) = read_lean_location(&self.path, self.tenant)?;
        let mut last = self
            .last
            .lock()
            .map_err(|_| anyhow::anyhow!("credential lock poisoned"))?;
        if *last == bytes {
            return Ok(false);
        }
        if (
            location.endpoint.as_str(),
            location.bucket.as_str(),
            location.region.as_str(),
        ) != (
            self.boot.0.as_str(),
            self.boot.1.as_str(),
            self.boot.2.as_str(),
        ) {
            bail!("lean OTLP R2 credential changed its endpoint, bucket or region; refusing the rotation");
        }
        self.operator.store(Arc::new(lean_operator(&location)?));
        *last = bytes;
        Ok(true)
    }

    fn guard(&self, key: &str) -> Result<()> {
        if !key.starts_with(&self.prefix) || key.contains("..") {
            bail!("lean OTLP R2 access outside the tenant handoff prefix");
        }
        Ok(())
    }
}

impl OtelHandoffSource for LeanOtelR2Source {
    fn list<'a>(
        &'a self,
        prefix: &'a str,
        start_after: Option<&'a str>,
        limit: usize,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            self.guard(prefix)?;
            let operator = self.operator.load_full();
            let keys =
                OtelHandoffSource::list(operator.as_ref(), prefix, start_after, limit).await?;
            for key in &keys {
                self.guard(key)?;
            }
            Ok(keys)
        })
    }

    fn list_receipt_hours<'a>(
        &'a self,
        prefix: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<i32>>> + Send + 'a>> {
        Box::pin(async move {
            self.guard(prefix)?;
            let operator = self.operator.load_full();
            OtelHandoffSource::list_receipt_hours(operator.as_ref(), prefix).await
        })
    }

    fn head<'a>(
        &'a self,
        key: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<(u64, String)>> + Send + 'a>> {
        Box::pin(async move {
            self.guard(key)?;
            let operator = self.operator.load_full();
            OtelHandoffSource::head(operator.as_ref(), key).await
        })
    }

    fn read_exact<'a>(
        &'a self,
        key: &'a str,
        expected_bytes: u64,
        expected_sha256: &'a str,
        expected_etag: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move {
            self.guard(key)?;
            let operator = self.operator.load_full();
            OtelHandoffSource::read_exact(
                operator.as_ref(),
                key,
                expected_bytes,
                expected_sha256,
                expected_etag,
            )
            .await
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            self.guard(key)?;
            let operator = self.operator.load_full();
            OtelHandoffSource::delete(operator.as_ref(), key).await
        })
    }
}

// ---------------------------------------------------------------------------
// Presence + purge policy (the `otel_publish` data-path session)
// ---------------------------------------------------------------------------

/// The tenant's locked retention window and legal-hold hours.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeanPurgePolicy {
    pub retention_days: u32,
    /// Event hours (hours since the epoch) under an active or ambiguous hold.
    pub held_hours: Vec<i32>,
}

/// The control-plane facts the lean drain writes and reads. PostgreSQL in
/// production, in-memory in tests.
pub trait OtelDrainPresence: Send + Sync {
    /// `nano_shared.record_lake_otel_drain_heartbeat` (one row per tenant).
    fn heartbeat<'a>(
        &'a self,
        batches: u64,
        rows: u64,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    /// `nano_shared.read_lake_purge_policy()`; `None` when the tenant has none.
    fn purge_policy<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<LeanPurgePolicy>>> + Send + 'a>>;
}

pub struct PostgresOtelDrainPresence {
    pool: sqlx::PgPool,
    drain_identity: String,
    spans_location: String,
    metrics_location: String,
}

impl PostgresOtelDrainPresence {
    pub fn new(pool: sqlx::PgPool, tenant: Uuid, drain_identity: String) -> Self {
        Self {
            pool,
            drain_identity,
            spans_location: lean_dataset_location(tenant, OtelDataset::Spans),
            metrics_location: lean_dataset_location(tenant, OtelDataset::Metrics),
        }
    }
}

impl OtelDrainPresence for PostgresOtelDrainPresence {
    fn heartbeat<'a>(
        &'a self,
        batches: u64,
        rows: u64,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            sqlx::query("SELECT nano_shared.record_lake_otel_drain_heartbeat($1, $2, $3, $4, $5)")
                .bind(&self.drain_identity)
                .bind(&self.spans_location)
                .bind(&self.metrics_location)
                .bind(i64::try_from(batches)?)
                .bind(i64::try_from(rows)?)
                .execute(&self.pool)
                .await
                .context("record lean OTLP drain heartbeat")?;
            Ok(())
        })
    }

    fn purge_policy<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<LeanPurgePolicy>>> + Send + 'a>> {
        Box::pin(async move {
            let row: Option<(i32, Vec<i32>)> = sqlx::query_as(
                "SELECT retention_days, held_hours FROM nano_shared.read_lake_purge_policy()",
            )
            .fetch_optional(&self.pool)
            .await
            .context("read the tenant purge policy for the lean OTLP drain")?;
            Ok(row.and_then(|(days, held_hours)| {
                u32::try_from(days)
                    .ok()
                    .filter(|days| *days > 0)
                    .map(|retention_days| LeanPurgePolicy {
                        retention_days,
                        held_hours,
                    })
            }))
        })
    }
}

// ---------------------------------------------------------------------------
// Ledger: local drain markers
// ---------------------------------------------------------------------------

/// `OtelHandoffLedger` for the lean drain. A handoff object is drained once
/// per mirror: its marker `<mirror>/.drained/<dataset>/hour=<receipt>/<sha>`
/// is written after the object's Parquet is in the mirror. The "staged" set
/// is the mirror itself, so `reconcile_mirror` prunes by the age bound only.
pub struct LeanOtelHandoffLedger {
    tenant: Uuid,
    mirror: PathBuf,
    presence: Arc<dyn OtelDrainPresence>,
    policy: Mutex<Option<(Instant, Option<LeanPurgePolicy>)>>,
    last_heartbeat: Mutex<Option<Instant>>,
}

impl LeanOtelHandoffLedger {
    pub fn new(tenant: Uuid, mirror: PathBuf, presence: Arc<dyn OtelDrainPresence>) -> Self {
        Self {
            tenant,
            mirror,
            presence,
            policy: Mutex::new(None),
            last_heartbeat: Mutex::new(None),
        }
    }

    /// The purge policy read NOW (cache refreshed). Every delete decision
    /// uses this, never the cached copy: a legal hold placed a minute ago
    /// must stop the next expiry pass.
    pub async fn fresh_purge_policy(&self) -> Result<Option<LeanPurgePolicy>> {
        let policy = with_otel_retention_floor(self.presence.purge_policy().await?);
        *self
            .policy
            .lock()
            .map_err(|_| anyhow::anyhow!("policy lock poisoned"))? =
            Some((Instant::now(), policy.clone()));
        Ok(policy)
    }

    /// The purge policy, cached for [`POLICY_TTL`] (mirror floor only; never
    /// for deletes).
    pub async fn purge_policy(&self) -> Result<Option<LeanPurgePolicy>> {
        if let Some((at, policy)) = self
            .policy
            .lock()
            .map_err(|_| anyhow::anyhow!("policy lock poisoned"))?
            .as_ref()
        {
            if at.elapsed() < POLICY_TTL {
                return Ok(policy.clone());
            }
        }
        let policy = with_otel_retention_floor(self.presence.purge_policy().await?);
        *self
            .policy
            .lock()
            .map_err(|_| anyhow::anyhow!("policy lock poisoned"))? =
            Some((Instant::now(), policy.clone()));
        Ok(policy)
    }

    pub fn marker_path(
        mirror: &Path,
        dataset: OtelDataset,
        receipt_hour: &str,
        sha256: &str,
    ) -> PathBuf {
        mirror
            .join(DRAIN_MARKER_DIR)
            .join(dataset.as_str())
            .join(format!("hour={receipt_hour}"))
            .join(sha256)
    }
}

impl OtelHandoffLedger for LeanOtelHandoffLedger {
    fn drained_keys<'a>(
        &'a self,
        dataset: OtelDataset,
        candidates: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let mut drained = Vec::new();
            for key in candidates {
                let parsed = parse_handoff_key(key, self.tenant)?;
                if parsed.dataset != dataset {
                    bail!("lean OTLP ledger check crossed its dataset");
                }
                if Self::marker_path(
                    &self.mirror,
                    dataset,
                    &parsed.receipt_hour,
                    &parsed.content_sha256,
                )
                .is_file()
                {
                    drained.push(key.clone());
                }
            }
            Ok(drained)
        })
    }

    fn acknowledge<'a>(
        &'a self,
        acknowledgement: &'a DrainAcknowledgement,
    ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut drained = 0_u64;
            let mut rows = 0_u64;
            let mut directories = std::collections::BTreeSet::new();
            for batch in &acknowledgement.batches {
                let parsed = parse_handoff_key(&batch.object_key, self.tenant)?;
                let outcome = if batch.tail_batch_sha256.is_some() {
                    drained += 1;
                    rows += u64::from(batch.rows_decoded);
                    "drained\n".to_string()
                } else {
                    format!(
                        "rejected {}\n",
                        batch.last_error.as_deref().unwrap_or("no rows")
                    )
                };
                let path = Self::marker_path(
                    &self.mirror,
                    acknowledgement.dataset,
                    &parsed.receipt_hour,
                    &parsed.content_sha256,
                );
                write_mirror_object(&path, outcome.as_bytes())?;
                if let Some(parent) = path.parent() {
                    directories.insert(parent.to_path_buf());
                }
            }
            // NAN-3886: the markers are durable before the cycle's drain
            // journal is removed (a marker's existence is all that counts).
            for directory in directories {
                std::fs::File::open(&directory)
                    .and_then(|handle| handle.sync_all())
                    .with_context(|| format!("sync lean OTLP drain markers {}", directory.display()))?;
            }
            // The cycle is committed once its markers are durable: retire
            // its journal BEFORE the presence write, so a control-DB outage
            // fails the cycle without rolling back (and re-draining) rows
            // that are already exactly-once in the mirror.
            finish_drain_journal(&self.mirror, acknowledgement.dataset)?;
            self.presence.heartbeat(drained, rows).await?;
            if let Ok(mut last) = self.last_heartbeat.lock() {
                *last = Some(Instant::now());
            }
            Ok(())
        })
    }

    fn staged_objects<'a>(
        &'a self,
        dataset: OtelDataset,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<LedgerTailObject>>> + Send + 'a>> {
        Box::pin(async move {
            mirror_objects(&self.mirror, dataset)?
                .into_iter()
                .map(|(event_hour, path, bytes)| {
                    let sha256 = path
                        .file_stem()
                        .and_then(|stem| stem.to_str())
                        .context("mirrored OTLP object name is not UTF-8")?
                        .to_string();
                    Ok(LedgerTailObject {
                        event_hour,
                        object_uri: path.to_string_lossy().into_owned(),
                        etag: String::new(),
                        bytes,
                        sha256,
                    })
                })
                .collect()
        })
    }

    fn heartbeat<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let due = self
                .last_heartbeat
                .lock()
                .map(|last| last.is_none_or(|at| at.elapsed() >= IDLE_HEARTBEAT_INTERVAL))
                .unwrap_or(true);
            if !due {
                return Ok(());
            }
            self.presence.heartbeat(0, 0).await?;
            if let Ok(mut last) = self.last_heartbeat.lock() {
                *last = Some(Instant::now());
            }
            Ok(())
        })
    }

    fn retention_days<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<u32>>> + Send + 'a>> {
        Box::pin(async move {
            Ok(self
                .purge_policy()
                .await?
                .map(|policy| policy.retention_days))
        })
    }
}

// ---------------------------------------------------------------------------
// NAN-3886: persisted listing state and the per-cycle drain journal
// ---------------------------------------------------------------------------

/// `<mirror>/.drained/<dataset>.scan.json`
pub fn lean_scan_state_path(mirror: &Path, dataset: OtelDataset) -> PathBuf {
    mirror
        .join(DRAIN_MARKER_DIR)
        .join(format!("{}.scan.json", dataset.as_str()))
}

/// The listing state a previous drain process over this mirror left behind.
/// Missing, unreadable, or without the dataset's marker directory (the
/// markers are what the state's progress stands for) = a fresh state: the
/// drain then lists the live hours and sweeps everything below them once,
/// which only re-reads keys whose markers are present.
pub fn load_lean_scan_state(mirror: &Path, dataset: OtelDataset) -> LeanScanState {
    if !mirror.join(DRAIN_MARKER_DIR).join(dataset.as_str()).is_dir() {
        return LeanScanState::default();
    }
    let path = lean_scan_state_path(mirror, dataset);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|error| {
            tracing::warn!(dataset = dataset.as_str(), %error, "lean OTLP drain scan state unreadable; starting a fresh sweep");
            LeanScanState::default()
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => LeanScanState::default(),
        Err(error) => {
            tracing::warn!(dataset = dataset.as_str(), %error, "lean OTLP drain scan state unreadable; starting a fresh sweep");
            LeanScanState::default()
        }
    }
}

/// Persist the listing state (atomic rename; not synced: losing it costs
/// one re-sweep, never a duplicate or a lost row).
pub fn save_lean_scan_state(mirror: &Path, dataset: OtelDataset, state: &LeanScanState) -> Result<()> {
    write_mirror_object(&lean_scan_state_path(mirror, dataset), &serde_json::to_vec(state)?)
}

// ---------------------------------------------------------------------------
// NAN-3894: coverage attestation (hosted SLO `complete_window`)
// ---------------------------------------------------------------------------

/// OTLP event times are client-supplied and objects are keyed by RECEIPT
/// hour: a row whose client clock runs fast can carry an event time up to
/// this far after its receipt time. A window starting at `start` therefore
/// needs every receipt hour from `start - COVERAGE_CLIENT_SKEW` on.
pub const COVERAGE_CLIENT_SKEW: Duration = Duration::from_secs(3_600);
/// The window may end at most this long after the last drain cycle that
/// proved the whole live window drained (the hosted evaluator asks for
/// windows ending "now"; a healthy drain proves the live window every
/// ~10 s). Objects received inside this tail may still be in flight.
pub const COVERAGE_LIVE_SLACK: Duration = Duration::from_secs(300);

/// `<mirror>/.drained/<dataset>.evicted.json`: the newest event hour the
/// byte cap ever evicted from (an object of it, at least).
pub fn mirror_eviction_path(mirror: &Path, dataset: OtelDataset) -> PathBuf {
    mirror
        .join(DRAIN_MARKER_DIR)
        .join(format!("{}.evicted.json", dataset.as_str()))
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct MirrorEviction {
    newest_evicted_hour: Option<i32>,
}

/// Newest event hour the mirror's byte cap evicted from. Unreadable = an
/// error: coverage must never be attested over an unknown eviction.
pub fn newest_evicted_hour(mirror: &Path, dataset: OtelDataset) -> Result<Option<i32>> {
    match std::fs::read(mirror_eviction_path(mirror, dataset)) {
        Ok(bytes) => Ok(serde_json::from_slice::<MirrorEviction>(&bytes)
            .context("lean OTLP mirror eviction record is not valid JSON")?
            .newest_evicted_hour),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).context("read the lean OTLP mirror eviction record"),
    }
}

/// Record (durably, before the files go) the event hours a cap eviction is
/// about to remove objects from.
pub fn record_mirror_eviction(mirror: &Path, evicting: &[(OtelDataset, i32)]) -> Result<()> {
    for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
        let Some(hour) = evicting
            .iter()
            .filter(|(evicted, _)| *evicted == dataset)
            .map(|(_, hour)| *hour)
            .max()
        else {
            continue;
        };
        let previous = newest_evicted_hour(mirror, dataset)?;
        let newest = previous.map_or(hour, |previous| previous.max(hour));
        if previous != Some(newest) {
            let record = MirrorEviction { newest_evicted_hour: Some(newest) };
            write_mirror_object_synced(&mirror_eviction_path(mirror, dataset), &serde_json::to_vec(&record)?)?;
        }
    }
    Ok(())
}

/// One stretch of time the mirror cannot attest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CoverageGap {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
    /// `undrained` (receipt hours with objects not yet proven drained),
    /// `evicted` (event hours the byte cap removed rows from), `in_flight`
    /// (since the last cycle that proved the live window).
    pub reason: &'static str,
}

/// What a lean mirror can attest for one dataset (`GET /v1/otel/coverage`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeanCoverage {
    pub dataset: &'static str,
    /// Every row from here on is in the mirror, except inside `gaps`
    /// (receipt-hour coverage, raised past any evicted event hour). `None`:
    /// nothing is attested (fresh or rebuilding mirror).
    pub covered_since: Option<DateTime<Utc>>,
    pub gaps: Vec<CoverageGap>,
    pub backlogged: bool,
    pub live_proven_at: Option<DateTime<Utc>>,
}

fn hour_start(hour: i32) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(i64::from(hour) * 3_600, 0).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn unix(seconds: i64) -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(seconds, 0).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

/// The coverage report of one dataset.
pub fn lean_coverage(
    dataset: OtelDataset,
    state: &LeanScanState,
    newest_evicted_hour: Option<i32>,
    now: DateTime<Utc>,
) -> LeanCoverage {
    let mut gaps = Vec::new();
    let mut hours = state.unproven_hours.iter().copied().peekable();
    while let Some(first) = hours.next() {
        let mut last = first;
        while hours.peek() == Some(&(last + 1)) {
            last += 1;
            hours.next();
        }
        gaps.push(CoverageGap { start: hour_start(first), end: hour_start(last + 1), reason: "undrained" });
    }
    let covered = state.covered_since_hour.map(|hour| match newest_evicted_hour {
        Some(evicted) => hour.max(evicted + 1),
        None => hour,
    });
    if let Some(evicted) = newest_evicted_hour {
        let start = state.covered_since_hour.map_or(evicted, |hour| hour.min(evicted));
        gaps.push(CoverageGap { start: hour_start(start), end: hour_start(evicted + 1), reason: "evicted" });
    }
    let slack = chrono::Duration::from_std(COVERAGE_LIVE_SLACK).unwrap_or_default();
    if let Some(proven) = state.live_proven_unix.map(unix) {
        if now - proven > slack {
            gaps.push(CoverageGap { start: proven, end: now, reason: "in_flight" });
        }
    }
    gaps.sort_by_key(|gap| gap.start);
    LeanCoverage {
        dataset: dataset.as_str(),
        covered_since: covered.map(hour_start),
        gaps,
        backlogged: state.backlogged,
        live_proven_at: state.live_proven_unix.map(unix),
    }
}

/// NAN-3894: whether the mirror holds EVERY row of `[start, end)`. True only
/// when all of these hold (anything unknown is false):
/// * coverage is attested (`covered_since_hour`, set by a periodic sweep
///   that reached the mirror floor) from `start - COVERAGE_CLIENT_SKEW`;
/// * no receipt hour from `start - COVERAGE_CLIENT_SKEW` up to now may still
///   hold an undrained object (late deliveries land in later receipt hours);
/// * no evicted event hour reaches `start`;
/// * the last cycle left nothing undrained, the live window was proven
///   drained no earlier than `end - COVERAGE_LIVE_SLACK`, and `end` is not
///   in the future.
pub fn lean_window_complete(
    state: &LeanScanState,
    newest_evicted_hour: Option<i32>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    now: DateTime<Utc>,
) -> bool {
    let (Ok(skew), Ok(slack)) = (
        chrono::Duration::from_std(COVERAGE_CLIENT_SKEW),
        chrono::Duration::from_std(COVERAGE_LIVE_SLACK),
    ) else {
        return false;
    };
    if end <= start || end > now || state.backlogged {
        return false;
    }
    let Ok(first_receipt_hour) = i32::try_from((start - skew).timestamp().div_euclid(3_600)) else {
        return false;
    };
    let Some(covered) = state.covered_since_hour else {
        return false;
    };
    if covered > first_receipt_hour {
        return false;
    }
    if newest_evicted_hour.is_some_and(|evicted| start < hour_start(evicted + 1)) {
        return false;
    }
    if state.unproven_hours.range(first_receipt_hour..).next().is_some() {
        return false;
    }
    state
        .live_proven_unix
        .is_some_and(|proven| end <= unix(proven) + slack)
}

/// `<mirror>/.drained/<dataset>.journal.json`
pub fn drain_journal_path(mirror: &Path, dataset: OtelDataset) -> PathBuf {
    mirror
        .join(DRAIN_MARKER_DIR)
        .join(format!("{}.journal.json", dataset.as_str()))
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct DrainJournal {
    /// Mirror files this cycle creates, relative to the mirror root.
    files: Vec<String>,
    /// Handoff keys this cycle acknowledges (their markers).
    keys: Vec<String>,
}

/// Record, durably and BEFORE any of them is written, the mirror files and
/// the handoff keys of one drain cycle.
pub fn begin_drain_journal(mirror: &Path, dataset: OtelDataset, files: &[PathBuf], keys: &[String]) -> Result<()> {
    let journal = DrainJournal {
        files: files
            .iter()
            .map(|path| {
                path.strip_prefix(mirror)
                    .ok()
                    .and_then(|relative| relative.to_str())
                    .map(str::to_string)
                    .context("lean OTLP drain journal file is outside the mirror")
            })
            .collect::<Result<_>>()?,
        keys: keys.to_vec(),
    };
    write_mirror_object_synced(&drain_journal_path(mirror, dataset), &serde_json::to_vec(&journal)?)
}

/// The cycle's markers are durable: its journal is no longer needed.
pub fn finish_drain_journal(mirror: &Path, dataset: OtelDataset) -> Result<()> {
    match std::fs::remove_file(drain_journal_path(mirror, dataset)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("remove the lean OTLP drain journal"),
    }
}

/// Roll back a drain cycle that did not finish: remove every mirror file it
/// created and every marker it wrote, then the journal, so its objects are
/// re-drained exactly once. Returns the files and markers removed. Runs at
/// boot, at the start of every lean cycle, and right after a failed one.
pub fn recover_drain_journal(mirror: &Path, dataset: OtelDataset, tenant: Uuid) -> Result<usize> {
    let path = drain_journal_path(mirror, dataset);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error).context("read the lean OTLP drain journal"),
    };
    let journal: DrainJournal =
        serde_json::from_slice(&bytes).context("lean OTLP drain journal is not valid JSON")?;
    let mut removed = 0;
    let remove = |target: &Path| -> Result<usize> {
        match std::fs::remove_file(target) {
            Ok(()) => Ok(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error).with_context(|| format!("roll back {}", target.display())),
        }
    };
    for file in &journal.files {
        let relative = Path::new(file);
        ensure!(
            relative.starts_with(dataset.as_str())
                && relative
                    .components()
                    .all(|part| matches!(part, std::path::Component::Normal(_))),
            "lean OTLP drain journal names a file outside its dataset mirror"
        );
        removed += remove(&mirror.join(relative))?;
    }
    for key in &journal.keys {
        let parsed = parse_handoff_key(key, tenant)?;
        ensure!(parsed.dataset == dataset, "lean OTLP drain journal crossed its dataset");
        removed += remove(&LeanOtelHandoffLedger::marker_path(
            mirror,
            dataset,
            &parsed.receipt_hour,
            &parsed.content_sha256,
        ))?;
    }
    std::fs::remove_file(&path).context("remove the rolled-back lean OTLP drain journal")?;
    Ok(removed)
}

// ---------------------------------------------------------------------------
// Maintenance: marker pruning, mirror compaction, handoff expiry
// ---------------------------------------------------------------------------

/// Remove drain markers whose receipt hour is below `floor_hour` (the drain
/// skips such keys unread, so their markers are dead). Returns hours removed.
pub fn prune_drained_markers(
    mirror: &Path,
    dataset: OtelDataset,
    floor_hour: i32,
) -> Result<usize> {
    let root = mirror.join(DRAIN_MARKER_DIR).join(dataset.as_str());
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok(0);
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let Some(hour) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix("hour="))
            .and_then(receipt_epoch_hour)
        else {
            continue;
        };
        if hour < floor_hour {
            std::fs::remove_dir_all(entry.path()).with_context(|| {
                format!("prune lean OTLP drain markers {}", entry.path().display())
            })?;
            removed += 1;
        }
    }
    Ok(removed)
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct CompactionReport {
    pub hours_compacted: usize,
    pub files_in: usize,
    pub rows: u64,
}

/// Fold every event hour of one dataset that holds more than one file into
/// ONE Parquet file, so the mirror's query glob grows by hours, not by drain
/// cycles. Closed hours (before `current_hour`) are compacted whenever they
/// hold two or more files; the open hour once it passes
/// [`OPEN_HOUR_COMPACT_FILES`].
///
/// Crash-safe by directory swap: the compacted file is written into
/// `event_hour=H.compacting/`, then `event_hour=H` is renamed to
/// `event_hour=H.old` and the new directory takes its place; neither side
/// directory parses as an event hour, so a query never reads both.
/// [`recover_compaction`] settles a crash at any point. Run it on the drain
/// task only (it must not race the drain's own writes into the hour).
pub fn compact_mirror(
    mirror: &Path,
    dataset: OtelDataset,
    current_hour: i32,
) -> Result<CompactionReport> {
    compact_mirror_with_durability(mirror, dataset, current_hour, false)
}

/// Persist directory swaps before deleting the old copy on a durable local volume.
pub fn compact_mirror_durable(mirror: &Path, dataset: OtelDataset, current_hour: i32) -> Result<CompactionReport> {
    compact_mirror_with_durability(mirror, dataset, current_hour, true)
}

fn compact_mirror_with_durability(mirror: &Path, dataset: OtelDataset, current_hour: i32, durable: bool) -> Result<CompactionReport> {
    recover_compaction_with_durability(mirror, dataset, durable)?;
    // NAN-3886: never fold a file an unfinished drain cycle may still roll
    // back; the next drain cycle settles the journal first.
    if drain_journal_path(mirror, dataset).exists() {
        return Ok(CompactionReport::default());
    }
    let mut by_hour = std::collections::BTreeMap::<i32, Vec<PathBuf>>::new();
    for (hour, path, _) in mirror_objects(mirror, dataset)? {
        by_hour.entry(hour).or_default().push(path);
    }
    let schema = Arc::new(otel_arrow_schema(dataset));
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(16_384))
        .build();
    let root = mirror.join(dataset.as_str());
    let mut report = CompactionReport::default();
    for (hour, files) in by_hour {
        let due = if hour < current_hour {
            files.len() > 1
        } else {
            files.len() > OPEN_HOUR_COMPACT_FILES
        };
        if !due {
            continue;
        }
        let live = root.join(format!("event_hour={hour}"));
        let staging = root.join(format!("event_hour={hour}.compacting"));
        let retired = root.join(format!("event_hour={hour}.old"));
        // Streamed to disk (hashed on the way), never buffered: a busy
        // tenant's hour can be far larger than the pod's memory limit, and an
        // OOM here would recur on every restart (the emptyDir survives).
        std::fs::create_dir_all(&staging)?;
        let temporary = staging.join(format!(".{}.tmp", Uuid::now_v7()));
        let output = HashingWriter {
            inner: std::io::BufWriter::new(std::fs::File::create(&temporary)?),
            digest: Sha256::new(),
        };
        let mut writer = ArrowWriter::try_new(output, schema.clone(), Some(properties.clone()))?;
        let mut rows = 0_u64;
        for file in &files {
            let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(file)?)
                .with_context(|| format!("open mirrored OTLP object {}", file.display()))?
                .build()?;
            for batch in reader {
                let batch = batch?;
                if batch.schema().fields() != schema.fields() {
                    bail!(
                        "mirrored OTLP object {} is not the native OTLP schema",
                        file.display()
                    );
                }
                rows += batch.num_rows() as u64;
                writer.write(&batch)?;
            }
        }
        let mut output = writer.into_inner()?;
        std::io::Write::flush(&mut output.inner)?;
        output
            .inner
            .get_ref()
            .sync_all()
            .context("sync the compacted OTLP mirror hour")?;
        let sha256 = hex::encode(output.digest.finalize());
        std::fs::rename(&temporary, staging.join(format!("{sha256}.parquet")))
            .context("name the compacted OTLP mirror hour")?;
        if durable {
            std::fs::File::open(&staging)?.sync_all()?;
            std::fs::File::open(&root)?.sync_all()?;
        }
        std::fs::rename(&live, &retired).context("retire the uncompacted OTLP mirror hour")?;
        std::fs::rename(&staging, &live).context("install the compacted OTLP mirror hour")?;
        if durable { std::fs::File::open(&root)?.sync_all()?; }
        std::fs::remove_dir_all(&retired).context("remove the retired OTLP mirror hour")?;
        if durable { std::fs::File::open(&root)?.sync_all()?; }
        report.hours_compacted += 1;
        report.files_in += files.len();
        report.rows += rows;
    }
    Ok(report)
}

/// `Write` that hashes every byte it forwards (the compacted file is named
/// by its SHA-256 without being held in memory).
struct HashingWriter<W> {
    inner: W,
    digest: Sha256,
}

impl<W: std::io::Write> std::io::Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.digest.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Settle an interrupted [`compact_mirror`]: a staging directory whose live
/// hour still exists is discarded (the swap never started); a staging
/// directory whose live hour is gone is installed (the swap was half done);
/// a retired directory is removed once the live hour exists, or restored when
/// neither a live hour nor a staging directory exists.
pub fn recover_compaction(mirror: &Path, dataset: OtelDataset) -> Result<()> {
    recover_compaction_with_durability(mirror, dataset, false)
}

pub fn recover_compaction_durable(mirror: &Path, dataset: OtelDataset) -> Result<()> {
    recover_compaction_with_durability(mirror, dataset, true)
}

fn recover_compaction_with_durability(mirror: &Path, dataset: OtelDataset, durable: bool) -> Result<()> {
    let root = mirror.join(dataset.as_str());
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok(());
    };
    let mut names = Vec::new();
    for entry in entries {
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    for name in &names {
        if let Some(hour) = name
            .strip_prefix("event_hour=")
            .and_then(|rest| rest.strip_suffix(".compacting"))
        {
            let live = root.join(format!("event_hour={hour}"));
            if live.exists() {
                std::fs::remove_dir_all(root.join(name))?;
            } else {
                std::fs::rename(root.join(name), &live)?;
            }
            if durable { std::fs::File::open(&root)?.sync_all()?; }
        }
    }
    for name in &names {
        if let Some(hour) = name
            .strip_prefix("event_hour=")
            .and_then(|rest| rest.strip_suffix(".old"))
        {
            let live = root.join(format!("event_hour={hour}"));
            if live.exists() {
                if durable { std::fs::File::open(&root)?.sync_all()?; }
                std::fs::remove_dir_all(root.join(name))?;
            } else {
                std::fs::rename(root.join(name), &live)?;
            }
            if durable { std::fs::File::open(&root)?.sync_all()?; }
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
pub struct ExpiryReport {
    pub deleted: usize,
    /// True when the tenant has an active or ambiguous legal hold: the pass
    /// deleted nothing.
    pub held: bool,
}

/// NAN-4084: how often the handoff retention pass runs. Each pass lists
/// every dataset's handoff prefix (R2 Class A), and retention is
/// receipt-hour granular, so a 60 s cadence bought nothing over 10 min.
pub const HANDOFF_EXPIRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// NAN-4084: when the lean drain loop runs [`expire_handoff_objects`]: every
/// [`HANDOFF_EXPIRY_INTERVAL`], or at the next maintenance pass while the
/// last one was behind (a dataset's pass deleted a full batch).
#[derive(Debug, Clone, Default)]
pub struct HandoffExpiryPacer {
    last: Option<std::time::Instant>,
    behind: bool,
}

impl HandoffExpiryPacer {
    pub fn due(&self, now: std::time::Instant) -> bool {
        self.behind
            || self
                .last
                .is_none_or(|at| now.saturating_duration_since(at) >= HANDOFF_EXPIRY_INTERVAL)
    }

    pub fn record(&mut self, now: std::time::Instant, behind: bool) {
        self.last = Some(now);
        self.behind = behind;
    }
}

/// Delete handoff objects of one dataset whose receipt hour is older than the
/// retention window (at most `limit` per pass, oldest first).
///
/// Legal holds pause the pass ENTIRELY while any active or ambiguous hold
/// exists for the tenant (`held_hours` non-empty), the same coordinator policy
/// the lean part deletes apply (9003440 "a legal hold pauses ALL delete
/// kinds"). An object's receipt hour does not bound its rows' event hours
/// (OTLP timestamps are client-supplied: a client clock a few minutes fast
/// already puts rows in the hour AFTER receipt), so a per-hour comparison
/// against the receipt hour could delete held rows. `policy` must be read
/// fresh for the pass (see [`LeanOtelHandoffLedger::fresh_purge_policy`]).
pub async fn expire_handoff_objects(
    source: &dyn OtelHandoffSource,
    tenant: Uuid,
    dataset: OtelDataset,
    policy: &LeanPurgePolicy,
    now: chrono::DateTime<chrono::Utc>,
    limit: usize,
) -> Result<ExpiryReport> {
    let now_hour = i32::try_from(now.timestamp().div_euclid(3_600))?;
    // The OTLP floor applies even to a policy that did not come through the
    // ledger (NAN-3894).
    let retention_hours = i32::try_from(u64::from(otel_retention_days(policy.retention_days)) * 24)?;
    // Delete only once the whole receipt hour is past the window.
    let cutoff = now_hour - retention_hours - 1;
    let mut report = ExpiryReport::default();
    if !policy.held_hours.is_empty() {
        report.held = true;
        return Ok(report);
    }
    let prefix = handoff_prefix(tenant, dataset);
    for key in source.list(&prefix, None, limit).await? {
        let parsed = match parse_handoff_key(&key, tenant) {
            Ok(parsed) if parsed.dataset == dataset => parsed,
            Ok(_) => bail!("OTLP handoff listing crossed its dataset prefix"),
            Err(_) => continue,
        };
        let Some(receipt) = receipt_epoch_hour(&parsed.receipt_hour) else {
            continue;
        };
        if receipt >= cutoff {
            break;
        }
        source
            .delete(&key)
            .await
            .with_context(|| format!("expire OTLP handoff object {key}"))?;
        report.deleted += 1;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::otel_handoff::{
        handoff_object_key, DrainCycleReport, MirrorPolicy, OtelDrainBinding, OtelHandoffDrain,
        LEAN_SWEEP_INTERVAL, LEAN_SWEEP_LIST_CALLS_PER_CYCLE,
    };
    use chrono::{DateTime, TimeZone, Utc};
    use serde_json::json;
    use std::collections::BTreeMap;

    const TENANT: &str = "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

    fn tenant() -> Uuid {
        Uuid::parse_str(TENANT).unwrap()
    }

    #[derive(Default)]
    struct FakeR2 {
        objects: Mutex<BTreeMap<String, Vec<u8>>>,
        deleted: Mutex<Vec<String>>,
        listed_after: Mutex<Vec<Option<String>>>,
        /// NAN-3886: every list call as `(prefix, start_after)` (receipt-hour
        /// listings included), the keys each object list returned, and the
        /// exact reads served.
        lists: Mutex<Vec<(String, Option<String>)>>,
        listed_keys: Mutex<Vec<usize>>,
        reads: Mutex<Vec<String>>,
    }

    impl FakeR2 {
        fn etag(bytes: &[u8]) -> String {
            format!("\"{}\"", &hex::encode(Sha256::digest(bytes))[..32])
        }
    }

    impl OtelHandoffSource for FakeR2 {
        fn list<'a>(
            &'a self,
            prefix: &'a str,
            start_after: Option<&'a str>,
            limit: usize,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>>> + Send + 'a>> {
            Box::pin(async move {
                self.listed_after
                    .lock()
                    .unwrap()
                    .push(start_after.map(str::to_string));
                self.lists
                    .lock()
                    .unwrap()
                    .push((prefix.to_string(), start_after.map(str::to_string)));
                let keys: Vec<String> = self
                    .objects
                    .lock()
                    .unwrap()
                    .keys()
                    .filter(|key| key.starts_with(prefix))
                    .filter(|key| start_after.is_none_or(|cursor| key.as_str() > cursor))
                    .take(limit)
                    .cloned()
                    .collect();
                self.listed_keys.lock().unwrap().push(keys.len());
                Ok(keys)
            })
        }
        /// One delimiter listing, like S3: it returns hours, not keys.
        fn list_receipt_hours<'a>(
            &'a self,
            prefix: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<i32>>> + Send + 'a>> {
            Box::pin(async move {
                self.lists.lock().unwrap().push((prefix.to_string(), None));
                let objects = self.objects.lock().unwrap();
                Ok(crate::otel_handoff::receipt_hours_under(
                    prefix,
                    objects.keys().map(String::as_str),
                ))
            })
        }
        fn head<'a>(
            &'a self,
            key: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<(u64, String)>> + Send + 'a>> {
            Box::pin(async move {
                let objects = self.objects.lock().unwrap();
                let bytes = objects.get(key).context("absent")?;
                Ok((bytes.len() as u64, Self::etag(bytes)))
            })
        }
        fn read_exact<'a>(
            &'a self,
            key: &'a str,
            expected_bytes: u64,
            expected_sha256: &'a str,
            expected_etag: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
            Box::pin(async move {
                self.reads.lock().unwrap().push(key.to_string());
                let objects = self.objects.lock().unwrap();
                let bytes = objects.get(key).context("absent")?;
                ensure!(
                    bytes.len() as u64 == expected_bytes
                        && hex::encode(Sha256::digest(bytes)) == expected_sha256
                        && Self::etag(bytes) == expected_etag,
                    "exact read fence"
                );
                Ok(bytes.clone())
            })
        }
        fn delete<'a>(
            &'a self,
            key: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                self.objects.lock().unwrap().remove(key);
                self.deleted.lock().unwrap().push(key.to_string());
                Ok(())
            })
        }
    }

    #[derive(Default)]
    struct MemoryPresence {
        beats: Mutex<Vec<(u64, u64)>>,
        policy: Mutex<Option<LeanPurgePolicy>>,
        /// NAN-3886: fail the drained-cycle heartbeat (after the markers).
        fail_beats: Mutex<bool>,
    }

    impl OtelDrainPresence for MemoryPresence {
        fn heartbeat<'a>(
            &'a self,
            batches: u64,
            rows: u64,
        ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
            Box::pin(async move {
                if *self.fail_beats.lock().unwrap() {
                    bail!("presence heartbeat unavailable");
                }
                self.beats.lock().unwrap().push((batches, rows));
                Ok(())
            })
        }
        fn purge_policy<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<Option<LeanPurgePolicy>>> + Send + 'a>> {
            Box::pin(async move { Ok(self.policy.lock().unwrap().clone()) })
        }
    }

    fn binding() -> OtelDrainBinding {
        OtelDrainBinding {
            tenant_uuid: tenant(),
            logical_tenant_key: TENANT.to_string(),
            bucket: lean_tenant_bucket(tenant()),
            spans_location: lean_dataset_location(tenant(), OtelDataset::Spans),
            metrics_location: lean_dataset_location(tenant(), OtelDataset::Metrics),
            drain_identity: "lake-otel-ingest-lean".to_string(),
            max_rows: 50_000,
            max_objects: 256,
            lookback_hours: 48,
        }
    }

    fn span(trace: &str, span: &str, start_nanos: u64) -> serde_json::Value {
        json!({
            "schema_version": "nano-otlp-lake-v1",
            "dataset": "spans",
            "source_type": "otlp_trace",
            "ingest_time_unix_nano": start_nanos + 5_000,
            "event": {
                "traceId": trace,
                "spanId": span,
                "startTimeUnixNano": start_nanos.to_string(),
                "endTimeUnixNano": (start_nanos + 1_000_000).to_string(),
                "name": "GET /checkout",
                "kind": 2,
                "attributes": [{"key": "http.route", "value": {"stringValue": "/checkout"}}],
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "shop"}}]}
            }
        })
    }

    fn metric(name: &str, nanos: u64, value: f64) -> serde_json::Value {
        json!({
            "schema_version": "nano-otlp-lake-v1",
            "dataset": "metrics",
            "source_type": "otlp_metric",
            "ingest_time_unix_nano": nanos + 5_000,
            "event": {
                "name": name,
                "unit": "1",
                "timeUnixNano": nanos.to_string(),
                "kind": "gauge",
                "value": value,
                "attributes": [],
                "resource": {"attributes": [{"key": "service.name", "value": {"stringValue": "shop"}}, {"key": "host.name", "value": {"stringValue": "web-1"}}]}
            }
        })
    }

    fn ndjson(rows: &[serde_json::Value]) -> Vec<u8> {
        let mut out = Vec::new();
        for row in rows {
            serde_json::to_writer(&mut out, row).unwrap();
            out.push(b'\n');
        }
        out
    }

    fn land(store: &FakeR2, dataset: OtelDataset, at: DateTime<Utc>, body: Vec<u8>) -> String {
        let sha = hex::encode(Sha256::digest(&body));
        let key = handoff_object_key(tenant(), dataset, at, &sha).unwrap();
        store.objects.lock().unwrap().insert(key.clone(), body);
        key
    }

    fn lean_drain(
        mirror: &Path,
        store: Arc<FakeR2>,
        presence: Arc<MemoryPresence>,
    ) -> OtelHandoffDrain {
        let ledger = Arc::new(LeanOtelHandoffLedger::new(
            tenant(),
            mirror.to_path_buf(),
            presence,
        ));
        OtelHandoffDrain::lean(
            binding(),
            store,
            ledger,
            mirror.to_path_buf(),
            MirrorPolicy::default(),
        )
        .unwrap()
    }

    fn mirror_rows(mirror: &Path, dataset: OtelDataset) -> u64 {
        mirror_objects(mirror, dataset)
            .unwrap()
            .iter()
            .map(|(_, path, _)| {
                ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(path).unwrap())
                    .unwrap()
                    .build()
                    .unwrap()
                    .map(|batch| batch.unwrap().num_rows() as u64)
                    .sum::<u64>()
            })
            .sum()
    }

    fn now_nanos() -> u64 {
        u64::try_from(Utc::now().timestamp_nanos_opt().unwrap()).unwrap()
    }

    #[test]
    fn credential_is_pinned_to_the_tenant_handoff_prefix_and_bucket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credential.json");
        let write = |prefix: &str, bucket: &str| {
            std::fs::write(
                &path,
                serde_json::to_vec(&json!({
                    "endpoint": "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
                    "region": "auto",
                    "bucket": bucket,
                    "prefix": prefix,
                    "access_key_id": "k",
                    "secret_access_key": "s"
                }))
                .unwrap(),
            )
            .unwrap();
        };
        let own_bucket = lean_tenant_bucket(tenant());
        write(&lean_handoff_credential_prefix(tenant()), &own_bucket);
        let source = LeanOtelR2Source::open(&path, tenant()).unwrap();
        assert!(
            !source.reload().unwrap(),
            "unchanged credential is not swapped"
        );
        write("lake/parts/v1/", &own_bucket);
        assert!(source.reload().is_err(), "a widened prefix is refused");
        write(
            &lean_handoff_credential_prefix(tenant()),
            "nano-shared-r2-other",
        );
        assert!(
            LeanOtelR2Source::open(&path, tenant()).is_err(),
            "another bucket is refused"
        );
        let other = Uuid::now_v7();
        write(&lean_handoff_credential_prefix(other), &own_bucket);
        assert!(
            LeanOtelR2Source::open(&path, tenant()).is_err(),
            "another tenant's prefix is refused"
        );
        // The access guard refuses any key outside the tenant prefix.
        assert!(source
            .guard(&format!(
                "otel-handoff-v1/tenant_uuid={other}/dataset=spans/x"
            ))
            .is_err());
        assert!(source.guard("lake/parts/v1/x").is_err());
        assert!(source
            .guard(&format!(
                "{}dataset=spans/../../x",
                lean_handoff_credential_prefix(tenant())
            ))
            .is_err());
        assert!(source
            .guard(&format!(
                "{}dataset=spans/hour=2026100700/a.ndjson",
                lean_handoff_credential_prefix(tenant())
            ))
            .is_ok());
    }

    #[test]
    fn lean_heartbeat_locations_satisfy_the_drain_assignment_check() {
        // 9000760: both locations inside s3://nano-shared-r2-<tenant>/ and distinct.
        let spans = lean_dataset_location(tenant(), OtelDataset::Spans);
        let metrics = lean_dataset_location(tenant(), OtelDataset::Metrics);
        assert!(spans.starts_with(&format!("s3://nano-shared-r2-{TENANT}/")));
        assert!(metrics.starts_with(&format!("s3://nano-shared-r2-{TENANT}/")));
        assert_ne!(spans, metrics);
        assert!(
            binding().validate().is_ok(),
            "the lean binding passes the drain binding fence"
        );
    }

    #[tokio::test]
    async fn spans_and_metrics_drain_into_the_mirror_once_and_report_presence() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let presence = Arc::new(MemoryPresence::default());
        let drain = lean_drain(mirror.path(), store.clone(), presence.clone());
        assert!(drain.is_lean());
        let t = now_nanos() - 60_000_000_000;
        land(
            &store,
            OtelDataset::Spans,
            Utc::now(),
            ndjson(&[
                span(&"1".repeat(32), &"a".repeat(16), t),
                span(&"1".repeat(32), &"b".repeat(16), t + 10),
            ]),
        );
        land(
            &store,
            OtelDataset::Spans,
            Utc::now(),
            ndjson(&[span(&"2".repeat(32), &"c".repeat(16), t + 20)]),
        );
        land(
            &store,
            OtelDataset::Metrics,
            Utc::now(),
            ndjson(&[
                metric("system.cpu.utilization", t, 0.4),
                metric("system.memory.utilization", t, 0.6),
            ]),
        );

        let spans = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(
            (
                spans.objects_drained,
                spans.rows_published,
                spans.tail_objects_published
            ),
            (2, 3, 0)
        );
        let metrics = drain.drain_once(OtelDataset::Metrics).await.unwrap();
        assert_eq!((metrics.objects_drained, metrics.rows_published), (1, 2));
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 3);
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Metrics), 2);
        assert_eq!(*presence.beats.lock().unwrap(), vec![(2, 3), (1, 2)]);

        // A second cycle drains nothing again; its idle heartbeat is
        // throttled (the drain beat under a minute ago), so the control DB
        // sees no extra write.
        let again = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((again.objects_seen, again.objects_drained), (2, 0));
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 3);
        assert_eq!(*presence.beats.lock().unwrap(), vec![(2, 3), (1, 2)]);
        // The handoff objects are the durable copy: nothing was deleted.
        assert!(store.deleted.lock().unwrap().is_empty());
        // The query side sees the mirror as the dataset.
        assert!(
            crate::otel_handoff::mirror_snapshot_cache(mirror.path(), OtelDataset::Spans)
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn an_empty_mirror_redrains_every_handoff_object() {
        let store = Arc::new(FakeR2::default());
        let t = now_nanos() - 60_000_000_000;
        land(
            &store,
            OtelDataset::Spans,
            Utc::now(),
            ndjson(&[span(&"3".repeat(32), &"d".repeat(16), t)]),
        );
        let first = tempfile::tempdir().unwrap();
        let drain = lean_drain(
            first.path(),
            store.clone(),
            Arc::new(MemoryPresence::default()),
        );
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        // A rescheduled pod: fresh mirror, same R2.
        let second = tempfile::tempdir().unwrap();
        let restarted = lean_drain(
            second.path(),
            store.clone(),
            Arc::new(MemoryPresence::default()),
        );
        assert_eq!(
            restarted
                .drain_once(OtelDataset::Spans)
                .await
                .unwrap()
                .rows_published,
            1
        );
        assert_eq!(mirror_rows(second.path(), OtelDataset::Spans), 1);
    }

    /// NAN-3290: a rescheduled pod (empty emptyDir: no mirror, no drain
    /// markers) with a backlog larger than one cycle serves the newest
    /// receipt hour after its FIRST cycle, then backfills the older hours.
    #[tokio::test]
    async fn a_restarted_lean_drain_serves_the_newest_hour_first() {
        let store = Arc::new(FakeR2::default());
        let now = Utc::now();
        let hour_of = |at: DateTime<Utc>| i32::try_from(at.timestamp().div_euclid(3_600)).unwrap();
        for age in 0..3_i64 {
            let at = now - chrono::Duration::hours(age);
            let base =
                u64::try_from(at.timestamp().div_euclid(3_600) * 3_600).unwrap() * 1_000_000_000;
            for index in 0..4_u64 {
                land(
                    &store,
                    OtelDataset::Spans,
                    at,
                    ndjson(&[span(
                        &format!("{age:016x}{index:016x}"),
                        &"a".repeat(16),
                        base + index,
                    )]),
                );
            }
        }
        let restarted = |mirror: &Path| {
            let ledger = Arc::new(LeanOtelHandoffLedger::new(
                tenant(),
                mirror.to_path_buf(),
                Arc::new(MemoryPresence::default()),
            ));
            OtelHandoffDrain::lean(
                OtelDrainBinding {
                    max_objects: 4,
                    ..binding()
                },
                store.clone(),
                ledger,
                mirror.to_path_buf(),
                MirrorPolicy::default(),
            )
            .unwrap()
        };
        let mirror = tempfile::tempdir().unwrap();
        let drain = restarted(mirror.path());
        let first = drain.drain_once(OtelDataset::Spans).await.unwrap();
        // NAN-3886: cycle one lists the live window (current + previous
        // hour, 8 keys); the full live window saturates max_objects, so the
        // backfill sweep waits for a later cycle.
        assert_eq!(
            (first.objects_seen, first.objects_drained, first.backlogged, first.sweep),
            (8, 4, true, false)
        );
        let hours = mirror_objects(mirror.path(), OtelDataset::Spans)
            .unwrap()
            .into_iter()
            .map(|(hour, _, _)| hour)
            .collect::<Vec<_>>();
        assert_eq!(
            hours,
            vec![hour_of(now)],
            "only the live hour after cycle one"
        );
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 4);
        for _ in 0..6 {
            drain.drain_once(OtelDataset::Spans).await.unwrap();
        }
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 12);
    }

    #[tokio::test]
    async fn malformed_objects_are_marked_rejected_not_retried() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let presence = Arc::new(MemoryPresence::default());
        let drain = lean_drain(mirror.path(), store.clone(), presence.clone());
        land(
            &store,
            OtelDataset::Spans,
            Utc::now(),
            b"{not json}\n".to_vec(),
        );
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((report.objects_rejected, report.rows_published), (1, 0));
        let again = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(
            again.objects_rejected, 0,
            "the rejected object is acknowledged"
        );
        // The acknowledgement beat; the idle cycle right after is throttled.
        assert_eq!(*presence.beats.lock().unwrap(), vec![(0, 0)]);
    }

    #[tokio::test]
    async fn objects_older_than_the_mirror_floor_are_skipped_unread() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let presence = Arc::new(MemoryPresence::default());
        *presence.policy.lock().unwrap() = Some(LeanPurgePolicy {
            retention_days: 1,
            held_hours: vec![],
        });
        let drain = lean_drain(mirror.path(), store.clone(), presence);
        // A 1-day tenant retention is floored to OTEL_MIN_RETENTION_DAYS
        // (NAN-3894), so the object must be older than that to be skipped.
        let old = Utc::now() - chrono::Duration::days(40);
        land(
            &store,
            OtelDataset::Spans,
            old,
            ndjson(&[span(
                &"4".repeat(32),
                &"e".repeat(16),
                now_nanos() - 40 * 86_400_000_000_000,
            )]),
        );
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((report.objects_seen, report.rows_published), (0, 0));
    }

    /// The lean backfill sweep stops at the mirror floor: with a long
    /// retention the prefix holds many keys below the floor, and the sweep
    /// never lists (or reads) them. An object older than the lookback but
    /// inside the floor is still re-drained into an empty mirror.
    #[tokio::test]
    async fn a_lean_sweep_never_lists_below_the_mirror_floor() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let presence = Arc::new(MemoryPresence::default());
        *presence.policy.lock().unwrap() = Some(LeanPurgePolicy {
            retention_days: 365,
            held_hours: vec![],
        });
        let drain = lean_drain(mirror.path(), store.clone(), presence);
        let ten_days = Utc::now() - chrono::Duration::days(10);
        land(
            &store,
            OtelDataset::Spans,
            ten_days,
            ndjson(&[span(
                &"5".repeat(32),
                &"f".repeat(16),
                now_nanos() - 10 * 86_400_000_000_000,
            )]),
        );
        let ancient = land(
            &store,
            OtelDataset::Spans,
            Utc::now() - chrono::Duration::days(200),
            b"never read\n".to_vec(),
        );
        // A fresh mirror sweeps below the live window on its first cycle.
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(
            (report.objects_seen, report.objects_drained, report.objects_rejected, report.sweep),
            (1, 1, 0, true)
        );
        assert!(!store.reads.lock().unwrap().contains(&ancient));
        let floor = hour_of(Utc::now()) - i32::try_from(MirrorPolicy::DEFAULT_MAX_AGE_HOURS).unwrap();
        let dataset_prefix = handoff_prefix(tenant(), OtelDataset::Spans);
        for (prefix, start_after) in store.lists.lock().unwrap().iter() {
            match prefix.strip_prefix(&dataset_prefix) {
                // The live listing and the receipt-hour listing.
                Some("") => {
                    if let Some(cursor) = start_after {
                        assert!(cursor >= &OtelHandoffDrain::floor_cursor(&dataset_prefix, floor).unwrap());
                    }
                }
                Some(hour) => {
                    let label = hour.strip_prefix("hour=").unwrap().trim_end_matches('/');
                    assert!(receipt_epoch_hour(label).unwrap() >= floor, "{prefix}");
                }
                None => panic!("listed outside the dataset prefix: {prefix}"),
            }
        }
    }

    #[tokio::test]
    async fn an_idle_drain_heartbeats_at_most_once_a_minute() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let presence = Arc::new(MemoryPresence::default());
        let drain = lean_drain(mirror.path(), store, presence.clone());
        for _ in 0..5 {
            drain.drain_once(OtelDataset::Spans).await.unwrap();
            drain.drain_once(OtelDataset::Metrics).await.unwrap();
        }
        assert_eq!(*presence.beats.lock().unwrap(), vec![(0, 0)]);
    }

    /// NAN-4084: the drain loop backs off on `objects_pending == 0`, so a
    /// cycle must report every undrained object it found, and none once the
    /// objects it drained are only acknowledged keys still in R2.
    #[tokio::test]
    async fn a_cycle_reports_pending_objects_only_while_any_are_undrained() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let presence = Arc::new(MemoryPresence::default());
        let drain = lean_drain(mirror.path(), store.clone(), presence);
        let reports = drain_until_idle(&drain, OtelDataset::Spans).await;
        assert!(reports.iter().all(|report| report.objects_pending == 0), "nothing landed: {reports:?}");
        land_spans(&store, Utc::now(), "nan4084", 3);
        let found = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((found.objects_pending, found.objects_drained), (1, 1));
        let reports = drain_until_idle(&drain, OtelDataset::Spans).await;
        let last = reports.last().unwrap();
        assert_eq!(last.objects_pending, 0, "the drained key is still listed but not pending");
        assert!(last.objects_seen >= 1, "the acknowledged key stays in R2: {last:?}");
    }

    #[test]
    fn the_handoff_expiry_runs_every_ten_minutes_and_sooner_only_while_behind() {
        assert_eq!(HANDOFF_EXPIRY_INTERVAL, std::time::Duration::from_secs(600));
        let start = std::time::Instant::now();
        let mut pacer = HandoffExpiryPacer::default();
        assert!(pacer.due(start), "the first maintenance pass expires");
        pacer.record(start, false);
        let minute = std::time::Duration::from_secs(60);
        for pass in 1..10 {
            assert!(!pacer.due(start + minute * pass), "maintenance pass {pass} skips the listing");
        }
        assert!(pacer.due(start + HANDOFF_EXPIRY_INTERVAL));
        // A full batch: the next maintenance pass continues instead of waiting 10 min.
        pacer.record(start + HANDOFF_EXPIRY_INTERVAL, true);
        assert!(pacer.due(start + HANDOFF_EXPIRY_INTERVAL + minute));
        pacer.record(start + HANDOFF_EXPIRY_INTERVAL + minute, false);
        assert!(!pacer.due(start + HANDOFF_EXPIRY_INTERVAL + minute * 2));
    }

    #[tokio::test]
    async fn compaction_folds_each_closed_hour_into_one_file_without_losing_rows() {
        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let drain = lean_drain(
            mirror.path(),
            store.clone(),
            Arc::new(MemoryPresence::default()),
        );
        let hour_start = Utc::now().timestamp().div_euclid(3_600) * 3_600 - 7_200; // two hours ago
        let base = u64::try_from(hour_start).unwrap() * 1_000_000_000;
        for index in 0..5_u64 {
            land(
                &store,
                OtelDataset::Spans,
                Utc::now(),
                ndjson(&[span(
                    &format!("{index:032x}"),
                    &"f".repeat(16),
                    base + index * 1_000,
                )]),
            );
            drain.drain_once(OtelDataset::Spans).await.unwrap();
        }
        assert_eq!(
            mirror_objects(mirror.path(), OtelDataset::Spans)
                .unwrap()
                .len(),
            5
        );
        let current = i32::try_from(Utc::now().timestamp().div_euclid(3_600)).unwrap();
        let report = compact_mirror(mirror.path(), OtelDataset::Spans, current).unwrap();
        assert_eq!(
            (report.hours_compacted, report.files_in, report.rows),
            (1, 5, 5)
        );
        assert_eq!(
            mirror_objects(mirror.path(), OtelDataset::Spans)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 5);
        // Idempotent; and the open hour is left alone below its threshold.
        assert_eq!(
            compact_mirror(mirror.path(), OtelDataset::Spans, current)
                .unwrap()
                .hours_compacted,
            0
        );
    }

    #[test]
    fn interrupted_compaction_recovers_to_exactly_one_copy() {
        let mirror = tempfile::tempdir().unwrap();
        let root = mirror.path().join("spans");
        // Crash after staging, before the swap: discard the staging copy.
        std::fs::create_dir_all(root.join("event_hour=10")).unwrap();
        std::fs::write(root.join("event_hour=10/a.parquet"), b"x").unwrap();
        std::fs::create_dir_all(root.join("event_hour=10.compacting")).unwrap();
        std::fs::write(root.join("event_hour=10.compacting/b.parquet"), b"y").unwrap();
        // Crash between the two renames: install the staged copy.
        std::fs::create_dir_all(root.join("event_hour=11.old")).unwrap();
        std::fs::write(root.join("event_hour=11.old/a.parquet"), b"x").unwrap();
        std::fs::create_dir_all(root.join("event_hour=11.compacting")).unwrap();
        std::fs::write(root.join("event_hour=11.compacting/b.parquet"), b"y").unwrap();
        // Crash before removing the retired copy.
        std::fs::create_dir_all(root.join("event_hour=12")).unwrap();
        std::fs::write(root.join("event_hour=12/b.parquet"), b"y").unwrap();
        std::fs::create_dir_all(root.join("event_hour=12.old")).unwrap();
        std::fs::write(root.join("event_hour=12.old/a.parquet"), b"x").unwrap();
        recover_compaction(mirror.path(), OtelDataset::Spans).unwrap();
        let mut left = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        left.sort();
        assert_eq!(
            left,
            vec!["event_hour=10", "event_hour=11", "event_hour=12"]
        );
        assert!(root.join("event_hour=10/a.parquet").is_file());
        assert!(root.join("event_hour=11/b.parquet").is_file());
        assert!(root.join("event_hour=12/b.parquet").is_file());
    }

    #[tokio::test]
    async fn expiry_deletes_only_past_retention_and_any_legal_hold_pauses_it() {
        let store = Arc::new(FakeR2::default());
        let now = Utc.with_ymd_and_hms(2026, 10, 7, 12, 0, 0).unwrap();
        let old = land(
            &store,
            OtelDataset::Spans,
            now - chrono::Duration::days(40),
            b"a".to_vec(),
        );
        let older = land(
            &store,
            OtelDataset::Spans,
            now - chrono::Duration::days(35),
            b"b".to_vec(),
        );
        let fresh = land(
            &store,
            OtelDataset::Spans,
            now - chrono::Duration::days(2),
            b"c".to_vec(),
        );
        let metrics = land(
            &store,
            OtelDataset::Metrics,
            now - chrono::Duration::days(40),
            b"d".to_vec(),
        );
        // A hold on an hour AFTER both objects' receipt hours still pauses
        // everything: a client clock running fast puts rows past receipt.
        let after_receipt = |days: i64| {
            i32::try_from((now - chrono::Duration::days(days)).timestamp() / 3_600).unwrap()
        };
        for held_hours in [
            vec![after_receipt(36)],
            vec![after_receipt(1)],
            vec![after_receipt(45)],
        ] {
            let held = LeanPurgePolicy {
                retention_days: 30,
                held_hours,
            };
            let report = expire_handoff_objects(
                store.as_ref(),
                tenant(),
                OtelDataset::Spans,
                &held,
                now,
                100,
            )
            .await
            .unwrap();
            assert_eq!(
                report,
                ExpiryReport {
                    deleted: 0,
                    held: true
                }
            );
            assert!(
                store.deleted.lock().unwrap().is_empty(),
                "nothing is deleted under a hold"
            );
        }
        // Hold released: both past-retention spans objects go; the fresh one
        // and the other dataset stay.
        let released = LeanPurgePolicy {
            retention_days: 30,
            held_hours: vec![],
        };
        let report = expire_handoff_objects(
            store.as_ref(),
            tenant(),
            OtelDataset::Spans,
            &released,
            now,
            100,
        )
        .await
        .unwrap();
        assert_eq!(
            report,
            ExpiryReport {
                deleted: 2,
                held: false
            }
        );
        assert_eq!(*store.deleted.lock().unwrap(), vec![old, older]);
        let objects = store.objects.lock().unwrap();
        assert!(objects.contains_key(&fresh) && objects.contains_key(&metrics));
        drop(objects);
        // An object inside the window (by one hour) is never deleted.
        let edge = land(
            &store,
            OtelDataset::Spans,
            now - chrono::Duration::days(30),
            b"e".to_vec(),
        );
        let report = expire_handoff_objects(
            store.as_ref(),
            tenant(),
            OtelDataset::Spans,
            &released,
            now,
            100,
        )
        .await
        .unwrap();
        assert_eq!(report.deleted, 0);
        assert!(store.objects.lock().unwrap().contains_key(&edge));
    }

    #[tokio::test]
    async fn the_expiry_policy_is_read_fresh_not_from_the_cache() {
        let presence = Arc::new(MemoryPresence::default());
        *presence.policy.lock().unwrap() = Some(LeanPurgePolicy {
            retention_days: 30,
            held_hours: vec![],
        });
        let mirror = tempfile::tempdir().unwrap();
        let ledger =
            LeanOtelHandoffLedger::new(tenant(), mirror.path().to_path_buf(), presence.clone());
        assert!(ledger
            .purge_policy()
            .await
            .unwrap()
            .unwrap()
            .held_hours
            .is_empty());
        // A hold lands; the cached read still says none, the fresh read sees it.
        presence.policy.lock().unwrap().as_mut().unwrap().held_hours = vec![1];
        assert!(ledger
            .purge_policy()
            .await
            .unwrap()
            .unwrap()
            .held_hours
            .is_empty());
        assert_eq!(
            ledger
                .fresh_purge_policy()
                .await
                .unwrap()
                .unwrap()
                .held_hours,
            vec![1]
        );
    }

    /// The plan's acceptance pin: OTLP span and metric NDJSON go through the
    /// lean drain and come back from the same planners the `/v1/otel/*`
    /// routes run (recent traces, services overview, metric names), over the
    /// mirror source the binary builds for a lean tenant (no pin).
    #[tokio::test]
    #[ignore = "requires digest-verified NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256"]
    async fn native_lean_drain_serves_traces_services_and_metrics() {
        use crate::otel_iceberg::{
            plan_metric_names, plan_recent_traces, plan_services_overview, OtelQuerySource,
            OtelServicesSort,
        };
        use crate::planner::{ObjectStoreCredentials, TenantQueryConfig};
        let runtime = crate::native::NativeChdb::load_verified(
            std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
            &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
        )
        .unwrap();
        std::mem::forget(runtime.clone());
        let executor = crate::executor::NativeExecutor::start(runtime, 1).unwrap();

        let mirror = tempfile::tempdir().unwrap();
        let store = Arc::new(FakeR2::default());
        let presence = Arc::new(MemoryPresence::default());
        let drain = lean_drain(mirror.path(), store.clone(), presence);
        let t = now_nanos() - 120_000_000_000;
        land(
            &store,
            OtelDataset::Spans,
            Utc::now(),
            ndjson(&[
                span(&"a1".repeat(16), &"01".repeat(8), t),
                span(&"a1".repeat(16), &"02".repeat(8), t + 1_000),
                span(&"b2".repeat(16), &"03".repeat(8), t + 2_000),
            ]),
        );
        land(
            &store,
            OtelDataset::Metrics,
            Utc::now(),
            ndjson(&[
                metric("system.cpu.utilization", t, 0.25),
                metric("system.memory.utilization", t, 0.5),
            ]),
        );
        drain.drain_once(OtelDataset::Spans).await.unwrap();
        drain.drain_once(OtelDataset::Metrics).await.unwrap();

        let tenant_id = tenant().to_string();
        let source = |dataset: OtelDataset| -> OtelQuerySource {
            let cache = crate::otel_handoff::mirror_snapshot_cache(mirror.path(), dataset)
                .unwrap()
                .unwrap();
            OtelQuerySource::from(TenantQueryConfig {
                tenant_id: tenant_id.clone(),
                source: format!("{}/data/tail/", lean_dataset_location(tenant(), dataset)),
                iceberg_metadata_file_path: "hosted-staged-hot-tail".to_string(),
                max_query_bytes: 1 << 30,
                max_memory_bytes: 1 << 30,
                max_execution_seconds: 60,
                threads: 1,
                credentials: ObjectStoreCredentials::DefaultChain,
                snapshot_cache: Some(cache),
            })
        };
        let rows = |data: Vec<u8>| -> Vec<serde_json::Value> {
            data.split(|byte| *byte == b'\n')
                .filter(|row| !row.is_empty())
                .map(|row| serde_json::from_slice(row).unwrap())
                .collect()
        };
        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now() + chrono::Duration::minutes(1);

        let spans = source(OtelDataset::Spans);
        let plan = plan_recent_traces(&spans, &tenant_id, start, end, None, false, None, None, 50)
            .unwrap();
        let traces = rows(
            executor
                .execute_sql(plan.sql, plan.params)
                .await
                .unwrap()
                .data,
        );
        assert_eq!(traces.len(), 2, "two traces: {traces:?}");
        let plan =
            plan_services_overview(&spans, &tenant_id, start, end, None, OtelServicesSort::Name)
                .unwrap();
        let services = rows(
            executor
                .execute_sql(plan.sql, plan.params)
                .await
                .unwrap()
                .data,
        );
        assert_eq!(services.len(), 1, "{services:?}");
        assert_eq!(services[0]["service"], "shop");
        assert_eq!(
            services[0]["request_count"]
                .as_u64()
                .or_else(|| services[0]["request_count"].as_str()?.parse().ok()),
            Some(3)
        );

        let metrics = source(OtelDataset::Metrics);
        let plan = plan_metric_names(&metrics, &tenant_id, None, start, end).unwrap();
        let names = rows(
            executor
                .execute_sql(plan.sql, plan.params)
                .await
                .unwrap()
                .data,
        );
        assert_eq!(names.len(), 2, "{names:?}");
    }

    /// The cell image ships `lake_otel_ingest` behind `lean_otel_drain_v1`
    /// (scripts/build-publish-lake-cell.sh), and the lean contract it serves
    /// is derived from the tenant alone.
    #[test]
    fn cell_feature_lean_otel_drain_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_otel_drain_v1"));
        assert_eq!(
            lean_handoff_credential_prefix(tenant()),
            format!("otel-handoff-v1/tenant_uuid={TENANT}/")
        );
        assert_eq!(
            lean_tenant_bucket(tenant()),
            format!("nano-shared-r2-{TENANT}")
        );
        assert!(lean_dataset_location(tenant(), OtelDataset::Spans)
            .ends_with(handoff_prefix(tenant(), OtelDataset::Spans).trim_end_matches('/')));
    }

    #[test]
    fn markers_below_the_floor_are_pruned() {
        let mirror = tempfile::tempdir().unwrap();
        let old = LeanOtelHandoffLedger::marker_path(
            mirror.path(),
            OtelDataset::Spans,
            "2026090100",
            &"a".repeat(64),
        );
        let new = LeanOtelHandoffLedger::marker_path(
            mirror.path(),
            OtelDataset::Spans,
            "2026100700",
            &"b".repeat(64),
        );
        for path in [&old, &new] {
            write_mirror_object(path, b"drained\n").unwrap();
        }
        let floor = receipt_epoch_hour("2026100600").unwrap();
        assert_eq!(
            prune_drained_markers(mirror.path(), OtelDataset::Spans, floor).unwrap(),
            1
        );
        assert!(!old.exists() && new.exists());
    }

    // ---- NAN-3886: restart resumes, incremental listing -------------------

    fn hour_of(at: DateTime<Utc>) -> i32 {
        i32::try_from(at.timestamp().div_euclid(3_600)).unwrap()
    }

    fn at_nanos(at: DateTime<Utc>) -> u64 {
        u64::try_from(at.timestamp_nanos_opt().unwrap()).unwrap()
    }

    /// Land one span object received at `at` with `rows` distinct spans.
    fn land_spans(store: &FakeR2, at: DateTime<Utc>, tag: &str, rows: u64) -> String {
        let trace = &hex::encode(Sha256::digest(tag.as_bytes()))[..24];
        let body = (0..rows)
            .map(|row| span(&format!("{trace}{row:08x}"), &format!("{row:016x}"), at_nanos(at) + row))
            .collect::<Vec<_>>();
        land(store, OtelDataset::Spans, at, ndjson(&body))
    }

    fn lean_drain_with(
        mirror: &Path,
        store: Arc<FakeR2>,
        presence: Arc<MemoryPresence>,
        binding: OtelDrainBinding,
    ) -> OtelHandoffDrain {
        let ledger = Arc::new(LeanOtelHandoffLedger::new(tenant(), mirror.to_path_buf(), presence));
        OtelHandoffDrain::lean(binding, store, ledger, mirror.to_path_buf(), MirrorPolicy::default()).unwrap()
    }

    /// Cycles until nothing is pending and no sweep is in progress.
    async fn drain_until_idle(drain: &OtelHandoffDrain, dataset: OtelDataset) -> Vec<DrainCycleReport> {
        let mut reports = Vec::new();
        for _ in 0..200 {
            let report = drain.drain_once(dataset).await.unwrap();
            let idle = !report.backlogged
                && report.objects_drained == 0
                && report.objects_rejected == 0
                && drain
                    .lean_scan_state(dataset)
                    .unwrap()
                    .is_some_and(|state| state.sweep.is_none());
            reports.push(report);
            if idle {
                return reports;
            }
        }
        panic!("the lean drain never went idle");
    }

    fn marker_count(mirror: &Path, dataset: OtelDataset) -> usize {
        let root = mirror.join(DRAIN_MARKER_DIR).join(dataset.as_str());
        let Ok(hours) = std::fs::read_dir(root) else {
            return 0;
        };
        hours
            .map(|hour| std::fs::read_dir(hour.unwrap().path()).unwrap().count())
            .sum()
    }

    /// A roll with the mirror on a persistent volume: the new process keeps
    /// the resident Parquet, re-reads nothing, lists only its live window,
    /// and drains only what arrived since.
    #[tokio::test]
    async fn a_restarted_drain_over_the_same_mirror_resumes_without_redraining() {
        let store = Arc::new(FakeR2::default());
        let now = Utc::now();
        let mut objects = 0;
        let mut rows = 0;
        // Live hours, an hour below the live window, one beyond the lookback.
        for (age, count) in [(0_i64, 5), (1, 4), (6, 3), (60, 2)] {
            for index in 0..count {
                land_spans(&store, now - chrono::Duration::hours(age), &format!("{age}x{index}"), 2);
                objects += 1;
                rows += 2;
            }
        }
        let mirror = tempfile::tempdir().unwrap();
        let first = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        let reports = drain_until_idle(&first, OtelDataset::Spans).await;
        assert_eq!(reports.iter().map(|report| report.objects_drained).sum::<usize>(), objects);
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), rows);
        assert_eq!(store.reads.lock().unwrap().len(), objects);
        // The maintenance pass folds closed hours between cycles.
        compact_mirror(mirror.path(), OtelDataset::Spans, hour_of(Utc::now())).unwrap();
        drop(first);

        let reads = store.reads.lock().unwrap().len();
        let lists = store.lists.lock().unwrap().len();
        let presence = Arc::new(MemoryPresence::default());
        let restarted = lean_drain(mirror.path(), store.clone(), presence.clone());
        let resumed = restarted.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(
            (resumed.objects_drained, resumed.objects_rejected, resumed.backlogged, resumed.full_scan, resumed.sweep),
            (0, 0, false, false, false),
            "{resumed:?}"
        );
        assert_eq!(resumed.list_calls, 1, "only the live window is listed: {resumed:?}");
        assert_eq!(store.lists.lock().unwrap().len(), lists + 1);
        assert_eq!(store.reads.lock().unwrap().len(), reads, "nothing is re-read");
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), rows, "no duplicate rows");
        assert!(presence.beats.lock().unwrap().iter().all(|(batches, _)| *batches == 0));
        // The live listing resumed at the persisted watermark, not the
        // 48 h lookback.
        let state = restarted.lean_scan_state(OtelDataset::Spans).unwrap().unwrap();
        assert!(state.watermark_hour.unwrap() >= hour_of(Utc::now()) - 2, "{state:?}");

        // Objects that arrive after the restart are drained, once.
        for index in 0..3 {
            land_spans(&store, Utc::now(), &format!("after{index}"), 1);
        }
        let fresh = restarted.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((fresh.objects_drained, fresh.rows_published), (3, 3));
        assert_eq!(store.reads.lock().unwrap().len(), reads + 3);
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), rows + 3);
        let again = restarted.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!(again.objects_drained, 0);
    }

    /// A cycle cut off between its first Parquet write and its last marker
    /// (a journal left on the volume) is rolled back and its objects
    /// re-drain exactly once; a cycle whose markers are durable is never
    /// rolled back.
    #[tokio::test]
    async fn an_interrupted_cycle_is_rolled_back_and_redrained_exactly_once() {
        let store = Arc::new(FakeR2::default());
        let mirror = tempfile::tempdir().unwrap();
        let presence = Arc::new(MemoryPresence::default());
        for index in 0..4 {
            land_spans(&store, Utc::now(), &format!("a{index}"), 2);
        }
        // The presence write fails AFTER the markers are durable: the cycle
        // fails, but it is committed — nothing is rolled back or re-drained
        // (a control-DB outage must not stall the mirror).
        *presence.fail_beats.lock().unwrap() = true;
        let drain = lean_drain(mirror.path(), store.clone(), presence.clone());
        assert!(drain.drain_once(OtelDataset::Spans).await.is_err());
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 8);
        assert_eq!(marker_count(mirror.path(), OtelDataset::Spans), 4);
        assert!(!drain_journal_path(mirror.path(), OtelDataset::Spans).exists());
        *presence.fail_beats.lock().unwrap() = false;
        assert_eq!(drain.drain_once(OtelDataset::Spans).await.unwrap().objects_drained, 0);
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 8);

        // A crash after the markers, before the journal was removed.
        let before = mirror_objects(mirror.path(), OtelDataset::Spans).unwrap();
        let keys = (0..2)
            .map(|index| land_spans(&store, Utc::now(), &format!("b{index}"), 1))
            .collect::<Vec<_>>();
        assert_eq!(drain.drain_once(OtelDataset::Spans).await.unwrap().objects_drained, 2);
        let written = mirror_objects(mirror.path(), OtelDataset::Spans)
            .unwrap()
            .into_iter()
            .filter(|object| !before.contains(object))
            .map(|(_, path, _)| path)
            .collect::<Vec<_>>();
        assert!(!written.is_empty());
        begin_drain_journal(mirror.path(), OtelDataset::Spans, &written, &keys).unwrap();
        // Compaction never folds a file a journal may still roll back.
        let current = hour_of(Utc::now());
        assert_eq!(
            compact_mirror(mirror.path(), OtelDataset::Spans, current + 1).unwrap(),
            CompactionReport::default()
        );
        drop(drain);
        let restarted = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        let redrained = restarted.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((redrained.objects_drained, redrained.rows_published), (2, 2));
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 10, "exactly once");
        assert!(!drain_journal_path(mirror.path(), OtelDataset::Spans).exists());
        assert_eq!(marker_count(mirror.path(), OtelDataset::Spans), 6);
    }

    /// A backlog below the live window (an empty mirror after a roll) pages
    /// through incrementally: each cycle lists the live window plus a bounded
    /// number of sweep pages resumed from the cursor, never the whole
    /// backlog, and the newest backlog hours fill first.
    #[tokio::test]
    async fn a_backlogged_drain_lists_a_bounded_number_of_pages_per_cycle() {
        let store = Arc::new(FakeR2::default());
        let now = Utc::now();
        let (old_hours, per_hour, live) = (6_i64, 20, 5);
        for age in 3..3 + old_hours {
            for index in 0..per_hour {
                land_spans(&store, now - chrono::Duration::hours(age), &format!("{age}x{index}"), 1);
            }
        }
        for index in 0..live {
            land_spans(&store, now, &format!("live{index}"), 1);
        }
        let total = usize::try_from(old_hours).unwrap() * per_hour + live;
        let mirror = tempfile::tempdir().unwrap();
        let drain = lean_drain_with(
            mirror.path(),
            store.clone(),
            Arc::new(MemoryPresence::default()),
            OtelDrainBinding { max_objects: 16, ..binding() },
        );
        let mut cycles = 0;
        let mut keys_listed = 0;
        loop {
            let (calls, keys) = (store.lists.lock().unwrap().len(), store.listed_keys.lock().unwrap().len());
            let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
            cycles += 1;
            let made = store.lists.lock().unwrap().len() - calls;
            let listed = store.listed_keys.lock().unwrap()[keys..].iter().sum::<usize>();
            keys_listed += listed;
            assert!(!report.full_scan, "{report:?}");
            assert_eq!(made, report.list_calls, "{report:?}");
            // live listing + receipt-hour listing + bounded sweep pages
            assert!(made <= 2 + LEAN_SWEEP_LIST_CALLS_PER_CYCLE, "{report:?}");
            // Never the whole backlog: the live keys plus at most the rest
            // of the hour it resumed in and the next one.
            assert!(listed <= live + 2 * per_hour, "cycle {cycles} listed {listed} keys: {report:?}");
            if cycles == 1 {
                let hours = mirror_objects(mirror.path(), OtelDataset::Spans)
                    .unwrap()
                    .into_iter()
                    .map(|(hour, _, _)| hour)
                    .collect::<std::collections::BTreeSet<_>>();
                assert_eq!(
                    hours,
                    [hour_of(now - chrono::Duration::hours(3)), hour_of(now)].into_iter().collect(),
                    "the live hour and the newest backlog hour fill first"
                );
            }
            if !report.backlogged && report.objects_drained == 0 {
                break;
            }
            assert!(cycles < 50, "no progress");
        }
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), u64::try_from(total).unwrap());
        let reads = store.reads.lock().unwrap().clone();
        assert_eq!(reads.len(), total, "every object read exactly once");
        assert_eq!(reads.iter().collect::<std::collections::BTreeSet<_>>().len(), total);
        // ~8 drain cycles; a full re-list per cycle would have listed
        // `total` keys each time.
        assert!(keys_listed < cycles * total / 2, "{keys_listed} keys over {cycles} cycles");
        assert!(drain.lean_scan_state(OtelDataset::Spans).unwrap().unwrap().sweep.is_none());
    }

    /// An object that lands in an hour older than the live window (an
    /// outage longer than the lookback) is not listed by every cycle, but the
    /// next periodic sweep — whose schedule survives a restart — drains it.
    #[tokio::test]
    async fn a_late_object_in_an_old_hour_is_drained_by_the_next_sweep() {
        let store = Arc::new(FakeR2::default());
        let mirror = tempfile::tempdir().unwrap();
        land_spans(&store, Utc::now(), "live", 1);
        let drain = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        drain_until_idle(&drain, OtelDataset::Spans).await;
        let late = land_spans(&store, Utc::now() - chrono::Duration::hours(100), "late", 2);
        let idle = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((idle.objects_drained, idle.sweep, idle.list_calls), (0, false, 1), "{idle:?}");
        assert!(!store.reads.lock().unwrap().contains(&late));
        drop(drain);

        // The sweep interval elapses (the schedule is persisted with the
        // mirror, so a restart neither forgets nor re-runs it early).
        let mut state = load_lean_scan_state(mirror.path(), OtelDataset::Spans);
        let completed = state.last_sweep_completed_unix.expect("the first sweep completed");
        let restarted = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        let early = restarted.drain_once(OtelDataset::Spans).await.unwrap();
        assert_eq!((early.objects_drained, early.sweep), (0, false));
        drop(restarted);
        state.last_sweep_completed_unix =
            Some(completed - i64::try_from(LEAN_SWEEP_INTERVAL.as_secs()).unwrap());
        save_lean_scan_state(mirror.path(), OtelDataset::Spans, &state).unwrap();
        let restarted = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        let reports = drain_until_idle(&restarted, OtelDataset::Spans).await;
        assert!(reports[0].sweep);
        assert_eq!(reports.iter().map(|report| report.objects_drained).sum::<usize>(), 1);
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 3);
        assert_eq!(store.reads.lock().unwrap().iter().filter(|key| **key == late).count(), 1);
    }

    /// A restart after an outage longer than the live window: the hours the
    /// outage left behind are handed to a sweep that stops at the old
    /// watermark, so nothing proven before the outage is listed again.
    #[tokio::test]
    async fn a_restart_after_a_long_outage_sweeps_only_the_gap() {
        let store = Arc::new(FakeR2::default());
        let mirror = tempfile::tempdir().unwrap();
        let now = Utc::now();
        land_spans(&store, now - chrono::Duration::hours(20), "before", 1);
        let drain = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        drain_until_idle(&drain, OtelDataset::Spans).await;
        drop(drain);
        // The pod was down for ~10 h: its last complete cycle ran then.
        let mut state = load_lean_scan_state(mirror.path(), OtelDataset::Spans);
        let old_watermark = hour_of(now) - 10;
        state.watermark_hour = Some(old_watermark);
        save_lean_scan_state(mirror.path(), OtelDataset::Spans, &state).unwrap();
        for age in [9_i64, 5, 3, 0] {
            land_spans(&store, now - chrono::Duration::hours(age), &format!("gap{age}"), 1);
        }
        let lists = store.lists.lock().unwrap().len();
        let restarted = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        let reports = drain_until_idle(&restarted, OtelDataset::Spans).await;
        assert_eq!(reports.iter().map(|report| report.objects_drained).sum::<usize>(), 4);
        assert_eq!(mirror_rows(mirror.path(), OtelDataset::Spans), 5);
        let dataset_prefix = handoff_prefix(tenant(), OtelDataset::Spans);
        for (prefix, start_after) in &store.lists.lock().unwrap()[lists..] {
            let rest = prefix.strip_prefix(&dataset_prefix).unwrap();
            if let Some(label) = rest.strip_prefix("hour=") {
                let hour = receipt_epoch_hour(label.trim_end_matches('/')).unwrap();
                assert!(hour >= old_watermark, "listed {prefix} below the old watermark");
            } else if let Some(cursor) = start_after {
                // The live window: never more than LEAN_LIVE_WINDOW_HOURS back.
                assert!(
                    cursor >= &OtelHandoffDrain::floor_cursor(&dataset_prefix, hour_of(now) - 3).unwrap(),
                    "{cursor}"
                );
            }
        }
        // A hand-off sweep is not the periodic one: its schedule is unchanged.
        let after = restarted.lean_scan_state(OtelDataset::Spans).unwrap().unwrap();
        assert_eq!(after.last_sweep_completed_unix, state.last_sweep_completed_unix);
        assert!(after.watermark_hour.unwrap() >= hour_of(Utc::now()) - 2);
    }

    // ---- NAN-3894: coverage attestation ------------------------------------

    fn hour_start_of(hour: i32) -> DateTime<Utc> {
        Utc.timestamp_opt(i64::from(hour) * 3_600, 0).unwrap()
    }

    /// An object whose exact read always fails (its content does not match
    /// the SHA-256 its key names): the drain retries it, never drains it.
    fn land_unreadable(store: &FakeR2, at: DateTime<Utc>) -> String {
        let key = handoff_object_key(
            tenant(),
            OtelDataset::Spans,
            at,
            &hex::encode(Sha256::digest(b"some other body")),
        )
        .unwrap();
        store
            .objects
            .lock()
            .unwrap()
            .insert(key.clone(), ndjson(&[span(&"9".repeat(32), &"9".repeat(16), at_nanos(at))]));
        key
    }

    #[tokio::test]
    async fn an_empty_or_rebuilding_mirror_attests_nothing() {
        let store = Arc::new(FakeR2::default());
        let mirror = tempfile::tempdir().unwrap();
        let drain = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        let now = Utc::now();
        let window = (now - chrono::Duration::hours(3), now);
        // Never drained: no state at all.
        assert!(!drain.lean_window_complete(OtelDataset::Spans, window.0, window.1));
        let coverage = drain.lean_coverage(OtelDataset::Spans).unwrap().unwrap();
        assert_eq!(coverage.covered_since, None);
        // A rebuild in progress (the backlog below the live window is not
        // swept yet) still attests nothing.
        for index in 0..6 {
            land_spans(&store, now - chrono::Duration::hours(5), &format!("old{index}"), 1);
        }
        for index in 0..4 {
            land_spans(&store, now, &format!("live{index}"), 1);
        }
        let small = lean_drain_with(
            mirror.path(),
            store.clone(),
            Arc::new(MemoryPresence::default()),
            OtelDrainBinding { max_objects: 4, ..binding() },
        );
        let first = small.drain_once(OtelDataset::Spans).await.unwrap();
        assert!(first.backlogged);
        assert!(!small.lean_window_complete(OtelDataset::Spans, window.0, Utc::now()));
    }

    #[tokio::test]
    async fn a_window_inside_coverage_is_complete_and_survives_a_restart() {
        let store = Arc::new(FakeR2::default());
        let mirror = tempfile::tempdir().unwrap();
        let now = Utc::now();
        for age in [0_i64, 1, 5, 30] {
            land_spans(&store, now - chrono::Duration::hours(age), &format!("c{age}"), 1);
        }
        let drain = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        drain_until_idle(&drain, OtelDataset::Spans).await;
        let state = drain.lean_scan_state(OtelDataset::Spans).unwrap().unwrap();
        let covered = state.covered_since_hour.expect("the first sweep reached the floor");
        assert_eq!(covered, hour_of(Utc::now()) - i32::try_from(MirrorPolicy::DEFAULT_MAX_AGE_HOURS).unwrap());
        let end = Utc::now();
        assert!(drain.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::days(7), end));
        // The earliest attested start: coverage plus the client-skew hour.
        assert!(drain.lean_window_complete(OtelDataset::Spans, hour_start_of(covered + 1), end));
        assert!(!drain.lean_window_complete(OtelDataset::Spans, hour_start_of(covered + 1) - chrono::Duration::seconds(1), end));
        // Before coverage: partial.
        assert!(!drain.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::days(31), end));
        // A window ending in the future cannot be attested.
        assert!(!drain.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::hours(1), end + chrono::Duration::hours(1)));
        let report = drain.lean_coverage(OtelDataset::Spans).unwrap().unwrap();
        assert_eq!((report.covered_since, report.gaps.clone(), report.backlogged), (Some(hour_start_of(covered)), vec![], false));
        drop(drain);

        // A new process over the same mirror attests the same, before its
        // first cycle, and after it.
        let restarted = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        let end = Utc::now();
        assert!(restarted.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::days(7), end));
        restarted.drain_once(OtelDataset::Spans).await.unwrap();
        assert!(restarted.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::days(7), Utc::now()));
    }

    #[tokio::test]
    async fn a_retry_backlog_or_eviction_inside_the_window_is_partial() {
        let store = Arc::new(FakeR2::default());
        let mirror = tempfile::tempdir().unwrap();
        let now = Utc::now();
        land_spans(&store, now, "live", 1);
        // A sweep passes over an object whose exact read fails.
        let unreadable = land_unreadable(&store, now - chrono::Duration::hours(5));
        let drain = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        drain_until_idle(&drain, OtelDataset::Spans).await;
        let retry_hour = hour_of(now - chrono::Duration::hours(5));
        let state = drain.lean_scan_state(OtelDataset::Spans).unwrap().unwrap();
        assert!(state.covered_since_hour.is_some());
        assert_eq!(state.unproven_hours.iter().copied().collect::<Vec<_>>(), vec![retry_hour]);
        let end = Utc::now();
        // The retry hour lies after `start - skew`: partial.
        assert!(!drain.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::days(1), end));
        assert!(!drain.lean_window_complete(OtelDataset::Spans, hour_start_of(retry_hour + 1), end));
        // A window starting more than the skew after it is complete.
        assert!(drain.lean_window_complete(OtelDataset::Spans, hour_start_of(retry_hour + 2), end));
        let report = drain.lean_coverage(OtelDataset::Spans).unwrap().unwrap();
        assert_eq!(
            report.gaps,
            vec![crate::otel_lean::CoverageGap {
                start: hour_start_of(retry_hour),
                end: hour_start_of(retry_hour + 1),
                reason: "undrained"
            }]
        );
        // Once the object reads clean, the next periodic sweep proves it.
        let body = store.objects.lock().unwrap().remove(&unreadable).unwrap();
        let fixed = land(&store, OtelDataset::Spans, now - chrono::Duration::hours(5), body);
        assert_ne!(fixed, unreadable);
        let mut persisted = load_lean_scan_state(mirror.path(), OtelDataset::Spans);
        persisted.last_sweep_completed_unix = Some(0);
        save_lean_scan_state(mirror.path(), OtelDataset::Spans, &persisted).unwrap();
        drop(drain);
        let drain = lean_drain(mirror.path(), store.clone(), Arc::new(MemoryPresence::default()));
        drain_until_idle(&drain, OtelDataset::Spans).await;
        assert!(drain.lean_scan_state(OtelDataset::Spans).unwrap().unwrap().unproven_hours.is_empty());
        let end = Utc::now();
        assert!(drain.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::days(1), end));

        // The byte cap evicts from an event hour inside the window: partial
        // for any window starting at or before the end of that hour.
        let evicted = hour_of(now) - 3;
        record_mirror_eviction(mirror.path(), &[(OtelDataset::Spans, evicted)]).unwrap();
        record_mirror_eviction(mirror.path(), &[(OtelDataset::Spans, evicted - 10)]).unwrap();
        assert_eq!(newest_evicted_hour(mirror.path(), OtelDataset::Spans).unwrap(), Some(evicted));
        assert_eq!(newest_evicted_hour(mirror.path(), OtelDataset::Metrics).unwrap(), None);
        let end = Utc::now();
        assert!(!drain.lean_window_complete(OtelDataset::Spans, end - chrono::Duration::days(1), end));
        assert!(!drain.lean_window_complete(OtelDataset::Spans, hour_start_of(evicted), end));
        assert!(drain.lean_window_complete(OtelDataset::Spans, hour_start_of(evicted + 1), end));
        let report = drain.lean_coverage(OtelDataset::Spans).unwrap().unwrap();
        assert_eq!(report.covered_since, Some(hour_start_of(evicted + 1)));
        assert!(report.gaps.iter().any(|gap| gap.reason == "evicted" && gap.end == hour_start_of(evicted + 1)));

        // A live backlog: the live window is not proven, so a window ending
        // now is partial.
        for index in 0..300 {
            land_spans(&store, Utc::now(), &format!("burst{index}"), 1);
        }
        let report = drain.drain_once(OtelDataset::Spans).await.unwrap();
        assert!(report.backlogged);
        assert!(!drain.lean_window_complete(OtelDataset::Spans, hour_start_of(evicted + 1), Utc::now()));
        let mut state = drain.lean_scan_state(OtelDataset::Spans).unwrap().unwrap();
        assert!(state.backlogged);
        // ...and once the last proof is older than the slack, a window
        // ending now is partial even without new data.
        state.backlogged = false;
        state.live_proven_unix = Some(Utc::now().timestamp() - 600);
        let end = Utc::now();
        assert!(!lean_window_complete(&state, Some(evicted), hour_start_of(evicted + 1), end, end));
        assert!(lean_window_complete(
            &state,
            Some(evicted),
            hour_start_of(evicted + 1),
            end - chrono::Duration::seconds(400),
            end
        ));
    }

    /// NAN-3894: the mirror and the effective OTLP retention each hold the
    /// longest SLO window plus the coverage skew hour, so a max-length SLO
    /// can attest complete. Referenced by constant, never by literal.
    #[test]
    fn mirror_age_and_otel_retention_cover_the_longest_slo_window() {
        let needed_hours = i64::from(SLO_WINDOW_DAYS_MAX) * 24
            + i64::try_from(COVERAGE_CLIENT_SKEW.as_secs().div_ceil(3_600)).unwrap();
        assert!(i64::from(MirrorPolicy::DEFAULT_MAX_AGE_HOURS) >= needed_hours);
        assert!(i64::from(MirrorPolicy::default().max_age_hours) >= needed_hours);
        for tenant_days in [0, 1, 7, 30] {
            assert!(i64::from(otel_retention_days(tenant_days)) * 24 >= needed_hours);
        }
        // Retention only grows: a longer tenant setting is kept as is.
        assert_eq!(otel_retention_days(400), 400);
        assert_eq!(otel_retention_days(OTEL_MIN_RETENTION_DAYS + 1), OTEL_MIN_RETENTION_DAYS + 1);
    }

    /// A tenant whose log retention is shorter than the longest SLO window
    /// still keeps OTLP for the floor: the ledger reports the floored
    /// retention, expiry keeps a 20-day-old object, and a full-length SLO
    /// window attests complete.
    #[tokio::test]
    async fn a_short_tenant_retention_still_attests_the_longest_slo_window() {
        let presence = Arc::new(MemoryPresence::default());
        *presence.policy.lock().unwrap() = Some(LeanPurgePolicy { retention_days: 7, held_hours: vec![] });
        let mirror = tempfile::tempdir().unwrap();
        let ledger = LeanOtelHandoffLedger::new(tenant(), mirror.path().to_path_buf(), presence.clone());
        assert_eq!(
            ledger.fresh_purge_policy().await.unwrap().map(|policy| policy.retention_days),
            Some(OTEL_MIN_RETENTION_DAYS)
        );
        assert_eq!(
            ledger.purge_policy().await.unwrap().map(|policy| policy.retention_days),
            Some(OTEL_MIN_RETENTION_DAYS)
        );

        let store = Arc::new(FakeR2::default());
        let now = Utc::now();
        let kept = land(&store, OtelDataset::Spans, now - chrono::Duration::days(20), b"k".to_vec());
        let gone = land(
            &store,
            OtelDataset::Spans,
            now - chrono::Duration::days(i64::from(OTEL_MIN_RETENTION_DAYS) + 2),
            b"g".to_vec(),
        );
        let short = LeanPurgePolicy { retention_days: 7, held_hours: vec![] };
        let report = expire_handoff_objects(store.as_ref(), tenant(), OtelDataset::Spans, &short, now, 100)
            .await
            .unwrap();
        assert_eq!(report.deleted, 1);
        assert_eq!(*store.deleted.lock().unwrap(), vec![gone]);
        assert!(store.objects.lock().unwrap().contains_key(&kept));

        land_spans(&store, now, "live", 1);
        let drain = lean_drain(mirror.path(), store.clone(), presence);
        drain_until_idle(&drain, OtelDataset::Spans).await;
        let end = Utc::now();
        let start = end - chrono::Duration::days(i64::from(SLO_WINDOW_DAYS_MAX));
        assert!(drain.lean_window_complete(OtelDataset::Spans, start, end));
    }
}
