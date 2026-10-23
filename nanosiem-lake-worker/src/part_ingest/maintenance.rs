// SPDX-License-Identifier: AGPL-3.0-or-later

//! `maintenance[T]`: the tenant prevalence SlateDB compactor inside the lean
//! cell (cell feature `lean_prevalence_maintenance_v1`).
//!
//! ingest[T] writes the tenant prevalence DB but never compacts it: the
//! owner refuses `compactions/*` and large `compacted/*` objects from the
//! ingest principal (9007100). Without a compactor, L0 reaches SlateDB's
//! `l0_max_ssts`, memtable flushes stop, and ingest's writes wait in
//! backpressure forever (a lean test tenant, 2026-09-30). This role runs SlateDB's
//! compactor as the tenant's MAINTENANCE principal:
//!
//! - its credential exchange is `role: "maintenance"`, accepting only
//!   `lake_prevalence_state` (exact-prefix, read-only) plus the owner's
//!   maintenance bearer (`writer_class: maintenance`); no part, log, sign or
//!   edge grant is accepted;
//! - every compactor write goes through the owner (`OwnerStore`, maintenance
//!   class); nothing can fall through to the read credential;
//! - the compactor is bounded: one job, one subcompaction, two 1 MiB fetches
//!   in flight, inside the role's fixed 250m / 512 MiB budget;
//! - credentials are refreshed at half their lifetime (a fresh bootstrap
//!   from the supervisor, then a new exchange); a transient failure
//!   (timeout, connect error, 5xx, 429, no bootstrap answer) retries with
//!   equal-jitter backoff, never inside the supervisor's mint interval,
//!   until the held credential is about to expire; only then, or on a final
//!   401/403, does the role exit (NAN-4326). The heartbeat reports the DB's
//!   L0 count.

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use nanosiem_lake_cell::child::{ControlChannel, TenantService};
use nanosiem_lake_cell::contract::{Assignment, Heartbeat, WakeReason};
use slatedb::admin::AdminBuilder;
use slatedb::config::{CompactionWorkerOptions, CompactorOptions, CompressionCodec};
use slatedb::object_store::ObjectStore;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use super::cell::{ExchangeRefused, ExchangeResponse, EXPIRY_SKEW, REFRESH_AT_FRACTION};
use super::prevalence_owner_store::{MaintenanceAccess, OwnerStore};

/// The only class the maintenance role accepts.
pub const MAINTENANCE_ACCEPTS: &[&str] = &["lake_prevalence_state"];

/// A validated maintenance exchange.
pub struct MaintenanceGrant {
    pub access: MaintenanceAccess,
    /// The earliest of the read credential's and the bearer's expiry.
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// The tenant's prevalence state prefix.
pub fn state_prefix(tenant: &str) -> String {
    format!("lake/prevalence-state/v1/tenant={tenant}/")
}

/// Exchange a single-use bootstrap token for the maintenance grant.
pub async fn exchange_maintenance(token: &[u8], assignment: &Assignment, received: Instant) -> Result<MaintenanceGrant> {
    exchange_maintenance_within(token, assignment, received, TIMING.exchange_timeout).await
}

async fn exchange_maintenance_within(token: &[u8], assignment: &Assignment, received: Instant, timeout: Duration) -> Result<MaintenanceGrant> {
    let tenant = assignment.tenant.as_str();
    let control_url = assignment.control_url.as_deref().context("assignment has no control_url for the credential exchange")?;
    ensure!(control_url.starts_with("https://") || cfg!(test), "credential exchange must use https");
    let token = std::str::from_utf8(token).context("bootstrap token is not text")?.trim();
    let url = format!("{}/v1/lake/cells/{}/credential-exchange", control_url.trim_end_matches('/'), assignment.cell_id);
    let response = reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "tenant_id": tenant, "role": "maintenance", "accepts": MAINTENANCE_ACCEPTS }))
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(ExchangeRefused::with_token_age(status.as_u16(), received.elapsed()).into());
    }
    let body = Zeroizing::new(response.bytes().await?.to_vec());
    let exchange: ExchangeResponse = serde_json::from_slice(&body).context("credential exchange response")?;
    grant_from(exchange, assignment)
}

/// Validate a maintenance exchange response: exactly the read-only state
/// credential and the maintenance owner bearer, nothing else.
pub fn grant_from(exchange: ExchangeResponse, assignment: &Assignment) -> Result<MaintenanceGrant> {
    let tenant = assignment.tenant.as_str();
    ensure!(
        exchange.schema_version == 1 && exchange.tenant_id == tenant && exchange.role == "maintenance",
        "exchange response binding differs"
    );
    ensure!(exchange.owner_sign.is_none() && exchange.notices.is_none() && exchange.edge_log_consumer_token.is_none()
        && exchange.edge_log_consumer_endpoint.is_none() && exchange.lake_part_delete_grant.is_none()
        && exchange.lake_part_gc.is_none(),
        "maintenance exchange carries a grant the maintenance role must not hold");
    let [credential] = exchange.credentials.as_slice() else {
        bail!("maintenance exchange must return exactly one credential");
    };
    let prefix = state_prefix(tenant);
    ensure!(credential.credential_class == "lake_prevalence_state" && credential.permission == "object-read-only"
        && credential.prefixes == [prefix.clone()],
        "maintenance credential must be the exact-prefix read-only prevalence state class");
    let owner = exchange.prevalence_owner.context("maintenance exchange has no prevalence owner bearer")?;
    ensure!(owner.tenant_id == tenant, "prevalence owner is bound to another tenant");
    if let Some(epoch) = exchange.writer_epoch {
        ensure!(owner.writer_epoch >= 0 && owner.writer_epoch as u64 == epoch, "prevalence owner epoch differs from the exchange");
    }
    let mut read = super::cell::location_of(credential);
    read.prefix = prefix;
    let now = chrono::Utc::now();
    // The bearer's own expiry when the exchange states it, else the
    // conservative lifetime (no warning: the maintenance exchange may omit it).
    let bearer_expiry = match owner.expires_at.as_deref() {
        Some(at) => crate::cell_refresh::owner_bearer_expiry(at, now),
        None => now + crate::cell_refresh::OWNER_BEARER_FALLBACK_LIFETIME,
    };
    let expires_at = chrono::DateTime::parse_from_rfc3339(&credential.expires_at)?.with_timezone(&chrono::Utc)
        .min(bearer_expiry);
    let owner_ca_file = assignment.part_signing.as_ref().and_then(|signing| signing.ca_file.clone());
    Ok(MaintenanceGrant { access: MaintenanceAccess { read, owner, owner_ca_file }, expires_at })
}

/// The bounded compactor: one job, one subcompaction, two 1 MiB input
/// fetches, outputs of at most [`MAX_COMPACTED_SST_BYTES`].
pub fn compactor_options() -> CompactorOptions {
    CompactorOptions {
        poll_interval: Duration::from_secs(1),
        // NAN-3747: empty tenants need no per-second remote metadata refresh.
        // Active jobs still poll at the base cadence and emit heartbeats.
        idle_poll_interval: Some(Duration::from_secs(60)),
        max_concurrent_compactions: 1,
        object_store_max_retries: Some(3),
        worker: Some(CompactionWorkerOptions {
            max_concurrent_compactions: 1,
            idle_compactions_poll_interval: Some(Duration::from_secs(60)),
            max_sst_size: MAX_COMPACTED_SST_BYTES,
            max_subcompactions: 1,
            max_fetch_tasks: 2,
            bytes_to_fetch: 1024 * 1024,
            compression_codec: Some(CompressionCodec::Zstd),
            ..CompactionWorkerOptions::default()
        }),
        ..CompactorOptions::default()
    }
}

/// Largest compacted SST the compactor writes. Every output is one owner
/// POST, and the owner route times out at 30 s: 64 MiB uploads well within
/// it (and matches the ingest-class `compacted` cap), far under the 512 MiB
/// maintenance family cap.
pub const MAX_COMPACTED_SST_BYTES: usize = 64 * 1024 * 1024;

/// Run the compactor on the tenant DB through `store` (the maintenance
/// owner store) until `cancel`.
pub async fn run_compactor(store: Arc<dyn ObjectStore>, options: CompactorOptions, cancel: CancellationToken) -> Result<()> {
    let admin = AdminBuilder::new("db", store).build();
    admin.run_compactor_with_options(cancel, options).await.context("prevalence compactor")?;
    Ok(())
}

/// The largest L0 of any tree in the DB's latest manifest (`None`: no
/// manifest yet). SlateDB stops memtable flushes at `l0_max_ssts`.
pub async fn l0_count(store: Arc<dyn ObjectStore>) -> Result<Option<usize>> {
    let admin = AdminBuilder::new("db", store).build();
    let Some(manifest) = admin.read_manifest(None).await? else { return Ok(None) };
    let value = serde_json::to_value(&manifest)?;
    Ok(Some(max_l0(&value)))
}

fn max_l0(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => map.iter().map(|(key, child)| match (key.as_str(), child) {
            ("l0", serde_json::Value::Array(items)) => items.len().max(max_l0(child)),
            _ => max_l0(child),
        }).max().unwrap_or(0),
        serde_json::Value::Array(items) => items.iter().map(max_l0).max().unwrap_or(0),
        _ => 0,
    }
}

/// The run loop's clock (tests shrink it).
#[derive(Debug, Clone, Copy)]
struct LoopTiming {
    /// The supervisor's spacing between two bootstrap mints for this process
    /// (`nanosiem_lake_cell::supervisor::REFRESH_MIN_INTERVAL`). A request
    /// is never sent sooner: the supervisor would only hold it to the end.
    min_request_interval: Duration,
    /// How long one refresh waits for the supervisor's bootstrap answer.
    /// Longer than `min_request_interval`, so a request the supervisor
    /// deferred is still answered in time.
    answer_timeout: Duration,
    /// The exchange POST's own timeout.
    exchange_timeout: Duration,
    /// Transient refresh failures retry after equal-jitter backoff from
    /// `refresh_backoff_base`, doubling to `refresh_backoff_max`, and never
    /// sooner than `min_request_interval`.
    refresh_backoff_base: Duration,
    refresh_backoff_max: Duration,
    /// L0 is re-read (and a stopped compactor noticed) this often.
    poll: Duration,
    /// Every manifest read is abandoned after this: slatedb's object store
    /// retries a 403 without limit, so an expired read credential would
    /// otherwise hold the loop forever (NAN-3129).
    read_timeout: Duration,
    /// Compactor restart backoff: `base << failures`, at most `max`. It is a
    /// deadline the loop waits on beside the refresh, never a sleep inside
    /// a branch, so its length cannot delay a credential refresh.
    backoff_base: Duration,
    backoff_max: Duration,
}

impl LoopTiming {
    fn backoff(&self, failures: u32) -> Duration {
        self.backoff_base.saturating_mul(1 << failures.min(5)).min(self.backoff_max)
    }

    /// When to retry after the `attempt`-th consecutive transient refresh
    /// failure.
    fn refresh_retry(&self, attempt: u32) -> Duration {
        crate::cell_refresh::equal_jitter_backoff(attempt, self.refresh_backoff_base, self.refresh_backoff_max)
            .max(self.min_request_interval)
    }
}

const TIMING: LoopTiming = LoopTiming {
    min_request_interval: Duration::from_secs(60),
    answer_timeout: Duration::from_secs(90),
    exchange_timeout: Duration::from_secs(15),
    refresh_backoff_base: Duration::from_secs(30),
    refresh_backoff_max: Duration::from_secs(240),
    poll: Duration::from_secs(30),
    read_timeout: Duration::from_secs(20),
    backoff_base: Duration::from_secs(5),
    backoff_max: Duration::from_secs(120),
};

/// What the run loop observed, read by the heartbeat.
#[derive(Debug)]
struct LoopStats {
    /// Largest L0 at the last successful read; -1: unknown / no manifest.
    l0: AtomicI64,
    compactor_restarts: AtomicU64,
    last_error: std::sync::Mutex<Option<String>>,
    /// Unix ms of the last completed manifest read or credential refresh.
    last_progress_ms: AtomicU64,
    /// The current grant's issue and expiry (unix ms).
    issued_ms: AtomicI64,
    expires_ms: AtomicI64,
}

impl LoopStats {
    fn new(issued: chrono::DateTime<chrono::Utc>, expires: chrono::DateTime<chrono::Utc>) -> Self {
        let stats = Self {
            l0: AtomicI64::new(-1),
            compactor_restarts: AtomicU64::new(0),
            last_error: std::sync::Mutex::new(None),
            last_progress_ms: AtomicU64::new(0),
            issued_ms: AtomicI64::new(0),
            expires_ms: AtomicI64::new(0),
        };
        stats.set_grant(issued, expires);
        stats.progress();
        stats
    }

    fn set_grant(&self, issued: chrono::DateTime<chrono::Utc>, expires: chrono::DateTime<chrono::Utc>) {
        self.issued_ms.store(issued.timestamp_millis(), Ordering::Relaxed);
        self.expires_ms.store(expires.timestamp_millis(), Ordering::Relaxed);
    }

    fn expires_at(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_millis(self.expires_ms.load(Ordering::Relaxed)).unwrap_or_default()
    }

    fn lifetime_ms(&self) -> i64 {
        (self.expires_ms.load(Ordering::Relaxed) - self.issued_ms.load(Ordering::Relaxed)).max(0)
    }

    /// The scheduled refresh: [`REFRESH_AT_FRACTION`] of the grant's
    /// lifetime, leaving the other half for transient-failure retries.
    fn refresh_due(&self) -> chrono::DateTime<chrono::Utc> {
        let issued = self.issued_ms.load(Ordering::Relaxed);
        let at = issued + (self.lifetime_ms() as f64 * REFRESH_AT_FRACTION) as i64;
        chrono::DateTime::from_timestamp_millis(at).unwrap_or_default()
    }

    /// Past this the held grant counts as expired and the role exits for a
    /// respawn: [`EXPIRY_SKEW`] before `expires_at` (at most 1/20 of a short
    /// lifetime, so a fresh grant is never born expired).
    fn deadline(&self) -> chrono::DateTime<chrono::Utc> {
        self.expires_at() - EXPIRY_SKEW.min(chrono::Duration::milliseconds(self.lifetime_ms() / 20))
    }

    fn progress(&self) {
        self.last_progress_ms.store(chrono::Utc::now().timestamp_millis().max(0) as u64, Ordering::Relaxed);
    }

    /// The grant is in the final 10% of its lifetime (the refresh that
    /// should have replaced it has not succeeded).
    fn refresh_at_risk(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        let (issued, expires) = (self.issued_ms.load(Ordering::Relaxed), self.expires_ms.load(Ordering::Relaxed));
        now.timestamp_millis() >= expires - (expires - issued).max(0) / 10
    }
}

/// A failed credential refresh.
enum RefreshError {
    /// The process must exit (final refusal, cell move).
    Fatal(anyhow::Error),
    /// Try again while the current grant is still valid.
    Retry(anyhow::Error),
}

/// The side effects of the run loop (the service, or a test double).
#[async_trait]
trait LoopOps: Send + Sync {
    fn stats(&self) -> &LoopStats;
    /// Re-exchange and apply the new grant (recorded in `stats`).
    async fn refresh(&self) -> Result<(), RefreshError>;
    async fn fatal(&self, message: &str);
    async fn read_l0(&self) -> Result<Option<usize>>;
    fn spawn_compactor(&self) -> tokio::task::JoinHandle<Result<()>>;
}

/// The maintenance run loop. Nothing in a branch waits without a bound:
/// a due refresh always runs first (`biased`) and is cut off at the grant's
/// deadline, manifest reads are timed out, and the compactor restart
/// backoff is a deadline, not a sleep.
///
/// Refresh: due at half the grant's lifetime; a transient failure retries
/// with equal-jitter backoff (never inside the supervisor's mint interval)
/// up to the grant's deadline. The loop exits only on a final refusal or
/// once the held grant reaches its deadline without a replacement (NAN-4326:
/// one timed-out exchange plus one rate-limited request used to exhaust a
/// 120 s refresh-ahead window and kill the role).
async fn drive(ops: &dyn LoopOps, timing: LoopTiming) -> Result<()> {
    let stats = ops.stats();
    let mut failures = 0_u32;
    let mut refresh_failures = 0_u32;
    let mut compactor = ops.spawn_compactor();
    let mut restart_at: Option<tokio::time::Instant> = None;
    let mut retry_refresh_at: Option<chrono::DateTime<chrono::Utc>> = None;
    let mut poll = tokio::time::interval(timing.poll);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let refresh_at = retry_refresh_at.unwrap_or_else(|| stats.refresh_due());
        let wait = (refresh_at - chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO);
        let restart_deadline = restart_at.unwrap_or_else(tokio::time::Instant::now);
        tokio::select! {
            biased;
            _ = tokio::time::sleep(wait) => {
                // The attempt (bootstrap wait + exchange) may not outlive the
                // held grant: past its deadline the role must respawn instead.
                let budget = (stats.deadline() - chrono::Utc::now()).to_std().unwrap_or(Duration::ZERO);
                let outcome = match tokio::time::timeout(budget, ops.refresh()).await {
                    Ok(outcome) => outcome,
                    Err(_) => Err(RefreshError::Retry(anyhow::anyhow!(
                        "maintenance credential refresh did not finish before the held grant's deadline"))),
                };
                match outcome {
                    Ok(()) => {
                        refresh_failures = 0;
                        retry_refresh_at = None;
                        stats.progress();
                    }
                    Err(RefreshError::Fatal(error)) => {
                        ops.fatal(&format!("{error:#}")).await;
                        return Err(error);
                    }
                    Err(RefreshError::Retry(error)) => {
                        refresh_failures += 1;
                        let now = chrono::Utc::now();
                        let deadline = stats.deadline();
                        if now >= deadline {
                            let error = error.context(format!(
                                "maintenance grant expires at {} with no replacement after {refresh_failures} attempt(s)",
                                stats.expires_at()));
                            tracing::error!(error = %format!("{error:#}"), "maintenance credential lapsing; exiting for a respawn");
                            ops.fatal(&format!("{error:#}")).await;
                            return Err(error);
                        }
                        let delay = chrono::Duration::from_std(timing.refresh_retry(refresh_failures)).unwrap_or_default();
                        // Leave the last attempt at least one exchange timeout.
                        let last_start = deadline - chrono::Duration::from_std(timing.exchange_timeout).unwrap_or_default();
                        let at = (now + delay).min(last_start).max(now);
                        tracing::warn!(error = %format!("{error:#}"), attempt = refresh_failures, retry_at = %at,
                            deadline = %deadline, "maintenance credential refresh failed; retrying");
                        retry_refresh_at = Some(at);
                    }
                }
            }
            _ = tokio::time::sleep_until(restart_deadline), if restart_at.is_some() => {
                restart_at = None;
                compactor = ops.spawn_compactor();
                stats.compactor_restarts.fetch_add(1, Ordering::Relaxed);
            }
            _ = poll.tick() => {
                match tokio::time::timeout(timing.read_timeout, ops.read_l0()).await {
                    Ok(Ok(count)) => {
                        stats.l0.store(count.map_or(-1, |n| n as i64), Ordering::Relaxed);
                        stats.progress();
                    }
                    Ok(Err(error)) => tracing::warn!(error = %format!("{error:#}"), "prevalence manifest unreadable"),
                    Err(_) => tracing::warn!(timeout_secs = timing.read_timeout.as_secs_f64(),
                        "prevalence manifest read timed out"),
                }
                if restart_at.is_none() && compactor.is_finished() {
                    let outcome = (&mut compactor).await;
                    failures += 1;
                    let message = match outcome {
                        Ok(Ok(())) => "the compactor stopped".to_owned(),
                        Ok(Err(error)) => format!("{error:#}"),
                        Err(join) => format!("compactor task: {join}"),
                    };
                    tracing::error!(error = %message, failures, "prevalence compactor stopped; restarting");
                    *stats.last_error.lock().expect("error lock") = Some(message);
                    restart_at = Some(tokio::time::Instant::now() + timing.backoff(failures));
                } else if restart_at.is_none() && stats.l0.load(Ordering::Relaxed) >= 0 {
                    failures = 0;
                }
            }
        }
    }
}

/// The read credential, swappable in place: the compactor keeps its store
/// (and any compaction in flight) across credential refreshes.
#[derive(Debug)]
pub struct RotatingReadCredential {
    current: std::sync::RwLock<Arc<slatedb::object_store::aws::AwsCredential>>,
}

impl RotatingReadCredential {
    fn new(read: &super::s3_store::S3Location) -> Self {
        Self { current: std::sync::RwLock::new(Arc::new(Self::credential(read))) }
    }

    fn credential(read: &super::s3_store::S3Location) -> slatedb::object_store::aws::AwsCredential {
        slatedb::object_store::aws::AwsCredential {
            key_id: read.access_key_id.clone(),
            secret_key: read.secret_access_key.clone(),
            token: read.session_token.clone(),
        }
    }

    fn set(&self, read: &super::s3_store::S3Location) {
        *self.current.write().expect("credential lock") = Arc::new(Self::credential(read));
    }
}

#[async_trait]
impl slatedb::object_store::CredentialProvider for RotatingReadCredential {
    type Credential = slatedb::object_store::aws::AwsCredential;
    async fn get_credential(&self) -> slatedb::object_store::Result<Arc<Self::Credential>> {
        Ok(self.current.read().expect("credential lock").clone())
    }
}

/// The exact-prefix read store over a rotating credential.
fn read_store(read: &super::s3_store::S3Location, credential: Arc<RotatingReadCredential>) -> Result<Arc<dyn ObjectStore>> {
    ensure!(read.endpoint.starts_with("https://") || cfg!(test), "prevalence object-store endpoint must use HTTPS");
    let store = slatedb::object_store::aws::AmazonS3Builder::new()
        .with_bucket_name(&read.bucket)
        .with_region(&read.region)
        .with_endpoint(&read.endpoint)
        .with_allow_http(read.endpoint.starts_with("http://"))
        .with_credentials(credential)
        .build()?;
    Ok(Arc::new(slatedb::object_store::prefix::PrefixStore::new(Arc::new(store), read.prefix.as_str())))
}

/// The owner request journal, `<state_dir>/owner-pending`: 0700, never left
/// to the umask (OwnerStore refuses a journal others can read or write).
/// The state dir is maintenance[T]'s own (`<tenant>/maintenance`), never
/// ingest's prevalence directory.
pub fn private_journal(state_dir: &std::path::Path) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let journal = state_dir.join("owner-pending");
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&journal)?;
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o700))
        .context("make the owner request journal private")?;
    Ok(journal)
}

/// The cell-facing maintenance service.
pub struct MaintenanceService {
    assignment: Assignment,
    timing: LoopTiming,
    /// When this process last asked the supervisor for a bootstrap.
    last_request: std::sync::Mutex<Option<tokio::time::Instant>>,
    grant: tokio::sync::Mutex<MaintenanceGrant>,
    secrets: tokio::sync::mpsc::Sender<Zeroizing<Vec<u8>>>,
    secrets_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Zeroizing<Vec<u8>>>>,
    stats: LoopStats,
}

impl MaintenanceService {
    pub async fn start(assignment: &Assignment, secret: Zeroizing<Vec<u8>>) -> Result<Arc<Self>> {
        Self::start_with(assignment, secret, TIMING).await
    }

    async fn start_with(assignment: &Assignment, secret: Zeroizing<Vec<u8>>, timing: LoopTiming) -> Result<Arc<Self>> {
        let issued = chrono::Utc::now();
        let grant = exchange_maintenance_within(&secret, assignment, Instant::now(), timing.exchange_timeout).await?;
        let stats = LoopStats::new(issued, grant.expires_at);
        let (secrets, secrets_rx) = tokio::sync::mpsc::channel(2);
        Ok(Arc::new(Self {
            assignment: assignment.clone(),
            timing,
            last_request: std::sync::Mutex::new(None),
            grant: tokio::sync::Mutex::new(grant),
            secrets,
            secrets_rx: tokio::sync::Mutex::new(secrets_rx),
            stats,
        }))
    }

    /// Get a fresh bootstrap from the supervisor and re-exchange.
    async fn refresh(&self, control: &ControlChannel) -> Result<MaintenanceGrant> {
        let mut secrets = self.secrets_rx.lock().await;
        // A bootstrap that arrived after an earlier attempt stopped waiting
        // is stale (single-use, maybe near its TTL): ask for a new one.
        while secrets.try_recv().is_ok() {}
        // Never inside the supervisor's mint interval (it would only hold
        // the request to the interval's end).
        let earliest = self.last_request.lock().expect("request lock").map(|at| at + self.timing.min_request_interval);
        if let Some(at) = earliest {
            tokio::time::sleep_until(at).await;
        }
        *self.last_request.lock().expect("request lock") = Some(tokio::time::Instant::now());
        control.request_secrets().await?;
        let secret = tokio::time::timeout(self.timing.answer_timeout, secrets.recv())
            .await
            .context("no fresh bootstrap token from the supervisor")?
            .context("secrets channel closed")?;
        drop(secrets);
        exchange_maintenance_within(&secret, &self.assignment, Instant::now(), self.timing.exchange_timeout).await
    }

    /// Serve the control channel and run the compactor loop until either
    /// ends (the process's whole life after a successful start).
    pub async fn serve(self: Arc<Self>, control: ControlChannel) -> Result<()> {
        tokio::select! {
            result = nanosiem_lake_cell::child::run_service(self.clone(), control.clone()) => result.context("maintenance control channel"),
            result = self.run(control.clone()) => result.context("prevalence compactor loop"),
        }
    }

    /// Run the compactor until the process ends. Credentials are refreshed
    /// in place before they expire (the compactor and its in-flight job keep
    /// running); a compactor that stops is restarted with backoff.
    pub async fn run(self: Arc<Self>, control: ControlChannel) -> Result<()> {
        let (credential, owner, reads) = {
            let grant = self.grant.lock().await;
            let credential = Arc::new(RotatingReadCredential::new(&grant.access.read));
            let reads = read_store(&grant.access.read, credential.clone())?;
            let journal = private_journal(&self.assignment.state_dir)?;
            let owner = Arc::new(OwnerStore::new_maintenance(reads.clone(), MaintenanceAccess {
                read: grant.access.read.clone(),
                owner: grant.access.owner.clone(),
                owner_ca_file: grant.access.owner_ca_file.clone(),
            }, &journal)?);
            (credential, owner, reads)
        };
        let timing = self.timing;
        let ops = ServiceLoop { service: self.clone(), control, credential, owner, reads };
        drive(&ops, timing).await
    }
}

/// The service's side of the run loop.
struct ServiceLoop {
    service: Arc<MaintenanceService>,
    control: ControlChannel,
    credential: Arc<RotatingReadCredential>,
    owner: Arc<OwnerStore>,
    reads: Arc<dyn ObjectStore>,
}

#[async_trait]
impl LoopOps for ServiceLoop {
    fn stats(&self) -> &LoopStats {
        &self.service.stats
    }

    async fn refresh(&self) -> Result<(), RefreshError> {
        let issued = chrono::Utc::now();
        let grant = match self.service.refresh(&self.control).await {
            Ok(grant) => grant,
            Err(error) => {
                // Only a final 401/403 (revocation, spent token) stops the
                // role now; timeouts, connect errors, 5xx, 429 and a missing
                // bootstrap answer retry within the held grant's validity.
                let refused = error.downcast_ref::<ExchangeRefused>().is_some_and(ExchangeRefused::is_final);
                if refused {
                    tracing::error!(error = %format!("{error:#}"), "maintenance credential refresh refused");
                }
                let error = error.context("maintenance credential refresh");
                return Err(if refused { RefreshError::Fatal(error) } else { RefreshError::Retry(error) });
            }
        };
        // A cell move: this process's pending records belong to the old
        // epoch. Exit for a respawn.
        self.owner.set_bearer(&grant.access.owner).map_err(RefreshError::Fatal)?;
        self.credential.set(&grant.access.read);
        self.service.stats.set_grant(issued, grant.expires_at);
        *self.service.grant.lock().await = grant;
        Ok(())
    }

    async fn fatal(&self, message: &str) {
        let _ = self.control.fatal(message).await;
    }

    async fn read_l0(&self) -> Result<Option<usize>> {
        l0_count(self.reads.clone()).await
    }

    fn spawn_compactor(&self) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(run_compactor(self.owner.clone(), compactor_options(), CancellationToken::new()))
    }
}

#[async_trait]
impl TenantService for MaintenanceService {
    async fn handle_rpc(self: Arc<Self>, _request_id: u64, mut stream: tokio::net::UnixStream) {
        use tokio::io::AsyncWriteExt;
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
    }

    async fn wake(self: Arc<Self>, _reason: WakeReason) {}

    fn heartbeat(&self) -> Heartbeat {
        let stats = &self.stats;
        let l0 = stats.l0.load(Ordering::Relaxed);
        let error = stats.last_error.lock().expect("error lock").clone();
        Heartbeat {
            busy: true,
            // The last completed manifest read or credential refresh: a
            // wedged loop stops advancing it (NAN-3129).
            last_progress_unix_ms: stats.last_progress_ms.load(Ordering::Relaxed),
            credential_refresh_at_risk: stats.refresh_at_risk(chrono::Utc::now()),
            queue_depth: l0.max(0) as u64,
            detail: Some(format!("l0={} restarts={}{}", if l0 < 0 { "unknown".into() } else { l0.to_string() },
                stats.compactor_restarts.load(Ordering::Relaxed),
                error.map(|e| format!(" last_error={}", e.chars().take(120).collect::<String>())).unwrap_or_default())),
            ..Default::default()
        }
    }

    async fn secrets(self: Arc<Self>, secret: Zeroizing<Vec<u8>>) {
        let _ = self.secrets.send(secret).await;
    }
}

#[cfg(test)]
mod tests;
