// SPDX-License-Identifier: AGPL-3.0-or-later

//! The scheduler/runner: claims due feeds inside a concurrency budget, runs
//! each through the engine with the HEC sink and fenced checkpoints, and
//! records the outcome.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde_json::{Value, json};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

use super::feed::{
    ClaimedFeed, DEFAULT_SCHEDULE, RunRecord, RunStatus, effective_schedule, failure_delay, next_scheduled, spec_sha256,
};
use super::directory::{IDENTITY_UNCONFIGURED, IdentityDirectories};
use super::hec::{HecConfig, HecSink};
use super::ingest::IngestRoute;
use super::store::{FeedStore, StoreError};
use crate::auth::Credentials;
use crate::engine::{self, CheckpointStore, EngineConfig, EngineError, RunInput, RunOutput, Sink};
use crate::identity::IdentitySink;
use crate::policy::EgressDeny;
use crate::spec::{ConnectorSpec, Kind};
use crate::vrl_exec::VrlError;

#[derive(Clone)]
pub struct RunnerConfig {
    /// Recorded on leases and run records.
    pub node_id: String,
    pub poll_interval: Duration,
    /// Runs in flight at once.
    pub max_concurrent: usize,
    /// Run wall clock when the feed sets none (the spec's own limit is
    /// clamped to it as well).
    pub default_max_run_secs: u64,
    /// No feed may run longer than this.
    pub max_run_secs_ceiling: u64,
    /// Lease = run wall clock + this.
    pub lease_grace_secs: u64,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
    /// Engine template (VRL worker exe, broker, ceilings). The run's
    /// `max_run_secs` ceiling is set per feed.
    pub engine: EngineConfig,
    pub hec: HecConfig,
    /// Where events go and with which token (the NAN-4907 seam).
    pub ingest: Arc<dyn IngestRoute>,
    /// Written after every successful tick (container health check).
    pub health_file: Option<std::path::PathBuf>,
    /// G22: the user directory `kind: identity` feeds write into. `None`:
    /// identity feeds fail with [`IDENTITY_UNCONFIGURED`].
    pub identity: Option<Arc<dyn IdentityDirectories>>,
}

impl RunnerConfig {
    pub fn new(node_id: impl Into<String>, engine: EngineConfig, ingest: Arc<dyn IngestRoute>) -> Self {
        Self {
            node_id: node_id.into(),
            poll_interval: Duration::from_secs(30),
            max_concurrent: 4,
            default_max_run_secs: 600,
            max_run_secs_ceiling: 3600,
            lease_grace_secs: 60,
            backoff_base: Duration::from_secs(30),
            backoff_max: Duration::from_secs(3600),
            engine,
            hec: HecConfig::default(),
            ingest,
            health_file: None,
            identity: None,
        }
    }

    fn run_secs(&self, feed_max: Option<u64>) -> u64 {
        feed_max.unwrap_or(self.default_max_run_secs).clamp(1, self.max_run_secs_ceiling)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickSummary {
    pub claimed: usize,
    pub budget_full: bool,
    /// NAN-5217: nano's ingestion pause is on; nothing was claimed.
    pub ingestion_paused: bool,
}

pub struct Runner {
    store: Arc<dyn FeedStore>,
    cfg: RunnerConfig,
    budget: Arc<Semaphore>,
    tasks: Mutex<JoinSet<RunRecord>>,
}

impl Runner {
    pub fn new(store: Arc<dyn FeedStore>, cfg: RunnerConfig) -> Arc<Self> {
        Arc::new(Self {
            budget: Arc::new(Semaphore::new(cfg.max_concurrent.max(1))),
            store,
            cfg,
            tasks: Mutex::new(JoinSet::new()),
        })
    }

    /// One scheduling pass: claim what the budget allows and start it. Runs
    /// continue in the background ([`Runner::drain`] waits for them).
    pub async fn tick(self: &Arc<Self>) -> Result<TickSummary, StoreError> {
        {
            let mut tasks = self.tasks.lock().await;
            while tasks.try_join_next().is_some() {}
        }
        // NAN-5217: while ingestion is paused, claim nothing: pull feeds stop
        // pulling, and their checkpoints stay where they are so the next run
        // after resume picks up exactly where the last one stopped.
        if self.store.ingestion_paused().await {
            return Ok(TickSummary { ingestion_paused: true, ..TickSummary::default() });
        }
        let mut permits: Vec<OwnedSemaphorePermit> = Vec::new();
        while let Ok(p) = self.budget.clone().try_acquire_owned() {
            permits.push(p);
        }
        if permits.is_empty() {
            return Ok(TickSummary { budget_full: true, ..TickSummary::default() });
        }
        let lease = {
            let cfg = self.cfg.clone();
            move |feed_max: Option<u64>| cfg.run_secs(feed_max) + cfg.lease_grace_secs
        };
        let claims = self.store.claim_due(&self.cfg.node_id, permits.len(), &lease).await?;
        let mut summary = TickSummary::default();
        for claim in claims {
            let Some(p) = permits.pop() else { break };
            summary.claimed += 1;
            let me = Arc::clone(self);
            self.tasks.lock().await.spawn(async move {
                let _p = p;
                me.run_and_finish(claim).await
            });
        }
        Ok(summary)
    }

    /// Wait for every started run (tests, shutdown).
    pub async fn drain(&self) -> Vec<RunRecord> {
        let mut out = Vec::new();
        let mut tasks = self.tasks.lock().await;
        while let Some(r) = tasks.join_next().await {
            if let Ok(rec) = r {
                out.push(rec);
            }
        }
        out
    }

    /// Abort every in-flight run (tests: a crash).
    pub async fn abort_all(&self) {
        let mut tasks = self.tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }

    /// Tick forever; stop when `shutdown` resolves, then let in-flight runs
    /// finish (their own wall clock bounds that).
    pub async fn run_until(self: Arc<Self>, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        tracing::info!(node = %self.cfg.node_id, poll_secs = self.cfg.poll_interval.as_secs(), "connector feed runner started");
        let mut paused_logged = false;
        loop {
            match self.tick().await {
                Ok(s) => {
                    if s.ingestion_paused && !paused_logged {
                        tracing::warn!("ingestion is paused: no connector feed runs are claimed until it is resumed");
                    } else if !s.ingestion_paused && paused_logged {
                        tracing::info!("ingestion resumed: connector feed runs are claimed again");
                    }
                    paused_logged = s.ingestion_paused;
                    if s.claimed > 0 {
                        tracing::debug!(?s, "connector runner tick");
                    }
                    if let Some(path) = &self.cfg.health_file {
                        if let Err(e) = std::fs::write(path, "ready\n") {
                            tracing::warn!(error = %e, "connector health heartbeat failed");
                        }
                    }
                }
                Err(e) => tracing::error!(error = %e, "connector runner tick failed"),
            }
            tokio::select! {
                _ = &mut shutdown => break,
                _ = tokio::time::sleep(self.cfg.poll_interval) => {}
            }
        }
        tracing::info!("connector feed runner stopping; waiting for in-flight runs");
        self.drain().await;
    }

    async fn run_and_finish(&self, claim: ClaimedFeed) -> RunRecord {
        let record = self.run_claimed(&claim).await;
        emit_metrics(&claim, &record);
        audit(&claim, &record);
        if let Err(e) = self.store.finish(&claim, &record).await {
            tracing::error!(feed_id = %claim.feed.feed_id, error = %e, "connector run outcome was not recorded");
        }
        record
    }

    /// Execute one claimed feed. Never panics into the scheduler; every
    /// failure becomes a `failed` record.
    pub async fn run_claimed(&self, claim: &ClaimedFeed) -> RunRecord {
        let mut rec = RunRecord::started(Utc::now());
        let feed = &claim.feed;
        let spec = match prepare(claim) {
            Ok(s) => s,
            Err(e) => return self.close(claim, rec, None, Some(e)),
        };
        if spec.kind == Kind::Identity {
            return self.run_identity(claim, rec, spec).await;
        }
        let (ingest_url, token) = match self.cfg.ingest.route(feed) {
            Ok(r) => r,
            Err(e) => return self.close(claim, rec, Some(&spec), Some(e)),
        };
        let sink = match HecSink::new(&ingest_url, token, feed.feed_id, &feed.connector, self.cfg.hec.clone()) {
            Ok(s) => Arc::new(s),
            Err(e) => return self.close(claim, rec, Some(&spec), Some(e.to_string())),
        };
        let checkpoints = match self.store.load_checkpoints(claim).await {
            Ok(c) => c,
            Err(e) => return self.close(claim, rec, Some(&spec), Some(e.to_string())),
        };
        // VRL worker fairness is per feed. The feed's own ingest host is
        // never a vendor. The engine enforces the run wall clock; the
        // backstop covers a stuck sink or store call it cannot interrupt.
        let (result, fenced, backstop) =
            self.run_engine(claim, &spec, checkpoints, sink.clone(), ingest_deny(&ingest_url)).await;
        rec.checkpoints_committed = fenced.commits.load(Ordering::SeqCst);
        rec.batches = sink.stats.batches.load(Ordering::SeqCst);
        rec.bytes = sink.stats.bytes.load(Ordering::SeqCst);
        rec.events = sink.stats.events.load(Ordering::SeqCst);
        rec.ingest_retries = sink.stats.retries.load(Ordering::SeqCst);
        rec.rejected_events = sink.stats.rejected_events.load(Ordering::SeqCst);
        rec.last_receipt = sink.stats.last_receipt.lock().expect("receipt").clone();
        let lease_lost = fenced.lost.load(Ordering::SeqCst) > 0;
        match result {
            Ok(Ok(out)) => {
                rec.pages = out.pages;
                rec.requests = out.requests;
                rec.dropped_duplicates = out.dropped_duplicates;
                rec.status = RunStatus::Success;
                self.close(claim, rec, Some(&spec), None)
            }
            Ok(Err(e)) => {
                rec.status = failure_status(&mut rec, &e, lease_lost);
                self.close(claim, rec, Some(&spec), Some(e.to_string()))
            }
            Err(_) => {
                rec.status = RunStatus::Timeout;
                self.close(claim, rec, Some(&spec), Some(format!("run exceeded its {} s backstop", backstop.as_secs())))
            }
        }
    }

    /// G22: a `kind: identity` feed. Same lease, fencing, checkpoints and
    /// run record as a collector; the rows go to the user directory instead
    /// of Vector, and the feed's identity provider row records the outcome.
    async fn run_identity(&self, claim: &ClaimedFeed, mut rec: RunRecord, spec: ConnectorSpec) -> RunRecord {
        let feed = &claim.feed;
        let Some(directories) = &self.cfg.identity else {
            return self.close(claim, rec, Some(&spec), Some(IDENTITY_UNCONFIGURED.to_string()));
        };
        let directory = match directories.open(feed).await {
            Ok(d) => d,
            Err(e) => return self.close(claim, rec, Some(&spec), Some(e)),
        };
        if let Err(e) = directory.started().await {
            return self.close(claim, rec, Some(&spec), Some(e));
        }
        let checkpoints = match self.store.load_checkpoints(claim).await {
            Ok(c) => c,
            Err(e) => {
                directory.finished(false, Some(&e.to_string()), 0, 0).await;
                return self.close(claim, rec, Some(&spec), Some(e.to_string()));
            }
        };
        let max_memberships = engine::compile(&spec, &self.cfg.engine.ceilings)
            .map(|c| c.limits.max_identity_memberships)
            .unwrap_or(5_000_000);
        // NAN-4931: every directory write is fenced by this claim's lease.
        let fence = Arc::new(super::store::ClaimFence { store: self.store.clone(), claim: claim.clone() });
        let sink = Arc::new(IdentitySink::new(directory.clone(), max_memberships).with_fence(fence));
        let (result, fenced, backstop) = self.run_engine(claim, &spec, checkpoints, sink.clone(), EgressDeny::default()).await;
        rec.checkpoints_committed = fenced.commits.load(Ordering::SeqCst);
        let rows = sink.stats.rows.load(Ordering::SeqCst);
        rec.events = rows;
        rec.batches = 0;
        let duration_ms = (Utc::now() - rec.started_at).num_milliseconds();
        let lease_lost = fenced.lost.load(Ordering::SeqCst) > 0;
        let s = &sink.stats;
        tracing::info!(
            target: "nano_connector::audit",
            feed_id = %feed.feed_id,
            rows,
            tombstones = s.tombstones.load(Ordering::SeqCst),
            retired = s.retired.load(Ordering::SeqCst),
            managers_resolved = s.managers_resolved.load(Ordering::SeqCst),
            managers_unresolved = s.managers_unresolved.load(Ordering::SeqCst),
            members = s.members.load(Ordering::SeqCst),
            groups = s.groups.load(Ordering::SeqCst),
            groups_applied = s.groups_applied.load(Ordering::SeqCst),
            members_unmatched = s.members_unmatched.load(Ordering::SeqCst),
            "identity feed run delivered"
        );
        match result {
            Ok(Ok(out)) => {
                directory.finished(true, None, duration_ms, rows).await;
                rec.pages = out.pages;
                rec.requests = out.requests;
                rec.status = RunStatus::Success;
                self.close(claim, rec, Some(&spec), None)
            }
            Ok(Err(e)) => {
                let message = e.to_string();
                directory.finished(false, Some(&truncate(&message, 1000)), duration_ms, rows).await;
                rec.status = failure_status(&mut rec, &e, lease_lost);
                self.close(claim, rec, Some(&spec), Some(message))
            }
            Err(_) => {
                let message = format!("run exceeded its {} s backstop", backstop.as_secs());
                directory.finished(false, Some(&message), duration_ms, rows).await;
                rec.status = RunStatus::Timeout;
                self.close(claim, rec, Some(&spec), Some(message))
            }
        }
    }

    /// The engine run of a claimed feed with fenced checkpoints, under the
    /// run wall clock and the runner's backstop.
    async fn run_engine(
        &self,
        claim: &ClaimedFeed,
        spec: &ConnectorSpec,
        checkpoints: std::collections::HashMap<String, Value>,
        sink: Arc<dyn Sink>,
        egress_deny: EgressDeny,
    ) -> (Result<Result<RunOutput, EngineError>, tokio::time::error::Elapsed>, Arc<FencedCheckpoints>, Duration) {
        let feed = &claim.feed;
        let fenced = Arc::new(FencedCheckpoints {
            store: Arc::clone(&self.store),
            claim: claim.clone(),
            commits: AtomicU64::new(0),
            lost: AtomicU64::new(0),
        });
        let run_secs = self.cfg.run_secs(feed.max_run_secs);
        let mut ecfg = self.cfg.engine.clone();
        ecfg.ceilings.max_run_secs = run_secs;
        let input = RunInput {
            config: feed.config.clone(),
            credentials: Credentials::new(
                feed.vendor_credentials.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect(),
            ),
            checkpoints,
            artifact: None,
            artifact_extra: Default::default(),
            enabled_streams: None,
            tenant: Some(feed.feed_id.to_string()),
            egress_deny,
        };
        let backstop = Duration::from_secs(run_secs + self.cfg.lease_grace_secs / 2);
        let result = tokio::time::timeout(backstop, engine::run(&ecfg, spec, input, sink, fenced.clone())).await;
        (result, fenced, backstop)
    }

    fn close(&self, claim: &ClaimedFeed, mut rec: RunRecord, spec: Option<&ConnectorSpec>, error: Option<String>) -> RunRecord {
        let now = Utc::now();
        rec.finished_at = now;
        let mut credential_refused = false;
        if let Some(e) = error {
            if rec.status == RunStatus::Success {
                rec.status = RunStatus::Failed;
            }
            rec.errors = 1;
            let e = match super::hec::credential_refusal_in(&e) {
                Some(refusal) if rec.status == RunStatus::Failed => {
                    credential_refused = true;
                    refusal.to_string()
                }
                _ => e,
            };
            rec.error = Some(truncate(&e, 1000));
        }
        let schedule = effective_schedule(claim.feed.schedule.as_deref(), spec.and_then(|s| s.schedule.as_deref()));
        let regular = next_scheduled(schedule, now).unwrap_or_else(|e| {
            tracing::warn!(feed_id = %claim.feed.feed_id, error = %e, "invalid feed schedule; using the default");
            next_scheduled(DEFAULT_SCHEDULE, now).unwrap_or(now + ChronoDuration::minutes(5))
        });
        rec.next_run_at = if rec.ok() {
            regular
        } else if credential_refused {
            // Not a transient failure: retrying each batch cannot help until
            // the ingest token is fixed.
            (now + ChronoDuration::seconds(super::hec::CREDENTIAL_REFUSED_RETRY_SECS)).max(regular)
        } else if rec.deferred {
            let jitter = 1.0 + rand::random::<f64>();
            let d = self.cfg.poll_interval.mul_f64(jitter);
            (now + ChronoDuration::from_std(d).unwrap_or(ChronoDuration::minutes(1))).min(regular)
        } else {
            let failures = claim.feed.consecutive_failures + 1;
            let jitter = rand::random::<f64>() * 2.0 - 1.0;
            let d = failure_delay(failures, self.cfg.backoff_base, self.cfg.backoff_max, jitter);
            // Back off, but never sooner than the regular schedule.
            (now + ChronoDuration::from_std(d).unwrap_or(ChronoDuration::hours(1))).max(regular)
        };
        rec
    }
}

/// The status of a run the engine failed.
fn failure_status(rec: &mut RunRecord, e: &EngineError, lease_lost: bool) -> RunStatus {
    match e {
        _ if lease_lost => RunStatus::LeaseLost,
        EngineError::WallClock(_) => RunStatus::Timeout,
        // No VRL worker slot: this node is busy, the feed is fine. Retry
        // soon without counting a failure.
        EngineError::Vrl(VrlError::PoolExhausted(..)) => {
            rec.deferred = true;
            RunStatus::Timeout
        }
        _ => RunStatus::Failed,
    }
}

/// Parse the pinned spec and check its digest.
fn prepare(claim: &ClaimedFeed) -> Result<ConnectorSpec, String> {
    let feed = &claim.feed;
    let digest = spec_sha256(&feed.spec_yaml);
    if !digest.eq_ignore_ascii_case(&feed.spec_sha256) {
        return Err(format!("pinned spec digest mismatch (feed pins {}, spec is {digest})", feed.spec_sha256));
    }
    let spec = ConnectorSpec::from_yaml(&feed.spec_yaml).map_err(|e| format!("spec: {e}"))?;
    if !matches!(spec.kind, Kind::Collector | Kind::Identity) {
        return Err("only collector and identity specs run as pull feeds".into());
    }
    Ok(spec)
}

/// Engine checkpoints → the store, fenced on the claim's lease.
struct FencedCheckpoints {
    store: Arc<dyn FeedStore>,
    claim: ClaimedFeed,
    commits: AtomicU64,
    lost: AtomicU64,
}

#[async_trait::async_trait]
impl CheckpointStore for FencedCheckpoints {
    async fn save(&self, stream: &str, state: &Value) -> Result<(), String> {
        match self.store.save_checkpoint(&self.claim, stream, state).await {
            Ok(()) => {
                self.commits.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            Err(e) => {
                if matches!(e, StoreError::LeaseLost) {
                    self.lost.fetch_add(1, Ordering::SeqCst);
                }
                Err(e.to_string())
            }
        }
    }
}

/// Deny the feed's ingest host to the vendor side of the run.
pub fn ingest_deny(ingest_url: &str) -> EgressDeny {
    let host = url::Url::parse(ingest_url).ok().and_then(|u| u.host_str().map(str::to_string));
    EgressDeny { hosts: host.into_iter().map(|h| h.trim_end_matches('.').to_ascii_lowercase()).collect(), cidrs: vec![] }
}

/// The operator egress deny for a runner, from `CONNECTOR_EGRESS_DENY_CIDRS`
/// and `CONNECTOR_EGRESS_DENY_HOSTS` (comma-separated). The broker already
/// refuses private, loopback and link-local addresses; this adds the
/// deployment's own public ranges and names.
pub fn platform_egress_deny(cidrs: Option<&str>, hosts: Option<&str>) -> Result<EgressDeny, String> {
    let split = |v: Option<&str>| -> Vec<String> {
        v.unwrap_or_default().split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
    };
    let cidrs = split(cidrs);
    let hosts = split(hosts);
    for h in &hosts {
        let name = h.strip_prefix('.').unwrap_or(h);
        if !crate::policy::is_plain_hostname(&name.to_ascii_lowercase()) {
            return Err(format!("CONNECTOR_EGRESS_DENY_HOSTS: `{h}` is not a host name or .suffix"));
        }
    }
    let c: Vec<&str> = cidrs.iter().map(String::as_str).collect();
    let h: Vec<&str> = hosts.iter().map(String::as_str).collect();
    EgressDeny::parse(&h, &c).map_err(|e| format!("CONNECTOR_EGRESS_DENY_CIDRS: {e}"))
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

/// Prometheus-style metrics (no-ops unless the host installs a recorder).
fn emit_metrics(claim: &ClaimedFeed, rec: &RunRecord) {
    let labels = [("connector", claim.feed.connector.clone()), ("status", rec.status.as_str().to_string())];
    metrics::counter!("nano_connector_runs_total", &labels).increment(1);
    if rec.deferred {
        metrics::counter!("nano_connector_runs_deferred_total", "connector" => claim.feed.connector.clone()).increment(1);
    }
    let l = [("connector", claim.feed.connector.clone())];
    metrics::counter!("nano_connector_events_total", &l).increment(rec.events);
    metrics::counter!("nano_connector_bytes_total", &l).increment(rec.bytes);
    metrics::counter!("nano_connector_pages_total", &l).increment(rec.pages as u64);
    metrics::counter!("nano_connector_ingest_retries_total", &l).increment(rec.ingest_retries);
    metrics::counter!("nano_connector_errors_total", &l).increment(rec.errors as u64);
    metrics::histogram!("nano_connector_run_seconds", &l)
        .record((rec.finished_at - rec.started_at).num_milliseconds() as f64 / 1000.0);
    if rec.ok() {
        metrics::gauge!("nano_connector_last_success_timestamp_seconds", &l).set(rec.finished_at.timestamp() as f64);
    }
}

/// One structured audit line per run (target `nano_connector::audit`); the
/// durable record is the store's run row.
fn audit(claim: &ClaimedFeed, rec: &RunRecord) {
    let fields = audit_fields(claim, rec);
    if rec.ok() {
        tracing::info!(target: "nano_connector::audit", run = %fields, "connector feed run");
    } else {
        tracing::warn!(target: "nano_connector::audit", run = %fields, "connector feed run");
    }
}

pub fn audit_fields(claim: &ClaimedFeed, rec: &RunRecord) -> Value {
    let iso = |t: DateTime<Utc>| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    json!({
        "feed_id": claim.feed.feed_id,
        "run_id": claim.run_id,
        "connector": claim.feed.connector,
        "source_type": claim.feed.source_type,
        "spec_sha256": claim.feed.spec_sha256,
        "node": claim.node,
        "lease_generation": claim.lease_generation,
        "status": rec.status.as_str(),
        "started_at": iso(rec.started_at),
        "finished_at": iso(rec.finished_at),
        "events": rec.events,
        "bytes": rec.bytes,
        "batches": rec.batches,
        "pages": rec.pages,
        "requests": rec.requests,
        "ingest_retries": rec.ingest_retries,
        "rejected_events": rec.rejected_events,
        "dropped_duplicates": rec.dropped_duplicates,
        "checkpoints_committed": rec.checkpoints_committed,
        "errors": rec.errors,
        "error": rec.error,
        "last_receipt": rec.last_receipt,
        "next_run_at": iso(rec.next_run_at),
        "deferred": rec.deferred,
    })
}
