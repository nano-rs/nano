//! The scheduler/runner: claims due feeds per tenant inside a per-tenant and
//! a global concurrency budget, runs each through the engine with the HEC
//! sink and fenced checkpoints, and records the outcome.

use std::collections::HashMap;
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
use super::hec::{HecConfig, HecSink};
use super::store::{CredentialPass, FeedStore, PendingDelete, StoreError};
use crate::auth::Credentials;
use crate::engine::{self, CheckpointStore, EngineConfig, EngineError, RunInput, Sink};
use crate::identity::{CoordinatorClient, IdentitySink, IdentitySinkOptions};
use crate::policy::EgressDeny;
use crate::spec::ConnectorSpec;
use crate::vrl_exec::VrlError;

#[derive(Clone)]
pub struct RunnerConfig {
    /// Recorded on leases and run records.
    pub node_id: String,
    pub poll_interval: Duration,
    /// Runs in flight across all tenants.
    pub max_concurrent: usize,
    /// Runs in flight per tenant.
    pub max_per_tenant: usize,
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
    /// Feeds per tenant per tick whose ingest credential issuance is advanced.
    pub credential_batch: usize,
    /// `kind: identity` feeds: the server-owned lean coordinator
    /// assignments (`NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE`). `None`:
    /// identity feeds fail with `identity_coordinator_unconfigured`.
    pub identity_assignments: Option<Arc<nanosiem_core::enrichment::lean_assignments::LeanAssignmentSource>>,
    /// Dedicated / open core (NAN-3767): the deployment's own coordinator
    /// and Vector enrichment ingress. Takes precedence over
    /// `identity_assignments`; refused on hosted-shared.
    pub identity_local: Option<Arc<crate::identity::LocalIdentity>>,
    /// Identity sink switches (`is_admin` emission, spill dir, chunking).
    pub identity: IdentitySinkOptions,
    /// Uninstalled feeds per tenant per tick whose delete is attempted.
    pub delete_batch: usize,
    /// Lease on one delete attempt (the coordinator's feed delete rewrites
    /// the directory snapshot).
    pub delete_lease_secs: u64,
}

impl RunnerConfig {
    pub fn new(node_id: impl Into<String>, engine: EngineConfig) -> Self {
        Self {
            node_id: node_id.into(),
            poll_interval: Duration::from_secs(30),
            max_concurrent: 8,
            max_per_tenant: 2,
            default_max_run_secs: 600,
            max_run_secs_ceiling: 3600,
            lease_grace_secs: 60,
            backoff_base: Duration::from_secs(30),
            backoff_max: Duration::from_secs(3600),
            engine,
            hec: HecConfig::default(),
            credential_batch: 8,
            identity_assignments: None,
            identity_local: None,
            identity: IdentitySinkOptions::default(),
            delete_batch: 4,
            delete_lease_secs: 900,
        }
    }

    fn run_secs(&self, feed_max: Option<u64>) -> u64 {
        feed_max.unwrap_or(self.default_max_run_secs).clamp(1, self.max_run_secs_ceiling)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TickSummary {
    pub tenants: usize,
    pub claimed: usize,
    pub skipped_tenant_budget: usize,
    pub claim_errors: usize,
    /// Per-feed ingest credential issuance progress, summed over tenants.
    pub credentials: CredentialPass,
    pub credential_errors: usize,
    /// Uninstalled feeds whose delete attempt started this tick.
    pub deletes: usize,
    pub delete_errors: usize,
}

pub struct Runner {
    store: Arc<dyn FeedStore>,
    cfg: RunnerConfig,
    global: Arc<Semaphore>,
    tenants: Mutex<HashMap<uuid::Uuid, Arc<Semaphore>>>,
    tasks: Mutex<JoinSet<RunRecord>>,
    /// Delete attempts of uninstalled feeds (outside the run budgets).
    deletes: Mutex<JoinSet<()>>,
}

impl Runner {
    pub fn new(store: Arc<dyn FeedStore>, cfg: RunnerConfig) -> Arc<Self> {
        Arc::new(Self {
            global: Arc::new(Semaphore::new(cfg.max_concurrent.max(1))),
            store,
            cfg,
            tenants: Mutex::new(HashMap::new()),
            tasks: Mutex::new(JoinSet::new()),
            deletes: Mutex::new(JoinSet::new()),
        })
    }

    async fn tenant_budget(&self, tenant: uuid::Uuid) -> Arc<Semaphore> {
        self.tenants
            .lock()
            .await
            .entry(tenant)
            .or_insert_with(|| Arc::new(Semaphore::new(self.cfg.max_per_tenant.max(1))))
            .clone()
    }

    /// One scheduling pass: claim what the budgets allow and start it. Runs
    /// continue in the background ([`Runner::drain`] waits for them).
    pub async fn tick(self: &Arc<Self>) -> Result<TickSummary, StoreError> {
        // Reap finished runs so the set does not grow.
        {
            let mut tasks = self.tasks.lock().await;
            while tasks.try_join_next().is_some() {}
        }
        {
            let mut deletes = self.deletes.lock().await;
            while deletes.try_join_next().is_some() {}
        }
        let slots = self.store.tenants().await?;
        let mut summary = TickSummary { tenants: slots.len(), ..Default::default() };
        for slot in slots {
            // Credential issuance first, so a feed whose token was just
            // revealed can be claimed in this same tick.
            match self.store.provision_credentials(&slot, self.cfg.credential_batch).await {
                Ok(pass) => {
                    summary.credentials.requested += pass.requested;
                    summary.credentials.waiting += pass.waiting;
                    summary.credentials.issued += pass.issued;
                    summary.credentials.failed += pass.failed;
                }
                Err(e) => {
                    summary.credential_errors += 1;
                    tracing::warn!(tenant_id = %slot.tenant_id, error = %e, "connector feed credential pass failed for tenant");
                }
            }
            // Uninstalled feeds: remove their external state, then the row.
            match self.store.claim_deletes(&slot, &self.cfg.node_id, self.cfg.delete_batch, self.cfg.delete_lease_secs).await {
                Ok(claims) => {
                    for claim in claims {
                        summary.deletes += 1;
                        let me = Arc::clone(self);
                        self.deletes.lock().await.spawn(async move { me.delete_feed(claim).await });
                    }
                }
                Err(e) => {
                    summary.delete_errors += 1;
                    tracing::warn!(tenant_id = %slot.tenant_id, error = %e, "connector feed delete claim failed for tenant");
                }
            }
            let budget = self.tenant_budget(slot.tenant_id).await;
            let mut permits: Vec<(OwnedSemaphorePermit, OwnedSemaphorePermit)> = Vec::new();
            while let Ok(t) = budget.clone().try_acquire_owned() {
                match self.global.clone().try_acquire_owned() {
                    Ok(g) => permits.push((t, g)),
                    Err(_) => break,
                }
            }
            if permits.is_empty() {
                summary.skipped_tenant_budget += 1;
                continue;
            }
            let lease = {
                let cfg = self.cfg.clone();
                move |feed_max: Option<u64>| cfg.run_secs(feed_max) + cfg.lease_grace_secs
            };
            let claims = match self.store.claim_due(&slot, &self.cfg.node_id, permits.len(), &lease).await {
                Ok(c) => c,
                Err(e) => {
                    summary.claim_errors += 1;
                    tracing::warn!(tenant_id = %slot.tenant_id, error = %e, "connector feed claim failed for tenant");
                    continue;
                }
            };
            for claim in claims {
                let Some(p) = permits.pop() else { break };
                summary.claimed += 1;
                let me = Arc::clone(self);
                self.tasks.lock().await.spawn(async move {
                    let _p = p;
                    me.run_and_finish(claim).await
                });
            }
        }
        Ok(summary)
    }

    /// Wait for every started run (tests, shutdown).
    pub async fn drain(&self) -> Vec<RunRecord> {
        {
            let mut deletes = self.deletes.lock().await;
            while deletes.join_next().await.is_some() {}
        }
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
        loop {
            match self.tick().await {
                Ok(s) => {
                    if s.claimed > 0 { tracing::debug!(?s, "connector runner tick"); }
                    if let Ok(path) = std::env::var("CONNECTOR_HEALTH_FILE") {
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

    /// One uninstalled feed: an identity feed's `<feed>:users` and
    /// `<feed>:groups` are removed at the claimed tenant's coordinator
    /// (2xx or 404 each), then the row is hard-deleted. Any failure is
    /// recorded with a backoff and retried by a later tick; nothing is
    /// dropped silently.
    async fn delete_feed(&self, claim: PendingDelete) {
        let outcome = if claim.identity { self.delete_identity_subfeeds(&claim).await } else { Ok(()) };
        let feed = claim.feed_id;
        match &outcome {
            Ok(()) => tracing::info!(target: "nano_connector::audit", tenant_id = %claim.slot.tenant_id, feed_id = %feed, identity = claim.identity, "uninstalled connector feed removed"),
            Err(e) => tracing::warn!(
                target: "nano_connector::audit",
                tenant_id = %claim.slot.tenant_id, feed_id = %feed, attempts = claim.attempts + 1, error = %e,
                "uninstalled connector feed could not be removed yet; retrying with backoff"
            ),
        }
        if let Err(e) = self.store.finish_delete(&claim, outcome).await {
            tracing::warn!(tenant_id = %claim.slot.tenant_id, feed_id = %feed, error = %e, "connector feed delete could not be recorded");
        }
    }

    async fn delete_identity_subfeeds(&self, claim: &PendingDelete) -> Result<(), String> {
        // The tenant is the claim's (the store's inventory), never a spec's.
        let client = self.identity_client(claim.slot.tenant_id)?;
        let feed = claim.feed_id.hyphenated().to_string();
        for sub in [crate::identity::USERS_SUBFEED, crate::identity::GROUPS_SUBFEED] {
            client.delete_feed(&format!("{feed}:{sub}")).await?;
        }
        Ok(())
    }

    async fn run_and_finish(&self, claim: ClaimedFeed) -> RunRecord {
        let record = self.run_claimed(&claim).await;
        emit_metrics(&claim, &record);
        audit(&claim, &record);
        if let Err(e) = self.store.finish(&claim, &record).await {
            tracing::error!(tenant_id = %claim.slot.tenant_id, feed_id = %claim.feed.feed_id, error = %e,
                "connector run outcome was not recorded");
        }
        record
    }

    /// Execute one claimed feed. Never panics into the scheduler; every
    /// failure becomes a `failed` record.
    pub async fn run_claimed(&self, claim: &ClaimedFeed) -> RunRecord {
        let started = Utc::now();
        let feed = &claim.feed;
        let mut rec = RunRecord {
            status: RunStatus::Failed,
            started_at: started,
            finished_at: started,
            events: 0,
            bytes: 0,
            batches: 0,
            pages: 0,
            requests: 0,
            ingest_retries: 0,
            rejected_events: 0,
            dropped_duplicates: 0,
            checkpoints_committed: 0,
            errors: 0,
            error: None,
            last_receipt: None,
            next_run_at: started,
            deferred: false,
        };
        let spec = match self.prepare(claim) {
            Ok(s) => s,
            Err(e) => return self.close(claim, rec, None, Some(e)),
        };
        let run_sink = match self.sink_for(claim, &spec) {
            Ok(s) => s,
            Err(e) => return self.close(claim, rec, Some(&spec), Some(e)),
        };
        let checkpoints = match self.store.load_checkpoints(claim).await {
            Ok(c) => c,
            Err(e) => return self.close(claim, rec, Some(&spec), Some(e.to_string())),
        };
        let fenced = Arc::new(FencedCheckpoints { store: Arc::clone(&self.store), claim: claim.clone(), commits: AtomicU64::new(0), lost: AtomicU64::new(0) });
        let run_secs = self.cfg.run_secs(feed.max_run_secs);
        let mut ecfg = self.cfg.engine.clone();
        ecfg.ceilings.max_run_secs = run_secs;
        let input = RunInput {
            config: feed.config.clone(),
            credentials: Credentials::new(feed.vendor_credentials.iter().map(|(k, v)| (k.clone(), v.expose().to_string())).collect()),
            checkpoints,
            artifact: None,
            artifact_extra: Default::default(),
            enabled_streams: None,
            // VRL worker fairness is per tenant. A per-tenant egress deny
            // list has no column yet; the platform deny lives in
            // `EngineConfig.platform_deny`. The feed's own ingest host is
            // never a vendor.
            tenant: Some(claim.slot.tenant_id.to_string()),
            egress_deny: run_sink.egress_deny(&feed.ingest_url),
            feed_id: Some(feed.feed_id.to_string()),
        };
        // The engine enforces `run_secs`; this backstop covers a stuck sink
        // or store call the engine cannot interrupt.
        let backstop = Duration::from_secs(run_secs + self.cfg.lease_grace_secs / 2);
        let result = tokio::time::timeout(backstop, engine::run(&ecfg, &spec, input, run_sink.as_sink(), fenced.clone())).await;
        if result.is_err() {
            if let RunSink::Identity(s) = &run_sink {
                use crate::identity::IdentityTarget;
                let _ = tokio::time::timeout(Duration::from_secs(15), s.abort()).await;
            }
        }
        rec.checkpoints_committed = fenced.commits.load(Ordering::SeqCst);
        run_sink.record(&mut rec);
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
                rec.status = match &e {
                    _ if lease_lost => RunStatus::LeaseLost,
                    EngineError::WallClock(_) => RunStatus::Timeout,
                    // No VRL worker slot: this node is busy, the feed is
                    // fine. Retry soon without counting a failure.
                    EngineError::Vrl(VrlError::PoolExhausted(..)) => {
                        rec.deferred = true;
                        RunStatus::Timeout
                    }
                    _ => RunStatus::Failed,
                };
                self.close(claim, rec, Some(&spec), Some(e.to_string()))
            }
            Err(_) => {
                rec.status = RunStatus::Timeout;
                self.close(claim, rec, Some(&spec), Some(format!("run exceeded its {} s backstop", backstop.as_secs())))
            }
        }
    }

    /// The run's sink: the feed's HEC ingress for a collector, the claimed
    /// tenant's identity directory for `kind: identity`. The tenant is the
    /// claim's (the store's inventory), never the spec's, config's or an
    /// event's.
    fn sink_for(&self, claim: &ClaimedFeed, spec: &ConnectorSpec) -> Result<RunSink, String> {
        let feed = &claim.feed;
        if spec.kind == crate::spec::Kind::Identity {
            let client = self.identity_client(claim.slot.tenant_id)?;
            let mut opts = self.cfg.identity.clone();
            opts.max_memberships = opts
                .max_memberships
                .min(spec.limits.max_identity_memberships)
                .min(self.cfg.engine.ceilings.max_identity_memberships);
            let mut sink = IdentitySink::new(client, feed.feed_id, Utc::now(), opts);
            if let Some(local) = &self.cfg.identity_local {
                sink = sink.with_vector(Arc::clone(&local.vector));
            }
            return Ok(RunSink::Identity(Arc::new(sink)));
        }
        HecSink::new(&feed.ingest_url, feed.ingest_token.clone(), feed.feed_id, &feed.connector, self.cfg.hec.clone())
            .map(|s| RunSink::Hec(Arc::new(s)))
            .map_err(|e| e.to_string())
    }

    /// The claimed tenant's identity coordinator: the dedicated deployment's
    /// own (NAN-3767), else the hosted assignments map. Neither: the feed
    /// fails with `identity_coordinator_unconfigured`.
    fn identity_client(&self, tenant: uuid::Uuid) -> Result<CoordinatorClient, String> {
        if let Some(local) = &self.cfg.identity_local {
            return local.client(tenant);
        }
        let source = self.cfg.identity_assignments.as_ref().ok_or(
            "identity_coordinator_unconfigured: this runner has no identity directory path (open core: CONNECTOR_IDENTITY_COORDINATOR_URL, CONNECTOR_IDENTITY_VECTOR_URL and NANO_LAKE_TENANT_ID; hosted: NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE)",
        )?;
        CoordinatorClient::for_tenant(source, tenant)
    }

    /// Parse the pinned spec and check its digest.
    fn prepare(&self, claim: &ClaimedFeed) -> Result<ConnectorSpec, String> {
        let feed = &claim.feed;
        let digest = spec_sha256(&feed.spec_yaml);
        if !digest.eq_ignore_ascii_case(&feed.spec_sha256) {
            return Err(format!("pinned spec digest mismatch (feed pins {}, spec is {digest})", feed.spec_sha256));
        }
        let spec = ConnectorSpec::from_yaml(&feed.spec_yaml).map_err(|e| format!("spec: {e}"))?;
        if !matches!(spec.kind, crate::spec::Kind::Collector | crate::spec::Kind::Identity) {
            return Err("only collector and identity specs run as feeds".into());
        }
        Ok(spec)
    }

    fn close(&self, claim: &ClaimedFeed, mut rec: RunRecord, spec: Option<&ConnectorSpec>, error: Option<String>) -> RunRecord {
        let now = Utc::now();
        rec.finished_at = now;
        // NAN-3660: the ingress refused the feed's credential. Record the
        // refusal itself (not the engine's wrapper) so the operator sees
        // "credential_revoked: ... rotate the feed credential".
        let mut credential_refused = false;
        if let Some(e) = error {
            if rec.status == RunStatus::Success {
                rec.status = RunStatus::Failed;
            }
            rec.errors = 1;
            let e = match crate::service::hec::credential_refusal_in(&e) {
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
            // the credential is rotated (which makes the feed due at once).
            // Never re-enroll here: a tenant's revoke stays in force.
            (now + ChronoDuration::seconds(crate::service::hec::CREDENTIAL_REFUSED_RETRY_SECS)).max(regular)
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

/// Where a run's rows go.
enum RunSink {
    Hec(Arc<HecSink>),
    Identity(Arc<IdentitySink>),
}

impl RunSink {
    fn as_sink(&self) -> Arc<dyn Sink> {
        match self {
            Self::Hec(s) => s.clone(),
            Self::Identity(s) => s.clone(),
        }
    }

    /// The vendor side of a run may reach neither the feed's ingress nor
    /// the tenant's coordinator.
    fn egress_deny(&self, ingest_url: &str) -> EgressDeny {
        match self {
            Self::Hec(_) => ingest_deny(ingest_url),
            Self::Identity(s) => EgressDeny { hosts: s.coordinator_host().into_iter().chain(s.vector_host()).collect(), cidrs: vec![] },
        }
    }

    fn record(&self, rec: &mut RunRecord) {
        match self {
            Self::Hec(sink) => {
                rec.batches = sink.stats.batches.load(Ordering::SeqCst);
                rec.bytes = sink.stats.bytes.load(Ordering::SeqCst);
                rec.events = sink.stats.events.load(Ordering::SeqCst);
                rec.ingest_retries = sink.stats.retries.load(Ordering::SeqCst);
                rec.rejected_events = sink.stats.rejected_events.load(Ordering::SeqCst);
                rec.last_receipt = sink.stats.last_receipt.lock().expect("receipt").clone();
            }
            Self::Identity(sink) => {
                rec.batches = sink.stats.requests.load(Ordering::SeqCst);
                rec.bytes = sink.stats.bytes.load(Ordering::SeqCst);
                rec.events = sink.stats.rows.load(Ordering::SeqCst);
                rec.last_receipt = Some(format!("identity-run:{}", sink.run_id()));
            }
        }
    }
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
fn ingest_deny(ingest_url: &str) -> EgressDeny {
    let host = url::Url::parse(ingest_url).ok().and_then(|u| u.host_str().map(str::to_string));
    EgressDeny { hosts: host.into_iter().map(|h| h.trim_end_matches('.').to_ascii_lowercase()).collect(), cidrs: vec![] }
}

/// The platform egress deny for a runner, from `CONNECTOR_EGRESS_DENY_CIDRS`
/// and `CONNECTOR_EGRESS_DENY_HOSTS` (comma-separated) plus the ingest host
/// suffix. On a shared deployment the CIDR list is mandatory: it must name
/// the cluster's pod / service / node ranges that are not already
/// non-public (e.g. GUA IPv6 pod ranges, node public IPs).
pub fn platform_egress_deny(cidrs: Option<&str>, hosts: Option<&str>, ingest_suffix: Option<&str>, shared: bool) -> Result<EgressDeny, String> {
    let split = |v: Option<&str>| -> Vec<String> {
        v.unwrap_or_default().split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
    };
    let cidrs = split(cidrs);
    let mut hosts = split(hosts);
    if let Some(sfx) = ingest_suffix.map(|s| s.trim().trim_matches('.').to_ascii_lowercase()).filter(|s| !s.is_empty()) {
        hosts.push(format!(".{sfx}"));
    }
    if shared && cidrs.is_empty() {
        return Err("CONNECTOR_EGRESS_DENY_CIDRS is required on enterprise_shared (cluster pod/service/node ranges)".into());
    }
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
        "tenant_id": claim.slot.tenant_id,
        "feed_id": claim.feed.feed_id,
        "run_id": claim.run_id,
        "connector": claim.feed.connector,
        "source_slug": claim.feed.source_slug,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_deny_is_required_on_shared_and_covers_ingest() {
        assert!(platform_egress_deny(None, None, Some("ingest.example.net"), true).unwrap_err().contains("CONNECTOR_EGRESS_DENY_CIDRS"));
        let d = platform_egress_deny(Some("10.0.0.0/8, 2600:1900::/28,"), Some("kube.internal.example.net"), Some(".ingest.example.net"), true).unwrap();
        assert!(d.denies_host("tenant-a.ingest.example.net") && d.denies_host("ingest.example.net"));
        assert!(d.denies_host("kube.internal.example.net") && !d.denies_host("api.vendor.com"));
        assert!(d.denies_ip("2600:1900::1".parse().unwrap()) && d.denies_ip("10.2.3.4".parse().unwrap()));
        assert!(platform_egress_deny(Some("10.0.0.0/33"), None, None, false).is_err());
        assert!(platform_egress_deny(None, Some("http://x"), None, false).is_err());
        assert!(platform_egress_deny(None, None, None, false).unwrap().hosts.is_empty());
        assert_eq!(ingest_deny("https://Tenant.Ingest.example.net:443/services/collector").hosts, vec!["tenant.ingest.example.net".to_string()]);
    }
}
