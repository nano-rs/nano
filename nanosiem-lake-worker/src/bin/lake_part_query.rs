// SPDX-License-Identifier: AGPL-3.0-or-later

//! `query[T]`: the lean-lake per-tenant query process (NAN-2869), and
//! `detect[T]`: the tenant's finding drain plus, when the assignment says
//! `detect_runs_rules`, its own rule-search engine (the same part_query
//! engine and chDB session as query[T], sized from detect's memory.max).
//!
//! Started only by the cell supervisor (`--cell-control-fd 3`). The cell
//! handshake runs first, single-threaded: it waits warm for an assignment,
//! applies the tenant jail (uid, landlock, seccomp) in-process and receives
//! the bootstrap secret over a sealed memfd. Only then does the async
//! runtime start and the engine open the tenant's verified part log.

use anyhow::Context;
use nanosiem_lake_worker::cell_refresh::{owner_bearer_expiry, CredentialRefresher, RefreshingSigner};
use nanosiem_lake_worker::part_query::credentials::{QueryCredentialSwap, R2ReadAuthority};
use nanosiem_lake_worker::part_query::job_results::JobResultStore;
use nanosiem_lake_worker::part_query::engine::DETECT_ADMISSION_DEADLINE;
use nanosiem_lake_worker::part_query::server::{compiler_sha256, load_identity_snapshot, open_engine_timed, open_ioc_store, r2_operator, resolve_bootstrap, resolve_detect_bootstrap, DetectBootstrap, ExchangedCredential, OpenOptions, QueryBootstrap, QueryService, StartupPhases};
use futures::FutureExt;
use nanosiem_lake_worker::part_ingest::cell::{trusted_from, HttpPartSigner};
use nanosiem_lake_worker::part_ingest::r2_put::R2PartStore;
use nanosiem_lake_worker::part_ingest::s3_store::S3Location;
use nanosiem_lake_worker::part_ingest::finding_outbox::{drain_pass_cached, retention_overdue_ms, DrainLogCache, DrainPass};
use nanosiem_lake_worker::part_ingest::finding_append::{FindingAppendRequest, FindingAppendResponse, FindingAppendTransport, submit_stream};
use nanosiem_lake_cell::contract::{Assignment, Role};
use nanosiem_lake_cell::child::TenantService;
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// detect[T]'s verified-cache ceiling and per-query share when it runs
/// rules (query[T] defaults to 8 GiB / 2 GiB; rules read short windows).
const DETECT_CACHE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const DETECT_CACHE_QUERY_BYTES: u64 = 512 * 1024 * 1024;
/// Rules look back minutes to an hour; prewarm only recent parts.
const DETECT_PREWARM_HOURS: u64 = 2;

/// The detect role's epoch-bound finding drain. Without `detect_runs_rules`
/// (the legacy 256 MiB role) this is the whole process: native reads and the
/// detection gate live in query[T], reached via the cell router, and keeping
/// this service alive gives the supervisor its heartbeat and shutdown path
/// without loading chDB. With it, [`DetectService`] adds the rule engine.
#[derive(Default)]
struct FindingDrainService {
    refresher: std::sync::OnceLock<Arc<CredentialRefresher>>,
    busy: AtomicBool,
    last_progress_ms: AtomicU64,
    /// Unpublished outbox rows at the last pass start (heartbeat `queue_depth`).
    backlog: AtomicU64,
    /// `created_at` unix ms of the oldest unpublished row; 0 = none. The
    /// heartbeat reports its live age, so a pass that hangs still ages it.
    oldest_pending_ms: AtomicI64,
    /// NAN-4610: `published_at` unix ms of the oldest delivered row still
    /// retained, from the last scheduled retention check; 0 = none retained
    /// or not yet checked. The heartbeat ages it, so a prune that stops
    /// deleting shows as a growing `retention_overdue_seconds`.
    oldest_retained_published_ms: AtomicI64,
    wake: tokio::sync::Notify,
    next_peer: AtomicU64,
    peers: tokio::sync::Mutex<std::collections::BTreeMap<u64, tokio::sync::oneshot::Sender<tokio::net::UnixStream>>>,
    /// Fresh bootstrap secrets for the drain loop's re-exchange (NAN-3017).
    secrets: std::sync::Mutex<Option<tokio::sync::mpsc::Sender<zeroize::Zeroizing<Vec<u8>>>>>,
}

impl FindingDrainService {
    async fn connect_ingest(&self, control: &nanosiem_lake_cell::child::ControlChannel) -> anyhow::Result<tokio::net::UnixStream> {
        let id = self.next_peer.fetch_add(1, Ordering::Relaxed) + 1;
        let (send, recv) = tokio::sync::oneshot::channel();
        self.peers.lock().await.insert(id, send);
        if let Err(error) = control.connect_ingest(id).await {
            self.peers.lock().await.remove(&id);
            return Err(error.into());
        }
        let result = tokio::time::timeout(std::time::Duration::from_secs(30), recv).await;
        self.peers.lock().await.remove(&id);
        Ok(result.context("ingest peer stream timed out")??)
    }
}

struct SupervisorFindingTransport<'a> {
    service: &'a FindingDrainService,
    control: &'a nanosiem_lake_cell::child::ControlChannel,
}

#[async_trait::async_trait]
impl FindingAppendTransport for SupervisorFindingTransport<'_> {
    async fn submit(&self, request: &FindingAppendRequest) -> anyhow::Result<FindingAppendResponse> {
        submit_stream(self.service.connect_ingest(self.control).await?, request).await
    }
}

#[async_trait::async_trait]
impl TenantService for FindingDrainService {
    async fn handle_rpc(self: Arc<Self>, _request_id: u64, _stream: tokio::net::UnixStream) {
        // The cell router never sends a request to this role. Closing a direct
        // stream fails closed if an old router tries to use the former route.
    }

    async fn peer_rpc(self: Arc<Self>, request_id: u64, stream: tokio::net::UnixStream) {
        if let Some(sender) = self.peers.lock().await.remove(&request_id) {
            let _ = sender.send(stream);
        } else {
            tracing::warn!(request_id, "unexpected ingest peer stream");
        }
    }

    async fn wake(self: Arc<Self>, reason: nanosiem_lake_cell::contract::WakeReason) {
        // A gate commit follows durable finding publication. Drain promptly
        // even when the ordinary poll is asleep and idle timeout is short.
        if reason == nanosiem_lake_cell::contract::WakeReason::Detection {
            self.busy.store(true, Ordering::Relaxed);
            self.wake.notify_one();
        }
    }

    async fn secrets(self: Arc<Self>, secret: zeroize::Zeroizing<Vec<u8>>) {
        let sender = self.secrets.lock().expect("secrets lock").clone();
        match sender {
            Some(sender) => { let _ = sender.send(secret).await; }
            None => tracing::warn!("fresh bootstrap secret arrived before the finding drain started"),
        }
    }

    fn heartbeat(&self) -> nanosiem_lake_cell::contract::Heartbeat {
        let backlog = self.backlog.load(Ordering::Relaxed);
        let oldest = self.oldest_pending_ms.load(Ordering::Relaxed);
        let now_ms = chrono::Utc::now().timestamp_millis();
        let age_s = if backlog > 0 && oldest > 0 {
            (now_ms - oldest).max(0) as f64 / 1000.0
        } else {
            0.0
        };
        let retained = self.oldest_retained_published_ms.load(Ordering::Relaxed);
        let overdue_s = retention_overdue_ms((retained != 0).then_some(retained), now_ms) as f64 / 1000.0;
        nanosiem_lake_cell::contract::Heartbeat {
            credential_refresh_at_risk: self.refresher.get().is_some_and(|refresh| refresh.at_risk()),
            busy: self.busy.load(Ordering::Relaxed),
            last_progress_unix_ms: self.last_progress_ms.load(Ordering::Relaxed),
            // detect: finding-outbox backlog and the age of its oldest row.
            queue_depth: backlog,
            lag_seconds: age_s,
            detail: (backlog > 0).then(|| format!("finding outbox: {backlog} pending, oldest {age_s:.0}s")),
            finding_outbox: Some(nanosiem_lake_cell::contract::FindingOutboxStatus {
                backlog, oldest_age_seconds: age_s, retention_overdue_seconds: overdue_s,
            }),
            ..Default::default()
        }
    }
}

/// product[T] (NAN-3148, cell `product_state_role`): the tenant's product
/// state builder. It opens the same engine as query[T] (under product's own
/// cgroup budget), never receives a routed request, and runs the single
/// [`Publisher`](nanosiem_lake_worker::part_query::product_publish::Publisher)
/// that builds and publishes the snapshots query[T] reads.
struct ProductService {
    query: Arc<QueryService>,
    status: Arc<nanosiem_lake_worker::part_query::product_publish::PublisherStatus>,
}

#[async_trait::async_trait]
impl TenantService for ProductService {
    async fn handle_rpc(self: Arc<Self>, _request_id: u64, _stream: tokio::net::UnixStream) {
        // The router never sends product[T] a request; a stray stream closes.
    }

    async fn wake(self: Arc<Self>, _reason: nanosiem_lake_cell::contract::WakeReason) {}

    async fn secrets(self: Arc<Self>, secret: zeroize::Zeroizing<Vec<u8>>) {
        self.query.clone().secrets(secret).await;
    }

    fn heartbeat(&self) -> nanosiem_lake_cell::contract::Heartbeat {
        let query = self.query.heartbeat();
        let pending = self.status.pending_demands.load(Ordering::Relaxed);
        let version = self.status.version.load(Ordering::Relaxed);
        nanosiem_lake_cell::contract::Heartbeat {
            credential_refresh_at_risk: query.credential_refresh_at_risk,
            busy: self.status.busy.load(Ordering::Relaxed),
            // Startup counts as progress; a stall is a missing heartbeat.
            last_progress_unix_ms: self.status.last_progress_ms.load(Ordering::Relaxed).max(query.last_progress_unix_ms),
            queue_depth: pending,
            detail: Some(format!("product state v{version}: {} cycles built, {} skipped, {} demands built, {pending} pending",
                self.status.cycles_built.load(Ordering::Relaxed), self.status.cycles_skipped.load(Ordering::Relaxed),
                self.status.demands_built.load(Ordering::Relaxed))),
            ..Default::default()
        }
    }
}

/// detect[T] with `detect_runs_rules`: rule searches, the detection gate and
/// prevalence run HERE, in detect's own chDB under detect's cgroup, so a
/// scheduled rule can neither slow nor kill analyst search in query[T] (and
/// analyst load cannot delay detections). The finding drain runs beside it.
struct DetectService {
    drain: Arc<FindingDrainService>,
    query: Arc<QueryService>,
}

#[async_trait::async_trait]
impl TenantService for DetectService {
    async fn handle_rpc(self: Arc<Self>, request_id: u64, stream: tokio::net::UnixStream) {
        self.query.clone().handle_rpc(request_id, stream).await;
    }

    async fn peer_rpc(self: Arc<Self>, request_id: u64, stream: tokio::net::UnixStream) {
        self.drain.clone().peer_rpc(request_id, stream).await;
    }

    async fn wake(self: Arc<Self>, reason: nanosiem_lake_cell::contract::WakeReason) {
        self.drain.clone().wake(reason).await;
        // The supervisor sends a Detection wake with every routed rule RPC;
        // each request already catches up the part log itself, so only the
        // other reasons (data arrival, prewarm) reach the engine.
        if reason != nanosiem_lake_cell::contract::WakeReason::Detection {
            self.query.clone().wake(reason).await;
        }
    }

    /// One detect exchange refreshes both halves: the drain loop re-exchanges
    /// and swaps the engine's read credentials with its own.
    async fn secrets(self: Arc<Self>, secret: zeroize::Zeroizing<Vec<u8>>) {
        self.drain.clone().secrets(secret).await;
    }

    fn heartbeat(&self) -> nanosiem_lake_cell::contract::Heartbeat {
        detect_heartbeat(self.drain.heartbeat(), self.query.heartbeat())
    }
}

/// detect[T]'s heartbeat with the rule engine: its `queue_depth` is the
/// engine's, and the drain's outbox facts travel in `finding_outbox`
/// (NAN-4610: before, they were dropped, so `finding_outbox_age` read 0 for
/// every rule-running tenant however stuck its drain was).
fn detect_heartbeat(drain: nanosiem_lake_cell::contract::Heartbeat, query: nanosiem_lake_cell::contract::Heartbeat)
    -> nanosiem_lake_cell::contract::Heartbeat {
    nanosiem_lake_cell::contract::Heartbeat {
        credential_refresh_at_risk: drain.credential_refresh_at_risk,
        busy: drain.busy || query.busy,
        last_progress_unix_ms: drain.last_progress_unix_ms.max(query.last_progress_unix_ms),
        queue_depth: query.queue_depth,
        finding_outbox: drain.finding_outbox,
        detail: drain.detail,
        ..Default::default()
    }
}

fn location(credential: &ExchangedCredential) -> S3Location {
    S3Location { endpoint: credential.endpoint.clone(), region: credential.region.clone(),
        bucket: credential.bucket.clone(), prefix: String::new(),
        access_key_id: credential.access_key_id.clone(), secret_access_key: credential.secret_access_key.clone(),
        session_token: Some(credential.session_token.clone()) }
}

/// The earliest expiry across the detect exchange's credentials. The
/// owner-sign bearer (600 s) is normally the earliest, so the shared schedule
/// re-exchanges at half of it (300 s), exactly as ingest[T] does.
fn detect_expiry(detect: &DetectBootstrap) -> anyhow::Result<chrono::DateTime<chrono::Utc>> {
    let mut expires = owner_bearer_expiry(&detect.owner_sign.expires_at, chrono::Utc::now());
    // The engine's read credentials (incl. an enrichment_reader) ride in the
    // same exchange; refresh before the earliest of them too.
    if let Some(query) = detect.query.expires_at {
        expires = expires.min(query);
    }
    expires = expires.min(chrono::DateTime::parse_from_rfc3339(&detect.finding_drain.expires_at)?.with_timezone(&chrono::Utc));
    for credential in [&detect.part, &detect.log] {
        let at = credential.expires_at.as_deref().context("detect storage credential has no expiry")?;
        expires = expires.min(chrono::DateTime::parse_from_rfc3339(at)?.with_timezone(&chrono::Utc));
    }
    Ok(expires)
}

/// A drain pass running this long logs a warning each interval.
const LONG_PASS_LOG: std::time::Duration = std::time::Duration::from_secs(60);
/// An idle drain (outbox empty) logs one summary per this interval.
const IDLE_LOG_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

#[derive(Default)]
struct IdleLog {
    passes: u64,
    since: Option<std::time::Instant>,
}

fn record_backlog(service: &FindingDrainService, report: &DrainPass) {
    // Rows acknowledged this pass leave the backlog now; the next pass
    // re-reads the exact count and oldest row.
    service.backlog.store(report.backlog.saturating_sub(report.committed as u64), Ordering::Relaxed);
    service.oldest_pending_ms.store(report.oldest_created_ms.unwrap_or(0), Ordering::Relaxed);
    // Only a pass that ran the scheduled check updates the retained age; a
    // failed check keeps the last reading (which keeps ageing).
    if let Some(retention) = report.retention {
        service.oldest_retained_published_ms
            .store(retention.oldest_retained_published_ms.unwrap_or(0), Ordering::Relaxed);
    }
}

/// Every pass that saw pending rows, claimed rows or skipped them logs one
/// line; empty passes (the 1 s idle poll) roll up into one line a minute.
fn log_pass(report: &DrainPass, elapsed_ms: u64, idle: &mut IdleLog) {
    let now_ms = chrono::Utc::now().timestamp_millis();
    if report.backlog == 0 && report.seen == 0 {
        idle.passes += 1;
        let since = *idle.since.get_or_insert_with(std::time::Instant::now);
        if since.elapsed() >= IDLE_LOG_EVERY {
            tracing::info!(passes = idle.passes, "finding drain idle: outbox empty");
            *idle = IdleLog::default();
        }
        return;
    }
    let oldest_age_s = report.oldest_age_ms(now_ms) / 1000;
    match report.skipped {
        Some(reason) => tracing::warn!(backlog = report.backlog, oldest_age_s, elapsed_ms, reason,
            "finding drain pass skipped"),
        None => tracing::info!(backlog = report.backlog, oldest_age_s, seen = report.seen,
            preexisting_receipts = report.preexisting_receipts, replay_checked = report.replay_checked,
            replayed = report.replayed, published = report.published, committed = report.committed, elapsed_ms,
            "finding drain pass"),
    }
}

/// Backoff after a failed drain pass. A failed pass rolls its outbox
/// transaction back, so the batch is retried whole; it never ends the process.
fn drain_backoff(failures: u32) -> std::time::Duration {
    std::time::Duration::from_secs(1u64 << failures.min(5)).min(std::time::Duration::from_secs(30))
}

/// Trusted-local drain shares the durable receipt/append protocol but has no
/// owner, storage exchange or hosted database principal.
async fn trusted_local_drain_loop(
    assignment: &Assignment,
    bootstrap: nanosiem_lake_worker::part_query::trusted_local_detect::TrustedLocalDetectBootstrap,
    service: &FindingDrainService,
    control: &nanosiem_lake_cell::child::ControlChannel,
) -> anyhow::Result<()> {
    use nanosiem_lake_worker::part_ingest::finding_outbox::drain_pass_trusted_local;
    use nanosiem_lake_worker::parts::part_log::LocalObjectStore;
    let signer = bootstrap.signer()?;
    let trusted = assignment.part_signing.as_ref().map(trusted_from).transpose()?
        .unwrap_or_else(|| signer.trusted());
    let store = LocalObjectStore::new(&assignment.parts_dir)?;
    let pool = PgPoolOptions::new().max_connections(1)
        .connect(bootstrap.database_url.as_str()).await
        .map_err(|_| anyhow::anyhow!("connect local finding drain failed"))?;
    let transport = SupervisorFindingTransport { service, control };
    // NAN-4718: drafts an earlier process left behind. In the background:
    // a legacy backlog is thousands of directories, and the first pass must
    // not wait for it (a live pass's scratch is locked, so the sweep skips it).
    drop(nanosiem_lake_worker::part_ingest::finding_outbox::spawn_stale_drain_draft_sweep(assignment.tmp_dir.clone()));
    let mut cache = DrainLogCache::default();
    let mut failures = 0u32;
    let mut idle = IdleLog::default();
    loop {
        service.busy.store(true, Ordering::Relaxed);
        let started = std::time::Instant::now();
        let observe = |backlog, oldest: Option<i64>| {
            service.backlog.store(backlog, Ordering::Relaxed);
            service.oldest_pending_ms.store(oldest.unwrap_or(0), Ordering::Relaxed);
        };
        let result = drain_pass_trusted_local(&pool, &store, &signer, &trusted,
            assignment.tenant.as_str(), bootstrap.writer_epoch, &transport,
            &assignment.tmp_dir, chrono::Utc::now().timestamp_millis(), &observe, &mut cache).await;
        service.busy.store(false, Ordering::Relaxed);
        let pause = match result {
            Ok(report) => {
                failures = 0;
                record_backlog(service, &report);
                service.last_progress_ms.store(chrono::Utc::now().timestamp_millis() as u64, Ordering::Relaxed);
                log_pass(&report, started.elapsed().as_millis() as u64, &mut idle);
                std::time::Duration::from_secs(1)
            }
            Err(error) => {
                let pause = drain_backoff(failures);
                failures = failures.saturating_add(1);
                tracing::error!(%error, failures, "local finding drain failed; outbox retained for retry");
                pause
            }
        };
        tokio::select! {
            _ = tokio::time::sleep(pause) => {},
            _ = service.wake.notified(), if failures == 0 => {},
        }
    }
}

/// `refresher` is built from [`detect_expiry`] by the caller, so the rule
/// engine's read authority (when detect runs rules) asks the same schedule
/// for a refresh; `query_swap` then receives each refreshed read credential.
#[allow(clippy::too_many_arguments)]
async fn drain_loop(assignment: &Assignment, detect: DetectBootstrap, service: &FindingDrainService,
    control: &nanosiem_lake_cell::child::ControlChannel, cell_id: &str, control_url: Option<&str>,
    refresher: Arc<CredentialRefresher>, query_swap: Option<Arc<QueryCredentialSwap>>) -> anyhow::Result<()> {
    let _ = service.refresher.set(refresher.clone());
    let signing = assignment.part_signing.as_ref().context("detect assignment has no signing config")?;
    let trusted = trusted_from(signing)?;
    let http_signer = Arc::new(HttpPartSigner::new(&signing.url, &detect.owner_sign.token, &signing.signer_key_id, trusted.clone(),
        signing.ca_file.as_deref())?);
    let store = R2PartStore::new_split_read(&location(&detect.part), &location(&detect.log),
        assignment.tenant.as_str(), &assignment.state_dir.join("spill"))?;
    let pool = std::sync::RwLock::new(PgPoolOptions::new().max_connections(1)
        .connect(&detect.finding_drain.database_url).await.context("connect tenant finding drain")?);
    // NAN-3017: `refresher` re-exchanges before the owner bearer (10 min),
    // the drain DB credential and the R2 keys expire, instead of exiting.
    // A 401 from the owner (bearer expired) re-exchanges now and retries once.
    let signer = RefreshingSigner::new(http_signer.clone(), refresher.clone());
    let (secret_tx, mut secret_rx) = tokio::sync::mpsc::channel(2);
    *service.secrets.lock().expect("secrets lock") = Some(secret_tx);
    let (generation, epoch) = (detect.assignment_generation, detect.writer_epoch);
    tracing::info!(generation, epoch, expires_at = %refresher.expires_at(), "detect finding drain started");
    // NAN-4718: drafts an earlier process left behind. In the background:
    // a legacy backlog is thousands of directories, and the first pass must
    // not wait for it (a live pass's scratch is locked, so the sweep skips it).
    drop(nanosiem_lake_worker::part_ingest::finding_outbox::spawn_stale_drain_draft_sweep(assignment.tmp_dir.clone()));
    let transport = SupervisorFindingTransport { service, control };

    // The schedule, the exchange that answers it and the drain run
    // CONCURRENTLY. Polling the first two only between drain passes let one
    // long pass (a first drain, a crash replay) outlive the 600 s owner
    // bearer: it signed with the startup bearer and got 401.
    let schedule = refresher.clone().run(control.clone());
    let refresh = async {
        let mut database_url = detect.finding_drain.database_url.clone();
        while let Some(secret) = secret_rx.recv().await {
            let fresh = resolve_detect_bootstrap(&secret, assignment.tenant.as_str(), cell_id, control_url).await;
            drop(secret);
            let fresh = match fresh {
                Ok(fresh) => fresh,
                Err(error) => {
                    let is_final = error.downcast_ref::<nanosiem_lake_worker::part_ingest::cell::ExchangeRefused>()
                        .is_some_and(nanosiem_lake_worker::part_ingest::cell::ExchangeRefused::is_final);
                    let retrying = refresher.failed(is_final);
                    tracing::warn!(error = %format!("{error:#}"), retrying, "detect credential refresh failed");
                    continue;
                }
            };
            anyhow::ensure!(fresh.assignment_generation == generation && fresh.writer_epoch == epoch,
                "detect assignment moved (generation {} epoch {}); restart required",
                fresh.assignment_generation, fresh.writer_epoch);
            let swapped: anyhow::Result<chrono::DateTime<chrono::Utc>> = async {
                let expires = detect_expiry(&fresh)?;
                if fresh.finding_drain.database_url != database_url {
                    let next = PgPoolOptions::new().max_connections(1)
                        .connect(&fresh.finding_drain.database_url).await.context("reconnect tenant finding drain")?;
                    *pool.write().expect("pool lock") = next;
                    database_url = fresh.finding_drain.database_url.clone();
                }
                store.replace_split_read(&location(&fresh.part), &location(&fresh.log))?;
                if let Some(swap) = &query_swap {
                    swap.apply(&fresh.query).context("swap the rule engine's read credentials")?;
                }
                http_signer.set_bearer(&fresh.owner_sign.token);
                http_signer.reload_ca_logged();
                Ok(expires)
            }.await;
            match swapped {
                Ok(expires) => {
                    refresher.refreshed(expires);
                    tracing::info!(expires_at = %expires, "detect credentials refreshed");
                }
                Err(error) => {
                    let retrying = refresher.failed(false);
                    tracing::warn!(error = %format!("{error:#}"), retrying, "detect credential swap failed");
                }
            }
        }
        Err::<(), _>(anyhow::anyhow!("detect refresh channel closed"))
    };
    let drain = async {
        let mut failures = 0u32;
        let mut idle = IdleLog::default();
        // NAN-3096: one incrementally advanced log view for the drain's life.
        let mut log_cache = DrainLogCache::default();
        loop {
            let (expired, given_up) = refresher.status();
            let mut pause = std::time::Duration::from_secs(1);
            if expired {
                // Signing with an expired bearer would 401: wait for the
                // refresh, but never silently.
                pause = std::time::Duration::from_secs(5);
                tracing::warn!(given_up, expires_at = %refresher.expires_at(),
                    "finding drain pass skipped: detect credentials expired; waiting for refresh");
            } else {
                service.busy.store(true, Ordering::Relaxed);
                let current = pool.read().expect("pool lock").clone();
                let started = std::time::Instant::now();
                let observe = |backlog: u64, oldest: Option<i64>| {
                    service.backlog.store(backlog, Ordering::Relaxed);
                    service.oldest_pending_ms.store(oldest.unwrap_or(0), Ordering::Relaxed);
                };
                let pass = drain_pass_cached(&current, &store, &signer, &trusted, assignment.tenant.as_str(),
                    epoch, &transport, &assignment.tmp_dir, chrono::Utc::now().timestamp_millis(), &observe,
                    &mut log_cache);
                tokio::pin!(pass);
                // A pass that runs long is visible while it runs, not only
                // when (if) it returns.
                let mut watchdog = tokio::time::interval_at(tokio::time::Instant::now() + LONG_PASS_LOG,
                    LONG_PASS_LOG);
                let result = loop {
                    tokio::select! {
                        result = &mut pass => break result,
                        _ = watchdog.tick() => tracing::warn!(elapsed_s = started.elapsed().as_secs(),
                            backlog = service.backlog.load(Ordering::Relaxed),
                            "finding drain pass still running"),
                    }
                };
                service.busy.store(false, Ordering::Relaxed);
                let elapsed_ms = started.elapsed().as_millis() as u64;
                match result {
                    Ok(report) => {
                        failures = 0;
                        record_backlog(service, &report);
                        service.last_progress_ms.store(chrono::Utc::now().timestamp_millis() as u64, Ordering::Relaxed);
                        log_pass(&report, elapsed_ms, &mut idle);
                    }
                    Err(error) => {
                        // Rows stay in the outbox; the next pass retries them.
                        pause = drain_backoff(failures);
                        failures = failures.saturating_add(1);
                        tracing::error!(error = %format!("{error:#}"), failures, elapsed_ms, retry_in_s = pause.as_secs(),
                            "tenant finding drain pass failed; retrying");
                    }
                }
            }
            tokio::select! {
                // The scheduler writes findings through Postgres, outside this child. Keep
                // the idle poll shorter than the signed finding visibility budget.
                _ = tokio::time::sleep(pause) => {},
                _ = service.wake.notified(), if failures == 0 => {},
            }
        }
    };
    tokio::select! {
        // Expired with refresh given up: exit so the supervisor respawns.
        result = schedule => { result?; anyhow::bail!("detect credential refresher stopped") }
        result = refresh => result,
        _ = drain => anyhow::bail!("finding drain stopped"),
    }
}

/// The query engine and its HTTP service over the tenant's verified part
/// log: query[T]'s whole job, and detect[T]'s rule engine when it runs rules.
/// `refresher` is the schedule the read authority asks when a read is
/// refused (query's own, or detect's shared drain schedule).
struct OpenedQuery {
    service: Arc<QueryService>,
    swap: Option<Arc<QueryCredentialSwap>>,
}

async fn open_query_service(assignment: &Assignment, mut bootstrap: QueryBootstrap, control_url: Option<&str>,
    refresher: Option<Arc<CredentialRefresher>>, phases: &mut StartupPhases,
    control: &nanosiem_lake_cell::child::ControlChannel) -> anyhow::Result<OpenedQuery> {
    let detect = assignment.role == Role::Detect;
    let product = assignment.role == Role::Product;
    if product {
        // Product state reads signed partials and the edge parts of each
        // window: a modest verified cache of its own (never query's).
        bootstrap.engine.cache_bytes = Some(bootstrap.engine.cache_bytes.unwrap_or(DETECT_CACHE_BYTES).min(DETECT_CACHE_BYTES));
    }
    if detect {
        // Rules read their lookback window (minutes to an hour) and signed
        // prevalence partials: a small verified cache and a short prewarm
        // keep detect's disk and startup within its own budget.
        bootstrap.engine.cache_bytes = Some(bootstrap.engine.cache_bytes.unwrap_or(DETECT_CACHE_BYTES).min(DETECT_CACHE_BYTES));
        bootstrap.engine.cache_query_bytes = Some(bootstrap.engine.cache_query_bytes.unwrap_or(DETECT_CACHE_QUERY_BYTES).min(DETECT_CACHE_QUERY_BYTES));
        bootstrap.engine.prewarm_hours = bootstrap.engine.prewarm_hours.min(DETECT_PREWARM_HOURS);
    }
    // The platform IOC view (on-demand indicator lookups) comes from the
    // supervisor-rendered mounts when the cell renders them; configure_cell
    // refuses a half-rendered pair. A cell without mounts serves without it.
    // Stored enrichment is never masked at read time (NAN-4168).
    if assignment.platform_bundle_file.is_some() || assignment.platform_bundle_dir.is_some() || assignment.platform_policy_file.is_some() {
        if let Err(error) = nanosiem_lake_worker::enrichment_read::configure_cell(assignment) {
            let _ = control.fatal(&format!("platform assignment: {error:#}")).await;
            return Err(error);
        }
    }
    let r2 = match &bootstrap.r2 {
        Some(credentials) => Some(R2ReadAuthority::new(bootstrap.bucket.clone(), r2_operator(&bootstrap.bucket, credentials)?, refresher.clone())),
        None => None,
    };
    let options = OpenOptions {
        bootstrap,
        r2: r2.clone(),
        parts_dir: Some(assignment.parts_dir.clone()),
        state_dir: assignment.state_dir.clone(),
        // detect[T] sizes its engine below its role limit (see
        // `memory_budget::DETECT_ENGINE_RESERVE_BYTES`); the smaller of this
        // and memory.max wins in `QueryMemoryBudget::derive`.
        memory_cap_bytes: if detect {
            nanosiem_lake_worker::part_query::memory_budget::detect_engine_cap(assignment.memory_cap_bytes)
        } else {
            assignment.memory_cap_bytes
        },
        cpu_millis: assignment.cpu_millis,
        size_classes: !detect && !product,
    };
    tracing::info!(role = assignment.role.as_str(), "query startup: identity and IOC begin");
    let identity_snapshot = load_identity_snapshot(&options.bootstrap, &options.state_dir)?;
    let ioc_store = open_ioc_store(&options.bootstrap)?;
    // NAN-3042: durable job results go to R2 through the exchanged
    // `job_results` grant only; without it jobs fail typed (503). Detect
    // never runs durable jobs (the query-scope job runner reaches query[T]).
    let job_results = if !detect && !product {
        if let Some(location) = &options.bootstrap.trusted_local_job_results {
            if assignment.control_url.is_some() || options.bootstrap.job_results_r2.is_some() {
                anyhow::bail!("trusted-local result storage cannot be used with hosted control");
            }
            Some(JobResultStore::new_trusted_local(assignment.tenant.as_str(), location)?)
        } else { Some(JobResultStore::new(assignment.tenant.as_str(), refresher.clone())) }
    } else { None };
    if let Some(job_results) = &job_results {
        match &options.bootstrap.job_results_r2 {
            Some(credentials) => job_results.install(Some(job_results.operator_for(credentials)?)),
            None if job_results.is_granted() => {},
            None => tracing::warn!("credential exchange carried no job_results grant; durable search jobs are unavailable"),
        }
    }
    phases.lap("identity_and_ioc");
    tracing::info!(role = assignment.role.as_str(), "query startup: engine open begin");
    let (engine, gate) = match open_engine_timed(&options, phases).await.context("open part query engine") {
        Ok(opened) => opened,
        Err(error) => {
            let _ = control.fatal(&format!("{error:#}")).await;
            return Err(error);
        }
    };
    let compiler_sha256 = compiler_sha256(&options.bootstrap.engine.compiler, &options.state_dir)?;
    phases.lap("compiler_digest");
    let native_artifact_sha256 = options.bootstrap.engine.chdb_sha256.clone();
    let prewarm_hours = options.bootstrap.engine.prewarm_hours;
    // NAN-3004: a zero-downtime pod warming behind the serving one gates
    // its first readiness on the prewarm (the supervisor asks for it).
    let prewarm_gates_readiness = options.bootstrap.engine.prewarm_gates_readiness || assignment.query_prewarm_before_ready;
    let service: Arc<QueryService> = QueryService::new(
        engine, gate, assignment.state_dir.clone(), compiler_sha256, native_artifact_sha256, identity_snapshot, prewarm_hours,
        ioc_store.clone().map(|store| store as Arc<dyn nanosiem_lake_worker::parts::part_log::ObjectStore>),
    );
    // NAN-3148: product state is built by product[T] when the cell runs it;
    // query[T] then only reads the published snapshots.
    // NAN-3799: the supervisor names the published dir (on the persistent
    // hot volume when the cell has one); older supervisors leave it unset.
    let product_dir = assignment.product_dir.clone()
        .unwrap_or_else(|| assignment.tenant_dir.join(Role::Product.as_str()));
    if product {
        service.enable_product_state_publisher(product_dir)?;
    } else if assignment.role == Role::Query && assignment.product_state_role {
        service.enable_product_state_consumer(product_dir)?;
        tracing::info!("product state is built by product[T]; query reads published snapshots only");
    } else if !detect {
        service.enable_product_state_maintenance();
    }
    if detect {
        // A rule is background work: it waits for a native slot longer
        // than an analyst would, instead of failing its window with a 429.
        service.set_admission_deadline(DETECT_ADMISSION_DEADLINE);
        // NAN-4772: no analyst reaches detect[T]; its rules use every slot.
        service.engine().serve_without_analysts();
    }
    if let Some(job_results) = &job_results {
        service.attach_job_results(job_results.clone())?;
    }
    let swap = refresher.as_ref().map(|refresher| Arc::new(QueryCredentialSwap {
        tenant_id: assignment.tenant.as_str().to_string(),
        cell_id: assignment.cell_id.clone(),
        control_url: control_url.map(str::to_string),
        role: assignment.role,
        bucket: options.bootstrap.bucket.clone(),
        r2,
        ioc: ioc_store,
        job_results,
        refresher: refresher.clone(),
    }));
    // Prove already-live cell-local files in the background (NAN-2989:
    // ready at once unless the bootstrap asks to gate on the prewarm).
    if product {
        // No search is served here: nothing to prove ahead of a request
        // (each build proves the files it reads).
        service.mark_ready_without_prewarm();
    } else if prewarm_gates_readiness {
        service.clone().spawn_prewarm();
    } else {
        service.clone().start_ready_with_background_prewarm();
    }
    // NAN-3392: query[T] keeps its part-log view caught up in the
    // background instead of a catch-up GET on every request.
    if !detect && !product {
        service.clone().spawn_log_refresher();
    }
    // NAN-3058: query[T] backfills the identity observation index of the
    // parts that predate the flag; detect never serves identity.
    if assignment.identity_observations && !detect && !product {
        service.clone().spawn_identity_backfill();
    }
    // NAN-4190: query[T] keeps the window entity index (NAN-4772: always).
    if !detect && !product {
        service.clone().spawn_entity_index();
    }
    phases.lap("service_ready");
    phases.log(assignment.tenant.as_str());
    Ok(OpenedQuery { service, swap })
}

/// Stack of every query runtime thread (workers and blocking pool), NAN-3141.
const QUERY_THREAD_STACK_BYTES: usize = 16 * 1024 * 1024;

fn main() -> anyhow::Result<()> {
    // FIRST: before any runtime, thread, or tenant I/O.
    let boot = nanosiem_lake_cell::child::bootstrap_with_native_init(|assignment| {
        nanosiem_lake_worker::cgroup_memory::prepare(assignment.jail.cgroup_dir.as_deref());
        if matches!(assignment.role, Role::Query | Role::Product) || (assignment.role == Role::Detect && assignment.detect_runs_rules) {
            nanosiem_lake_worker::native::initialize_cell_runtime()?;
        }
        Ok(())
    })?;
    nanosiem_lake_worker::process_limits::initialize()?;
    nanosiem_lake_worker::cell_logging::init_child_tracing();
    nanosiem_lake_worker::cgroup_memory::initialize(boot.assignment.jail.cgroup_dir.as_deref());
    let threads = usize::try_from((boot.assignment.cpu_millis / 1000).clamp(1, 4)).unwrap_or(1) + 1;
    tokio::runtime::Builder::new_multi_thread()
        .on_thread_start(|| {
            if let Err(error) = nanosiem_lake_cell::crash_capture::register_thread() {
                eprintln!("lake_native_crash alternate stack registration failed: {error}");
            }
        })
        .worker_threads(threads)
        // NAN-3141: request futures are polled on these threads (and search
        // jobs `block_on` the blocking pool, which shares this size). The
        // 2 MiB default turned a ~1 MiB `query` future (a ~2.3 MiB poll
        // frame) into a SIGSEGV on the guard page; with 16 MiB of reserved,
        // lazily committed stack a future regression of that kind costs
        // memory, not availability. The size budget itself is enforced by
        // `part_query::{server,engine}::future_size_tests`.
        .thread_stack_size(QUERY_THREAD_STACK_BYTES)
        .enable_all()
        .build()?
        .block_on(async move {
            let mut phases = StartupPhases::default();
            let (assignment, secret, control) = boot.into_async()?;
            // NAN-3492: the tenant's rarity threshold for requests that
            // carry none (stored tenant value, else 3).
            nanosiem_lake_worker::prevalence::bind_tenant_rarity_threshold(
                nanosiem_lake_worker::prevalence::assignment_rarity_threshold(&assignment),
            );
            if !matches!(assignment.role, Role::Query | Role::Detect | Role::Product) {
                anyhow::bail!("lake_part_query was assigned a non-query role");
            }
            // `control_url` joins the assignment with the cell credential
            // exchange; read it through serde so this binary works with
            // supervisors that predate the field (dev cells need none).
            let control_url = serde_json::to_value(&assignment)
                .ok()
                .and_then(|value| value.get("control_url").and_then(|url| url.as_str().map(str::to_string)));
            if assignment.role == Role::Detect && control_url.is_none() {
                use nanosiem_lake_worker::part_query::trusted_local_detect::TrustedLocalDetectBootstrap;
                let local = TrustedLocalDetectBootstrap::parse(&secret, assignment.tenant.as_str(), None)?;
                drop(secret);
                let drain = Arc::new(FindingDrainService::default());
                let serve = if assignment.detect_runs_rules {
                    let opened = open_query_service(&assignment, local.query.clone(), None, None, &mut phases, &control).await?;
                    nanosiem_lake_cell::child::run_service(
                        Arc::new(DetectService { drain: drain.clone(), query: opened.service }), control.clone()).boxed()
                } else {
                    nanosiem_lake_cell::child::run_service(drain.clone(), control.clone()).boxed()
                };
                tokio::select! {
                    result = serve => result,
                    result = trusted_local_drain_loop(&assignment, local, &drain, &control) => result,
                }?;
                return Ok(());
            }
            tracing::info!(role = assignment.role.as_str(), "query startup: credential exchange begin");
            let (bootstrap, detect) = if assignment.role == Role::Detect {
                match resolve_detect_bootstrap(&secret, assignment.tenant.as_str(), &assignment.cell_id, control_url.as_deref()).await {
                    Ok(detect) => (Ok(detect.query.clone()), Some(detect)),
                    Err(error) => (Err(error), None),
                }
            } else {
                (resolve_bootstrap(&secret, assignment.tenant.as_str(), &assignment.cell_id, control_url.as_deref(), assignment.role).await, None)
            };
            drop(secret);
            phases.lap("credential_exchange");
            tracing::info!(role = assignment.role.as_str(), "query startup: credential exchange complete");
            let bootstrap = match bootstrap {
                Ok(bootstrap) => bootstrap,
                Err(error) => {
                    let _ = control.fatal(&format!("bootstrap: {error:#}")).await;
                    return Err(error);
                }
            };
            if let Some(detect) = detect {
                // The detect exchange is fully checked (tenant, epoch, writer
                // credentials and trusted owner authority) above. Its read
                // credential opens the rule engine only when the supervisor
                // sized this role for it (`detect_runs_rules`).
                let drain = Arc::new(FindingDrainService::default());
                let refresher = match detect_expiry(&detect) {
                    Ok(expires) => CredentialRefresher::new(expires),
                    Err(error) => {
                        let _ = control.fatal(&format!("detect credential expiry: {error:#}")).await;
                        return Err(error);
                    }
                };
                let (serve, query_swap) = if assignment.detect_runs_rules {
                    let opened = open_query_service(&assignment, bootstrap, control_url.as_deref(), Some(refresher.clone()), &mut phases, &control).await?;
                    tracing::info!(memory_cap_bytes = assignment.memory_cap_bytes, cpu_millis = assignment.cpu_millis,
                        "detect runs rule searches in its own engine");
                    let service = Arc::new(DetectService { drain: drain.clone(), query: opened.service });
                    (nanosiem_lake_cell::child::run_service(service, control.clone()).boxed(), opened.swap)
                } else {
                    drop(bootstrap);
                    (nanosiem_lake_cell::child::run_service(drain.clone(), control.clone()).boxed(), None)
                };
                tokio::select! {
                    result = serve => result,
                    result = drain_loop(&assignment, detect, &drain, &control, &assignment.cell_id, control_url.as_deref(), refresher, query_swap) => {
                        if let Err(error) = &result { let _ = control.fatal(&format!("finding drain: {error:#}")).await; }
                        result
                    },
                }?;
                return Ok(());
            }
            // NAN-3017: the read credential expires (6 h); query is resident,
            // so it re-exchanges on the shared schedule and swaps in place.
            let refresher = bootstrap.expires_at.map(CredentialRefresher::new);
            let opened = open_query_service(&assignment, bootstrap, control_url.as_deref(), refresher.clone(), &mut phases, &control).await?;
            if let Some(swap) = opened.swap {
                opened.service.attach_credentials(swap)?;
            }
            let service = opened.service;
            if assignment.role == Role::Product {
                // NAN-3720: product[T] is background work; it never wins a
                // core over search, also where it shares one.
                let product_nice = nanosiem_lake_worker::part_query::product_publish::ROLE_NICE;
                match nanosiem_lake_worker::part_query::product_publish::lower_process_priority(product_nice) {
                    Ok(threads) => tracing::info!(threads, nice = product_nice, "product state builder runs at background priority"),
                    Err(error) => tracing::warn!(%error, "product state builder priority not lowered"),
                }
                let status = Arc::new(nanosiem_lake_worker::part_query::product_publish::PublisherStatus::default());
                let publisher = match nanosiem_lake_worker::part_query::product_publish::Publisher::new(service.engine_arc(), status.clone()) {
                    Ok(publisher) => publisher,
                    Err(error) => {
                        let _ = control.fatal(&format!("product publisher: {error:#}")).await;
                        return Err(error);
                    }
                };
                tracing::info!(memory_cap_bytes = assignment.memory_cap_bytes, cpu_millis = assignment.cpu_millis,
                    version = publisher.manifest().version, "product state builder started");
                let product = Arc::new(ProductService { query: service, status });
                let refresh = async {
                    match refresher {
                        Some(refresher) => refresher.run(control.clone()).await
                            .and_then(|()| Err::<(), _>(anyhow::anyhow!("product credential refresher stopped"))),
                        None => std::future::pending().await,
                    }
                };
                return tokio::select! {
                    result = nanosiem_lake_cell::child::run_service(product, control.clone()) => result,
                    _ = publisher.run() => Err(anyhow::anyhow!("product publisher stopped")),
                    result = refresh => {
                        let error = result.err().unwrap_or_else(|| anyhow::anyhow!("product credential refresher stopped"));
                        let _ = control.fatal(&format!("{error:#}")).await;
                        Err(error)
                    }
                };
            }
            match refresher {
                Some(refresher) => tokio::select! {
                    result = nanosiem_lake_cell::child::run_service(service, control.clone()) => result,
                    // Expired with refresh given up: exit so the supervisor
                    // respawns with a fresh bootstrap.
                    result = refresher.run(control.clone()) => {
                        let error = result.err().unwrap_or_else(|| anyhow::anyhow!("query credential refresher stopped"));
                        let _ = control.fatal(&format!("{error:#}")).await;
                        Err(error)
                    }
                },
                None => nanosiem_lake_cell::child::run_service(service, control).await,
            }
        })?;
    // Skip atexit handlers: chDB's static destructors are not exit-safe (the
    // reader never unloads it either). Every lease/state file is already
    // durable or disposable at this point.
    // SAFETY: `_exit` terminates the process without running destructors.
    unsafe { libc::_exit(0) }
}

#[cfg(test)]
mod refresh_health_tests {
    use super::*;

    #[test]
    fn detect_heartbeat_reports_credential_risk_until_replacement_arrives() {
        let service = FindingDrainService::default();
        assert!(!service.heartbeat().credential_refresh_at_risk);
        let refresher = CredentialRefresher::new(chrono::Utc::now() - chrono::Duration::seconds(1));
        assert!(service.refresher.set(refresher.clone()).is_ok());
        // Independent of finding-drain progress or backlog: idle detect must
        // also expose a lost refresh on the supervisor's metrics endpoint.
        assert!(service.heartbeat().credential_refresh_at_risk);
        refresher.refreshed(chrono::Utc::now() + chrono::Duration::seconds(600));
        assert!(!service.heartbeat().credential_refresh_at_risk);
    }

    /// NAN-4610: the drain's outbox facts reach the supervisor for both
    /// detect shapes (drain-only and with the rule engine), including how
    /// far delivered rows have outlived retention.
    #[test]
    fn detect_heartbeat_carries_the_drain_outbox_facts() {
        use nanosiem_lake_worker::part_ingest::finding_outbox::RetentionCheck;
        let service = FindingDrainService::default();
        let now = chrono::Utc::now().timestamp_millis();
        let fresh = service.heartbeat().finding_outbox.unwrap();
        assert_eq!((fresh.backlog, fresh.oldest_age_seconds, fresh.retention_overdue_seconds), (0, 0.0, 0.0));
        let report = DrainPass {
            backlog: 1_200, committed: 200, oldest_created_ms: Some(now - 700_000),
            retention: Some(RetentionCheck { oldest_retained_published_ms: Some(now - 10 * 86_400_000) }),
            ..DrainPass::default()
        };
        record_backlog(&service, &report);
        let drain = service.heartbeat();
        let outbox = drain.finding_outbox.unwrap();
        assert_eq!(outbox.backlog, 1_000);
        assert!(outbox.oldest_age_seconds >= 700.0, "{outbox:?}");
        // 10 days published against the 7-day window (NAN-4668) = 3 days overdue.
        assert!((3.0 * 86_400.0..3.0 * 86_400.0 + 60.0).contains(&outbox.retention_overdue_seconds), "{outbox:?}");
        // A pass without a retention check keeps the last reading.
        record_backlog(&service, &DrainPass::default());
        assert!(service.heartbeat().finding_outbox.unwrap().retention_overdue_seconds >= 3.0 * 86_400.0);
        // Healthy: the oldest delivered row is inside the window.
        record_backlog(&service, &DrainPass { retention: Some(RetentionCheck { oldest_retained_published_ms: Some(now - 86_400_000) }),
            ..DrainPass::default() });
        assert_eq!(service.heartbeat().finding_outbox.unwrap().retention_overdue_seconds, 0.0);

        // With the rule engine: queue_depth is the engine's, the outbox block the drain's.
        record_backlog(&service, &report);
        let query = nanosiem_lake_cell::contract::Heartbeat { queue_depth: 3, busy: true, ..Default::default() };
        let detect = detect_heartbeat(service.heartbeat(), query);
        assert_eq!(detect.queue_depth, 3);
        let view = detect.finding_outbox_view();
        assert_eq!(view.backlog, 1_000);
        assert!(view.oldest_age_seconds >= 700.0 && view.retention_overdue_seconds >= 86_400.0, "{view:?}");
        assert!(detect.detail.as_deref().is_some_and(|d| d.contains("1000 pending")), "{detect:?}");
    }
}
