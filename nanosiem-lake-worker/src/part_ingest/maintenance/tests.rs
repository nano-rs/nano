// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn max_l0_reads_every_tree() {
    let manifest = serde_json::json!({"id": 3, "core": {"l0": [1, 2, 3], "trees": [{"l0": [1]}, {"l0": [1, 2, 3, 4, 5]}]}});
    assert_eq!(max_l0(&manifest), 5);
    assert_eq!(max_l0(&serde_json::json!({"l0": []})), 0);
}

fn assignment() -> Assignment {
    serde_json::from_value(serde_json::json!({
        "tenant": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "role": "maintenance", "cell_id": "c1",
        "tenant_dir": "/t", "parts_dir": "/t/parts", "state_dir": "/t/maintenance", "tmp_dir": "/t/maintenance/tmp",
        "memory_cap_bytes": 536870912, "cpu_millis": 250, "eps": 20.0,
        "jail": {"uid": 1, "gid": 1, "rw_paths": [], "ro_paths": [], "system_ro_paths": [], "tcp_connect_ports": [],
            "cgroup_dir": null, "require_landlock": false, "max_processes": null, "max_open_files": 64}
    })).unwrap()
}

fn response() -> serde_json::Value {
    let tenant = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
    serde_json::json!({
        "schema_version": 1, "tenant_id": tenant, "role": "maintenance", "writer_epoch": 3,
        "credentials": [{"credential_class": "lake_prevalence_state", "endpoint": "https://r2.example", "region": "auto",
            "bucket": format!("nano-shared-r2-{tenant}"), "permission": "object-read-only",
            "prefixes": [format!("lake/prevalence-state/v1/tenant={tenant}/")],
            "access_key_id": "k", "secret_access_key": "s", "session_token": "t",
            "expires_at": (chrono::Utc::now() + chrono::Duration::seconds(600)).to_rfc3339()}],
        "prevalence_owner": {"url": "https://owner.example/v1/prevalence-state/mutate", "bearer": "maint",
            "tenant_id": tenant, "assignment_generation": 2, "writer_epoch": 3}
    })
}

/// The platform response shape is accepted; anything more (or less)
/// than the read-only state credential plus the maintenance bearer is not.
#[test]
fn maintenance_exchange_accepts_exactly_the_contract_shape() {
    let parse = |value: serde_json::Value| grant_from(serde_json::from_value(value).unwrap(), &assignment());
    let grant = parse(response()).unwrap();
    assert_eq!(grant.access.read.prefix, "lake/prevalence-state/v1/tenant=aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/");
    assert_eq!(grant.access.owner.bearer, "maint");
    assert!(grant.expires_at <= chrono::Utc::now() + chrono::Duration::seconds(600));
    let mut extra = response();
    extra["owner_sign"] = serde_json::json!({"token": "x", "audience": "owner", "scope": "lake-parts:sign"});
    assert!(parse(extra).is_err(), "an owner-sign bearer is refused");
    let mut two = response();
    let copy = two["credentials"][0].clone();
    two["credentials"].as_array_mut().unwrap().push(copy);
    assert!(parse(two).is_err(), "exactly one credential");
    let mut write = response();
    write["credentials"][0]["permission"] = serde_json::json!("object-read-write");
    assert!(parse(write).is_err(), "read-only only");
    let mut other = response();
    other["prevalence_owner"]["tenant_id"] = serde_json::json!("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    assert!(parse(other).is_err(), "owner bound to this tenant");
    let mut epoch = response();
    epoch["writer_epoch"] = serde_json::json!(4);
    assert!(parse(epoch).is_err(), "owner epoch matches the exchange");
    let mut role = response();
    role["role"] = serde_json::json!("ingest");
    assert!(parse(role).is_err(), "role binding");
    let mut missing = response();
    missing.as_object_mut().unwrap().remove("prevalence_owner");
    assert!(parse(missing).is_err(), "the maintenance bearer is required");
}

#[test]
fn compactor_outputs_stay_under_the_owner_route_budget() {
    let options = compactor_options();
    let worker = options.worker.expect("worker options");
    assert_eq!(worker.max_sst_size, 64 * 1024 * 1024, "each owner POST stays well within the owner's 30 s");
    assert_eq!((options.max_concurrent_compactions, worker.max_subcompactions, worker.max_fetch_tasks), (1, 1, 2));
}

/// cell26 (2026-09-30): maintenance[T] crash-looped on "owner request
/// journal must be private": its journal directory was created under the
/// umask (0755) before the owner store checked it. The journal is now made
/// 0700 explicitly, also when an earlier run left it looser, and the
/// owner store accepts it.
#[test]
fn the_maintenance_journal_is_private_whatever_the_umask_left() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("maintenance");
    // An earlier run (or a create_dir_all under umask 022) left it 0755.
    std::fs::create_dir_all(state.join("owner-pending")).unwrap();
    std::fs::set_permissions(state.join("owner-pending"), std::fs::Permissions::from_mode(0o755)).unwrap();
    let journal = private_journal(&state).unwrap();
    assert_eq!(std::fs::metadata(&journal).unwrap().permissions().mode() & 0o777, 0o700);
    let mut grant = grant_from(serde_json::from_value(response()).unwrap(), &assignment()).unwrap();
    grant.access.owner.url = "http://127.0.0.1:1/v1/prevalence-state/mutate".into();
    let store = super::super::prevalence_owner_store::OwnerStore::new_maintenance(
        Arc::new(slatedb::object_store::memory::InMemory::new()), grant.access, &journal);
    assert!(store.is_ok(), "{:?}", store.err());
    // A fresh state dir works too.
    let fresh = private_journal(&dir.path().join("fresh")).unwrap();
    assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o700);
}

#[test]
fn the_bearer_expiry_is_used_when_the_exchange_states_it() {
    let mut value = response();
    let soon = chrono::Utc::now() + chrono::Duration::seconds(120);
    value["prevalence_owner"]["expires_at"] = serde_json::json!(soon.to_rfc3339());
    let grant = grant_from(serde_json::from_value(value).unwrap(), &assignment()).unwrap();
    assert!(grant.expires_at <= soon + chrono::Duration::seconds(1));
}

/// Production timing, scaled to milliseconds (the compactor backoff cap is
/// a sizeable part of the lifetime, the read timeout far below it).
const FAST: LoopTiming = LoopTiming {
    min_request_interval: Duration::from_millis(40),
    answer_timeout: Duration::from_millis(60),
    exchange_timeout: Duration::from_millis(20),
    refresh_backoff_base: Duration::from_millis(20),
    refresh_backoff_max: Duration::from_millis(80),
    poll: Duration::from_millis(75),
    read_timeout: Duration::from_millis(50),
    backoff_base: Duration::from_millis(12),
    backoff_max: Duration::from_millis(300),
};
const LIFETIME: chrono::Duration = chrono::Duration::milliseconds(1_000);

/// A loop double: refreshes mint a LIFETIME grant; the manifest read either
/// never returns (an expired credential under slatedb's unbounded 403
/// retries) or finds no manifest; the compactor stops at once (no DB yet).
struct FakeLoop {
    stats: LoopStats,
    hang_reads: bool,
    /// (refreshed at, the expiry of the grant it replaced)
    refreshes: std::sync::Mutex<Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)>>,
    fatal: std::sync::Mutex<Option<String>>,
    reads_started: AtomicU64,
}

impl FakeLoop {
    fn new(hang_reads: bool) -> Self {
        let now = chrono::Utc::now();
        Self {
            stats: LoopStats::new(now, now + LIFETIME),
            hang_reads,
            refreshes: Default::default(),
            fatal: Default::default(),
            reads_started: AtomicU64::new(0),
        }
    }

    /// Run the loop for `run`; it must neither exit nor let a grant lapse.
    async fn run_for(&self, run: Duration) {
        let outcome = tokio::time::timeout(run, drive(self, FAST)).await;
        assert!(outcome.is_err(), "the loop exited: {outcome:?} fatal={:?}", self.fatal.lock().unwrap());
        let refreshes = self.refreshes.lock().unwrap();
        // 2.5 s of 1 s grants refreshed at half their lifetime: at least three refreshes.
        assert!(refreshes.len() >= 3, "only {} refreshes", refreshes.len());
        for (at, expired) in refreshes.iter() {
            assert!(at < expired, "refreshed at {at} after the grant expired at {expired}");
        }
        assert!(self.stats.expires_at() > chrono::Utc::now(), "the current grant has lapsed");
    }
}

#[async_trait]
impl LoopOps for FakeLoop {
    fn stats(&self) -> &LoopStats {
        &self.stats
    }

    async fn refresh(&self) -> Result<(), RefreshError> {
        let now = chrono::Utc::now();
        self.refreshes.lock().unwrap().push((now, self.stats.expires_at()));
        self.stats.set_grant(now, now + LIFETIME);
        Ok(())
    }

    async fn fatal(&self, message: &str) {
        *self.fatal.lock().unwrap() = Some(message.to_owned());
    }

    async fn read_l0(&self) -> Result<Option<usize>> {
        self.reads_started.fetch_add(1, Ordering::Relaxed);
        if self.hang_reads {
            std::future::pending::<()>().await;
        }
        Ok(None)
    }

    fn spawn_compactor(&self) -> tokio::task::JoinHandle<Result<()>> {
        tokio::spawn(async { bail!("no manifest") })
    }
}

/// NAN-3129: with an expired read credential, slatedb's manifest read
/// retries 403 forever. The read is abandoned at its timeout, polls keep
/// going, and every refresh still lands before the grant expires.
#[tokio::test]
async fn a_hung_manifest_read_never_starves_the_refresh() {
    let ops = FakeLoop::new(true);
    let progress_at_start = ops.stats.last_progress_ms.load(Ordering::Relaxed);
    ops.run_for(Duration::from_millis(2_500)).await;
    assert!(ops.reads_started.load(Ordering::Relaxed) >= 10, "each hung read is abandoned and the next poll runs");
    assert_eq!(ops.stats.l0.load(Ordering::Relaxed), -1, "no read ever completed");
    // Progress moves only with refreshes here, never on a hung read.
    let last_refresh = ops.refreshes.lock().unwrap().last().unwrap().0.timestamp_millis() as u64;
    let progress = ops.stats.last_progress_ms.load(Ordering::Relaxed);
    assert!(progress > progress_at_start && progress >= last_refresh);
}

/// NAN-3129: a tenant with no prevalence DB yet: the compactor stops every
/// time and the restart backoff sits at its cap (a third of the lifetime). The
/// backoff is a deadline, not a sleep, so the credential never lapses.
#[tokio::test]
async fn a_no_manifest_tenant_keeps_its_credential_through_compactor_backoff() {
    let ops = FakeLoop::new(false);
    ops.run_for(Duration::from_millis(2_500)).await;
    assert!(ops.stats.compactor_restarts.load(Ordering::Relaxed) >= 3, "the compactor is restarted with backoff");
    assert_eq!(ops.stats.l0.load(Ordering::Relaxed), -1);
    assert!(ops.stats.last_error.lock().unwrap().as_deref().is_some_and(|e| e.contains("no manifest")));
}

#[test]
fn backoff_doubles_to_its_cap() {
    assert_eq!(TIMING.backoff(1), Duration::from_secs(10));
    assert_eq!(TIMING.backoff(4), Duration::from_secs(80));
    assert_eq!(TIMING.backoff(5), Duration::from_secs(120));
    assert_eq!(TIMING.backoff(40), Duration::from_secs(120));
}

#[test]
fn refresh_is_at_risk_only_in_the_final_tenth() {
    let issued = chrono::Utc::now();
    let stats = LoopStats::new(issued, issued + chrono::Duration::seconds(600));
    assert!(!stats.refresh_at_risk(issued + chrono::Duration::seconds(479)));
    assert!(!stats.refresh_at_risk(issued + chrono::Duration::seconds(539)));
    assert!(stats.refresh_at_risk(issued + chrono::Duration::seconds(540)));
    assert!(stats.refresh_at_risk(issued + chrono::Duration::seconds(700)));
}

#[test]
fn idle_prevalence_compaction_keeps_active_limits_and_heartbeat_cadence() {
    let options = super::compactor_options();
    let defaults = slatedb::config::CompactorOptions::default();
    assert_eq!(options.poll_interval, std::time::Duration::from_secs(1));
    assert_eq!(options.idle_poll_interval, Some(std::time::Duration::from_secs(60)));
    assert_eq!(options.worker_heartbeat_timeout, defaults.worker_heartbeat_timeout);
    let worker = options.worker.unwrap();
    let default_worker = slatedb::config::CompactionWorkerOptions::default();
    assert_eq!(worker.idle_compactions_poll_interval, Some(std::time::Duration::from_secs(60)));
    assert_eq!(worker.compactions_poll_interval, default_worker.compactions_poll_interval);
    assert_eq!(worker.heartbeat_interval, default_worker.heartbeat_interval);
    assert_eq!(worker.max_concurrent_compactions, 1);
    assert_eq!(worker.max_sst_size, super::MAX_COMPACTED_SST_BYTES);
}

/// The production constants agree with the supervisor and the shared
/// refresh module: a retry is never asked inside the mint interval, and a
/// request the supervisor deferred is still answered within the wait.
#[test]
fn production_refresh_timing_cooperates_with_the_supervisor() {
    assert_eq!(TIMING.min_request_interval, nanosiem_lake_cell::supervisor::REFRESH_MIN_INTERVAL);
    assert_eq!(TIMING.min_request_interval.as_secs() as i64, crate::cell_refresh::SUPERVISOR_REFRESH_MIN_INTERVAL.num_seconds());
    assert!(TIMING.answer_timeout > TIMING.min_request_interval, "a deferred answer arrives inside the wait");
    assert_eq!(TIMING.answer_timeout.as_secs() as i64, super::super::cell::REFRESH_ANSWER_TIMEOUT.num_seconds());
    for attempt in 1..20 {
        let delay = TIMING.refresh_retry(attempt);
        assert!(delay >= TIMING.min_request_interval && delay <= TIMING.refresh_backoff_max, "attempt {attempt}: {delay:?}");
    }
    // A 600 s owner bearer leaves 270 s between the scheduled refresh and
    // the deadline: room for at least three attempts at the worst case
    // (request spacing + full answer wait + exchange timeout are not all
    // sequential, but even 60 + 15 s per attempt fits three).
    // Whole milliseconds: the stats keep unix ms.
    let issued = chrono::DateTime::from_timestamp_millis(chrono::Utc::now().timestamp_millis()).unwrap();
    let stats = LoopStats::new(issued, issued + chrono::Duration::seconds(600));
    assert_eq!((stats.refresh_due() - issued).num_seconds(), 300);
    assert_eq!((stats.expires_at() - stats.deadline()).num_seconds(), 30);
}

// ---------------------------------------------------------------------------
// NAN-4326: the production refresh path end to end. The real
// MaintenanceService (start → serve → run_service + drive → refresh →
// exchange) runs against a fake control-plane exchange over HTTP and a fake
// supervisor on a real control socketpair that paces mints with the real
// `RefreshPacer` and answers with real `Secrets` memfds.
// ---------------------------------------------------------------------------

use nanosiem_lake_cell::child::ControlChannel;
use nanosiem_lake_cell::contract::{ToChild, ToSupervisor};
use nanosiem_lake_cell::fdpass::{self, AsyncSeqpacket};
use nanosiem_lake_cell::supervisor::{RefreshPace, RefreshPacer};
use std::collections::VecDeque;
use std::os::fd::AsFd;

/// Each grant the fake control plane mints lives this long.
const GRANT_MS: i64 = 3_000;

/// Production ratios in milliseconds: retries never inside the mint
/// interval, the answer wait longer than it, the backoff growing to a few
/// intervals.
const ROLE: LoopTiming = LoopTiming {
    min_request_interval: Duration::from_millis(200),
    answer_timeout: Duration::from_millis(400),
    exchange_timeout: Duration::from_millis(150),
    refresh_backoff_base: Duration::from_millis(100),
    refresh_backoff_max: Duration::from_millis(400),
    poll: Duration::from_millis(75),
    read_timeout: Duration::from_millis(50),
    backoff_base: Duration::from_millis(12),
    backoff_max: Duration::from_millis(300),
};

#[derive(Debug, Clone, Copy)]
enum Step {
    /// A valid maintenance grant.
    Grant,
    /// Never answers (the client's exchange timeout fires).
    Hang,
    /// This HTTP status, no body.
    Status(u16),
}

/// The control plane's `credential-exchange`, scripted per call.
struct FakeControlPlane {
    script: std::sync::Mutex<VecDeque<Step>>,
    otherwise: Step,
    calls: AtomicU64,
}

impl FakeControlPlane {
    async fn start(script: &[Step], otherwise: Step) -> (String, Arc<Self>) {
        use axum::response::IntoResponse;
        let plane = Arc::new(Self { script: std::sync::Mutex::new(script.iter().copied().collect()), otherwise, calls: AtomicU64::new(0) });
        let handler = plane.clone();
        let app = axum::Router::new().route("/v1/lake/cells/{cell}/credential-exchange", axum::routing::post(move || {
            let plane = handler.clone();
            async move {
                plane.calls.fetch_add(1, Ordering::SeqCst);
                let step = plane.script.lock().unwrap().pop_front().unwrap_or(plane.otherwise);
                match step {
                    Step::Grant => axum::Json(grant_response()).into_response(),
                    Step::Hang => {
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        axum::http::StatusCode::OK.into_response()
                    }
                    Step::Status(code) => axum::http::StatusCode::from_u16(code).unwrap().into_response(),
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, plane)
    }

    fn calls(&self) -> u64 {
        self.calls.load(Ordering::SeqCst)
    }
}

/// A maintenance grant living [`GRANT_MS`]; its stores point at a closed
/// local port (the compactor and manifest reads fail fast, offline).
fn grant_response() -> serde_json::Value {
    let mut value = response();
    value["credentials"][0]["endpoint"] = serde_json::json!("http://127.0.0.1:1");
    value["credentials"][0]["expires_at"] =
        serde_json::json!((chrono::Utc::now() + chrono::Duration::milliseconds(GRANT_MS)).to_rfc3339());
    value["prevalence_owner"]["url"] = serde_json::json!("http://127.0.0.1:1/v1/prevalence-state/mutate");
    value
}

/// The supervisor's side of the control socket: `RefreshSecrets` paced by
/// the real [`RefreshPacer`] and answered with a `Secrets` memfd; `Fatal`
/// recorded; heartbeats ignored.
#[derive(Default)]
struct FakeSupervisor {
    requests: AtomicU64,
    deferred: AtomicU64,
    fatal: std::sync::Mutex<Option<String>>,
}

impl FakeSupervisor {
    fn start(mint_interval: Duration) -> (ControlChannel, Arc<Self>) {
        let (supervisor_end, child_end) = fdpass::seqpacket_pair().unwrap();
        let control = ControlChannel::from_fd(child_end).unwrap();
        let sock = Arc::new(AsyncSeqpacket::new(supervisor_end).unwrap());
        let state = Arc::new(Self::default());
        let pacer = Arc::new(std::sync::Mutex::new(RefreshPacer::new(mint_interval)));
        let this = state.clone();
        tokio::spawn(async move {
            while let Ok(Some((message, _))) = sock.recv_json::<ToSupervisor>().await {
                match message {
                    ToSupervisor::RefreshSecrets => {
                        this.requests.fetch_add(1, Ordering::SeqCst);
                        let pace = pacer.lock().unwrap().request(std::time::Instant::now());
                        match pace {
                            RefreshPace::MintNow => send_secret(&sock).await,
                            RefreshPace::DeferUntil(at) => {
                                this.deferred.fetch_add(1, Ordering::SeqCst);
                                let (sock, pacer) = (sock.clone(), pacer.clone());
                                tokio::spawn(async move {
                                    tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await;
                                    pacer.lock().unwrap().deferred_due(std::time::Instant::now());
                                    send_secret(&sock).await;
                                });
                            }
                            RefreshPace::AlreadyDeferred => {}
                        }
                    }
                    ToSupervisor::Fatal { error } => *this.fatal.lock().unwrap() = Some(error),
                    _ => {}
                }
            }
        });
        (control, state)
    }

    fn fatal(&self) -> Option<String> {
        self.fatal.lock().unwrap().clone()
    }

    /// The `Fatal` the role sent before exiting (it may still be in the
    /// socket when the role's future returns).
    async fn wait_fatal(&self) -> Option<String> {
        for _ in 0..100 {
            if let Some(fatal) = self.fatal() {
                return Some(fatal);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }
}

async fn send_secret(sock: &AsyncSeqpacket) {
    let memfd = fdpass::secret_memfd(b"bootstrap-token").unwrap();
    let _ = sock.send_json(&ToChild::Secrets, &[memfd.as_fd()]).await;
}

/// How one role run ended.
struct RoleRun {
    /// `None`: still running when the test stopped watching.
    exited: Option<(Result<()>, chrono::DateTime<chrono::Utc>)>,
    /// The expiry of the grant the role held when it exited (or at the end).
    held_expiry: chrono::DateTime<chrono::Utc>,
    started: chrono::DateTime<chrono::Utc>,
}

/// Start the real service (its startup exchange is the script's first
/// step) and serve it for at most `watch`.
async fn run_role(plane_url: &str, control: ControlChannel, watch: Duration) -> RoleRun {
    let dir = tempfile::tempdir().unwrap();
    let mut assignment = assignment();
    assignment.control_url = Some(plane_url.to_owned());
    assignment.state_dir = dir.path().join("maintenance");
    let service = MaintenanceService::start_with(&assignment, Zeroizing::new(b"spawn-token".to_vec()), ROLE).await.unwrap();
    let started = chrono::Utc::now();
    let outcome = tokio::time::timeout(watch, service.clone().serve(control)).await;
    let exited = outcome.ok().map(|result| (result, chrono::Utc::now()));
    RoleRun { exited, held_expiry: service.stats.expires_at(), started }
}

/// One exchange times out; the retry (after the mint interval) succeeds
/// and the role keeps running on fresh grants.
#[tokio::test]
async fn one_exchange_timeout_then_success_does_not_exit() {
    let (url, plane) = FakeControlPlane::start(&[Step::Grant, Step::Hang], Step::Grant).await;
    let (control, supervisor) = FakeSupervisor::start(ROLE.min_request_interval);
    let run = run_role(&url, control, Duration::from_millis(5_000)).await;
    assert!(run.exited.is_none(), "the role exited: {:?} fatal={:?}", run.exited.map(|(r, _)| r), supervisor.fatal());
    assert!(plane.calls() >= 4, "start, the timed-out exchange, the retry and later refreshes: {}", plane.calls());
    assert!(run.held_expiry > chrono::Utc::now(), "the held grant is current");
    assert_eq!(supervisor.deferred.load(Ordering::SeqCst), 0, "the role never asks inside the mint interval");
}

/// The control plane answers 429 and the retry lands inside the
/// supervisor's (longer) mint interval: the supervisor answers it at the
/// interval's end instead of dropping it, the role is still waiting, and
/// the exchange succeeds.
#[tokio::test]
async fn rate_limited_then_success_does_not_exit() {
    let (url, plane) = FakeControlPlane::start(&[Step::Grant, Step::Status(429)], Step::Grant).await;
    let (control, supervisor) = FakeSupervisor::start(ROLE.min_request_interval + Duration::from_millis(150));
    let run = run_role(&url, control, Duration::from_millis(5_000)).await;
    assert!(run.exited.is_none(), "the role exited: {:?} fatal={:?}", run.exited.map(|(r, _)| r), supervisor.fatal());
    assert!(supervisor.deferred.load(Ordering::SeqCst) >= 1, "the retry was rate-limited by the supervisor");
    assert!(plane.calls() >= 3);
    assert!(run.held_expiry > chrono::Utc::now(), "the held grant is current");
}

/// Every refresh fails transiently: the role retries several times and
/// exits only at the held grant's deadline, before it expires.
#[tokio::test]
async fn persistent_failure_exits_before_the_held_grant_expires() {
    let (url, plane) = FakeControlPlane::start(&[Step::Grant], Step::Status(503)).await;
    let (control, supervisor) = FakeSupervisor::start(ROLE.min_request_interval);
    let run = run_role(&url, control, Duration::from_millis(6_000)).await;
    let (result, exited_at) = run.exited.expect("the role must exit once its grant is about to lapse");
    let error = format!("{:#}", result.expect_err("a lapsing grant is an error exit"));
    assert!(error.contains("no replacement"), "{error}");
    assert!(exited_at < run.held_expiry, "exited at {exited_at}, after the held grant expired at {}", run.held_expiry);
    let lifetime = chrono::Duration::milliseconds(GRANT_MS);
    assert!(exited_at >= run.held_expiry - lifetime / 5, "exited early at {exited_at}; grant expires {}", run.held_expiry);
    assert!(plane.calls() >= 1 + 3, "the start plus at least three refresh attempts: {}", plane.calls());
    assert!(supervisor.wait_fatal().await.is_some_and(|f| f.contains("no replacement")), "the supervisor is told why");
}

/// A 403 (revocation) stops the role at once, with no retry and long
/// before the held grant would expire.
#[tokio::test]
async fn forbidden_exits_promptly() {
    let (url, plane) = FakeControlPlane::start(&[Step::Grant, Step::Status(403)], Step::Grant).await;
    let (control, supervisor) = FakeSupervisor::start(ROLE.min_request_interval);
    let run = run_role(&url, control, Duration::from_millis(6_000)).await;
    let (result, exited_at) = run.exited.expect("a 403 must stop the role");
    let error = format!("{:#}", result.expect_err("a refusal is an error exit"));
    assert!(error.contains("403"), "{error}");
    let due = run.started + chrono::Duration::milliseconds(GRANT_MS / 2);
    assert!(exited_at < due + chrono::Duration::milliseconds(500), "exited at {exited_at}, refresh due {due}: not prompt");
    assert_eq!(plane.calls(), 2, "the start and the refused refresh; no retry");
    assert!(supervisor.wait_fatal().await.is_some_and(|f| f.contains("403")), "the supervisor is told why");
}
