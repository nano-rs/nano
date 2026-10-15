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

/// Production timing, scaled to milliseconds (same ratios: the backoff cap
/// equals REFRESH_AHEAD, the read timeout is far below it).
const FAST: LoopTiming = LoopTiming {
    refresh_ahead: chrono::Duration::milliseconds(300),
    refresh_retry: chrono::Duration::milliseconds(40),
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
        // 2.5 s of 1 s grants refreshed 300 ms early: at least three refreshes.
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
/// time and the restart backoff sits at its cap (== REFRESH_AHEAD). The
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
