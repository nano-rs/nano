// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4699 step 4: the jobs PG leader lease against a real PostgreSQL 18,
//! through the production constructor (`LeaderElection::new(..).with_timing(
//! LeaderTiming::JOBS).spawn_with(..)`) and its production `PgLeaseStore`
//! (pg_locks / pg_stat_activity probe, `pg_terminate_backend` eviction) as a
//! NON-superuser login, as in a region.
//!
//! Instance A reaches PostgreSQL through an in-test TCP relay that can be
//! blackholed (a node loss / partition: no FIN, the server keeps A's backend
//! open and idle). Instance B connects directly.

use nanosiem_core::leader::{LeaderElection, LeaderHooks, LeaderTiming};
use nanosiem_core::shutdown::ShutdownToken;
use sqlx::PgPool;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

include!("common/disposable_postgres.rs");

/// A disposable PostgreSQL 18 owned by this test process (native or docker on the worker).
fn owned_postgres() -> DisposablePostgres {
    let postgres = DisposablePostgres::start("pscale_admin");
    let backend = match &postgres.backend {
        DisposablePgBackend::Native { .. } => "native",
        DisposablePgBackend::Docker { .. } => "docker",
    };
    println!("NAN4668_OWNED_PG18 {backend}");
    postgres
}

const LOCK: i64 = 0x4e53_5445_5354;
const LOGIN: &str = "nano_lease_login";
const DATABASE: &str = "lease_fixture";

#[derive(Clone, Default)]
struct Ledger {
    events: Arc<Mutex<Vec<(&'static str, &'static str, Instant)>>>,
    running: Arc<AtomicUsize>,
    max_running: Arc<AtomicUsize>,
}

impl Ledger {
    fn last(&self, who: &str, what: &str) -> Option<Instant> {
        self.events.lock().unwrap().iter().rev().find(|(w, e, _)| *w == who && *e == what).map(|(_, _, t)| *t)
    }
}

struct Singletons {
    who: &'static str,
    ledger: Ledger,
    leading: Arc<AtomicBool>,
}

impl LeaderHooks for Singletons {
    async fn elected(&mut self) {
        let now = self.ledger.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.ledger.max_running.fetch_max(now, Ordering::SeqCst);
        self.leading.store(true, Ordering::SeqCst);
        self.ledger.events.lock().unwrap().push((self.who, "start", Instant::now()));
    }
    async fn stepped_down(&mut self) {
        self.ledger.running.fetch_sub(1, Ordering::SeqCst);
        self.leading.store(false, Ordering::SeqCst);
        self.ledger.events.lock().unwrap().push((self.who, "stop", Instant::now()));
    }
}

/// A TCP relay to PostgreSQL. While `blackholed`, it forwards nothing in either
/// direction and opens no upstream connection, but keeps every socket open.
struct Relay {
    port: u16,
    blackholed: Arc<AtomicBool>,
}

async fn wait_open(gate: &AtomicBool) {
    while gate.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn pump(mut from: tokio::net::tcp::OwnedReadHalf, mut to: tokio::net::tcp::OwnedWriteHalf, gate: Arc<AtomicBool>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        wait_open(&gate).await;
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        // Bytes read during a blackhole are held, never delivered, until it lifts.
        wait_open(&gate).await;
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = to.shutdown().await;
}

async fn start_relay(upstream: u16) -> Relay {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let blackholed = Arc::new(AtomicBool::new(false));
    let gate = Arc::clone(&blackholed);
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else { return };
            let gate = Arc::clone(&gate);
            tokio::spawn(async move {
                wait_open(&gate).await;
                let Ok(server) = tokio::net::TcpStream::connect(("127.0.0.1", upstream)).await else { return };
                let (cr, cw) = client.into_split();
                let (sr, sw) = server.into_split();
                tokio::spawn(pump(cr, sw, Arc::clone(&gate)));
                tokio::spawn(pump(sr, cw, gate));
            });
        }
    });
    Relay { port, blackholed }
}

struct Instance {
    shutdown: ShutdownToken,
    leading: Arc<AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

fn spawn(who: &'static str, port: u16, ledger: &Ledger) -> Instance {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(3))
        .connect_lazy(&format!("postgres://{LOGIN}@127.0.0.1:{port}/{DATABASE}"))
        .unwrap();
    let shutdown = ShutdownToken::new();
    let leading = Arc::new(AtomicBool::new(false));
    let hooks = Singletons { who, ledger: ledger.clone(), leading: Arc::clone(&leading) };
    // Production constructor and store; the jobs timing (no env overrides in the test).
    let handle = LeaderElection::new(pool, LOCK).with_timing(LeaderTiming::JOBS).spawn_with(shutdown.clone(), hooks);
    Instance { shutdown, leading, handle }
}

async fn until(limit: Duration, done: impl Fn() -> bool) -> Duration {
    let start = Instant::now();
    while !done() {
        assert!(start.elapsed() <= limit, "condition not reached within {limit:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    start.elapsed()
}

async fn holder_pid(admin: &PgPool) -> Option<i32> {
    let key = LOCK as u64;
    sqlx::query_scalar(
        "SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted AND objsubid = 1 \
           AND classid::bigint = $1 AND objid::bigint = $2",
    )
    .bind((key >> 32) as i64)
    .bind((key & 0xffff_ffff) as i64)
    .fetch_optional(admin)
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires script-owned disposable PostgreSQL 18"]
async fn jobs_lease_takeover_on_real_postgres_is_fenced_and_bounded() {
    let postgres = owned_postgres();
    let bootstrap = PgPool::connect(&postgres.url("postgres")).await.unwrap();
    sqlx::query(&format!("CREATE DATABASE {DATABASE}")).execute(&bootstrap).await.unwrap();
    sqlx::query(&format!("CREATE ROLE {LOGIN} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS"))
        .execute(&bootstrap)
        .await
        .unwrap();
    bootstrap.close().await;
    let admin = PgPool::connect(&postgres.url(DATABASE)).await.unwrap();
    let timing = LeaderTiming::JOBS;
    let ledger = Ledger::default();
    let relay = start_relay(postgres.port).await;

    // 1. A leads; B (direct) stays standby across more than `stale_after` while A renews.
    let a = spawn("A", relay.port, &ledger);
    until(Duration::from_secs(15), || a.leading.load(Ordering::SeqCst)).await;
    let a_pid = holder_pid(&admin).await.expect("A holds the lock server-side");
    let b = spawn("B", postgres.port, &ledger);
    tokio::time::sleep(timing.stale_after.unwrap() + Duration::from_secs(10)).await;
    assert!(a.leading.load(Ordering::SeqCst), "a renewing leader must keep the lease");
    assert!(!b.leading.load(Ordering::SeqCst), "the standby must not lead while the leader renews");
    assert_eq!(holder_pid(&admin).await, Some(a_pid), "a renewing leader was evicted");

    // 2. A is cut off (no FIN): it fences itself, then B evicts the idle backend and leads.
    let cut = Instant::now();
    relay.blackholed.store(true, Ordering::SeqCst);
    let b_leading = Arc::clone(&b.leading);
    let took = until(timing.takeover_bound().unwrap() + Duration::from_secs(10), || b_leading.load(Ordering::SeqCst)).await;
    let a_stop = ledger.last("A", "stop").expect("A fenced itself");
    let b_start = ledger.last("B", "start").expect("B took over");
    assert!(a_stop.duration_since(cut) <= timing.self_fence_bound() + Duration::from_secs(1), "A fenced after {:?}", a_stop.duration_since(cut));
    assert!(b_start > a_stop, "B led before A stopped");
    // The designed margin between the old leader's fence and the takeover is 15 s nominal.
    assert!(b_start.duration_since(a_stop) >= Duration::from_secs(10), "fence-to-takeover margin {:?}", b_start.duration_since(a_stop));
    assert!(took <= timing.takeover_bound().unwrap() + Duration::from_secs(3), "takeover took {took:?}");
    assert!(took >= Duration::from_secs(15), "B evicted a holder idle for less than stale_after ({took:?})");
    assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1, "two leaders ran singletons at once");
    let b_pid = holder_pid(&admin).await.expect("B holds the lock server-side");
    assert_ne!(b_pid, a_pid);
    let a_backend: i64 = sqlx::query_scalar("SELECT count(*) FROM pg_stat_activity WHERE pid = $1")
        .bind(a_pid)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(a_backend, 0, "A's stale backend was terminated");

    // 3. The partition heals: A must not lead again while B holds the lease.
    relay.blackholed.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_secs(20)).await;
    assert!(!a.leading.load(Ordering::SeqCst));
    assert!(b.leading.load(Ordering::SeqCst));
    assert_eq!(holder_pid(&admin).await, Some(b_pid));
    assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);

    // 4. B stops gracefully (a roll): its tasks stop, its session closes, A takes over within a retry.
    b.shutdown.cancel();
    b.handle.await.unwrap();
    let b_stop = ledger.last("B", "stop").expect("B stepped down");
    let a_leading = Arc::clone(&a.leading);
    let handover = until(Duration::from_secs(10), || a_leading.load(Ordering::SeqCst)).await;
    assert!(handover <= timing.retry + timing.database_timeout, "graceful handover took {handover:?}");
    assert!(ledger.last("A", "start").unwrap() >= b_stop);
    assert_eq!(ledger.max_running.load(Ordering::SeqCst), 1);

    a.shutdown.cancel();
    a.handle.await.unwrap();
    assert_eq!(holder_pid(&admin).await, None, "a stopped leader releases the lock");
    admin.close().await;
    println!("NAN4699_LEASE_PG takeover={took:?} margin={:?} handover={handover:?}", b_start.duration_since(a_stop));
}

/// NAN-4699 step 4: both jobs pods claim shadow investigations under the same
/// shared worker identity, so a run whose lease the other pod reclaimed must
/// not complete or fail the reclaimed order (the claim's attempt fences it).
#[cfg(feature = "enterprise")]
#[tokio::test]
#[ignore = "requires script-owned disposable PostgreSQL 18"]
async fn a_reclaimed_shadow_investigation_is_fenced_from_the_stale_run() {
    use nanosiem_core::auth::tenant::TrustedTenantContext;
    use nanosiem_core::enterprise_shared_shadow_investigation::{claim_due_in_transaction, complete_in_transaction, fail_in_transaction};
    let postgres = owned_postgres();
    let bootstrap = PgPool::connect(&postgres.url("postgres")).await.unwrap();
    sqlx::query("CREATE DATABASE shadow_fence").execute(&bootstrap).await.unwrap();
    bootstrap.close().await;
    let pool = PgPool::connect(&postgres.url("shadow_fence")).await.unwrap();
    // The columns the claim / complete / fail statements touch (as the core unit race test).
    sqlx::query("CREATE TABLE enterprise_shared_shadow_investigations (
        id uuid PRIMARY KEY, tenant_id uuid NOT NULL, case_id uuid NOT NULL,
        alert_id uuid, notebook_id uuid, trigger text NOT NULL DEFAULT 'manual',
        state text NOT NULL DEFAULT 'queued', not_before timestamptz NOT NULL DEFAULT NOW(),
        attempts int NOT NULL DEFAULT 0, claimed_by text, claimed_at timestamptz,
        lease_expires_at timestamptz, started_at timestamptz, finished_at timestamptz,
        error text, summary jsonb NOT NULL DEFAULT '{}',
        created_at timestamptz NOT NULL DEFAULT NOW(), updated_at timestamptz NOT NULL DEFAULT NOW()
    )").execute(&pool).await.unwrap();
    let tenant = TrustedTenantContext { tenant_id: uuid::Uuid::new_v4(), tenant_slug: "t".into() };
    let order = uuid::Uuid::new_v4();
    sqlx::query("INSERT INTO enterprise_shared_shadow_investigations (id, tenant_id, case_id) VALUES ($1, $2, $3)")
        .bind(order).bind(tenant.tenant_id).bind(uuid::Uuid::new_v4()).execute(&pool).await.unwrap();
    const SHARED: &str = "shared-detection-worker";
    let claim = || async {
        let mut tx = pool.begin().await.unwrap();
        let claimed = claim_due_in_transaction(&mut tx, &tenant, SHARED, 1).await.unwrap();
        tx.commit().await.unwrap();
        claimed
    };
    // Pod A claims (attempt 1); its lease runs out; pod B reclaims (attempt 2).
    let a = claim().await;
    assert_eq!(a.len(), 1);
    sqlx::query("UPDATE enterprise_shared_shadow_investigations SET lease_expires_at = NOW() - interval '1 second' WHERE id = $1")
        .bind(order).execute(&pool).await.unwrap();
    let b = claim().await;
    assert_eq!(b.len(), 1);
    assert_eq!((a[0].attempts, b[0].attempts), (1, 2));
    let summary = serde_json::json!({ "by": "A" });
    // A's late outcomes are refused; B's order stays running.
    let mut tx = pool.begin().await.unwrap();
    assert!(!complete_in_transaction(&mut tx, &tenant, order, a[0].attempts, SHARED, &summary).await.unwrap(), "stale run completed a reclaimed order");
    assert!(!fail_in_transaction(&mut tx, &tenant, order, a[0].attempts, SHARED, "timed out", false).await.unwrap(), "stale run failed a reclaimed order");
    tx.commit().await.unwrap();
    let (state, attempts): (String, i32) = sqlx::query_as("SELECT state, attempts FROM enterprise_shared_shadow_investigations WHERE id = $1")
        .bind(order).fetch_one(&pool).await.unwrap();
    assert_eq!((state.as_str(), attempts), ("running", 2));
    // B's own completion lands.
    let mut tx = pool.begin().await.unwrap();
    assert!(complete_in_transaction(&mut tx, &tenant, order, b[0].attempts, SHARED, &serde_json::json!({ "by": "B" })).await.unwrap());
    tx.commit().await.unwrap();
    let by: Option<String> = sqlx::query_scalar("SELECT summary ->> 'by' FROM enterprise_shared_shadow_investigations WHERE id = $1 AND state = 'completed'")
        .bind(order).fetch_one(&pool).await.unwrap();
    assert_eq!(by.as_deref(), Some("B"));
    pool.close().await;
}
