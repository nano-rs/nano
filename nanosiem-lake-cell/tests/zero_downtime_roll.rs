//! Zero-downtime cell roll gate (NAN-3004, `cell_zero_downtime_roll_v1`).
//!
//! Runs real cell supervisors with real jailed stub tenant processes, two
//! pods of the SAME cell at a time, the way a `RollingUpdate` (maxSurge 1,
//! maxUnavailable 0) overlaps them, and proves across the handover:
//!
//! - **continuous query availability**: a client that, like a Service,
//!   sends searches only to pods whose `/readyz` is 200 never fails and
//!   never finds zero ready pods during the planned roll; the new pod is not
//!   ready until its query processes finished their (gated) prewarm;
//! - **one writer**: the new pod runs no ingest while the old one writes,
//!   and the fake store (the edge-log DO lease + part-log CAS contract: the
//!   newest lease fences older epochs, a commit must start at the committed
//!   point) never sees a stale-epoch pull or commit, or a conflicting one;
//! - **no loss, no duplicates**: every event the source produced is
//!   committed exactly once, in order, across both handovers;
//! - a **crashed** writer pod (no release) is taken over after the peer TTL.
//!
//! Needs the same privileges as the isolation suite (uid switching,
//! landlock); re-executes itself in the same user-namespace sandbox.
//! `NANO_CELL_ISOLATION_REQUIRED=1` turns a missing sandbox into a failure.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::AUTHORIZATION;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use nanosiem_lake_cell::config::{CellConfig, IngestMode, Placement, TenantPlacement};
use nanosiem_lake_cell::contract::{Role, TenantId};
use nanosiem_lake_cell::router::{self, Router};
use nanosiem_lake_cell::secrets::StaticKeySource;
use nanosiem_lake_cell::supervisor::Supervisor;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const IN_SANDBOX: &str = "NANO_CELL_IN_SANDBOX";
const TOKEN: &str = "test-router-token-0123456789abcdef0123456789";
const QUERY_TOKEN: &str = "test-router-QUERY-token-0123456789abcdef012345";
const STUB: &str = env!("CARGO_BIN_EXE_nanosiem-lake-cell-stub");
const CELL_ID: &str = "zc";
const TENANTS: [&str; 2] = ["t1", "t2"];
/// A placed tenant with on-demand ingest: its query[T] is resident only
/// through `query_resident` (NAN-3008, the production default), and its
/// prewarm is the slowest, so a pod that turns Ready on its ingest-resident
/// tenants alone would answer it 503 "query prewarm is incomplete".
const QUERY_ONLY: &str = "t3";
const QUERY_ONLY_WARM_MS: u64 = 9000;
/// Every tenant the searches go to.
const SEARCH_TENANTS: [&str; 3] = ["t1", "t2", QUERY_ONLY];
const TTL_SECS: u64 = 5;
/// The drain window (`drain_secs`): the pod serves after readiness is
/// withdrawn, answering `Connection: close`.
const DRAIN_SECS: u64 = 2;
/// The Service client's pool idle timeout: below the drain window, the only
/// time a cell closes an idle keep-alive connection (the rule the search
/// side's lake-cell clients follow, `LAKE_CELL_POOL_IDLE_TIMEOUT`).
const POOL_IDLE: Duration = Duration::from_millis(1000);
/// Concurrent keep-alive callers (several pooled connections, some idle).
const KEEPALIVE_CALLERS: usize = 4;
/// How long a stub search takes (requests are in flight at every instant).
const SEARCH_MS: u64 = 60;

#[test]
fn zero_downtime_roll() {
    // SAFETY: geteuid never fails.
    let root = unsafe { libc::geteuid() } == 0;
    if std::env::var(IN_SANDBOX).is_err() && !root {
        return reexec_in_sandbox();
    }
    tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap().block_on(suite());
}

fn tool(name: &str) -> bool {
    std::process::Command::new("sh").args(["-c", &format!("command -v {name}")]).output().map(|o| o.status.success()).unwrap_or(false)
}

fn reexec_in_sandbox() {
    let required = std::env::var("NANO_CELL_ISOLATION_REQUIRED").is_ok();
    let subuid = std::fs::read_to_string("/etc/subuid").unwrap_or_default();
    let user = std::env::var("USER").unwrap_or_default();
    let range = subuid.lines().find_map(|l| {
        let mut it = l.split(':');
        if it.next() != Some(user.as_str()) {
            return None;
        }
        Some((it.next()?.to_owned(), it.next()?.to_owned()))
    });
    let (Some((start, count)), true, true) = (range, tool("systemd-run"), tool("unshare")) else {
        let msg = "SKIPPED: need root, or systemd-run + unshare + an /etc/subuid range";
        assert!(!required, "{msg}");
        eprintln!("{msg}");
        return;
    };
    let count: u32 = count.parse::<u32>().unwrap_or(65536).min(65535);
    let exe = std::env::current_exe().unwrap();
    let mut cmd = std::process::Command::new("systemd-run");
    cmd.args(["--user", "--quiet", "--wait", "--collect", "--pipe", "-p", "Delegate=yes", "--same-dir"]);
    for (k, v) in [
        (IN_SANDBOX, "1".to_owned()),
        ("HOME", std::env::var("HOME").unwrap_or_default()),
        ("PATH", std::env::var("PATH").unwrap_or_default()),
        ("RUST_LOG", std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())),
        ("RUST_BACKTRACE", "1".into()),
    ] {
        cmd.arg("-E").arg(format!("{k}={v}"));
    }
    cmd.args(["--", "unshare", "--user", "--map-root-user"])
        .arg(format!("--map-users=1:{start}:{count}"))
        .arg(format!("--map-groups=1:{start}:{count}"))
        .args(["--mount", "--propagation", "private", "--"]);
    if tool("setpriv") {
        cmd.args(["setpriv", "--inh-caps=-all", "--bounding-set=-all,+chown,+fowner,+kill,+setgid,+setuid,+sys_admin", "--"]);
    }
    cmd.arg(exe).args(["zero_downtime_roll", "--exact", "--nocapture", "--test-threads=1"]);
    let status = cmd.status().expect("run sandbox");
    assert!(status.success(), "zero-downtime roll suite failed inside the sandbox: {status}");
}

fn setup_dirs() -> PathBuf {
    let host = PathBuf::from(std::env::var("HOME").unwrap()).join(format!(".cache/nan3004/roll-{}", std::process::id()));
    std::fs::create_dir_all(&host).unwrap();
    // Tenant uids cannot traverse $HOME (0700): expose the tree at /mnt in
    // our private mount namespace.
    let src = std::ffi::CString::new(host.to_str().unwrap()).unwrap();
    let dst = std::ffi::CString::new("/mnt").unwrap();
    // SAFETY: bind mount in our own mount namespace.
    let rc = unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
    assert_eq!(rc, 0, "bind mount: {}", std::io::Error::last_os_error());
    let mnt = PathBuf::from("/mnt");
    std::fs::set_permissions(&mnt, std::fs::Permissions::from_mode(0o755)).unwrap();
    let bin = mnt.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::copy(STUB, bin.join("stub")).unwrap();
    std::fs::set_permissions(bin.join("stub"), std::fs::Permissions::from_mode(0o755)).unwrap();
    for d in ["run", "secret"] {
        std::fs::create_dir_all(mnt.join(d)).unwrap();
        std::fs::set_permissions(mnt.join(d), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(mnt.join("secret/router.token"), TOKEN).unwrap();
    std::fs::set_permissions(mnt.join("secret/router.token"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(mnt.join("secret/router-query.token"), QUERY_TOKEN).unwrap();
    std::fs::set_permissions(mnt.join("secret/router-query.token"), std::fs::Permissions::from_mode(0o400)).unwrap();
    mnt
}

// ------------------------------------------------------------------ fake store

/// One tenant's edge log + part log, reduced to the fencing contract.
#[derive(Default)]
struct TenantLog {
    /// Current lease epoch (the newest lease wins).
    epoch: u64,
    /// Source events 1..=head exist.
    head: u64,
    committed: u64,
    seqs: Vec<u64>,
    /// (epoch, consumer, from, to, at)
    commits: Vec<(u64, String, u64, u64, Instant)>,
    /// (epoch, consumer, at)
    leases: Vec<(u64, String, Instant)>,
    stale_pulls: u64,
    stale_commits: u64,
    conflicts: u64,
}

#[derive(Default)]
struct Store {
    logs: Mutex<HashMap<String, TenantLog>>,
}

impl Store {
    fn handle(&self, path: &str, body: &Value) -> Value {
        let mut parts = path.trim_start_matches('/').splitn(2, '/');
        let (Some(tenant), Some(op)) = (parts.next(), parts.next()) else { return json!({"kind": "bad_path"}) };
        let mut logs = self.logs.lock().unwrap();
        let log = logs.entry(tenant.to_owned()).or_default();
        let epoch = body["epoch"].as_u64().unwrap_or(0);
        match op {
            "lease" => {
                log.epoch += 1;
                let consumer = body["consumer"].as_str().unwrap_or("").to_owned();
                log.leases.push((log.epoch, consumer, Instant::now()));
                json!({"kind": "ok", "epoch": log.epoch, "committed": log.committed})
            }
            "pull" => {
                if epoch != log.epoch {
                    log.stale_pulls += 1;
                    return json!({"kind": "fenced"});
                }
                let after = body["after"].as_u64().unwrap_or(0);
                let events: Vec<u64> = (after + 1..=log.head.min(after + 500)).collect();
                json!({"kind": "ok", "events": events})
            }
            "commit" => {
                if epoch != log.epoch {
                    log.stale_commits += 1;
                    return json!({"kind": "fenced"});
                }
                let from = body["from"].as_u64().unwrap_or(u64::MAX);
                let events: Vec<u64> = body["events"].as_array().into_iter().flatten().filter_map(Value::as_u64).collect();
                let contiguous = events.iter().enumerate().all(|(i, e)| *e == from + 1 + i as u64);
                if from != log.committed || events.is_empty() || !contiguous {
                    log.conflicts += 1;
                    return json!({"kind": "conflict", "committed": log.committed});
                }
                let to = *events.last().unwrap();
                log.seqs.extend(&events);
                log.committed = to;
                let consumer = body["consumer"].as_str().unwrap_or("").to_owned();
                log.commits.push((epoch, consumer, from, to, Instant::now()));
                json!({"kind": "ok"})
            }
            _ => json!({"kind": "bad_op"}),
        }
    }

    fn produce(&self) {
        let mut logs = self.logs.lock().unwrap();
        for t in TENANTS {
            logs.entry(t.to_owned()).or_default().head += 1;
        }
    }

    fn with<T>(&self, t: &str, f: impl FnOnce(&TenantLog) -> T) -> T {
        let mut logs = self.logs.lock().unwrap();
        f(logs.entry(t.to_owned()).or_default())
    }
}

async fn serve_store(store: Arc<Store>) -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { continue };
            let store = store.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let store = store.clone();
                    async move {
                        let path = req.uri().path().to_owned();
                        let body = req.into_body().collect().await?.to_bytes();
                        let v: Value = serde_json::from_slice(&body).unwrap_or_default();
                        let out = store.handle(&path, &v);
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(out.to_string()))))
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
            });
        }
    });
    port
}

// ------------------------------------------------------------------ cells

async fn call(sock: &Path, method: Method, path: &str, token: Option<&str>) -> (u16, Value) {
    let stream = match tokio::net::UnixStream::connect(sock).await {
        Ok(s) => s,
        Err(e) => return (0, json!({"client_error": e.to_string()})),
    };
    let Ok((mut s, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await else {
        return (0, json!({"client_error": "handshake"}));
    };
    tokio::spawn(conn);
    let mut req = Request::builder().method(method).uri(path).header("host", "cell");
    if let Some(t) = token {
        req = req.header(AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = req.body(Full::new(Bytes::new())).unwrap();
    match s.send_request(req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            (status, serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into())))
        }
        Err(e) => (0, json!({"client_error": e.to_string()})),
    }
}

struct Cell {
    name: &'static str,
    sock: PathBuf,
    sup: Arc<Supervisor>,
    router: Arc<Router>,
    router_task: tokio::task::JoinHandle<std::io::Result<()>>,
    /// As an endpoint controller sees it (`/readyz`).
    ready: AtomicBool,
    gone: AtomicBool,
    /// The process exited: connections pinned to it are reset.
    exited: AtomicBool,
}

impl Cell {
    fn ingest_tenants(&self) -> Vec<String> {
        let st = self.sup.status();
        st.tenants
            .iter()
            .filter(|t| t.processes.iter().any(|p| p.role == Role::Ingest))
            .map(|t| t.tenant_id.to_string())
            .collect()
    }

    /// Kubelet SIGTERM: what `main` does, then the process exits (every
    /// connection still open is torn down, as by process exit).
    async fn terminate(&self) {
        self.sup.handover_quiesce().await;
        self.router.close(Duration::from_secs(5)).await;
        self.sup.drain_all().await;
        self.sup.halt();
        self.router_task.abort();
        let _ = std::fs::remove_file(&self.sock);
        self.gone.store(true, Ordering::SeqCst);
        self.exited.store(true, Ordering::SeqCst);
    }

    /// Node loss: nothing released, nothing flushed.
    fn crash(&self) {
        self.gone.store(true, Ordering::SeqCst);
        self.exited.store(true, Ordering::SeqCst);
        self.ready.store(false, Ordering::SeqCst);
        self.sup.shutdown_all();
        self.sup.halt();
        self.router_task.abort();
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn config(mnt: &Path, name: &str, uid_base: u32, store_port: u16, handover: bool) -> CellConfig {
    let peers: Vec<String> = ["a", "b", "c"].iter().map(|p| format!("unix:{}", mnt.join(format!("run/{p}.sock")).display())).collect();
    let mut v = json!({
        "cell_id": CELL_ID,
        "mode": "pooled",
        "data_dir": mnt.join(format!("{name}-data")),
        "state_dir": mnt.join(format!("{name}-state")),
        "ingest_binary": mnt.join("bin/stub"),
        "query_binary": mnt.join("bin/stub"),
        "prevalence_maintenance": true,
        "idle_timeout_secs": 600,
        "query_idle_timeout_secs": 600,
        "warm_query": 0,
        "warm_ingest": 0,
        "spawn_timeout_secs": 10,
        "shutdown_grace_ms": 3000,
        "stall_kill_secs": 120,
        "require_landlock": true,
        "uid_base": uid_base,
        "uid_slots": 50,
        "tcp_connect_ports": [store_port],
        // NAN-3523: pooled + `off` needs the dev/test opt-out.
        "isolation": {"cgroup": "off", "watchdog": true, "allow_pooled_watchdog_only": true},
        "listen_unix": mnt.join(format!("run/{name}.sock")),
        "router_token_file": mnt.join("secret/router.token"),
        "router_query_token_file": mnt.join("secret/router-query.token"),
        "placement_file": mnt.join(format!("{name}-placement.json")),
        "dev_key_dir": mnt.join("secret"),
        "resources": {"interval_ms": 500, "cell_cpu_millicores": 10_000_000, "cell_memory_bytes": (1u64 << 50),
            "restart_backoff_base_ms": 200},
        "zero_downtime_roll": {
            "peers": peers,
            "peer_poll_ms": 200,
            "writer_lease_ttl_secs": TTL_SECS,
            "discovery_grace_secs": 2,
            "drain_secs": DRAIN_SECS,
            "inflight_secs": 3,
            "standby_request_wait_secs": 5
        }
    });
    if !handover {
        v.as_object_mut().unwrap().remove("zero_downtime_roll");
    }
    serde_json::from_value(v).unwrap()
}

async fn start_cell(mnt: &Path, name: &'static str, uid_base: u32, store_port: u16) -> Arc<Cell> {
    start_cell_with(mnt, name, uid_base, store_port, true).await
}

async fn start_cell_with(mnt: &Path, name: &'static str, uid_base: u32, store_port: u16, handover: bool) -> Arc<Cell> {
    let cfg = config(mnt, name, uid_base, store_port, handover);
    let mut keys = StaticKeySource::default();
    let mut tenants = Vec::new();
    for t in SEARCH_TENANTS {
        let id = TenantId::new(t).unwrap();
        let warm_ms = if name == "abort" { 120_000 } else if t == QUERY_ONLY { QUERY_ONLY_WARM_MS } else { 1500 };
        for r in Role::ALL {
            let secret = format!("bootstrap-token:{t}:{};store=127.0.0.1:{store_port};warm_ms={warm_ms};search_ms={SEARCH_MS};cell={name}", r.as_str());
            keys = keys.with(&id, r, secret.as_bytes());
        }
        let mut p = TenantPlacement::legacy(id, 20.0);
        if t != QUERY_ONLY {
            p.ingest = IngestMode::Resident;
        }
        tenants.push(p);
    }
    let sup = Supervisor::new(cfg.clone(), Arc::new(keys)).expect("supervisor");
    sup.set_placement(Placement { cell_id: CELL_ID.into(), revision: 1, tenants }).unwrap();
    sup.start_background();
    let router = Router::new(sup.clone()).unwrap();
    let sock = cfg.listen_unix.clone().unwrap();
    let _ = std::fs::remove_file(&sock);
    let l = tokio::net::UnixListener::bind(&sock).unwrap();
    let router_task = tokio::spawn(router::serve_unix(router.clone(), l));
    Arc::new(Cell { name, sock, sup, router, router_task, ready: AtomicBool::new(false), gone: AtomicBool::new(false),
        exited: AtomicBool::new(false) })
}

async fn wait_for(what: &str, within: Duration, mut f: impl FnMut() -> bool) -> Duration {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < within, "timed out after {within:?} waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    t0.elapsed()
}

/// Shared by the endpoint poller, the client and the checks.
#[derive(Default)]
struct Traffic {
    cells: Mutex<Vec<Arc<Cell>>>,
    /// Count client outcomes only while armed (the planned roll).
    armed: AtomicBool,
    ok: AtomicU64,
    failed: Mutex<Vec<String>>,
    no_ready: Mutex<Vec<String>>,
    stop: AtomicBool,
    /// The keep-alive (Service-pinned) caller.
    ka_ok: AtomicU64,
    ka_failed: Mutex<Vec<String>>,
    /// Pooled connections the keep-alive caller opened, and responses that
    /// told it to close the connection (a draining pod).
    ka_connects: AtomicU64,
    ka_close_answers: AtomicU64,
}

async fn endpoint_poller(tr: Arc<Traffic>) {
    while !tr.stop.load(Ordering::SeqCst) {
        let cells = tr.cells.lock().unwrap().clone();
        for c in &cells {
            let ready = !c.gone.load(Ordering::SeqCst) && call(&c.sock, Method::GET, "/readyz", None).await.0 == 200;
            c.ready.store(ready, Ordering::SeqCst);
        }
        if tr.armed.load(Ordering::SeqCst) && !cells.iter().any(|c| c.ready.load(Ordering::SeqCst)) {
            tr.no_ready.lock().unwrap().push(format!("{:?}", cells.iter().map(|c| c.name).collect::<Vec<_>>()));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn client(tr: Arc<Traffic>) {
    let mut n = 0usize;
    while !tr.stop.load(Ordering::SeqCst) {
        n += 1;
        let ready: Vec<Arc<Cell>> = tr.cells.lock().unwrap().iter().filter(|c| c.ready.load(Ordering::SeqCst)).cloned().collect();
        let armed = tr.armed.load(Ordering::SeqCst);
        if let Some(c) = ready.get(n % ready.len().max(1)) {
            let t = SEARCH_TENANTS[n % SEARCH_TENANTS.len()];
            let (st, v) = call(&c.sock, Method::GET, &format!("/v1/tenants/{t}/query/v1/search?n={n}"), Some(QUERY_TOKEN)).await;
            if armed {
                if st == 200 && v["tenant"] == t {
                    tr.ok.fetch_add(1, Ordering::Relaxed);
                } else {
                    tr.failed.lock().unwrap().push(format!("{} {t}: {st} {v}", c.name));
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// One pooled keep-alive connection, pinned to the pod it connected to (a
/// ClusterIP Service picks the endpoint at connect time; an established
/// connection keeps going to that pod after its readiness is withdrawn).
struct Pooled {
    cell: Arc<Cell>,
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    idle_since: Instant,
}

/// A caller that behaves like the search service's pooled HTTP client
/// behind a Service: it reuses idle keep-alive connections (discarding
/// those idle longer than `POOL_IDLE` or closed by the server), opens a new
/// connection to a READY pod when none is free, never retries a request
/// that reached the server, and counts every non-200 answer or transport
/// error. The per-request fresh-connection `client` above cannot see the
/// keep-alive gap; this one reproduces it.
async fn keepalive_client(tr: Arc<Traffic>, pool: Arc<Mutex<Vec<Pooled>>>, id: usize) {
    let mut n = id * 1_000_000;
    while !tr.stop.load(Ordering::SeqCst) {
        n += 1;
        let armed = tr.armed.load(Ordering::SeqCst);
        let t = SEARCH_TENANTS[n % SEARCH_TENANTS.len()];
        let path = format!("/v1/tenants/{t}/query/v1/search?ka={n}");
        let outcome = keepalive_request(&tr, &pool, &path, n).await;
        if armed {
            match outcome {
                Some((name, 200, v)) if v["tenant"] == t => {
                    let _ = name;
                    tr.ka_ok.fetch_add(1, Ordering::Relaxed);
                }
                Some((name, st, v)) => tr.ka_failed.lock().unwrap().push(format!("{name} {t}: {st} {v}")),
                None => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(15 + (id as u64 * 7))).await;
    }
}

/// `None`: no ready pod to connect to (not counted, as the fresh client).
async fn keepalive_request(tr: &Traffic, pool: &Mutex<Vec<Pooled>>, path: &str, n: usize) -> Option<(&'static str, u16, Value)> {
    // Take a reusable pooled connection (pool idle timeout, server-closed).
    let mut conn = {
        let mut p = pool.lock().unwrap();
        p.retain(|c| !c.sender.is_closed() && c.idle_since.elapsed() < POOL_IDLE);
        p.pop()
    };
    loop {
        let mut c = match conn.take() {
            Some(c) => c,
            None => {
                let ready: Vec<Arc<Cell>> = tr.cells.lock().unwrap().iter().filter(|c| c.ready.load(Ordering::SeqCst)).cloned().collect();
                let cell = ready.get(n % ready.len().max(1))?.clone();
                let stream = match tokio::net::UnixStream::connect(&cell.sock).await {
                    Ok(s) => s,
                    Err(e) => return Some((cell.name, 0, json!({"connect_error": e.to_string()}))),
                };
                let (sender, driver) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await {
                    Ok(x) => x,
                    Err(e) => return Some((cell.name, 0, json!({"handshake_error": e.to_string()}))),
                };
                let exited = cell.clone();
                // The connection dies with the pod's process.
                tokio::spawn(async move {
                    tokio::select! {
                        _ = driver => {}
                        _ = async { while !exited.exited.load(Ordering::SeqCst) { tokio::time::sleep(Duration::from_millis(10)).await } } => {}
                    }
                });
                tr.ka_connects.fetch_add(1, Ordering::Relaxed);
                Pooled { cell, sender, idle_since: Instant::now() }
            }
        };
        if c.sender.ready().await.is_err() {
            // Closed between requests (Connection: close was honoured):
            // a pooled client just opens another one.
            continue;
        }
        let req = Request::builder().method(Method::GET).uri(path).header("host", "cell")
            .header(AUTHORIZATION, format!("Bearer {QUERY_TOKEN}")).body(Full::new(Bytes::new())).unwrap();
        let resp = match c.sender.try_send_request(req).await {
            Ok(r) => r,
            Err(mut e) => {
                // Never written: a pooled client retries it on another connection.
                if e.take_message().is_some() {
                    continue;
                }
                return Some((c.cell.name, 0, json!({"transport_error": e.into_error().to_string()})));
            }
        };
        let status = resp.status().as_u16();
        let closes = resp.headers().get(hyper::header::CONNECTION).is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"close"));
        if closes {
            tr.ka_close_answers.fetch_add(1, Ordering::Relaxed);
        }
        let bytes = match resp.into_body().collect().await {
            Ok(b) => b.to_bytes(),
            Err(e) => return Some((c.cell.name, 0, json!({"body_error": e.to_string()}))),
        };
        let v = serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
        let name = c.cell.name;
        if !closes {
            c.idle_since = Instant::now();
            pool.lock().unwrap().push(c);
        }
        return Some((name, status, v));
    }
}

struct DelayedMaintenanceKeys {
    inner: StaticKeySource,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl nanosiem_lake_cell::secrets::KeySource for DelayedMaintenanceKeys {
    async fn mint(&self, t: &TenantId, role: Role) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        if role == Role::Maintenance {
            self.entered.notify_one();
            self.release.notified().await;
        }
        nanosiem_lake_cell::secrets::KeySource::mint(&self.inner, t, role).await
    }
}

async fn drain_during_maintenance_mint(mnt: &Path, port: u16) -> bool {
    let t = TenantId::new("mint-race").unwrap();
    let mut cfg = config(mnt, "race", 59_000, port, true);
    cfg.zero_downtime_roll.as_mut().unwrap().discovery_grace_secs = 0;
    // Independent supervisor: no keeper or router is needed for this race.
    let keys = Arc::new(DelayedMaintenanceKeys {
        inner: StaticKeySource::default().with(&t, Role::Maintenance, b"bootstrap-token:mint-race:maintenance"),
        entered: tokio::sync::Notify::new(), release: tokio::sync::Notify::new(),
    });
    let sup = Supervisor::new(cfg, keys.clone()).unwrap();
    sup.set_placement(Placement { cell_id: CELL_ID.into(), revision: 1,
        tenants: vec![TenantPlacement::legacy(t.clone(), 20.0)] }).unwrap();
    let spawning = { let sup = sup.clone(); let t = t.clone();
        tokio::spawn(async move { sup.ensure_running(&t, Role::Maintenance).await }) };
    tokio::time::timeout(Duration::from_secs(10), keys.entered.notified()).await.unwrap();
    let reported_while_spawning = sup.writer_tenants().contains(&t);
    let draining = { let sup = sup.clone(); tokio::spawn(async move { sup.handover_quiesce().await }) };
    wait_for("drain begins during mint", Duration::from_secs(2), || sup.draining()).await;
    keys.release.notify_one();
    let refused = spawning.await.unwrap().is_err();
    draining.await.unwrap();
    let released = sup.writer_tenants().is_empty();
    sup.drain_all().await;
    sup.halt();
    reported_while_spawning && refused && released
}

async fn suite() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())))
        .with_writer(std::io::stderr)
        .try_init();
    let mnt = setup_dirs();
    let store = Arc::new(Store::default());
    let port = serve_store(store.clone()).await;
    let tr = Arc::new(Traffic::default());
    tokio::spawn(endpoint_poller(tr.clone()));
    tokio::spawn(client(tr.clone()));
    let ka_pool: Arc<Mutex<Vec<Pooled>>> = Arc::new(Mutex::new(Vec::new()));
    for id in 0..KEEPALIVE_CALLERS {
        tokio::spawn(keepalive_client(tr.clone(), ka_pool.clone(), id));
    }
    let producing = Arc::new(AtomicBool::new(true));
    {
        let (store, producing) = (store.clone(), producing.clone());
        tokio::spawn(async move {
            while producing.load(Ordering::SeqCst) {
                store.produce();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
    }
    let leases = |t: &str| store.with(t, |l| l.leases.len());
    let mut report: Vec<(String, bool, String)> = Vec::new();

    // ---- the running pod
    let a = start_cell(&mnt, "a", 60_000, port).await;
    tr.cells.lock().unwrap().push(a.clone());
    let a_ready = wait_for("pod a ready", Duration::from_secs(30), || a.ready.load(Ordering::SeqCst)).await;
    let a_writes = wait_for("pod a writes both tenants", Duration::from_secs(30), || {
        TENANTS.iter().all(|t| leases(t) == 1 && store.with(t, |l| l.committed > 0))
    })
    .await;
    report.push(("pod a: ready after its gated query warm, then writes".into(), true, format!("ready {a_ready:?}, writing {a_writes:?}")));

    // ---- an unready candidate aborts without changing incumbent writers
    tr.armed.store(true, Ordering::SeqCst);
    let abort = start_cell(&mnt, "abort", 65_000, port).await;
    tr.cells.lock().unwrap().push(abort.clone());
    tokio::time::sleep(Duration::from_secs(2)).await;
    let cold = call(&abort.sock, Method::GET, "/readyz", None).await.0 == 503;
    let before_abort: Vec<_> = TENANTS.iter().map(|t| store.with(t, |l| l.committed)).collect();
    let no_candidate_writer = abort.sup.writer_tenants().is_empty();
    abort.terminate().await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    report.push(("cold candidate abort: incumbent keeps serving and committing, no writer transfer".into(),
        cold && no_candidate_writer && a.ready.load(Ordering::SeqCst)
            && TENANTS.iter().enumerate().all(|(i, t)| leases(t) == 1 && store.with(t, |l| l.committed > before_abort[i]))
            && tr.failed.lock().unwrap().is_empty() && tr.no_ready.lock().unwrap().is_empty(),
        format!("cold {cold}, candidate writers {:?}", abort.sup.writer_tenants())));
    tr.cells.lock().unwrap().retain(|c| c.name != "abort");

    // ---- the roll: surge pod b
    tr.armed.store(true, Ordering::SeqCst);
    let b_started = Instant::now();
    let b = start_cell(&mnt, "b", 61_000, port).await;
    tr.cells.lock().unwrap().push(b.clone());
    let mut b_seen_unready = false;
    let mut b_wrote_early: Vec<String> = Vec::new();
    let t0 = Instant::now();
    while !b.ready.load(Ordering::SeqCst) {
        assert!(t0.elapsed() < Duration::from_secs(30), "pod b never became ready");
        if call(&b.sock, Method::GET, "/readyz", None).await.0 == 503 {
            b_seen_unready = true;
        }
        b_wrote_early.extend(b.ingest_tenants());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The moment b is Ready, every placed tenant's query[T] on it serves.
    let mut b_first: Vec<String> = Vec::new();
    for t in SEARCH_TENANTS {
        let (st, v) = call(&b.sock, Method::GET, &format!("/v1/tenants/{t}/query/v1/search?first"), Some(QUERY_TOKEN)).await;
        if st != 200 {
            b_first.push(format!("{t}: {st} {v}"));
        }
    }
    let b_ready_after = t0.elapsed();
    report.push(("pod b: Ready only once every placed tenant's query[T] serves (query_resident)".into(),
        b_first.is_empty() && b_ready_after >= Duration::from_millis(QUERY_ONLY_WARM_MS),
        format!("ready after {b_ready_after:?}, first searches failed: {b_first:?}")));
    // Overlap: both pods ready; b stays standby while a writes. The test
    // lists every pod name statically, so b also waits out one TTL on the
    // not-yet-existing `c.sock` (fail closed on a listed peer that never
    // answered); a DNS peer list only holds live pods. Terminate a after that
    // so the gap below measures the release protocol itself.
    let overlap = (Duration::from_secs(TTL_SECS) + Duration::from_millis(500)).saturating_sub(b_started.elapsed()).max(Duration::from_secs(2));
    tokio::time::sleep(overlap).await;
    b_wrote_early.extend(b.ingest_tenants());
    let standby = b.sup.status().handover.map(|h| h.standby.len()).unwrap_or(0);
    report.push(("pod b: not ready until its query prewarm completed".into(), b_seen_unready, format!("ready after {:?}", t0.elapsed())));
    report.push(("pod b: standby (no ingest) while pod a writes".into(),
        b_wrote_early.is_empty() && TENANTS.iter().all(|t| leases(t) == 1) && standby == TENANTS.len(),
        format!("early ingest {b_wrote_early:?}, standby {standby}")));

    let t1 = TenantId::new(TENANTS[0]).unwrap();
    report.push(("maintenance: incumbent holds compactor and standby rejects direct wake".into(),
        a.sup.ensure_running(&t1, Role::Maintenance).await.is_ok()
            && matches!(b.sup.ensure_running(&t1, Role::Maintenance).await,
                Err(nanosiem_lake_cell::supervisor::CellError::Standby(_))),
        "checked under maintenance spawn lock".into()));

    // ---- kubelet terminates a (b is Ready)
    let last_a_commit = |t: &str| store.with(t, |l| l.commits.iter().filter(|c| c.0 == 1).map(|c| c.4).max());
    let term = Instant::now();
    let a2 = a.clone();
    let drain = tokio::spawn(async move { a2.terminate().await });
    let takeover = wait_for("pod b takes over both writers", Duration::from_secs(20), || {
        TENANTS.iter().all(|t| leases(t) == 2 && store.with(t, |l| l.commits.iter().any(|c| c.0 == 2)))
    })
    .await;
    let gaps: Vec<String> = TENANTS
        .iter()
        .map(|t| {
            let first_b = store.with(t, |l| l.commits.iter().filter(|c| c.0 == 2).map(|c| c.4).min()).unwrap();
            let last_a = last_a_commit(t).unwrap_or(term);
            format!("{t}: {:?}", first_b.saturating_duration_since(last_a))
        })
        .collect();
    drain.await.unwrap();
    let drained = term.elapsed();
    report.push(("maintenance: predecessor releases every writer before successor admission".into(),
        a.sup.writer_tenants().is_empty() && b.sup.ensure_running(&t1, Role::Maintenance).await.is_ok(),
        format!("predecessor writers {:?}", a.sup.writer_tenants())));
    report.push(("planned roll: b claims each writer right after a releases it (flush + one poll)".into(), takeover < Duration::from_millis(1500),
        format!("takeover {takeover:?} after SIGTERM, commit gap {gaps:?}, a drained in {drained:?}")));
    tokio::time::sleep(Duration::from_secs(2)).await;
    tr.armed.store(false, Ordering::SeqCst);
    let (ok, failed, no_ready) =
        (tr.ok.load(Ordering::SeqCst), tr.failed.lock().unwrap().clone(), tr.no_ready.lock().unwrap().clone());
    report.push(("planned roll: every search answered (Service view)".into(), failed.is_empty() && ok > 50,
        format!("{ok} ok, {} failed {:?}", failed.len(), failed.iter().take(3).collect::<Vec<_>>())));
    report.push(("planned roll: never zero ready pods".into(), no_ready.is_empty(), format!("{} empty samples", no_ready.len())));
    let (ka_ok, ka_failed) = (tr.ka_ok.load(Ordering::SeqCst), tr.ka_failed.lock().unwrap().clone());
    report.push(("planned roll: every search on pooled keep-alive connections answered".into(), ka_failed.is_empty() && ka_ok > 50,
        format!("{ka_ok} ok, {} failed {:?}", ka_failed.len(), ka_failed.iter().take(3).collect::<Vec<_>>())));
    let (connects, closes) = (tr.ka_connects.load(Ordering::SeqCst), tr.ka_close_answers.load(Ordering::SeqCst));
    report.push(("planned roll: the draining pod retires pooled connections (Connection: close)".into(), closes > 0,
        format!("{closes} close answers, {connects} connections opened")));
    report.push(("pod b: ingest runs for both tenants".into(), b.ingest_tenants().len() == TENANTS.len(), format!("{:?}", b.ingest_tenants())));

    // ---- node loss: c warms, b dies without releasing
    let c = start_cell(&mnt, "c", 62_000, port).await;
    tr.cells.lock().unwrap().push(c.clone());
    wait_for("pod c ready", Duration::from_secs(30), || c.ready.load(Ordering::SeqCst)).await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let c_early = c.ingest_tenants();
    let crash = Instant::now();
    b.crash();
    let crash_takeover = wait_for("pod c takes over after the peer TTL", Duration::from_secs(TTL_SECS + 20), || {
        TENANTS.iter().all(|t| leases(t) == 3 && store.with(t, |l| l.commits.iter().any(|c| c.0 == 3)))
    })
    .await;
    report.push(("crash: c stays standby until b is gone, then takes over within the TTL".into(),
        c_early.is_empty() && crash_takeover >= Duration::from_secs(TTL_SECS - 1) && crash_takeover < Duration::from_secs(TTL_SECS + 10),
        format!("early {c_early:?}, takeover {crash_takeover:?} after the crash ({:?})", crash.elapsed())));

    // ---- drain the source and account for every event
    tokio::time::sleep(Duration::from_secs(1)).await;
    producing.store(false, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(50)).await;
    wait_for("every produced event committed", Duration::from_secs(20), || {
        TENANTS.iter().all(|t| store.with(t, |l| l.committed == l.head))
    })
    .await;
    for t in TENANTS {
        let (head, seqs_ok, fenced, conflicts, stale_pulls, epochs_ok, leases_n, commits_n) = store.with(t, |l| {
            let seqs_ok = l.seqs.len() as u64 == l.head && l.seqs.iter().enumerate().all(|(i, s)| *s == i as u64 + 1);
            let epochs_ok = l.commits.windows(2).all(|w| w[0].0 <= w[1].0 && w[0].4 <= w[1].4);
            (l.head, seqs_ok, l.stale_commits, l.conflicts, l.stale_pulls, epochs_ok, l.leases.len(), l.commits.len())
        });
        report.push((format!("{t}: every event committed exactly once, in order"), seqs_ok, format!("{head} events in {commits_n} commits")));
        report.push((format!("{t}: one writer at a time (no stale-epoch pull/commit, no conflict)"),
            fenced == 0 && conflicts == 0 && stale_pulls == 0 && epochs_ok && leases_n == 3,
            format!("stale commits {fenced}, stale pulls {stale_pulls}, conflicts {conflicts}, leases {leases_n}")));
    }

    tr.stop.store(true, Ordering::SeqCst);
    c.terminate().await;

    // ---- control: the same overlap WITHOUT the feature double-writes, so
    // the one-writer checks above are not vacuous.
    let store2 = Arc::new(Store::default());
    let port2 = serve_store(store2.clone()).await;
    let feeding = Arc::new(AtomicBool::new(true));
    {
        let (store2, feeding) = (store2.clone(), feeding.clone());
        tokio::spawn(async move {
            while feeding.load(Ordering::SeqCst) {
                store2.produce();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
    }
    let x = start_cell_with(&mnt, "x", 63_000, port2, false).await;
    wait_for("control pod x writes", Duration::from_secs(30), || store2.with("t1", |l| l.committed > 0)).await;
    let y = start_cell_with(&mnt, "y", 64_000, port2, false).await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    feeding.store(false, Ordering::SeqCst);
    let (stale, leases_n) = store2.with("t1", |l| (l.stale_pulls + l.stale_commits + l.conflicts, l.leases.len()));
    report.push(("control: without zero_downtime_roll the overlap runs two writers (fenced by storage)".into(),
        stale > 0 || leases_n > 2, format!("stale/conflicting requests {stale}, leases {leases_n}")));
    for cell in [&x, &y] {
        cell.sup.shutdown_all();
        cell.sup.halt();
        cell.router_task.abort();
    }

    report.push(("maintenance: SIGTERM during slow bootstrap mint prevents writer start".into(),
        drain_during_maintenance_mint(&mnt, port).await,
        "in-flight spawn reported as writing, then refused and released".into()));

    let mut failures = 0;
    println!("\n=== NAN-3004 zero-downtime roll ===");
    for (name, ok, detail) in &report {
        failures += usize::from(!ok);
        println!("{} {name:<78} {detail}", if *ok { "PASS" } else { "FAIL" });
    }
    println!("=== {} checks, {failures} failed ===", report.len());
    assert_eq!(failures, 0, "{failures} zero-downtime roll checks failed");
}
