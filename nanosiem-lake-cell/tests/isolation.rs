//! Isolation exit gate for the cell supervisor (NAN-2871, lean lake phase 5).
//!
//! Runs a real supervisor with real jailed stub tenant processes and probes
//! cross-tenant access from *inside* a tenant process:
//!
//! - cross-tenant file read (incl. files whose DAC would allow it),
//! - socket connect (pathname, abstract, router unix, router TCP), bind and
//!   listen,
//! - ptrace / process_vm_readv / signals,
//! - `/proc` snooping of other tenants and of the supervisor,
//! - credential access (another tenant's secret memfd, setuid, userns),
//! - one tenant hitting its memory limit does not affect another,
//! - an idle tenant costs ≈0 (no processes, no cgroup).
//!
//! The supervisor needs CAP_SETUID/SETGID and a writable cgroup subtree. On
//! a developer machine the test re-executes itself inside
//! `systemd-run --user -p Delegate=yes` + `unshare --user --map-root-user
//! --map-users=… --mount` (root in a user namespace with 65,535 mapped ids
//! and a delegated cgroup), which is the same privilege shape as a cell
//! container running as root in its own cgroup namespace. In CI as real
//! root it runs directly. Set `NANO_CELL_ISOLATION_REQUIRED=1` to make a
//! missing sandbox a failure instead of a skip.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::AUTHORIZATION;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use nanosiem_lake_cell::config::{CellConfig, CgroupPolicy, IngestMode, Placement, TenantPlacement};
use nanosiem_lake_cell::contract::{Role, TenantId};
use nanosiem_lake_cell::router::{self, Router};
use nanosiem_lake_cell::secrets::StaticKeySource;
use nanosiem_lake_cell::supervisor::Supervisor;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{chown, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const IN_SANDBOX: &str = "NANO_CELL_IN_SANDBOX";
const TOKEN: &str = "test-router-token-0123456789abcdef0123456789";
const QUERY_TOKEN: &str = "test-router-QUERY-token-0123456789abcdef012345";
const STUB: &str = env!("CARGO_BIN_EXE_nanosiem-lake-cell-stub");

fn tid(s: &str) -> TenantId {
    TenantId::new(s).unwrap()
}

fn secret(t: &str, r: Role) -> Vec<u8> {
    format!("bootstrap-token:{t}:{}", r.as_str()).into_bytes()
}

#[test]
fn isolation_suite() {
    // SAFETY: geteuid never fails.
    let root = unsafe { libc::geteuid() } == 0;
    // Docker's default root lacks CAP_SYS_ADMIN, which the mount replica
    // needs. Preserve the explicit required mode as a hard failure.
    if root && !has_cap_sys_admin() {
        let msg = "SKIPPED: root lacks CAP_SYS_ADMIN for the mount namespace replica";
        assert!(std::env::var("NANO_CELL_ISOLATION_REQUIRED").is_err(), "{msg}");
        eprintln!("{msg}");
        return;
    }
    if std::env::var(IN_SANDBOX).is_err() && !root {
        return reexec_in_sandbox();
    }
    // Namespaces are per thread: unshare the cgroup namespace (5A replica)
    // before the runtime starts its worker threads, like a pod's process.
    let _ = RO_CGROUP.set(setup_ro_cgroup());
    tokio::runtime::Builder::new_multi_thread().worker_threads(4).enable_all().build().unwrap().block_on(suite());
}

fn has_cap_sys_admin() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                line.strip_prefix("CapEff:")
                    .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
            })
        })
        .is_some_and(|caps| caps & (1 << 21) != 0)
}

fn tool(name: &str) -> bool {
    std::process::Command::new("sh")
        .args(["-c", &format!("command -v {name}")])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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
    // The live cell's exact capability set (FRO-737 mode 5A, CapEff
    // 0x2000e9): no DAC_OVERRIDE / DAC_READ_SEARCH / FSETID. Root's execve
    // inside the namespace gets permitted = bounding set.
    if std::env::var("NANO_CELL_ISOLATION_FULL_CAPS").is_err() && tool("setpriv") {
        cmd.args(["setpriv", "--inh-caps=-all", "--bounding-set=-all,+chown,+fowner,+kill,+setgid,+setuid,+sys_admin", "--"]);
    }
    cmd.arg(exe)
        .args(["isolation_suite", "--exact", "--nocapture", "--test-threads=1"]);
    let status = cmd.status().expect("run sandbox");
    assert!(status.success(), "isolation suite failed inside the sandbox: {status}");
}

/// Run `f` on this thread with fsuid/fsgid set to `dir`'s owner. The
/// sandbox holds the cell's exact capabilities (no DAC_OVERRIDE /
/// DAC_READ_SEARCH / FSETID), so fixture writes inside tenant-owned
/// directories must go through the owner's permissions, like the
/// supervisor's own repairs do.
fn as_owner_of<T>(dir: &Path, f: impl FnOnce() -> T) -> T {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
    struct Restore(u32, u32);
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: per-thread credential syscalls.
            unsafe {
                libc::setfsuid(self.0);
                libc::setfsgid(self.1);
            }
        }
    }
    // SAFETY: per-thread credential syscalls; restored by `Restore`.
    let _r = unsafe {
        let g = libc::setfsgid(m.gid()) as u32;
        let u = libc::setfsuid(m.uid()) as u32;
        Restore(u, g)
    };
    f()
}

// ------------------------------------------------------------------ client

async fn call(sock: &Path, method: Method, path: &str, body: Option<Value>, auth: bool) -> (u16, Value) {
    call_as(sock, method, path, body, auth.then_some(TOKEN)).await
}

async fn call_as(sock: &Path, method: Method, path: &str, body: Option<Value>, token: Option<&str>) -> (u16, Value) {
    let stream = match tokio::net::UnixStream::connect(sock).await {
        Ok(s) => s,
        Err(e) => return (0, json!({"client_error": e.to_string()})),
    };
    let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(conn);
    let mut req = Request::builder().method(method).uri(path).header("host", "cell");
    if let Some(t) = token {
        req = req.header(AUTHORIZATION, format!("Bearer {t}"));
    }
    let body = body.map(|b| b.to_string()).unwrap_or_default();
    let req = req.body(Full::new(Bytes::from(body))).unwrap();
    match s.send_request(req).await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let v = serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()));
            (status, v)
        }
        Err(e) => (0, json!({"client_error": e.to_string()})),
    }
}

struct Cell {
    sock: PathBuf,
    sup: Arc<Supervisor>,
}

impl Cell {
    async fn probe(&self, tenant: &str, kind: &str, query: &str) -> Value {
        let (st, v) = call(&self.sock, Method::GET, &format!("/v1/tenants/{tenant}/query/probe/{kind}?{query}"), None, true).await;
        assert_eq!(st, 200, "probe {kind} on {tenant}: {v}");
        v
    }
    async fn whoami(&self, tenant: &str) -> Value {
        self.probe(tenant, "whoami", "").await
    }
    /// One RPC straight to the tenant's Detect process, as the supervisor
    /// opens it (the router no longer forwards /detect there).
    async fn detect_probe(&self, tenant: &str, path: &str) -> (u16, Value) {
        let (_guard, request_id, stream) = match self.sup.open_rpc(&tid(tenant), Role::Detect).await {
            Ok(x) => x,
            Err(e) => return (0, json!({"client_error": e.to_string()})),
        };
        let (mut s, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
        tokio::spawn(conn);
        let req = Request::builder().method(Method::GET).uri(path).header("host", "cell")
            .header("x-nano-cell-tenant", tenant).header("x-nano-cell-request-id", request_id)
            .body(Full::new(Bytes::new())).unwrap();
        match s.send_request(req).await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let bytes = resp.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                (status, serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into())))
            }
            Err(e) => (0, json!({"client_error": e.to_string()})),
        }
    }
    async fn wake(&self, tenant: &str, role: &str, reason: &str) -> Value {
        let (st, v) = call(&self.sock, Method::POST, &format!("/v1/tenants/{tenant}/wake"),
            Some(json!({"role": role, "reason": reason})), true).await;
        assert_eq!(st, 200, "wake {tenant}/{role}: {v}");
        v
    }
    async fn status(&self) -> Value {
        call(&self.sock, Method::GET, "/v1/status", None, true).await.1
    }
    fn tenant_status(status: &Value, t: &str) -> Value {
        status["tenants"].as_array().unwrap().iter().find(|x| x["tenant_id"] == t).cloned().unwrap()
    }
    fn pid_of(status: &Value, t: &str, role: &str) -> Option<u64> {
        Self::tenant_status(status, t)["processes"].as_array()?.iter().find(|p| p["role"] == role)?["pid"].as_u64()
    }
}

// ------------------------------------------------------------------ report

#[derive(Default)]
struct Report {
    rows: Vec<(String, bool, String)>,
}

impl Report {
    /// Record a probe that must be DENIED.
    fn denied(&mut self, name: &str, v: &Value) {
        let ok = v["ok"] == false;
        self.rows.push((format!("DENY  {name}"), ok, compact(v)));
    }
    /// A probe that must be denied with exactly `errno` (not by accident).
    fn denied_errno(&mut self, name: &str, v: &Value, errno: i64) {
        let ok = v["ok"] == false && v["errno"] == errno;
        self.rows.push((format!("DENY  {name} (errno {errno})"), ok, compact(v)));
    }
    /// Record a positive control that must SUCCEED.
    fn allowed(&mut self, name: &str, v: &Value) {
        let ok = v["ok"] == true;
        self.rows.push((format!("ALLOW {name}"), ok, compact(v)));
    }
    fn check(&mut self, name: &str, ok: bool, detail: impl Into<String>) {
        self.rows.push((format!("CHECK {name}"), ok, detail.into()));
    }
    fn finish(self) {
        let mut failed = 0;
        println!("\n=== NAN-2871 isolation suite ===");
        for (name, ok, detail) in &self.rows {
            if !ok {
                failed += 1;
            }
            println!("{} {name:<70} {detail}", if *ok { "PASS" } else { "FAIL" });
        }
        println!("=== {} checks, {} failed ===", self.rows.len(), failed);
        let dir = PathBuf::from(std::env::var("HOME").unwrap()).join(".cache/nan2871");
        let _ = std::fs::create_dir_all(&dir);
        let rows: Vec<Value> =
            self.rows.iter().map(|(n, ok, d)| json!({"check": n, "pass": ok, "detail": d})).collect();
        let _ = std::fs::write(dir.join("isolation-report.json"), serde_json::to_vec_pretty(&rows).unwrap());
        assert_eq!(failed, 0, "{failed} isolation checks failed");
    }
}

fn compact(v: &Value) -> String {
    let s = v.to_string();
    s.chars().take(140).collect()
}

// ------------------------------------------------------------------ suite

fn setup_dirs() -> PathBuf {
    let host = PathBuf::from(std::env::var("HOME").unwrap()).join(format!(".cache/nan2871/iso-{}", std::process::id()));
    std::fs::create_dir_all(&host).unwrap();
    // Tenant uids cannot traverse $HOME (0700); expose the test tree at /mnt
    // inside our private mount namespace.
    let mnt = PathBuf::from("/mnt");
    let src = std::ffi::CString::new(host.to_str().unwrap()).unwrap();
    let dst = std::ffi::CString::new("/mnt").unwrap();
    // SAFETY: bind mount in our own mount namespace.
    let rc = unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()) };
    assert_eq!(rc, 0, "bind mount: {}", std::io::Error::last_os_error());
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
    let feeds = mnt.join("feeds");
    std::fs::create_dir_all(&feeds).unwrap();
    std::fs::write(feeds.join("ipinfo.mmdb"), b"shared feed").unwrap();
    std::fs::set_permissions(&feeds, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(feeds.join("ipinfo.mmdb"), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(mnt.join("secret/router.token"), TOKEN).unwrap();
    std::fs::write(mnt.join("secret/router-query.token"), QUERY_TOKEN).unwrap();
    std::fs::set_permissions(mnt.join("secret/router-query.token"), std::fs::Permissions::from_mode(0o400)).unwrap();
    std::fs::set_permissions(mnt.join("secret/router.token"), std::fs::Permissions::from_mode(0o600)).unwrap();
    mnt
}

const TEST_CGW: &str = "/run/test-delegator-cgroup";
static RO_CGROUP: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

/// Play the delegator: chown the scope's delegation files, then the
/// directory last (the done signal), to `uid`.
fn delegate_scope_to(uid: u32) {
    let root = Path::new(TEST_CGW);
    for f in ["cgroup.procs", "cgroup.threads", "cgroup.subtree_control", ""] {
        let p = if f.is_empty() { root.to_path_buf() } else { root.join(f) };
        chown(&p, Some(uid), Some(uid)).unwrap_or_else(|e| panic!("chown {}: {e}", p.display()));
    }
}

/// Replicate the 5A pod: a private /run (tmpfs, like the emptyDir at
/// /run/nano-cell-supervisor), /sys/fs/cgroup showing only our (delegated)
/// transient unit and read-only (EROFS for us, while we own the scope), and
/// our own cgroup namespace rooted there, like a pod's.
fn setup_ro_cgroup() -> bool {
    let c = |s: &str| std::ffi::CString::new(s).unwrap();
    let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let Some(rel) = own.lines().find_map(|l| l.strip_prefix("0::")).map(|r| r.trim().to_owned()) else { return false };
    let scope = format!("/sys/fs/cgroup{rel}");
    // SAFETY: mounts/unshare in our private mount namespace.
    unsafe {
        let try_ = |rc: i32, what: &str| {
            if rc != 0 {
                eprintln!("5A replica: {what}: {}", std::io::Error::last_os_error());
            }
            rc == 0
        };
        if !try_(libc::mount(c("tmpfs").as_ptr(), c("/run").as_ptr(), c("tmpfs").as_ptr(), libc::MS_NOSUID | libc::MS_NODEV, std::ptr::null()), "tmpfs /run") {
            return false;
        }
        if !try_(libc::mount(c(&scope).as_ptr(), c("/sys/fs/cgroup").as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null()), "bind scope") {
            return false;
        }
        let ro = libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        if !try_(libc::mount(std::ptr::null(), c("/sys/fs/cgroup").as_ptr(), std::ptr::null(), ro, std::ptr::null()), "remount ro") {
            return false;
        }
        if !try_(libc::unshare(libc::CLONE_NEWCGROUP), "unshare cgroupns") {
            return false;
        }
        // The test's own writable view (standing in for the node-side
        // delegator, which chowns the scope from outside).
        let _ = std::fs::create_dir_all(TEST_CGW);
        if !try_(libc::mount(c("cgroup2").as_ptr(), c(TEST_CGW).as_ptr(), c("cgroup2").as_ptr(), 0, std::ptr::null()), "test cgroup view") {
            return false;
        }
    }
    true
}

fn config(mnt: &Path, name: &str, cgroup: CgroupPolicy, idle_secs: u64) -> CellConfig {
    let v = json!({
        "cell_id": name,
        "mode": "pooled",
        "data_dir": mnt.join(format!("{name}-data")),
        "state_dir": mnt.join(format!("{name}-state")),
        "feed_dir": mnt.join("feeds"),
        "ingest_binary": mnt.join("bin/stub"),
        "query_binary": mnt.join("bin/stub"),
        "idle_timeout_secs": idle_secs,
        "query_idle_timeout_secs": idle_secs,
        // These checks exercise on-demand reaping; the NAN-2989 residency
        // rule (query kept while ingest works) is unit-tested in the supervisor.
        "query_resident_ingest_window_secs": 0,
        "query_resident_search_window_secs": 0,
        "query_resident": false,
        "warm_query": 1,
        "warm_ingest": 0,
        "spawn_timeout_secs": 10,
        "shutdown_grace_ms": 1000,
        "stall_kill_secs": 60,
        "require_landlock": true,
        // NAN-3523 opt-out: these cells run pooled before delegation
        // (adopt-after-start) and with `off`; fail-closed is unit-tested.
        "isolation": {"cgroup": cgroup, "watchdog": true, "allow_pooled_watchdog_only": true},
        "listen_unix": mnt.join(format!("run/{name}.sock")),
        "router_token_file": mnt.join("secret/router.token"),
        "router_query_token_file": mnt.join("secret/router-query.token"),
        "placement_file": mnt.join(format!("{name}-placement.json")),
        "dev_key_dir": mnt.join("secret"),
        // The sandbox shares the host's pid namespace, so the watchdog sees
        // every process on the box: size the cell far above it so host load
        // is never "cell contention" here.
        "resources": {"interval_ms": 250, "cell_cpu_millicores": 10_000_000, "cell_memory_bytes": (1u64 << 50),
            "throttle_period_ms": 50, "cpu_smoothing_secs": 0.5, "restart_backoff_base_ms": 200,
            // The throttle checks drive CPU through the query role; the
            // NAN-3008 query exemption is covered in tests/watchdog.rs.
            "query_unthrottled": false},
    });
    serde_json::from_value(v).unwrap()
}

async fn start_cell(cfg: CellConfig, tenants: &[(&str, f64)]) -> Cell {
    start_cell_placed(cfg, tenants.iter().map(|(t, eps)| TenantPlacement::legacy(tid(t), *eps)).collect()).await
}

async fn start_cell_placed(cfg: CellConfig, tenants: Vec<TenantPlacement>) -> Cell {
    let mut keys = StaticKeySource::default();
    for tp in &tenants {
        for r in Role::ALL {
            keys = keys.with(&tp.tenant_id, r, &secret(tp.tenant_id.as_str(), r));
        }
    }
    let sup = Supervisor::new(cfg.clone(), Arc::new(keys)).expect("supervisor");
    sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 1, tenants }).await.unwrap();
    sup.start_background();
    let router = Router::new(sup.clone()).unwrap();
    let sock = cfg.listen_unix.clone().unwrap();
    let l = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(router::serve_unix(router, l));
    Cell { sock, sup }
}

fn tenant_uid_procs(base: u32, slots: u32) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let end = base + 2 * slots + (65_534 - base - 2 * slots).min(slots);
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status")) else { continue };
        // A killed double-fork may remain in /proc as a zombie until its
        // adoptive parent reaps it. It cannot execute or hold resources.
        if s.lines().any(|line| line.starts_with("State:") && line.split_whitespace().nth(1) == Some("Z")) {
            continue;
        }
        if let Some(uid) = s.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|v| v.split_whitespace().next()?.parse::<u32>().ok()) {
            if uid >= base && uid < end {
                out.push((pid, uid));
            }
        }
    }
    out
}

async fn suite() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into())))
        .with_writer(std::io::stderr)
        .try_init();
    let mnt = setup_dirs();
    let ro_cgroup = *RO_CGROUP.get().unwrap_or(&false);
    let mut r = Report::default();
    let cfg = config(&mnt, "cell-a", CgroupPolicy::Auto, 6);
    // Adopt-after-start: the delegator has not handed the scope over yet.
    if ro_cgroup {
        delegate_scope_to(65534);
    }
    let cell = start_cell(cfg.clone(), &[("alpha", 20.0), ("bravo", 20.0)]).await;
    if ro_cgroup {
        let pre = cell.sup.limits_mode();
        r.check("adopt-after-start: boots in watchdog mode before delegation", format!("{pre:?}") == "Watchdog", format!("{pre:?}"));
        // Tenants running (plus a warm process) before the delegation appears.
        let a0 = cell.whoami("alpha").await;
        let b0 = cell.whoami("bravo").await;
        let (a0p, b0p) = (a0["pid"].as_u64().unwrap(), b0["pid"].as_u64().unwrap());
        delegate_scope_to(0);
        let t0 = Instant::now();
        // Keep both tenants busy (idle timeout is 6 s, the adoption poll 5 s).
        while format!("{:?}", cell.sup.limits_mode()) != "CgroupV2" && t0.elapsed() < Duration::from_secs(20) {
            tokio::time::sleep(Duration::from_millis(500)).await;
            cell.whoami("alpha").await;
            cell.whoami("bravo").await;
        }
        r.check("adopt-after-start: delegation adopted live", format!("{:?}", cell.sup.limits_mode()) == "CgroupV2",
            format!("after {:?}", t0.elapsed()));
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            cell.whoami("alpha").await;
            cell.whoami("bravo").await;
        }
        let cg_of = |pid: u64| std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default().trim().to_owned();
        let slot = |uid: u64| (uid - cfg.uid_base as u64) / 2;
        let (ea, eb) = (format!("0::/tenants/s{}/query", slot(a0["uid"].as_u64().unwrap())),
            format!("0::/tenants/s{}/query", slot(b0["uid"].as_u64().unwrap())));
        r.check("adopt-after-start: running tenants moved live into their leaves (same pids)",
            cg_of(a0p) == ea && cg_of(b0p) == eb, format!("{} / {}", cg_of(a0p), cg_of(b0p)));
        let a1 = cell.whoami("alpha").await;
        r.check("adopt-after-start: tenant kept serving through adoption", a1["pid"] == a0["pid"], format!("{} -> {}", a0p, a1["pid"]));
        let own = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
        r.check("adopt-after-start: supervisor alone in init/, limbo removed",
            own.trim() == "0::/init" && !Path::new(TEST_CGW).join("limbo").exists()
                && std::fs::read_to_string(Path::new(TEST_CGW).join("init/cgroup.procs")).unwrap_or_default().split_whitespace().count() == 1,
            own.trim().to_owned());
        let wv = std::fs::read_to_string(Path::new(TEST_CGW).join("warm/cgroup.procs")).unwrap_or_default();
        r.check("adopt-after-start: warm process moved to warm/", !wv.trim().is_empty(), wv.trim().replace('\n', ","));
        // Pre-adoption processes have no cgroup namespace: replace them so
        // the rest of the suite runs on processes jailed with it.
        cell.sup.drain(&tid("alpha"));
        cell.sup.drain(&tid("bravo"));
        tokio::time::sleep(Duration::from_millis(1500)).await;
    }
    let mode = cell.sup.limits_mode();
    println!("limits mode: {mode:?}; landlock ABI {}", nanosiem_lake_cell::supervisor::landlock_abi());
    r.check("limits mode is cgroup_v2 in the sandbox", format!("{mode:?}") == "CgroupV2", format!("{mode:?}"));
    // The 5A shape: /sys/fs/cgroup read-only, rooted at the (delegated)
    // cell scope; the supervisor must adopt through its private mount.
    let method = cell.status().await["cgroup_mount"].clone();
    r.check("5A replica: read-only /sys/fs/cgroup, adopted via the private cgroup2 mount",
        ro_cgroup && method == "private_mount", format!("ro {ro_cgroup}, method {method}"));

    // --- Positive controls: the jailed process works for its own tenant.
    let t0 = Instant::now();
    let a = cell.whoami("alpha").await;
    let cold_ms = t0.elapsed().as_millis();
    let b = cell.whoami("bravo").await;
    let uid_a = a["uid"].as_u64().unwrap();
    let uid_b = b["uid"].as_u64().unwrap();
    r.check("alpha/query runs as its own uid", uid_a != 0 && uid_a != uid_b, format!("alpha {uid_a}, bravo {uid_b}"));
    // NAN-2932: the router serves /detect reads from the tenant's query
    // process (the Detect child is the drain). Probe the Detect process's
    // own jail over a supervisor RPC stream, and prove the route placement.
    let (routed_status, routed) = call(&cell.sock, Method::GET, "/v1/tenants/alpha/detect/probe/whoami", None, true).await;
    r.check("alpha /detect route is served by alpha/query", routed_status == 200
        && routed["pid"] == a["pid"] && routed["uid"] == a["uid"], compact(&routed));
    let (detect_status, detect) = cell.detect_probe("alpha", "/probe/whoami").await;
    r.check("alpha/detect has a separate uid and process", detect_status == 200
        && detect["uid"].as_u64().is_some_and(|uid| uid != uid_a && uid != 0)
        && detect["pid"] != a["pid"], compact(&detect));
    let (detect_write, detect_result) = cell.detect_probe("alpha",
        &format!("/probe/write?path={}", cfg.data_dir.join("tenants/alpha/parts/detect-own").display())).await;
    r.check("alpha/detect can write only its tenant part directory", detect_write == 200 && detect_result["ok"] == true, compact(&detect_result));
    let (foreign_write, foreign_result) = cell.detect_probe("alpha",
        &format!("/probe/write?path={}", cfg.data_dir.join("tenants/bravo/parts/detect-foreign").display())).await;
    r.check("alpha/detect cannot write another tenant part directory", foreign_write != 200 || foreign_result["ok"] != true, compact(&foreign_result));
    r.check("secret delivered by fd (alpha)", a["secret_sha256"] == hex::encode(Sha256::digest(secret("alpha", Role::Query))), a["secret_sha256"].to_string());
    r.check("secrets are per tenant", a["secret_sha256"] != b["secret_sha256"], "");
    let env: Vec<String> = serde_json::from_value(a["env"].clone()).unwrap();
    let ps = &a["status"];
    r.check("jailed process has no capabilities", ps["CapEff"] == "0000000000000000" && ps["CapPrm"] == "0000000000000000" && ps["CapAmb"] == "0000000000000000", compact(ps));
    // Emptying the bounding set needs CAP_SETPCAP, which the 5A cell set
    // (CHOWN FOWNER KILL SETGID SETUID SYS_ADMIN) lacks: the drop is best
    // effort there, and no_new_privs + empty eff/prm/inh/amb are what keep
    // the tenant from regaining anything.
    let own_bnd = std::fs::read_to_string("/proc/self/status").ok().and_then(|s| {
        s.lines().find_map(|l| l.strip_prefix("CapBnd:")).and_then(|v| u64::from_str_radix(v.trim(), 16).ok())
    });
    let can_setpcap = own_bnd.is_some_and(|b| b & (1 << 8) != 0); // bit 8 = CAP_SETPCAP
    r.check(
        "capability bounding set emptied (or cell lacks CAP_SETPCAP)",
        ps["CapBnd"] == "0000000000000000" || (!can_setpcap && ps["CapInh"] == "0000000000000000"),
        compact(ps),
    );
    r.check("no_new_privs set, seccomp filter mode", ps["NoNewPrivs"] == "1" && ps["Seccomp"] == "2", compact(ps));
    r.check("no supplementary groups", ps["Groups"] == "", compact(ps));
    r.check("env carries no secret", env.iter().all(|k| ["PATH", "LANG", "TMPDIR", "HOME", "RUST_LOG"].contains(&k.as_str())), format!("{env:?}"));
    // ABI ≥ 9 kernels (7.1+) enforce every right this crate asks for.
    let want_full = nanosiem_lake_cell::supervisor::landlock_abi() >= 9;
    r.check("landlock enforced (full on ABI ≥ 9)", a["landlock"] != "none" && (!want_full || a["landlock"] == "full"), a["landlock"].to_string());
    // Debug build on a shared, loaded dev box: a generous bound; the
    // spawn_ms figures in the report are the measurement.
    r.check("first query (spawn + jail + route) < 5 s", cold_ms < 5000, format!("{cold_ms} ms"));
    let (_, hdrs) = call(&cell.sock, Method::GET, "/v1/tenants/alpha/query/headers", None, true).await;
    r.check("router token never forwarded to the tenant", hdrs.get("authorization").is_none() && hdrs["x-nano-cell-tenant"] == "alpha", compact(&hdrs));
    let (unauth, _) = call(&cell.sock, Method::GET, "/v1/tenants/alpha/query/probe/whoami", None, false).await;
    r.check("router rejects unauthenticated requests", unauth == 401, unauth.to_string());
    // Query-only token: query routes and status; everything else 403.
    let q = Some(QUERY_TOKEN);
    let (s, v) = call_as(&cell.sock, Method::GET, "/v1/tenants/alpha/query/probe/whoami", None, q).await;
    r.check("query token: query route allowed", s == 200 && v["tenant"] == "alpha", s.to_string());
    let (s, v) = call_as(&cell.sock, Method::GET, "/v1/tenants/alpha/query/headers", None, q).await;
    r.check("query token: never forwarded to the tenant", s == 200 && v.get("authorization").is_none(), compact(&v));
    let (s, _) = call_as(&cell.sock, Method::GET, "/v1/status", None, q).await;
    r.check("query token: status allowed", s == 200, s.to_string());
    // router-query-token-wake: the control plane's prewarm probe.
    let (s, v) = call_as(&cell.sock, Method::POST, "/v1/tenants/alpha/wake", Some(json!({"role": "query", "reason": "prewarm"})), q).await;
    r.check("query token: query-role wake allowed", s == 200 && v["role"] == "query", format!("{s} {}", compact(&v)));
    for (m, p, body) in [
        (Method::POST, "/v1/tenants/alpha/wake", Some(json!({"role": "ingest", "reason": "data_arrival"}))),
        (Method::POST, "/v1/tenants/alpha/wake", Some(json!({"role": "detect", "reason": "detection"}))),
        (Method::POST, "/v1/tenants/alpha/drain", None),
        (Method::GET, "/v1/signals", None),
        (Method::GET, "/metrics", None),
        (Method::GET, "/v1/nope", None),
    ] {
        let (s, _) = call_as(&cell.sock, m.clone(), p, body, q).await;
        r.check(&format!("query token: {m} {p} refused (403)"), s == 403, s.to_string());
    }
    let (s, _) = call_as(&cell.sock, Method::GET, "/v1/signals", None, Some(TOKEN)).await;
    r.check("full token: signals allowed", s == 200, s.to_string());
    let (np, _) = call(&cell.sock, Method::GET, "/v1/tenants/zulu/query/probe/whoami", None, true).await;
    r.check("tenant not placed on this cell is refused", np == 404, np.to_string());

    // Ingest writes a part; query of the same tenant can read it.
    cell.wake("alpha", "ingest", "data_arrival").await;
    cell.wake("bravo", "ingest", "data_arrival").await;
    tokio::time::sleep(Duration::from_millis(400)).await;
    let data = cfg.data_dir.join("tenants");
    let a_part = data.join("alpha/parts/part-000000.parquet");
    let b_part = data.join("bravo/parts/part-000000.parquet");
    r.allowed("alpha/query reads alpha's own part", &cell.probe("alpha", "read", &format!("path={}", a_part.display())).await);
    r.allowed("alpha/query reads the shared feed", &cell.probe("alpha", "read", "path=/mnt/feeds/ipinfo.mmdb").await);
    r.allowed("alpha/query reads its own /proc/<pid>/status", &cell.probe("alpha", "proc", &format!("pid={}&file=status", a["pid"])).await);

    // --- Cross-tenant files.
    r.denied("alpha reads bravo's part", &cell.probe("alpha", "read", &format!("path={}", b_part.display())).await);
    r.denied("alpha lists the tenants dir", &cell.probe("alpha", "list", &format!("path={}", data.display())).await);
    r.denied("alpha lists bravo's tenant dir", &cell.probe("alpha", "list", &format!("path={}", data.join("bravo").display())).await);
    r.denied("alpha stats bravo's query dir", &cell.probe("alpha", "list", &format!("path={}", data.join("bravo/query").display())).await);
    // Defense in depth: make a bravo file world-readable in world-traversable
    // dirs. DAC would now allow it; landlock must still deny.
    let leak = data.join("bravo/parts/world-readable.txt");
    as_owner_of(&data.join("bravo/parts"), || {
        std::fs::write(&leak, "bravo data").unwrap();
        std::fs::set_permissions(&leak, std::fs::Permissions::from_mode(0o644)).unwrap();
    });
    let saved: Vec<(PathBuf, u32)> = [data.clone(), data.join("bravo"), data.join("bravo/parts")]
        .into_iter()
        .map(|p| {
            use std::os::unix::fs::MetadataExt;
            let m = std::fs::metadata(&p).unwrap().mode() & 0o7777;
            as_owner_of(&p, || std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755 | (m & 0o2000))).unwrap());
            (p, m)
        })
        .collect();
    r.denied("alpha reads a world-readable bravo file (landlock alone)", &cell.probe("alpha", "read", &format!("path={}", leak.display())).await);
    for (p, m) in saved {
        as_owner_of(&p, || std::fs::set_permissions(&p, std::fs::Permissions::from_mode(m)).unwrap());
    }
    r.denied("alpha reads the supervisor uid map", &cell.probe("alpha", "read", &format!("path={}", cfg.state_dir.join("uids.json").display())).await);
    r.denied("alpha reads the router token", &cell.probe("alpha", "read", "path=/mnt/secret/router.token").await);
    r.denied("alpha reads /etc/shadow", &cell.probe("alpha", "read", "path=/etc/shadow").await);
    r.denied("alpha/query writes into its own parts dir (read-only)", &cell.probe("alpha", "write", &format!("path={}", data.join("alpha/parts/x").display())).await);
    r.denied("alpha/query reads alpha/ingest's state dir", &cell.probe("alpha", "list", &format!("path={}", data.join("alpha/ingest").display())).await);
    r.denied("alpha uses a shared /tmp", &cell.probe("alpha", "mkdir_tmp", "").await);

    // --- Sockets.
    let b_sock = data.join("bravo/query/listener.sock");
    let _l1 = as_owner_of(&data.join("bravo/query"), || {
        let _ = std::fs::remove_file(&b_sock);
        let l = std::os::unix::net::UnixListener::bind(&b_sock).unwrap();
        chown(&b_sock, Some(uid_b as u32), None).unwrap();
        std::fs::set_permissions(&b_sock, std::fs::Permissions::from_mode(0o777)).unwrap();
        l
    });
    use std::os::linux::net::SocketAddrExt;
    let abs = std::os::unix::net::SocketAddr::from_abstract_name(b"nano-cell-test-abstract").unwrap();
    let _l2 = std::os::unix::net::UnixListener::bind_addr(&abs).unwrap();
    r.check("harness can reach the abstract socket (control)", std::os::unix::net::UnixStream::connect_addr(&abs).is_ok(), "");
    r.denied("alpha connects to a socket in bravo's dir", &cell.probe("alpha", "connect_unix", &format!("path={}", b_sock.display())).await);
    r.denied("alpha connects to an abstract socket", &cell.probe("alpha", "connect_abstract", "name=nano-cell-test-abstract").await);
    r.denied("alpha connects to the router unix socket", &cell.probe("alpha", "connect_unix", &format!("path={}", cell.sock.display())).await);
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_addr = tcp.local_addr().unwrap();
    let router_tcp = Router::new(cell.sup.clone()).unwrap();
    tokio::spawn(router::serve_tcp(router_tcp, tcp));
    r.denied("alpha connects to the router over TCP", &cell.probe("alpha", "connect_tcp", &format!("addr={tcp_addr}")).await);
    r.denied("alpha binds a TCP port", &cell.probe("alpha", "bind_tcp", "addr=127.0.0.1:0").await);
    let lu = cell.probe("alpha", "listen_unix", "").await;
    r.denied("alpha listens on a unix socket", &lu["listen"]);
    r.denied("alpha opens an AF_UNIX datagram socket", &cell.probe("alpha", "unix_dgram", "").await);
    // NAN-3567: the datagram-pair route to an abstract socket, with a live
    // abstract datagram receiver standing in for bravo.
    let abs_dgram = std::os::unix::net::SocketAddr::from_abstract_name(b"nano-cell-test-abstract-dgram").unwrap();
    let _d = std::os::unix::net::UnixDatagram::bind_addr(&abs_dgram).unwrap();
    r.denied_errno(
        "alpha sends to an abstract socket from a datagram socketpair",
        &cell.probe("alpha", "unix_dgram_pair_sendto", "name=nano-cell-test-abstract-dgram").await,
        libc::EPERM as i64,
    );
    // Symlink race guard: plant a symlink where the supervisor repairs a
    // tenant dir; the repair must refuse, never chown the target.
    let tmp = data.join("bravo/ingest/tmp");
    as_owner_of(&data.join("bravo/ingest"), || {
        let _ = std::fs::remove_dir(&tmp);
        std::os::unix::fs::symlink(&cfg.state_dir, &tmp).unwrap();
    });
    cell.sup.drain(&tid("bravo"));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let (st_sym, _) = call(&cell.sock, Method::POST, "/v1/tenants/bravo/wake", Some(json!({"role": "ingest", "reason": "data_arrival"})), true).await;
    use std::os::unix::fs::MetadataExt;
    let state_owner = std::fs::metadata(&cfg.state_dir).unwrap().uid();
    r.check("symlinked tenant dir is refused, target not chowned", st_sym == 503 && state_owner == 0, format!("wake {st_sym}, state_dir uid {state_owner}"));
    as_owner_of(&data.join("bravo/ingest"), || std::fs::remove_file(&tmp).unwrap());
    cell.wake("bravo", "ingest", "data_arrival").await;
    cell.whoami("bravo").await;
    cell.whoami("alpha").await;
    cell.wake("alpha", "ingest", "prewarm").await;
    r.denied("alpha opens a netlink socket", &cell.probe("alpha", "socket_netlink", "").await);

    // --- ptrace, memory, signals.
    let st = cell.status().await;
    let b_q = Cell::pid_of(&st, "bravo", "query").unwrap();
    let a_i = Cell::pid_of(&st, "alpha", "ingest").unwrap();
    let sup_pid = std::process::id();
    r.denied("alpha ptraces bravo/query", &cell.probe("alpha", "ptrace", &format!("pid={b_q}")).await);
    r.denied("alpha/query ptraces alpha/ingest", &cell.probe("alpha", "ptrace", &format!("pid={a_i}")).await);
    r.denied("alpha ptraces the supervisor", &cell.probe("alpha", "ptrace", &format!("pid={sup_pid}")).await);
    r.denied("alpha process_vm_readv bravo", &cell.probe("alpha", "process_vm_readv", &format!("pid={b_q}")).await);
    r.denied("alpha signals bravo", &cell.probe("alpha", "kill", &format!("pid={b_q}")).await);
    r.denied("alpha signals the supervisor", &cell.probe("alpha", "kill", &format!("pid={sup_pid}")).await);
    r.denied("alpha signals bravo through a pidfd", &cell.probe("alpha", "pidfd_signal", &format!("pid={b_q}")).await);

    // --- /proc snooping.
    for f in ["environ", "cmdline", "maps", "status", "fd", "mem"] {
        r.denied(&format!("alpha reads /proc/<bravo>/{f}"), &cell.probe("alpha", "proc", &format!("pid={b_q}&file={f}")).await);
    }
    for f in ["environ", "cmdline", "status"] {
        r.denied(&format!("alpha reads /proc/<supervisor>/{f}"), &cell.probe("alpha", "proc", &format!("pid={sup_pid}&file={f}")).await);
    }
    r.denied("alpha lists /proc", &cell.probe("alpha", "list", "path=/proc").await);

    // --- Credential access.
    let mut any = false;
    for fd in 0..16 {
        let v = cell.probe("alpha", "proc_fd_read", &format!("pid={b_q}&fd={fd}")).await;
        any |= v["ok"] == true;
    }
    r.check("DENY  alpha reads any of bravo's fds (incl. its secret memfd)", !any, "fd 0..15");
    r.denied("alpha setuid(0)", &cell.probe("alpha", "setuid0", "").await);
    r.denied("alpha unshare(CLONE_NEWUSER)", &cell.probe("alpha", "unshare_userns", "").await);
    r.denied("alpha reads the dev key dir", &cell.probe("alpha", "list", "path=/mnt/secret").await);

    // --- Memory limit blast radius: alpha (512 MiB cap) allocates 900 MiB.
    let st = cell.status().await;
    let b_pid_before = Cell::pid_of(&st, "bravo", "query");
    let t_alloc = Instant::now();
    let (code, v) = call(&cell.sock, Method::GET, "/v1/tenants/alpha/query/probe/alloc?mb=900", None, true).await;
    println!("alloc returned after {:?}", t_alloc.elapsed());
    r.check("alpha's 900 MiB allocation fails (killed at its limit)", code != 200 || v["ok"] != true, format!("{code} {}", compact(&v)));
    tokio::time::sleep(Duration::from_millis(500)).await;
    let bw = cell.whoami("bravo").await;
    let st = cell.status().await;
    r.check("bravo keeps serving, same process", Some(bw["pid"].as_u64().unwrap()) == b_pid_before, format!("{b_pid_before:?} -> {}", bw["pid"]));
    let a_oom = Cell::tenant_status(&st, "alpha")["oom_kills"].as_u64().unwrap_or(0);
    let b_oom = Cell::tenant_status(&st, "bravo")["oom_kills"].as_u64().unwrap_or(0);
    r.check("alpha oom kill counted; bravo none", a_oom >= 1 && b_oom == 0, format!("alpha {a_oom}, bravo {b_oom}"));
    let a2 = cell.whoami("alpha").await;
    r.check("alpha respawns after its OOM", a2["pid"] != a["pid"] && a2["uid"] == a["uid"], format!("{} -> {}", a["pid"], a2["pid"]));
    let (hz, _) = call(&cell.sock, Method::GET, "/healthz", None, false).await;
    r.check("supervisor healthy after a tenant OOM", hz == 200, hz.to_string());
    let a_events = Cell::tenant_status(&st, "alpha")["limit_events"].clone();
    let cg_oom_event = a_events.as_array().is_some_and(|v| v.iter().any(|e| e["kind"] == "cgroup_oom_kill" && e["tenant"] == "alpha"));
    r.check("cgroup oom_kill surfaced as a limit event", mode != nanosiem_lake_cell::limits::LimitsMode::CgroupV2 || cg_oom_event, compact(&a_events));
    if mode == nanosiem_lake_cell::limits::LimitsMode::CgroupV2 {
        let own_cg = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let rel = own_cg.lines().find_map(|l| l.strip_prefix("0::")).unwrap().trim().to_owned();
        r.check("supervisor moved into init/", rel.ends_with("/init"), rel.clone());
        let cg_view = PathBuf::from(format!("/sys/fs/cgroup{}", rel.trim_end_matches("/init")));
        let slot_of = |uid: u64| (uid - cfg.uid_base as u64) / 2;
        let (a_slot, b_slot) = (slot_of(uid_a), slot_of(uid_b));
        let t_dir = cg_view.join(format!("tenants/s{b_slot}"));
        r.check("tenant cgroups are named by slot, never by tenant id",
            t_dir.is_dir() && !cg_view.join("tenants/bravo").exists() && !cg_view.join("tenants/alpha").exists(),
            format!("{}", t_dir.display()));
        // --- M4: a tenant sees nothing of the cell's cgroup layout.
        let tenants = cg_view.join("tenants");
        r.denied("alpha lists the tenants cgroup dir", &cell.probe("alpha", "list", &format!("path={}", tenants.display())).await);
        r.denied("alpha reads bravo's cgroup stats", &cell.probe("alpha", "read", &format!("path={}", t_dir.join("memory.current").display())).await);
        r.denied("alpha reads bravo's cgroup cpu.stat", &cell.probe("alpha", "read", &format!("path={}", t_dir.join("cpu.stat").display())).await);
        let a_dir = cg_view.join(format!("tenants/s{a_slot}"));
        // Positive control: alpha reads its own leaf.
        r.allowed("alpha reads its own cgroup leaf", &cell.probe("alpha", "read", &format!("path={}", a_dir.join("query/memory.current").display())).await);
        // Writes through the supervisor's WRITABLE view (the RO
        // /sys/fs/cgroup would refuse with EROFS whatever the policy).
        let w = PathBuf::from(nanosiem_lake_cell::limits::PRIVATE_CGROUP_MOUNT).join("tenants");
        let (wa, wb) = (w.join(format!("s{a_slot}")), w.join(format!("s{b_slot}")));
        r.check("writable cgroup view exists (control)", wa.join("memory.max").exists(), wa.display().to_string());
        // The writable mount is supervisor-private, even though its inodes
        // are the same ones exposed read-only at /sys/fs/cgroup.
        let private = PathBuf::from(nanosiem_lake_cell::limits::PRIVATE_CGROUP_MOUNT);
        r.denied("alpha cannot list the delegator mount", &cell.probe("alpha", "list", &format!("path={}", private.display())).await);
        r.denied("alpha cannot read the delegator mount root", &cell.probe("alpha", "read", &format!("path={}", private.join("cgroup.controllers").display())).await);
        r.denied("alpha cannot read bravo through the delegator mount", &cell.probe("alpha", "read", &format!("path={}", wb.join("memory.current").display())).await);
        r.denied_errno("alpha writes its own memory.max", &cell.probe("alpha", "write_data", &format!("path={}&data=max", wa.join("memory.max").display())).await, 13);
        r.denied_errno("alpha writes its own cpu.max", &cell.probe("alpha", "write_data", &format!("path={}&data=max", wa.join("cpu.max").display())).await, 13);
        r.denied_errno("alpha writes bravo's memory.max", &cell.probe("alpha", "write_data", &format!("path={}&data=max", wb.join("memory.max").display())).await, 13);
        r.denied_errno("alpha writes bravo's cpu.max", &cell.probe("alpha", "write_data", &format!("path={}&data=max", wb.join("cpu.max").display())).await, 13);
        let a_pid = cell.whoami("alpha").await["pid"].as_u64().unwrap();
        let b_pid = cell.whoami("bravo").await["pid"].as_u64().unwrap();
        r.denied_errno("alpha moves itself into bravo's leaf", &cell.probe("alpha", "write_data", &format!("path={}&data={a_pid}", wb.join("query/cgroup.procs").display())).await, 13);
        r.denied_errno("bravo moves itself into alpha's leaf", &cell.probe("bravo", "write_data", &format!("path={}&data={b_pid}", wa.join("query/cgroup.procs").display())).await, 13);
        r.denied_errno("alpha moves itself to the cell root (escape its limits)", &cell.probe("alpha", "write_data", &format!("path={}&data={a_pid}", PathBuf::from(nanosiem_lake_cell::limits::PRIVATE_CGROUP_MOUNT).join("init/cgroup.procs").display())).await, 13);
        let cs = cell.probe("alpha", "cgroup_self", "").await;
        r.check("alpha's /proc/self/cgroup shows no cell layout (own cgroup namespace)",
            cs["cgroup"] == "0::/", compact(&cs));
        r.denied_errno("alpha's nested userns maps uid 0 (single-threaded unshare)", &cell.probe("alpha", "map_root", "").await, 1);
        let rd = |f: &str| std::fs::read_to_string(t_dir.join(f)).unwrap_or_default().trim().to_owned();
        let l = nanosiem_lake_cell::resources::TenantLimits::from_placement(
            &TenantPlacement::legacy(tid("bravo"), 20.0), &cell.sup.capacity(), &cfg.resources);
        r.check("tenant cgroup: memory.low = guarantee, high = max = hard ceiling (no pressure with headroom)",
            rd("memory.low") == l.memory_guarantee_bytes.to_string() && rd("memory.high") == l.memory_hard_bytes.to_string()
                && rd("memory.max") == l.memory_hard_bytes.to_string(),
            format!("low {} high {} max {}", rd("memory.low"), rd("memory.high"), rd("memory.max")));
        r.check("tenant cgroup: cpu.weight ∝ guarantee, cpu.max = burst ceiling",
            rd("cpu.weight") == l.cpu_weight.to_string() && rd("cpu.max") == nanosiem_lake_cell::resources::cpu_max_line(l.cpu_ceiling_millicores),
            format!("weight {} max {:?}", rd("cpu.weight"), rd("cpu.max")));
        r.check("three role quotas and weights pin detect independently of query",
            std::fs::read_to_string(wa.join("query/cpu.max")).unwrap_or_default().trim() == "300000 100000"
                && std::fs::read_to_string(wa.join("ingest/cpu.max")).unwrap_or_default().trim() == "50000 100000"
                && std::fs::read_to_string(wa.join("detect/cpu.max")).unwrap_or_default().trim() == "50000 100000"
                && std::fs::read_to_string(wa.join("query/cpu.weight")).unwrap_or_default().trim() == "2000"
                && std::fs::read_to_string(wa.join("ingest/cpu.weight")).unwrap_or_default().trim() == "50"
                && std::fs::read_to_string(wa.join("detect/cpu.weight")).unwrap_or_default().trim() == "100",
            format!("query {:?}, ingest {:?}, detect {:?}",
                std::fs::read_to_string(wa.join("query/cpu.max")), std::fs::read_to_string(wa.join("ingest/cpu.max")),
                std::fs::read_to_string(wa.join("detect/cpu.max"))));
        // Exercise the kernel controller, not just the written cpu.max text.
        // cpu.stat's nr_throttled is local to the quota-bearing query leaf.
        // Bravo's query leaf is the unaffected sibling control.
        let throttled = |dir: &Path| -> u64 {
            std::fs::read_to_string(dir.join("cpu.stat")).unwrap_or_default().lines()
                .find_map(|line| line.strip_prefix("nr_throttled ").and_then(|v| v.parse().ok())).unwrap_or(0)
        };
        let (a_before, b_before) = (throttled(&wa.join("query")), throttled(&wb.join("query")));
        let spin = cell.probe("alpha", "spin", "threads=6&secs=5").await;
        r.allowed("alpha starts CPU load above its 3 vCPU query ceiling", &spin);
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let (a_after, b_after) = (throttled(&wa.join("query")), throttled(&wb.join("query")));
        r.check("cpu.max kernel controller throttles alpha", a_after > a_before,
            format!("alpha nr_throttled {a_before} -> {a_after}; bravo {b_before} -> {b_after}"));
        r.check("bravo remains alive while alpha is CPU throttled",
            cell.whoami("bravo").await["pid"].as_u64() == b_pid_before,
            format!("bravo pid before {b_pid_before:?}"));

        // --- NAN-4642: a placement reload that shrinks a tenant below its
        // usage while its process is being replaced (the 2026-10-26
        // cell-us-1 reload cgroup-OOM-killed a tenant's stopping detect).
        const MIB: u64 = 1 << 20;
        let num = |p: PathBuf| std::fs::read_to_string(&p).ok().and_then(|v| v.trim().parse::<u64>().ok());
        let oom_kills = |d: &Path| std::fs::read_to_string(d.join("memory.events")).unwrap_or_default().lines()
            .find_map(|l| l.strip_prefix("oom_kill ").and_then(|v| v.parse::<u64>().ok())).unwrap_or(0);
        let q_before = Cell::pid_of(&cell.status().await, "alpha", "query");
        r.allowed("alpha/query holds 300 MiB before the reload", &cell.probe("alpha", "alloc", "mb=300").await);
        let (q_used, t_used) = (num(a_dir.join("query/memory.current")).unwrap_or(0), num(a_dir.join("memory.current")).unwrap_or(0));
        // The supervisor's count: the tenant cgroup itself may be removed
        // and recreated once every alpha process has exited.
        let sup_ooms = |st: &Value| Cell::tenant_status(st, "alpha")["oom_kills"].as_u64().unwrap_or(0);
        let ooms_before = (oom_kills(&a_dir), sup_ooms(&cell.status().await));
        // The limits the stopping query runs under now: a shrink holds them
        // (not merely >= usage) until it has exited.
        let (q_max_before, t_max_before) = (num(a_dir.join("query/memory.max")), num(a_dir.join("memory.max")));
        // Query 3 -> 1 CPU (its threads change: it restarts) and every role
        // budget far below what alpha uses now.
        let shrunk = TenantPlacement {
            ingest_request_millicores: Some(50), ingest_limit_millicores: Some(500),
            ingest_request_memory_bytes: Some(32 * MIB), ingest_limit_memory_bytes: Some(64 * MIB),
            detect_request_millicores: Some(50), detect_limit_millicores: Some(500),
            detect_request_memory_bytes: Some(32 * MIB), detect_limit_memory_bytes: Some(64 * MIB),
            query_request_millicores: Some(250), query_limit_millicores: Some(1_000),
            query_request_memory_bytes: Some(32 * MIB), query_limit_memory_bytes: Some(128 * MIB),
            ..TenantPlacement::legacy(tid("alpha"), 20.0)
        };
        cell.sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 2,
            tenants: vec![shrunk.clone(), TenantPlacement::legacy(tid("bravo"), 20.0)] }).await.unwrap();
        let (q_max, t_max) = (num(a_dir.join("query/memory.max")), num(a_dir.join("memory.max")));
        let st = cell.status().await;
        let stopping = Cell::tenant_status(&st, "alpha")["processes"].as_array().unwrap().iter()
            .any(|p| p["role"] == "query" && p["stopping"] == true);
        r.check("reload shrink: the stopping query's leaf and the tenant keep their limit (>= usage) until it exits",
            stopping && q_max.is_some() && q_max == q_max_before && t_max.is_some() && t_max == t_max_before
                && q_max.is_some_and(|m| m >= q_used) && t_max.is_some_and(|m| m >= t_used) && q_used > 128 * MIB && t_used > 256 * MIB,
            format!("query max {q_max_before:?} -> {q_max:?} used {q_used}, tenant max {t_max_before:?} -> {t_max:?} used {t_used}, query stopping {stopping}"));
        tokio::time::sleep(Duration::from_millis(cfg.shutdown_grace_ms + 1500)).await;
        let ooms_after = (if a_dir.is_dir() { oom_kills(&a_dir) } else { 0 }, sup_ooms(&cell.status().await));
        let events = Cell::tenant_status(&cell.status().await, "alpha")["limit_events"].clone();
        let cg_ooms = events.as_array().map_or(0, |v| v.iter().filter(|e| e["kind"] == "cgroup_oom_kill").count());
        r.check("reload shrink: no cgroup OOM kill of the process being replaced",
            ooms_after.1 == ooms_before.1 && (ooms_after.0 == ooms_before.0 || ooms_after.0 == 0),
            format!("cgroup oom_kill {} -> {}, supervisor oom_kills {} -> {}, cgroup_oom_kill events {cg_ooms}",
                ooms_before.0, ooms_after.0, ooms_before.1, ooms_after.1));
        let q_after = cell.whoami("alpha").await["pid"].as_u64();
        let t_shrink = Instant::now();
        let target_t = nanosiem_lake_cell::resources::TenantLimits::from_placement(&shrunk, &cell.sup.capacity(), &cfg.resources).memory_hard_bytes;
        let (mut q_max, mut t_max) = (None, None);
        while t_shrink.elapsed() < Duration::from_secs(10) {
            (q_max, t_max) = (num(a_dir.join("query/memory.max")), num(a_dir.join("memory.max")));
            if q_max == Some(128 * MIB) && t_max == Some(target_t) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
            cell.whoami("alpha").await;
        }
        r.check("reload shrink: the new limits apply once the old process exited (replacement serving)",
            q_after.is_some() && q_after != q_before && q_max == Some(128 * MIB) && t_max == Some(target_t),
            format!("query {q_before:?} -> {q_after:?}, query max {q_max:?}, tenant max {t_max:?} (target {target_t}) after {:?}", t_shrink.elapsed()));

        // --- NAN-4642: an eps change reaches a running ingest (graceful
        // restart at the new budget), as tzd's 145 -> 220 did not.
        cell.wake("alpha", "ingest", "data_arrival").await;
        let st = cell.status().await;
        let ingest_of = |st: &Value| Cell::tenant_status(st, "alpha")["processes"].as_array().unwrap().iter()
            .find(|p| p["role"] == "ingest").cloned().unwrap_or(Value::Null);
        let i_before = ingest_of(&st);
        let crashes_before = Cell::tenant_status(&st, "alpha")["crashes"]["ingest"].as_u64().unwrap_or(0);
        let grown = TenantPlacement { eps: 40.0, ..TenantPlacement::legacy(tid("alpha"), 20.0) };
        cell.sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 3,
            tenants: vec![grown, TenantPlacement::legacy(tid("bravo"), 20.0)] }).await.unwrap();
        let t_eps = Instant::now();
        let mut i_after = Value::Null;
        while t_eps.elapsed() < Duration::from_secs(cfg.shutdown_grace_ms / 1000 + 10) {
            tokio::time::sleep(Duration::from_millis(250)).await;
            let _ = call(&cell.sock, Method::POST, "/v1/tenants/alpha/wake", Some(json!({"role": "ingest", "reason": "data_arrival"})), true).await;
            i_after = ingest_of(&cell.status().await);
            if i_after["ingest_eps"] == 40.0 && i_after["stopping"] != true {
                break;
            }
        }
        r.check("eps change: ingest restarts gracefully and runs at the new eps budget",
            i_before["ingest_eps"] == 20.0 && i_after["pid"] != i_before["pid"] && i_after["ingest_eps"] == 40.0
                && i_after["ingest_memory_cap_bytes"].as_u64() > i_before["ingest_memory_cap_bytes"].as_u64(),
            format!("{} -> {} after {:?}", compact(&i_before), compact(&i_after), t_eps.elapsed()));
        let crashes = Cell::tenant_status(&cell.status().await, "alpha")["crashes"]["ingest"].as_u64().unwrap_or(0);
        r.check("eps change: the ingest restart is a stop, not a crash", crashes == crashes_before, format!("{crashes_before} -> {crashes}"));
        // Back to the suite's placement for the checks below.
        cell.sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 4,
            tenants: vec![TenantPlacement::legacy(tid("alpha"), 20.0), TenantPlacement::legacy(tid("bravo"), 20.0)] }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(cfg.shutdown_grace_ms + 500)).await;
        cell.whoami("alpha").await;
        cell.wake("alpha", "ingest", "data_arrival").await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let (_, signals) = call(&cell.sock, Method::GET, "/v1/signals", None, true).await;
    let oom_sig = signals.as_array().unwrap().iter().any(|s| s["tenant_id"] == "alpha" && s["signal"] == "oom_kills" && s["severity"] != "ok");
    r.check("oom_kills signal raised for alpha", oom_sig, "");
    let (_, metrics) = call(&cell.sock, Method::GET, "/metrics", None, true).await;
    let m = metrics.as_str().unwrap_or("");
    r.check("per-tenant metrics exported", m.contains("nano_cell_tenant_process_up{tenant=\"alpha\",role=\"query\"}") && m.contains("nano_cell_tenant_oom_kills_total{tenant=\"alpha\"}"), "");

    // --- Orphans: a double-forked child must not survive its tenant's stop.
    let alpha_uids: Vec<u32> = {
        let st = cell.status().await;
        Cell::tenant_status(&st, "alpha")["processes"].as_array().unwrap().iter().map(|p| p["uid"].as_u64().unwrap() as u32).collect()
    };
    let roots_before: Vec<u32> = {
        let st = cell.status().await;
        Cell::tenant_status(&st, "alpha")["processes"].as_array().unwrap().iter().map(|p| p["pid"].as_u64().unwrap() as u32).collect()
    };
    r.allowed("alpha double-forks an orphan", &cell.probe("alpha", "orphan", "").await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let orphans: Vec<(u32, u32)> = tenant_uid_procs(cfg.uid_base, cfg.uid_slots)
        .into_iter()
        .filter(|(pid, uid)| alpha_uids.contains(uid) && !roots_before.contains(pid))
        .collect();
    r.check("orphan exists under alpha's uid (control)", !orphans.is_empty(), format!("{orphans:?}"));
    cell.sup.drain(&tid("alpha"));
    let t_drain = Instant::now();
    let mut left = orphans.clone();
    while !left.is_empty() && t_drain.elapsed() < Duration::from_secs(10) {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let now: Vec<u32> = tenant_uid_procs(cfg.uid_base, cfg.uid_slots).into_iter().map(|(p, _)| p).collect();
        left.retain(|(p, _)| now.contains(p));
    }
    r.check("orphan killed when alpha is stopped", left.is_empty(), format!("{left:?} after {:?}", t_drain.elapsed()));

    // --- Idle tenants cost ≈0.
    let idle = Duration::from_secs(cfg.idle_timeout_secs);
    let t0 = Instant::now();
    let slots = cfg.uid_slots;
    let base = cfg.uid_base;
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let st = cell.status().await;
        let running: usize = st["tenants"].as_array().unwrap().iter().map(|t| t["processes"].as_array().unwrap().len()).sum();
        if running == 0 || t0.elapsed() > idle * 3 + Duration::from_secs(5) {
            break;
        }
    }
    let st = cell.status().await;
    let running: usize = st["tenants"].as_array().unwrap().iter().map(|t| t["processes"].as_array().unwrap().len()).sum();
    r.check("idle tenants reaped (no processes)", running == 0, format!("{running} running after {:?}", t0.elapsed()));
    let leftover = tenant_uid_procs(base, slots);
    r.check("no process runs under any tenant uid", leftover.is_empty(), format!("{leftover:?}"));
    let reaps = Cell::tenant_status(&st, "bravo")["reaps"].clone();
    r.check("reaps counted", reaps["query"].as_u64().unwrap_or(0) >= 1, compact(&reaps));
    let own_cg = std::fs::read_to_string("/proc/self/cgroup").unwrap();
    let rel = own_cg.lines().find_map(|l| l.strip_prefix("0::")).unwrap().trim().trim_end_matches("/init").to_owned();
    let cg_root = PathBuf::from(format!("/sys/fs/cgroup{rel}"));
    if mode == nanosiem_lake_cell::limits::LimitsMode::CgroupV2 {
        let left: Vec<String> = std::fs::read_dir(cg_root.join("tenants"))
            .map(|d| d.flatten().filter(|e| e.path().is_dir()).map(|e| e.file_name().to_string_lossy().into_owned()).collect())
            .unwrap_or_default();
        r.check("idle tenants have no cgroup", left.is_empty(), format!("{left:?}"));
        let warm_mem = std::fs::read_to_string(cg_root.join("warm/memory.current")).unwrap_or_default();
        r.check("warm pool cost (1 unassigned stub process)", true, format!("{} bytes", warm_mem.trim()));
        let a_usage = Cell::tenant_status(&st, "alpha")["usage"]["memory_bytes"].as_u64().unwrap_or(u64::MAX);
        r.check("idle tenant memory = 0", a_usage == 0, a_usage.to_string());
    }
    // An idle tenant wakes on demand again.
    let t1 = Instant::now();
    let a3 = cell.whoami("alpha").await;
    r.check("idle tenant wakes on query (warm pool)", a3["uid"] == a["uid"], format!("{} ms", t1.elapsed().as_millis()));
    let sup_rss = std::fs::read_to_string("/proc/self/status").unwrap_or_default().lines()
        .find_map(|l| l.strip_prefix("VmRSS:").map(|v| v.trim().to_owned())).unwrap_or_default();
    r.check("supervisor RSS (test process incl. harness)", true, sup_rss);
    cell.sup.shutdown_all();
    // Its reconcile would otherwise sort the next cell's processes (same
    // supervisor pid, same cgroup scope) into cell-a's warm/.
    cell.sup.halt();

    // --- Fallback: no cgroup delegation → RSS watchdog.
    // Its own uid range: cell-a's supervisor (and its watchdog) still runs
    // in this pid namespace, and two cells must never share tenant uids.
    let mut cfg_w = config(&mnt, "cell-w", CgroupPolicy::Off, 60);
    cfg_w.uid_base = 61_000;
    cfg_w.uid_slots = 100;
    let wcell = start_cell(cfg_w, &[("delta", 20.0), ("echo", 20.0)]).await;
    r.check("fallback cell runs in watchdog mode", format!("{:?}", wcell.sup.limits_mode()) == "Watchdog", "");
    let d = wcell.whoami("delta").await;
    let e = wcell.whoami("echo").await;
    r.denied("watchdog cell: delta reads echo's part dir", &wcell.probe("delta", "list", &format!("path={}", mnt.join("cell-w-data/tenants/echo/parts").display())).await);
    r.denied("watchdog cell: delta ptraces echo", &wcell.probe("delta", "ptrace", &format!("pid={}", e["pid"])).await);
    let _ = call(&wcell.sock, Method::GET, "/v1/tenants/delta/query/probe/alloc?mb=1300", None, true).await;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let st = wcell.status().await;
    let wk = Cell::tenant_status(&st, "delta")["watchdog_kills"].as_u64().unwrap_or(0);
    r.check("watchdog kills delta over its three-role hard ceiling", wk >= 1, format!("watchdog_kills {wk}"));
    let ev = Cell::tenant_status(&st, "delta")["limit_events"].clone();
    let kill_ev = ev.as_array().and_then(|v| v.iter().find(|e| e["kind"] == "killed").cloned()).unwrap_or_default();
    r.check("watchdog kill event carries reason, observed and limit",
        kill_ev["reason"] == "memory_hard_ceiling" && kill_ev["observed"].as_f64() > kill_ev["limit"].as_f64(), compact(&kill_ev));
    let e2 = wcell.whoami("echo").await;
    r.check("echo unaffected by delta's kill", e2["pid"] == e["pid"], format!("{} -> {}", e["pid"], e2["pid"]));
    let d2 = wcell.whoami("delta").await;
    r.check("delta respawns", d2["pid"] != d["pid"], "");

    // CPU: echo has a 4-core aggregate ceiling (0.5 ingest + 0.5 detect + 3 query).
    // Six threads exceed that ceiling. It survives the watchdog throttle.
    let e_pid = e2["pid"].as_u64().unwrap() as u32;
    let spin = wcell.probe("echo", "spin", "threads=6&secs=8").await;
    r.allowed("echo starts a 6-thread CPU spin", &spin);
    let ticks = |pid: u32| {
        std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()
            .and_then(|s| nanosiem_lake_cell::procfs::parse_stat(&s)).map(|s| s.own_ticks).unwrap_or(0)
    };
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let (t0, c0) = (Instant::now(), ticks(e_pid));
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let mc = (ticks(e_pid) - c0) as f64 * 1000.0 / nanosiem_lake_cell::procfs::clk_tck() as f64 / t0.elapsed().as_secs_f64();
    let st = wcell.status().await;
    let es = Cell::tenant_status(&st, "echo");
    let throttle = es["resources"]["throttle"].clone();
    r.check("spinning echo throttled to its CPU ceiling", throttle["reason"] == "ceiling", compact(&throttle));
    r.check("throttle holds echo near 4000 mc (6 threads want ~6000)", mc < 5000.0, format!("{mc:.0} mc"));
    let throttle_ev = es["limit_events"].as_array().and_then(|v| v.iter().find(|e| e["kind"] == "throttled").cloned()).unwrap_or_default();
    r.check("throttle event carries reason, observed and limit", throttle_ev["reason"] == "cpu_ceiling" && throttle_ev["limit"] == 4000.0, compact(&throttle_ev));
    let e3 = wcell.whoami("echo").await;
    r.check("a throttled tenant is not killed and keeps serving", e3["pid"] == e2["pid"], format!("{} -> {}", e2["pid"], e3["pid"]));
    let (_, metrics) = call(&wcell.sock, Method::GET, "/metrics", None, true).await;
    let m = metrics.as_str().unwrap_or("");
    r.check("throttle exported in metrics", m.contains("nano_cell_tenant_limit_events_total{tenant=\"echo\",kind=\"throttled\"}"), "");
    wcell.sup.shutdown_all();
    wcell.sup.halt();

    resident_ingest(&mnt, &mut r).await;
    resident_query(&mnt, &mut r).await;
    purge_phase(&mnt, &mut r).await;
    detect_refused_phase(&mnt, &mut r).await;
    detect_runs_rules_phase(&mnt, &mut r).await;
    birth_preconditions_phase(&mnt, &mut r).await;

    r.finish();
}

/// NAN-3047: with `detect_runs_rules`, a tenant whose detect budget holds
/// the engine has every `/detect/...` request served by its own detect[T]
/// (never query[T]); a tenant on a legacy budget keeps the query path; a
/// budget change under a running detect restarts it into the new mode.
async fn detect_runs_rules_phase(mnt: &Path, r: &mut Report) {
    const GIB: u64 = 1 << 30;
    let mut cfg = config(mnt, "cell-x", CgroupPolicy::Off, 60);
    cfg.uid_base = 60_000;
    cfg.uid_slots = 100;
    cfg.detect_runs_rules = true;
    let sized = |t: &str, detect_bytes: u64| TenantPlacement {
        detect_request_millicores: Some(250), detect_limit_millicores: Some(1_000),
        detect_request_memory_bytes: Some((GIB / 2).min(detect_bytes)), detect_limit_memory_bytes: Some(detect_bytes),
        ingest_request_millicores: Some(50), ingest_limit_millicores: Some(500),
        ingest_request_memory_bytes: Some(GIB / 4), ingest_limit_memory_bytes: Some(GIB),
        query_request_millicores: Some(250), query_limit_millicores: Some(3_000),
        query_request_memory_bytes: Some(GIB / 4), query_limit_memory_bytes: Some(3 * GIB),
        ..TenantPlacement::legacy(tid(t), 20.0)
    };
    let cell = start_cell_placed(cfg.clone(), vec![sized("kilo", 3 * GIB / 2), TenantPlacement::legacy(tid("lima"), 20.0)]).await;
    let query_kilo = cell.whoami("kilo").await;
    let mut served = Vec::new();
    for path in ["/probe/whoami", "/probe/whoami?rule=1", "/probe/whoami?rule=2"] {
        served.push(call(&cell.sock, Method::GET, &format!("/v1/tenants/kilo/detect{path}"), None, true).await);
    }
    let st = cell.status().await;
    let detect_pid = Cell::pid_of(&st, "kilo", "detect");
    r.check("runs rules: every kilo /detect request is served by kilo/detect",
        served.iter().all(|(s, v)| *s == 200 && v["role"] == "detect" && v["pid"].as_u64() == detect_pid),
        format!("{served:?} detect pid {detect_pid:?}"));
    r.check("runs rules: kilo/query never serves a /detect request",
        served.iter().all(|(_, v)| v["pid"] != query_kilo["pid"]), compact(&query_kilo));
    let kilo = Cell::tenant_status(&st, "kilo");
    r.check("runs rules: status reports detect_runs_rules and the running detect's mode",
        kilo["detect_runs_rules"] == true
            && kilo["processes"].as_array().is_some_and(|ps| ps.iter().any(|p| p["role"] == "detect" && p["runs_rules"] == true)),
        compact(&kilo));
    let (ls, lv) = call(&cell.sock, Method::GET, "/v1/tenants/lima/detect/probe/whoami", None, true).await;
    r.check("runs rules: a legacy 256 MiB detect budget keeps the query[T] path",
        ls == 200 && lv["role"] == "query" && Cell::tenant_status(&cell.status().await, "lima")["detect_runs_rules"] == false, compact(&lv));
    // Shrink kilo's detect budget below the engine floor: the running
    // detect restarts, and /detect falls back to query[T].
    cell.sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 2,
        tenants: vec![sized("kilo", GIB / 4), TenantPlacement::legacy(tid("lima"), 20.0)] }).await.unwrap();
    let t0 = Instant::now();
    let mut after = (0u16, Value::Null);
    while t0.elapsed() < Duration::from_secs(10) {
        after = call(&cell.sock, Method::GET, "/v1/tenants/kilo/detect/probe/whoami", None, true).await;
        if after.1["role"] == "query" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let st = cell.status().await;
    r.check("runs rules: a budget change restarts detect and routes by the new mode",
        after.0 == 200 && after.1["role"] == "query" && Cell::pid_of(&st, "kilo", "detect") != detect_pid,
        format!("{} {} detect pid {:?} -> {:?}", after.0, compact(&after.1), detect_pid, Cell::pid_of(&st, "kilo", "detect")));
    cell.sup.shutdown_all();
    cell.sup.halt();
}

/// A key source that refuses `detect` the way the platform does for a lean
/// cluster without `lakeCells.detectDrain` (403 `detect_drain_disabled`),
/// until `allow` is set, and counts the detect mints it saw.
struct RefusingDetect {
    inner: StaticKeySource,
    allow: std::sync::atomic::AtomicBool,
    detect_mints: std::sync::atomic::AtomicU64,
}

#[async_trait::async_trait]
impl nanosiem_lake_cell::secrets::KeySource for RefusingDetect {
    async fn mint(&self, tenant: &TenantId, role: Role) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        use std::sync::atomic::Ordering;
        if role == Role::Detect {
            self.detect_mints.fetch_add(1, Ordering::SeqCst);
            if !self.allow.load(Ordering::SeqCst) {
                return Err(nanosiem_lake_cell::secrets::MintRefused::from_response(
                    tenant, role, 403, br#"{"error":"detect_drain_disabled"}"#, None).into());
            }
        }
        self.inner.mint(tenant, role).await
    }
}

/// A refused detect token backs off (no per-request re-mint), answers the
/// detect route with `role_spawn_blocked` + the refusal code, shows in the
/// status and metrics, leaves query serving, and clears once allowed.
async fn detect_refused_phase(mnt: &Path, r: &mut Report) {
    use std::sync::atomic::Ordering;
    let mut cfg = config(mnt, "cell-d", CgroupPolicy::Off, 60);
    cfg.uid_base = 64_000;
    cfg.uid_slots = 100;
    let t = tid("juliet");
    let mut inner = StaticKeySource::default();
    for role in Role::ALL {
        inner = inner.with(&t, role, &secret("juliet", role));
    }
    let keys = Arc::new(RefusingDetect { inner, allow: false.into(), detect_mints: 0.into() });
    let sup = Supervisor::new(cfg.clone(), keys.clone()).expect("supervisor");
    sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 1, tenants: vec![TenantPlacement::legacy(t.clone(), 20.0)] }).await.unwrap();
    sup.start_background();
    let router = Router::new(sup.clone()).unwrap();
    let sock = cfg.listen_unix.clone().unwrap();
    let l = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(router::serve_unix(router, l));
    let cell = Cell { sock, sup };

    let (s1, v1) = call(&cell.sock, Method::GET, "/v1/tenants/juliet/detect/probe/whoami", None, true).await;
    r.check("refused detect: route answers 503 role_spawn_blocked with the refusal code",
        s1 == 503 && v1["reason"] == "role_spawn_blocked" && v1["role"] == "detect" && v1["refusal"] == "detect_drain_disabled",
        compact(&v1));
    for _ in 0..5 {
        let _ = call(&cell.sock, Method::GET, "/v1/tenants/juliet/detect/probe/whoami", None, true).await;
    }
    let mints = keys.detect_mints.load(Ordering::SeqCst);
    r.check("refused detect: backoff, no re-mint per request", mints == 1, format!("{mints} detect mints for 6 requests"));
    let st = cell.status().await;
    let blocked = Cell::tenant_status(&st, "juliet")["role_spawn_blocked"].clone();
    r.check("refused detect: status role_spawn_blocked{role,reason}",
        blocked[0]["role"] == "detect" && blocked[0]["reason"] == "detect_drain_disabled" && blocked[0]["http_status"] == 403,
        compact(&blocked));
    let (_, metrics) = call(&cell.sock, Method::GET, "/metrics", None, true).await;
    let m = metrics.as_str().unwrap_or("");
    r.check("refused detect: metric nano_cell_role_spawn_blocked",
        m.contains("nano_cell_role_spawn_blocked{cell=\"cell-d\",tenant=\"juliet\",role=\"detect\",reason=\"detect_drain_disabled\"} 1"), "");
    let (_, signals) = call(&cell.sock, Method::GET, "/v1/signals", None, true).await;
    let sig = signals.as_array().or_else(|| signals["signals"].as_array()).and_then(|a| a.iter()
        .find(|g| g["signal"] == "role_spawn_blocked" && g["component"] == "detect").cloned()).unwrap_or_default();
    r.check("refused detect: role_spawn_blocked signal warns with the code",
        sig["severity"] == "warn" && sig["detail"].as_str().is_some_and(|d| d.contains("detect_drain_disabled")), compact(&sig));
    let q = cell.whoami("juliet").await;
    r.check("refused detect: query keeps serving", q["tenant"] == "juliet", compact(&q));

    // The platform grants detect: the next attempt after the backoff spawns it.
    keys.allow.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    let mut ok = (0u16, Value::Null);
    while t0.elapsed() < Duration::from_secs(10) {
        ok = call(&cell.sock, Method::GET, "/v1/tenants/juliet/detect/probe/whoami", None, true).await;
        if ok.0 == 200 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    r.check("refused detect: recovers once allowed (within the first backoff)", ok.0 == 200, format!("{} after {:?}", ok.0, t0.elapsed()));
    let st = cell.status().await;
    let blocked = Cell::tenant_status(&st, "juliet")["role_spawn_blocked"].clone();
    r.check("refused detect: block cleared after a successful spawn", blocked.as_array().is_some_and(|a| a.is_empty()), compact(&blocked));
    cell.sup.shutdown_all();
    cell.sup.halt();
}

/// The control plane at a lean birth: ingest mints answer `503
/// lean_assignment_pending` (Retry-After 1) until the first assignment
/// commits after `pending` refusals; every other role mints at once.
struct FirstAssignment {
    inner: StaticKeySource,
    pending: u64,
    ingest_mints: std::sync::atomic::AtomicU64,
}

#[async_trait::async_trait]
impl nanosiem_lake_cell::secrets::KeySource for FirstAssignment {
    async fn mint(&self, tenant: &TenantId, role: Role) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
        use std::sync::atomic::Ordering;
        if role == Role::Ingest && self.ingest_mints.fetch_add(1, Ordering::SeqCst) < self.pending {
            return Err(nanosiem_lake_cell::secrets::MintRefused::from_response(
                tenant, role, 503, br#"{"error":"lean_assignment_pending"}"#, Some(Duration::from_secs(1))).into());
        }
        self.inner.mint(tenant, role).await
    }
}

/// NAN-4314: a birth as it happens on every lean region. The placement
/// lands before the tenant's enrichment policy (the bundle sidecar writes
/// it on its next cycle) and before the first lean assignment commits
/// (ingest's token is `lean_assignment_pending` once). Resident ingest and
/// query start together. Both must start on their first attempt: no
/// "spawn failed" (enrichment mounts ENOENT, cgroup EEXIST, refused token),
/// no role_spawn_blocked, and each waits for its precondition instead.
async fn birth_preconditions_phase(mnt: &Path, r: &mut Report) {
    use std::sync::atomic::Ordering;
    let mut cfg = config(mnt, "cell-b", CgroupPolicy::Off, 60);
    cfg.uid_base = 59_000;
    cfg.uid_slots = 100;
    cfg.query_resident = true;
    let bundles = mnt.join("feeds/bundles");
    std::fs::create_dir_all(&bundles).unwrap();
    std::fs::set_permissions(&bundles, std::fs::Permissions::from_mode(0o755)).unwrap();
    cfg.platform_bundle_dir = Some(bundles);
    let policy_root = mnt.join("policy-b");
    std::fs::create_dir_all(&policy_root).unwrap();
    std::fs::set_permissions(&policy_root, std::fs::Permissions::from_mode(0o755)).unwrap();
    // A platform policy is only placed for a UUID tenant.
    const HOTEL: &str = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
    let t = tid(HOTEL);
    let policy = policy_root.join(HOTEL).join("policy.json");
    let mut placed = TenantPlacement::legacy(t.clone(), 20.0);
    placed.ingest = IngestMode::Resident;
    placed.platform_policy_file = Some(policy.clone());

    let mut inner = StaticKeySource::default();
    for role in Role::ALL {
        inner = inner.with(&t, role, &secret(HOTEL, role));
    }
    let keys = Arc::new(FirstAssignment { inner, pending: 1, ingest_mints: 0.into() });
    let sup = Supervisor::new(cfg.clone(), keys.clone()).expect("supervisor");
    sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 1, tenants: vec![placed] }).await.unwrap();
    sup.start_background();
    let router = Router::new(sup.clone()).unwrap();
    let sock = cfg.listen_unix.clone().unwrap();
    let l = tokio::net::UnixListener::bind(&sock).unwrap();
    tokio::spawn(router::serve_unix(router, l));
    let cell = Cell { sock, sup };

    // The sidecar's next cycle: the policy lands 1.5 s after the placement.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let early = cell.status().await;
    r.check("birth: nothing spawned (or failed) before the policy lands",
        Cell::tenant_status(&early, HOTEL)["processes"].as_array().is_some_and(|p| p.is_empty())
            && early["spawn_failures"] == 0, compact(&early["spawn_failures"]));
    std::fs::create_dir_all(policy.parent().unwrap()).unwrap();
    std::fs::set_permissions(policy.parent().unwrap(), std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(&policy, b"{}").unwrap();
    std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();

    let t0 = Instant::now();
    let mut st = cell.status().await;
    while (Cell::pid_of(&st, HOTEL, "ingest").is_none() || Cell::pid_of(&st, HOTEL, "query").is_none())
        && t0.elapsed() < Duration::from_secs(20)
    {
        tokio::time::sleep(Duration::from_millis(100)).await;
        st = cell.status().await;
    }
    let hotel = Cell::tenant_status(&st, HOTEL);
    r.check("birth: resident ingest and query both start once their preconditions land",
        Cell::pid_of(&st, HOTEL, "ingest").is_some() && Cell::pid_of(&st, HOTEL, "query").is_some(),
        format!("after {:?}: {}", t0.elapsed(), compact(&hotel["processes"])));
    r.check("birth: no spawn failed (no ENOENT/EEXIST/refused-token retries)", st["spawn_failures"] == 0,
        compact(&st["spawn_failures"]));
    r.check("birth: the pending assignment was waited out inside the spawn, not blocked",
        hotel["role_spawn_blocked"].as_array().is_some_and(|a| a.is_empty()) && keys.ingest_mints.load(Ordering::SeqCst) == 2,
        format!("{} ingest mints, blocked {}", keys.ingest_mints.load(Ordering::SeqCst), compact(&hotel["role_spawn_blocked"])));
    r.check("birth: each role started on its first attempt",
        hotel["crashes"]["ingest"] == 0 && hotel["crashes"]["query"] == 0, compact(&hotel["crashes"]));
    cell.sup.shutdown_all();
    cell.sup.halt();
}

/// C1: `ingest: resident` starts without a wake, outlives the idle timeout,
/// respawns with backoff after a crash; on-demand tenants are unchanged.
async fn resident_ingest(mnt: &Path, r: &mut Report) {
    let mut cfg = config(mnt, "cell-r", CgroupPolicy::Off, 3);
    cfg.uid_base = 62_000;
    cfg.uid_slots = 100;
    cfg.resources.restart_backoff_base_ms = 1000;
    let idle = Duration::from_secs(cfg.idle_timeout_secs);
    let mut resident = TenantPlacement::legacy(tid("foxtrot"), 20.0);
    resident.ingest = IngestMode::Resident;
    let cell = start_cell_placed(cfg.clone(), vec![resident, TenantPlacement::legacy(tid("golf"), 20.0)]).await;
    let ingest_pid = |st: &Value, t: &str| Cell::pid_of(st, t, "ingest");
    let wait_pid = |cell: &Cell, t: &'static str, not: Option<u64>, within: Duration| {
        let sock = cell.sock.clone();
        async move {
            let t0 = Instant::now();
            loop {
                let st = call(&sock, Method::GET, "/v1/status", None, true).await.1;
                if let Some(p) = ingest_pid(&st, t).filter(|p| Some(*p) != not) {
                    return Some((p, t0.elapsed(), st));
                }
                if t0.elapsed() > within {
                    return None;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    };

    let started = wait_pid(&cell, "foxtrot", None, Duration::from_secs(15)).await;
    r.check("resident: ingest starts at placement without /wake", started.is_some(),
        started.as_ref().map(|(p, e, _)| format!("pid {p} after {e:?}")).unwrap_or_else(|| "never started".into()));
    let Some((f1, _, st)) = started else {
        cell.sup.shutdown_all();
        cell.sup.halt();
        return;
    };
    r.check("resident: status reports ingest=resident", Cell::tenant_status(&st, "foxtrot")["ingest"] == "resident"
        && Cell::tenant_status(&st, "golf")["ingest"] == "on_demand", "");
    r.check("on-demand: tenant not started without a wake", Cell::tenant_status(&st, "golf")["processes"].as_array().unwrap().is_empty(), "");
    cell.wake("golf", "ingest", "data_arrival").await;

    // Past the idle timeout: the on-demand ingest is reaped, the resident one is not.
    let t0 = Instant::now();
    let mut st = cell.status().await;
    while ingest_pid(&st, "golf").is_some() && t0.elapsed() < idle * 3 + Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        st = cell.status().await;
    }
    tokio::time::sleep(idle).await;
    let st = cell.status().await;
    let golf_reaps = Cell::tenant_status(&st, "golf")["reaps"]["ingest"].as_u64().unwrap_or(0);
    r.check("on-demand: woken ingest reaped after the idle timeout", ingest_pid(&st, "golf").is_none() && golf_reaps >= 1,
        format!("reaps {golf_reaps} after {:?}", t0.elapsed()));
    let fox = Cell::tenant_status(&st, "foxtrot");
    r.check("resident: ingest survives past the idle timeout (same pid, no reap)",
        ingest_pid(&st, "foxtrot") == Some(f1) && fox["reaps"]["ingest"] == 0,
        format!("{f1} -> {:?} after {:?} (idle {idle:?})", ingest_pid(&st, "foxtrot"), t0.elapsed()));

    // Crash: respawned by the keeper after the restart backoff (1 s, then 2 s).
    let mut prev = f1;
    for (n, min_wait) in [(1u64, Duration::from_millis(900)), (2, Duration::from_millis(1900))] {
        // SAFETY: plain kill(2) of a tenant process this test owns.
        unsafe { libc::kill(prev as i32, libc::SIGKILL) };
        let again = wait_pid(&cell, "foxtrot", Some(prev), Duration::from_secs(15)).await;
        let detail = again.as_ref().map(|(p, e, st)| format!("{prev} -> {p} after {e:?}, crashes {}",
            Cell::tenant_status(st, "foxtrot")["crashes"]["ingest"])).unwrap_or_else(|| "not respawned".into());
        let ok = again.as_ref().is_some_and(|(_, e, st)| *e >= min_wait
            && Cell::tenant_status(st, "foxtrot")["crashes"]["ingest"].as_u64() == Some(n));
        r.check(&format!("resident: crash #{n} respawns after >= {min_wait:?} backoff"), ok, detail);
        match again {
            Some((p, _, _)) => prev = p,
            None => break,
        }
    }

    // Un-placed: drained and no longer kept.
    cell.sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 2,
        tenants: vec![TenantPlacement::legacy(tid("golf"), 20.0)] }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(cfg.shutdown_grace_ms + 3000)).await;
    let left: Vec<(u32, u32)> = tenant_uid_procs(cfg.uid_base, cfg.uid_slots);
    r.check("resident: un-placed tenant is drained and not respawned", left.is_empty(), format!("{left:?}"));
    cell.sup.shutdown_all();
    cell.sup.halt();
}

/// NAN-3008: with `query_resident` (the production default) every placed
/// tenant's query[T] runs before any search arrives: at cell start, after a
/// crash, and after a roll (a new supervisor on the same state); it is never
/// idle-reaped while placed; an un-placed tenant's query is drained.
async fn resident_query(mnt: &Path, r: &mut Report) {
    let mut cfg = config(mnt, "cell-q", CgroupPolicy::Off, 2);
    cfg.uid_base = 63_000;
    cfg.uid_slots = 100;
    cfg.query_resident = true;
    cfg.resources.restart_backoff_base_ms = 500;
    let idle = Duration::from_secs(cfg.query_idle_timeout_secs);
    // One resident-ingest tenant and one on-demand one: both get a query.
    let mut hotel = TenantPlacement::legacy(tid("hotel"), 20.0);
    hotel.ingest = IngestMode::Resident;
    let placed = vec![hotel, TenantPlacement::legacy(tid("india"), 20.0)];
    let query_pid = |st: &Value, t: &str| Cell::pid_of(st, t, "query");
    async fn wait_query(sock: &Path, t: &str, not: Option<u64>, within: Duration) -> Option<(u64, Duration)> {
        let t0 = Instant::now();
        loop {
            let st = call(sock, Method::GET, "/v1/status", None, true).await.1;
            if let Some(p) = Cell::pid_of(&st, t, "query").filter(|p| Some(*p) != not) {
                return Some((p, t0.elapsed()));
            }
            if t0.elapsed() > within {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    // Cell start: no search, no wake.
    let cell = start_cell_placed(cfg.clone(), placed.clone()).await;
    let mut pids = Vec::new();
    for t in ["hotel", "india"] {
        let up = wait_query(&cell.sock, t, None, Duration::from_secs(15)).await;
        r.check(&format!("resident query: {t} query starts at cell start without a search"), up.is_some(),
            up.map(|(p, e)| format!("pid {p} after {e:?}")).unwrap_or_else(|| "never started".into()));
        pids.push(up.map(|(p, _)| p));
    }
    // Past the query idle timeout, with no search: same pids, no reaps.
    tokio::time::sleep(idle * 3).await;
    let st = cell.status().await;
    for (t, pid) in ["hotel", "india"].iter().zip(&pids) {
        let reaps = Cell::tenant_status(&st, t)["reaps"]["query"].as_u64().unwrap_or(0);
        r.check(&format!("resident query: {t} never idle-reaped while placed"), pid.is_some() && query_pid(&st, t) == *pid && reaps == 0,
            format!("{pid:?} -> {:?}, reaps {reaps} after {:?} idle", query_pid(&st, t), idle * 3));
    }
    // Crash: the keeper restarts it after the backoff, without a search.
    if let Some(prev) = pids[0] {
        // SAFETY: plain kill(2) of a tenant process this test owns.
        unsafe { libc::kill(prev as i32, libc::SIGKILL) };
        let again = wait_query(&cell.sock, "hotel", Some(prev), Duration::from_secs(15)).await;
        r.check("resident query: restarted after a crash without a search", again.is_some(),
            again.map(|(p, e)| format!("{prev} -> {p} after {e:?}")).unwrap_or_else(|| "not restarted".into()));
    }
    // Un-placed: drained, not restarted; the placed sibling keeps running.
    let india_before = query_pid(&cell.status().await, "india");
    cell.sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 2,
        tenants: vec![TenantPlacement::legacy(tid("india"), 20.0)] }).await.unwrap();
    tokio::time::sleep(Duration::from_millis(cfg.shutdown_grace_ms + 3000)).await;
    let st = cell.status().await;
    let hotel_left = st["tenants"].as_array().unwrap().iter().find(|x| x["tenant_id"] == "hotel")
        .map(|x| x["processes"].as_array().is_some_and(|p| !p.is_empty())).unwrap_or(false);
    r.check("resident query: un-placed tenant's query is drained and not restarted", !hotel_left, format!("{st}").chars().take(140).collect::<String>());
    r.check("resident query: placed sibling untouched by the un-placement", query_pid(&st, "india") == india_before && india_before.is_some(), "");
    // Roll: a new supervisor on the same cell state starts query before any search.
    cell.sup.shutdown_all();
    cell.sup.halt();
    tokio::time::sleep(Duration::from_millis(cfg.shutdown_grace_ms + 500)).await;
    let _ = std::fs::remove_file(cfg.listen_unix.as_ref().unwrap());
    let rolled = start_cell_placed(cfg.clone(), placed).await;
    for t in ["hotel", "india"] {
        let up = wait_query(&rolled.sock, t, None, Duration::from_secs(15)).await;
        r.check(&format!("resident query: {t} query running after a roll before any search"), up.is_some(),
            up.map(|(p, e)| format!("pid {p} after {e:?}")).unwrap_or_else(|| "never started".into()));
    }
    rolled.sup.shutdown_all();
    rolled.sup.halt();
}

/// NAN-3000: a tenant removed from the placement is drained, its tree
/// (written by its own jailed process, owned by its uids) purged under the
/// cell's caps and verified, and the verified purge pushed to a fake
/// platform with the cell identity token. Its sibling keeps running, its
/// tree untouched.
async fn purge_phase(mnt: &Path, r: &mut Report) {
    use nanosiem_lake_cell::report::{PushOutcome, Reporter};
    const P1: &str = "0a1b2c3d-0000-4000-8000-00000000aaaa";
    const P2: &str = "0a1b2c3d-0000-4000-8000-00000000bbbb";
    const P3: &str = "0a1b2c3d-0000-4000-8000-00000000cccc";
    let mut cfg = config(mnt, "cell-p", CgroupPolicy::Off, 60);
    cfg.uid_base = 63_000;
    cfg.uid_slots = 100;
    let cell = start_cell(cfg.clone(), &[(P1, 20.0), (P2, 20.0), (P3, 20.0)]).await;
    let (p1, p2) = (cell.whoami(P1).await, cell.whoami(P2).await);
    cell.whoami(P3).await;
    let uid1 = p1["uid"].as_u64().unwrap_or(0) as u32;
    let tree = |t: &str| cfg.data_dir.join("tenants").join(t);
    for (t, rel) in [(P1, "query/tmp/scratch"), (P1, "query/reader-cache"), (P2, "query/reader-cache")] {
        let path = tree(t).join(rel);
        let v = cell.probe(t, "write", &format!("path={}", path.display())).await;
        r.check(&format!("purge setup: {} writes {rel}", &t[t.len() - 4..]), v["ok"] == true, compact(&v));
    }

    // The fake platform: TokenReview accepts only the current identity token.
    let identity = mnt.join("secret/cell-p-identity.token");
    std::fs::write(&identity, "projected-sa-token-cell-p").unwrap();
    type Seen = Arc<std::sync::Mutex<Vec<(Option<String>, Value)>>>;
    let seen: Seen = Default::default();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/api", l.local_addr().unwrap());
    let seen2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((s, _)) = l.accept().await {
            let seen = seen2.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                    let seen = seen.clone();
                    async move {
                        let ok_path = req.uri().path() == "/api/v1/lake/cells/cell-p/status";
                        let auth = req.headers().get(AUTHORIZATION).and_then(|h| h.to_str().ok()).map(str::to_owned);
                        let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
                        let v: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                        let code = if !ok_path { 404 } else if auth.as_deref() != Some("Bearer projected-sa-token-cell-p") { 401 } else { 204 };
                        seen.lock().unwrap().push((auth, v));
                        Ok::<_, std::convert::Infallible>(hyper::Response::builder().status(code).body(Full::new(Bytes::new())).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(s), svc).await;
            });
        }
    });
    let reporter = Reporter::new(&url, &cfg.cell_id, identity).unwrap().with_retry(2, Duration::from_millis(50));

    // P3: its ingest committed a part to the local part store (no
    // part_signing on this cell: `<T>/parts` is the store of record).
    // Written as the parts dir's owner (the ingest uid), like the stub's
    // own part writes; ingest has no probe route.
    let parts3 = tree(P3).join("parts");
    let wrote = as_owner_of(&parts3, || std::fs::write(parts3.join("part-000001"), b"committed part"));
    r.check("purge setup: cccc has a committed local part", wrote.is_ok(), format!("{wrote:?}"));

    // Placement change: P1 and P3 removed.
    cell.sup.set_placement(Placement { cell_id: cfg.cell_id.clone(), revision: 2,
        tenants: vec![TenantPlacement::legacy(tid(P2), 20.0)] }).await.unwrap();
    let t0 = Instant::now();
    let p1_id = tid(P1);
    while !cell.sup.purge_ledger().purged.contains_key(&p1_id) && t0.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let ledger = cell.sup.purge_ledger();
    let rec = ledger.purged.get(&p1_id).cloned();
    r.check("purge: removed tenant drained, purged and verified", rec.as_ref().is_some_and(|x| x.verified),
        format!("{rec:?} after {:?}", t0.elapsed()));
    r.check("purge: removed tenant's tree is gone", std::fs::symlink_metadata(tree(P1)).is_err(), tree(P1).display().to_string());
    let left: Vec<(u32, u32)> = tenant_uid_procs(cfg.uid_base, cfg.uid_slots).into_iter().filter(|(_, u)| *u == uid1).collect();
    r.check("purge: nothing runs under the removed tenant's uid", left.is_empty(), format!("{left:?}"));
    r.check("purge: bytes removed recorded (tmp + cache)", rec.as_ref().is_some_and(|x| x.bytes.tmp_bytes >= 1 && x.bytes.cache_bytes >= 1),
        format!("{:?}", rec.as_ref().map(|x| x.bytes)));
    // Zero cross-tenant: P2 kept its process and its file.
    let p2b = cell.whoami(P2).await;
    r.check("purge: sibling tenant kept its process", p2b["pid"] == p2["pid"], format!("{} -> {}", p2["pid"], p2b["pid"]));
    let st = cell.probe(P2, "stat", &format!("path={}", tree(P2).join("query/reader-cache").display())).await;
    r.check("purge: sibling tenant's tree untouched", st["ok"] == true, compact(&st));
    // Data of record: P3 is refused, kept draining, and flagged.
    let blocked = format!("nano_cell_purge_blocked{{tenant=\"{P3}\",reason=\"local_part_store_of_record\"}} 1");
    let t1 = Instant::now();
    let mut metrics = call(&cell.sock, Method::GET, "/metrics", None, true).await.1;
    while !metrics.as_str().unwrap_or("").contains(&blocked) && t1.elapsed() < Duration::from_secs(30) {
        tokio::time::sleep(Duration::from_millis(250)).await;
        metrics = call(&cell.sock, Method::GET, "/metrics", None, true).await.1;
    }
    let ledger = cell.sup.purge_ledger();
    r.check("purge: refused while the local part store (no part_signing) holds parts",
        ledger.pending.contains_key(&tid(P3)) && !ledger.purged.contains_key(&tid(P3))
            && std::fs::symlink_metadata(tree(P3)).is_ok() && metrics.as_str().unwrap_or("").contains(&blocked),
        format!("pending {:?}", ledger.pending.keys().collect::<Vec<_>>()));

    // Report: tenants = [P2 running, P3 draining], purged = [P1 verified]; then acknowledged.
    let s = reporter.push_once(cell.sup.as_ref()).await;
    let body = seen.lock().unwrap().last().map(|(_, v)| v.clone()).unwrap_or_default();
    r.check("purge report: platform accepted the push", s.outcome == PushOutcome::Accepted && s.acknowledged == vec![p1_id.clone()],
        format!("{s:?}"));
    r.check("purge report: carries the verified purge and not the removed tenant",
        body["purged"][0]["tenant_id"] == P1 && body["purged"][0]["verified"] == true && body["purged"][0]["reason"] == "drain"
            && body["tenants"] == json!([{"tenant_id": P2, "state": "running"}, {"tenant_id": P3, "state": "draining"}]) && body["placement_revision"] == 2,
        compact(&body));
    r.check("purge report: bearer is the cell identity token",
        seen.lock().unwrap().iter().all(|(a, _)| a.as_deref() == Some("Bearer projected-sa-token-cell-p")), "");
    r.check("purge report: acknowledged purge leaves the ledger", cell.sup.purge_ledger().purged.is_empty(), "");
    cell.sup.shutdown_all();
    cell.sup.halt();
}
