// SPDX-License-Identifier: AGPL-3.0-or-later

//! Stub `ingest[T]` / `query[T]` for the cell supervisor tests (NAN-2871).
//!
//! It implements the process contract exactly as a real tenant binary must
//! (bootstrap → jail → secrets → ready → heartbeats) and serves probe
//! endpoints the isolation suite uses to attempt cross-tenant access from
//! *inside* a jailed tenant process. Every probe reports the raw outcome
//! (`ok`, `errno`, `error`); the test decides what is a pass.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use nanosiem_lake_cell::child::{self, TenantService};
use nanosiem_lake_cell::contract::{Assignment, Heartbeat, Role, WakeReason};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Stub {
    control: child::ControlChannel,
    received_secrets: AtomicU64,
    a: Assignment,
    secret_sha256: String,
    landlock: String,
    busy: AtomicBool,
    parts: AtomicU64,
    last_progress: AtomicU64,
    hog: Mutex<Vec<Vec<u8>>>,
    /// query: `/v1/status` answers ready from this unix ms on (NAN-3004).
    ready_at_ms: u64,
    /// query: a `/v1/search` takes this long (a real search is not instant,
    /// so a roll that tears a pod down has requests in flight).
    search_ms: u64,
    /// ingest: the fenced single-writer model (NAN-3004 roll test).
    writer: Option<Arc<Writer>>,
}

/// Options the roll test passes in the bootstrap secret after the token:
/// `bootstrap-token:<t>:<role>;store=127.0.0.1:<port>;warm_ms=<ms>;search_ms=<ms>`. The
/// isolation suite's secrets carry none.
fn secret_options(secret: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(secret)
        .split(';')
        .skip(1)
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect()
}

/// A model of `ingest[T]` against the fake store of the roll test: the same
/// fencing contract as the edge-log DO (the newest lease wins; a stale
/// epoch's pull or commit answers `fenced`) and the part log (a commit must
/// start exactly at the committed point). Pulls every 50 ms, commits every
/// 250 ms, flushes on `Shutdown`, exits 3 the moment it is fenced.
struct Writer {
    store: String,
    tenant: String,
    consumer: String,
    state: tokio::sync::Mutex<WriterState>,
    /// NAN-4052 (`pg_lease=1` and an assigned writer lease): model the
    /// Postgres cell writer lease on the fake store, as ingest[T] does.
    pg_lease: Option<PgLease>,
}

/// The ingest[T] side of the cell writer lease: acquire before the edge-log
/// lease (held elsewhere: exit standby), renew by CAS every TTL/4, commit
/// only before `sent + TTL - TTL/5`, exit standby on loss, release on drain.
struct PgLease {
    holder: String,
    ttl_ms: u64,
    epoch: AtomicU64,
    valid_until: Mutex<std::time::Instant>,
}

impl PgLease {
    fn deadline(&self, sent: std::time::Instant) -> std::time::Instant {
        sent + Duration::from_millis(self.ttl_ms - self.ttl_ms / 5)
    }

    fn standby(&self, why: &str) -> ! {
        eprintln!("stub ingest {}: writer lease {why}; standing by", self.holder);
        std::process::exit(nanosiem_lake_cell::contract::WRITER_STANDBY_EXIT_CODE)
    }

    fn check(&self) {
        if std::time::Instant::now() >= *self.valid_until.lock().unwrap() {
            self.standby("deadline passed");
        }
    }
}

#[derive(Default)]
struct WriterState {
    epoch: u64,
    committed: u64,
    pulled: u64,
    buffer: Vec<u64>,
    stopped: bool,
}

async fn store_post(store: &str, path: &str, body: Value) -> anyhow::Result<Value> {
    let s = tokio::net::TcpStream::connect(store).await?;
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s)).await?;
    tokio::spawn(conn);
    let req = Request::builder().method("POST").uri(path).header("host", "store")
        .body(Full::new(Bytes::from(body.to_string())))?;
    let resp = sender.send_request(req).await?;
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

impl Writer {
    fn fenced(&self, what: &str) -> ! {
        eprintln!("stub ingest {}: fenced on {what}; exiting", self.consumer);
        std::process::exit(3)
    }

    async fn lease(&self) -> anyhow::Result<()> {
        let v = store_post(&self.store, &format!("/{}/lease", self.tenant), json!({"consumer": self.consumer})).await?;
        let mut st = self.state.lock().await;
        st.epoch = v["epoch"].as_u64().unwrap_or(0);
        st.committed = v["committed"].as_u64().unwrap_or(0);
        st.pulled = st.committed;
        Ok(())
    }

    async fn pull(&self) -> anyhow::Result<()> {
        let mut st = self.state.lock().await;
        if st.stopped {
            return Ok(());
        }
        let v = store_post(&self.store, &format!("/{}/pull", self.tenant), json!({"epoch": st.epoch, "after": st.pulled})).await?;
        if v["kind"] == "fenced" {
            self.fenced("pull");
        }
        for e in v["events"].as_array().into_iter().flatten().filter_map(Value::as_u64) {
            st.buffer.push(e);
            st.pulled = e;
        }
        Ok(())
    }

    async fn commit(&self, st: &mut WriterState) -> anyhow::Result<()> {
        if st.buffer.is_empty() {
            return Ok(());
        }
        if let Some(pg) = &self.pg_lease {
            pg.check();
        }
        let v = store_post(&self.store, &format!("/{}/commit", self.tenant),
            json!({"epoch": st.epoch, "from": st.committed, "events": st.buffer, "consumer": self.consumer})).await?;
        match v["kind"].as_str() {
            Some("ok") => {
                st.committed = *st.buffer.last().unwrap();
                st.buffer.clear();
                Ok(())
            }
            Some("fenced") | Some("conflict") => self.fenced("commit"),
            other => anyhow::bail!("commit answered {other:?}"),
        }
    }

    async fn acquire_pg_lease(self: &Arc<Self>) {
        let Some(pg) = &self.pg_lease else { return };
        let sent = std::time::Instant::now();
        let v = match store_post(&self.store, &format!("/{}/wlease_acquire", self.tenant), json!({"holder": pg.holder, "ttl_ms": pg.ttl_ms})).await {
            Ok(v) => v,
            Err(e) => pg.standby(&format!("store unreachable: {e}")),
        };
        if v["acquired"] != true {
            pg.standby(&format!("held by {}", v["holder"]));
        }
        pg.epoch.store(v["epoch"].as_u64().unwrap_or(0), Ordering::SeqCst);
        *pg.valid_until.lock().unwrap() = pg.deadline(sent);
        let me = self.clone();
        tokio::spawn(async move {
            let pg = me.pg_lease.as_ref().unwrap();
            loop {
                tokio::time::sleep(Duration::from_millis(pg.ttl_ms / 4)).await;
                let sent = std::time::Instant::now();
                let body = json!({"holder": pg.holder, "epoch": pg.epoch.load(Ordering::SeqCst), "ttl_ms": pg.ttl_ms});
                match store_post(&me.store, &format!("/{}/wlease_renew", me.tenant), body).await {
                    Ok(v) if v["renewed"] == true => *pg.valid_until.lock().unwrap() = pg.deadline(sent),
                    Ok(_) => pg.standby("taken by another pod generation"),
                    Err(_) => pg.check(),
                }
            }
        });
    }

    async fn run(self: Arc<Self>) {
        self.acquire_pg_lease().await;
        while let Err(e) = self.lease().await {
            eprintln!("stub ingest: lease: {e}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let mut last_commit = std::time::Instant::now();
        loop {
            if let Err(e) = self.pull().await {
                eprintln!("stub ingest: pull: {e}");
            }
            if last_commit.elapsed() >= Duration::from_millis(250) {
                let mut st = self.state.lock().await;
                if st.stopped {
                    return;
                }
                if let Err(e) = self.commit(&mut st).await {
                    eprintln!("stub ingest: commit: {e}");
                }
                last_commit = std::time::Instant::now();
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// `Shutdown`: stop pulling, commit what is buffered.
    async fn flush_and_stop(&self) {
        let mut st = self.state.lock().await;
        st.stopped = true;
        if let Err(e) = self.commit(&mut st).await {
            eprintln!("stub ingest: flush on shutdown: {e}");
        }
        if let Some(pg) = &self.pg_lease {
            *pg.valid_until.lock().unwrap() = std::time::Instant::now();
            let body = json!({"holder": pg.holder, "epoch": pg.epoch.load(Ordering::SeqCst)});
            let _ = store_post(&self.store, &format!("/{}/wlease_release", self.tenant), body).await;
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn outcome(rc: i64) -> Value {
    if rc >= 0 {
        json!({"ok": true, "rc": rc})
    } else {
        let e = errno();
        json!({"ok": false, "errno": e, "error": std::io::Error::from_raw_os_error(e).to_string()})
    }
}

fn io_outcome<T>(r: std::io::Result<T>) -> Value {
    match r {
        Ok(_) => json!({"ok": true}),
        Err(e) => json!({"ok": false, "errno": e.raw_os_error(), "error": e.to_string()}),
    }
}

fn sockaddr_un(path: &[u8], abstract_ns: bool) -> (libc::sockaddr_un, libc::socklen_t) {
    // SAFETY: zeroed sockaddr_un is valid.
    let mut a: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    a.sun_family = libc::AF_UNIX as u16;
    let off = if abstract_ns { 1 } else { 0 };
    for (i, b) in path.iter().enumerate().take(100) {
        a.sun_path[i + off] = *b as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + off + path.len() + if abstract_ns { 0 } else { 1 };
    (a, len as libc::socklen_t)
}

fn probe(kind: &str, q: &HashMap<String, String>, stub: &Stub) -> Value {
    let arg = |k: &str| q.get(k).cloned().unwrap_or_default();
    match kind {
        "whoami" => {
            // SAFETY: plain id getters.
            let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
            json!({
                "tenant": stub.a.tenant, "role": stub.a.role, "uid": uid, "gid": gid, "pid": std::process::id(),
                "secret_sha256": stub.secret_sha256, "landlock": stub.landlock,
                "env": std::env::vars().map(|(k, _)| k).collect::<Vec<_>>(),
                "parts_written": stub.parts.load(Ordering::Relaxed),
                "received_secrets": stub.received_secrets.load(Ordering::SeqCst),
                "memory_cap_bytes": stub.a.memory_cap_bytes,
                "status": self_status(),
            })
        }
        "read" => match std::fs::read(arg("path")) {
            Ok(b) => json!({"ok": true, "len": b.len(), "sha256": hex::encode(Sha256::digest(&b))}),
            Err(e) => json!({"ok": false, "errno": e.raw_os_error(), "error": e.to_string()}),
        },
        "list" => match std::fs::read_dir(arg("path")) {
            Ok(it) => json!({"ok": true, "entries": it.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect::<Vec<_>>()}),
            Err(e) => json!({"ok": false, "errno": e.raw_os_error(), "error": e.to_string()}),
        },
        "write" => io_outcome(std::fs::write(arg("path"), b"x")),
        "stat" => io_outcome(std::fs::metadata(arg("path"))),
        "connect_unix" | "connect_abstract" => {
            let abs = kind == "connect_abstract";
            let name = if abs { arg("name") } else { arg("path") };
            // SAFETY: socket/connect/close with a valid sockaddr_un.
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
                if fd < 0 {
                    return outcome(-1);
                }
                let (a, len) = sockaddr_un(name.as_bytes(), abs);
                let rc = libc::connect(fd, &a as *const _ as *const libc::sockaddr, len);
                let out = outcome(rc as i64);
                libc::close(fd);
                out
            }
        }
        "listen_unix" => {
            // Bind + listen a pathname socket in our own dir (listen must be denied).
            let path = stub.a.state_dir.join("probe.sock");
            let _ = std::fs::remove_file(&path);
            // SAFETY: as above.
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
                let (a, len) = sockaddr_un(path.to_string_lossy().as_bytes(), false);
                let b = libc::bind(fd, &a as *const _ as *const libc::sockaddr, len);
                let l = libc::listen(fd, 1);
                let out = json!({"bind": outcome(b as i64), "listen": outcome(l as i64)});
                libc::close(fd);
                out
            }
        }
        "connect_tcp" => {
            let addr: std::net::SocketAddr = match arg("addr").parse() {
                Ok(a) => a,
                Err(e) => return json!({"ok": false, "error": e.to_string()}),
            };
            io_outcome(std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)))
        }
        "bind_tcp" => io_outcome(std::net::TcpListener::bind(arg("addr"))),
        "unix_dgram" => {
            // SAFETY: socket + close.
            unsafe {
                let fd = libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
                let out = outcome(fd as i64);
                if fd >= 0 {
                    libc::close(fd);
                }
                out
            }
        }
        "unix_dgram_pair_sendto" => {
            // NAN-3567: an unnamed datagram pair aimed at an abstract name.
            let name = arg("name");
            let mut fds = [0; 2];
            // SAFETY: socketpair into a two-element buffer; sendto with a
            // valid sockaddr_un; close of fds we own.
            unsafe {
                let rc = libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr());
                if rc != 0 {
                    return outcome(rc as i64);
                }
                let (a, len) = sockaddr_un(name.as_bytes(), true);
                let sent = libc::sendto(fds[0], b"x".as_ptr().cast(), 1, 0, &a as *const _ as *const libc::sockaddr, len);
                let out = outcome(sent as i64);
                libc::close(fds[0]);
                libc::close(fds[1]);
                out
            }
        }
        "pidfd_signal" => {
            let pid: i32 = arg("pid").parse().unwrap_or(0);
            // SAFETY: pidfd_open + pidfd_send_signal(sig 0, a permission probe); close the fd.
            unsafe {
                let fd = libc::syscall(libc::SYS_pidfd_open, pid, 0);
                if fd < 0 {
                    return outcome(fd);
                }
                let rc = libc::syscall(libc::SYS_pidfd_send_signal, fd as i32, 0, std::ptr::null::<libc::siginfo_t>(), 0);
                let out = outcome(rc);
                libc::close(fd as i32);
                out
            }
        }
        "socket_netlink" => {
            // SAFETY: socket + close.
            unsafe {
                let fd = libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, 0);
                let out = outcome(fd as i64);
                if fd >= 0 {
                    libc::close(fd);
                }
                out
            }
        }
        "ptrace" => {
            let pid: i32 = arg("pid").parse().unwrap_or(0);
            // SAFETY: ptrace attach attempt; detach if it (wrongly) succeeded.
            unsafe {
                let rc = libc::ptrace(libc::PTRACE_ATTACH, pid, 0, 0);
                let out = outcome(rc);
                if rc == 0 {
                    libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
                }
                out
            }
        }
        "process_vm_readv" => {
            let pid: i32 = arg("pid").parse().unwrap_or(0);
            let addr: usize = arg("addr").parse().unwrap_or(0x400000);
            let mut buf = [0u8; 16];
            let local = libc::iovec { iov_base: buf.as_mut_ptr() as *mut _, iov_len: 16 };
            let remote = libc::iovec { iov_base: addr as *mut _, iov_len: 16 };
            // SAFETY: syscall with valid local iovec.
            outcome(unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) as i64 })
        }
        "proc" => {
            let path = format!("/proc/{}/{}", arg("pid"), arg("file"));
            if arg("file") == "fd" {
                match std::fs::read_dir(&path) {
                    Ok(it) => json!({"ok": true, "entries": it.count()}),
                    Err(e) => json!({"ok": false, "errno": e.raw_os_error(), "error": e.to_string()}),
                }
            } else {
                match std::fs::read(&path) {
                    Ok(b) => json!({"ok": true, "len": b.len(), "head": String::from_utf8_lossy(&b[..b.len().min(64)])}),
                    Err(e) => json!({"ok": false, "errno": e.raw_os_error(), "error": e.to_string()}),
                }
            }
        }
        "proc_fd_read" => {
            // Try to read another process's secret memfd through /proc.
            let path = format!("/proc/{}/fd/{}", arg("pid"), arg("fd"));
            io_outcome(std::fs::read(path))
        }
        "kill" => {
            let pid: i32 = arg("pid").parse().unwrap_or(0);
            // SAFETY: signal 0 is a permission probe; SIGTERM if asked.
            let sig = if arg("sig") == "term" { libc::SIGTERM } else { 0 };
            outcome(unsafe { libc::kill(pid, sig) } as i64)
        }
        "setuid0" => outcome(unsafe { libc::setuid(0) } as i64),
        "unshare_userns" => outcome(unsafe { libc::unshare(libc::CLONE_NEWUSER) } as i64),
        "mkdir_tmp" => io_outcome(std::fs::create_dir_all("/tmp/nano-cell-probe")),
        "alloc" => {
            let mb: usize = arg("mb").parse().unwrap_or(0);
            let mut v = Vec::with_capacity(mb);
            for _ in 0..mb {
                let mut chunk = vec![0u8; 1 << 20];
                for i in (0..chunk.len()).step_by(4096) {
                    chunk[i] = 1;
                }
                v.push(chunk);
            }
            stub.hog.lock().unwrap().extend(v);
            json!({"ok": true, "held_mb": stub.hog.lock().unwrap().len()})
        }
        "orphan" => {
            // Double-fork a sleeper that is re-parented away from us: the
            // supervisor must still find (uid) and kill it on stop.
            // SAFETY: fork; the children only call async-signal-safe
            // functions (fork, pause, _exit).
            unsafe {
                match libc::fork() {
                    0 => {
                        if libc::fork() == 0 {
                            loop {
                                libc::pause();
                            }
                        }
                        libc::_exit(0);
                    }
                    -1 => return outcome(-1),
                    pid => {
                        let mut st = 0;
                        libc::waitpid(pid, &mut st, 0);
                    }
                }
            }
            json!({"ok": true})
        }
        "cgroup_self" => match std::fs::read_to_string("/proc/self/cgroup") {
            Ok(s) => json!({"ok": true, "cgroup": s.trim()}),
            Err(e) => json!({"ok": false, "errno": e.raw_os_error(), "error": e.to_string()}),
        },
        "map_root" => {
            // A nested user namespace mapping the parent's uid 0, tried from
            // a single-threaded forked child (unshare(CLONE_NEWUSER) is
            // EINVAL in any multithreaded process, which would prove nothing).
            // SAFETY: fork; the child calls only async-signal-safe functions.
            unsafe {
                match libc::fork() {
                    0 => {
                        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
                            let e = *libc::__errno_location();
                            libc::_exit(e.clamp(1, 99));
                        }
                        let fd = libc::open(c"/proc/self/uid_map".as_ptr(), libc::O_WRONLY);
                        let ok = fd >= 0 && libc::write(fd, c"0 0 1\n".as_ptr() as *const _, 6) == 6;
                        libc::_exit(if ok { 0 } else { 100 });
                    }
                    -1 => outcome(-1),
                    pid => {
                        let mut st = 0;
                        libc::waitpid(pid, &mut st, 0);
                        let code = libc::WEXITSTATUS(st);
                        match code {
                            0 => json!({"ok": true, "step": "mapped uid 0"}),
                            100 => json!({"ok": false, "step": "uid_map"}),
                            e => json!({"ok": false, "step": "unshare", "errno": e}),
                        }
                    }
                }
            }
        }
        "fill_disk" => {
            use std::io::Write;
            let path = stub.a.tmp_dir.join("bounded-disk-probe");
            let result = (|| -> std::io::Result<()> {
                let mut file = std::fs::File::create(&path)?;
                let block = vec![1_u8; 1024 * 1024];
                for _ in 0..1024 { file.write_all(&block)?; }
                file.sync_all()
            })();
            let _ = std::fs::remove_file(&path);
            io_outcome(result)
        }
        "fill_pids" => {
            let mut handles = Vec::new();
            let end = std::time::Instant::now() + Duration::from_secs(5);
            let mut failure = None;
            for _ in 0..512 {
                match std::thread::Builder::new().stack_size(128 * 1024).spawn(move || {
                    while std::time::Instant::now() < end { std::thread::sleep(Duration::from_millis(20)); }
                }) {
                    Ok(handle) => handles.push(handle),
                    Err(error) => { failure = error.raw_os_error(); break; }
                }
            }
            let tasks = handles.len();
            for handle in handles { let _ = handle.join(); }
            json!({"ok": failure.is_none(), "errno": failure, "spawned": tasks})
        }
        "write_data" => io_outcome(std::fs::write(arg("path"), arg("data"))),
        "spin" => {
            // Burn CPU on `threads` threads for `secs` seconds (the CPU
            // throttle tests); returns immediately.
            let threads: usize = arg("threads").parse().unwrap_or(1).min(8);
            let secs: u64 = arg("secs").parse().unwrap_or(5).min(120);
            for _ in 0..threads {
                std::thread::spawn(move || {
                    let end = std::time::Instant::now() + Duration::from_secs(secs);
                    let mut x = 0u64;
                    while std::time::Instant::now() < end {
                        for i in 0..100_000u64 {
                            x = std::hint::black_box(x.wrapping_mul(31).wrapping_add(i));
                        }
                    }
                });
            }
            json!({"ok": true, "threads": threads, "secs": secs})
        }
        "exec" => {
            // A jailed process must not be able to exec an arbitrary binary.
            let p = CString::new(arg("path")).unwrap_or_default();
            // SAFETY: access() is a pure permission check.
            outcome(unsafe { libc::access(p.as_ptr(), libc::X_OK) } as i64)
        }
        _ => json!({"ok": false, "error": "unknown probe"}),
    }
}

/// Security-relevant fields of /proc/self/status.
fn self_status() -> Value {
    let s = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let keys = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters", "Groups"];
    s.lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(k, _)| keys.contains(k))
        .map(|(k, v)| (k.to_owned(), Value::String(v.trim().to_owned())))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

fn parse_query(q: Option<&str>) -> HashMap<String, String> {
    q.unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.replace("%2F", "/").replace("%3A", ":")))
        .collect()
}

impl Stub {
    async fn serve(self: Arc<Self>, req: Request<Incoming>) -> Result<Response<Full<Bytes>>, hyper::Error> {
        let path = req.uri().path().to_owned();
        let q = parse_query(req.uri().query());
        let headers: Value = req
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), Value::String(v.to_str().unwrap_or("").to_owned())))
            .collect::<serde_json::Map<_, _>>()
            .into();
        let _ = req.into_body().collect().await?;
        let body = match path.strip_prefix("/probe/") {
            Some("refresh") => {
                match self.control.request_secrets().await {
                    Ok(()) => json!({"ok": true, "received_secrets": self.received_secrets.load(Ordering::SeqCst)}),
                    Err(error) => json!({"ok": false, "error": error.to_string()}),
                }
            }
            Some(kind) => {
                let me = self.clone();
                let kind = kind.to_owned();
                // Probes block; keep them off the reactor.
                tokio::task::spawn_blocking(move || probe(&kind, &q, &me)).await.unwrap_or(json!({"ok": false}))
            }
            None if path == "/headers" => headers,
            None if path == "/v1/status" && self.a.role == Role::Query => {
                // The part-query status shape the supervisor's warm check reads.
                let ready = now_ms() >= self.ready_at_ms;
                let body = json!({"ok": ready, "ready": ready, "reason": if ready { "" } else { "not_ready" }});
                let mut resp = Response::new(Full::new(Bytes::from(body.to_string())));
                if !ready {
                    *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                }
                return Ok(resp);
            }
            None if path.starts_with("/v1/search") && self.a.role == Role::Query && now_ms() < self.ready_at_ms => {
                // query[T]'s `require_ready` before its gated prewarm is done.
                let body = json!({"ok": false, "ready": false, "error": "query prewarm is incomplete", "reason": "not_ready"});
                let mut resp = Response::new(Full::new(Bytes::from(body.to_string())));
                *resp.status_mut() = hyper::StatusCode::SERVICE_UNAVAILABLE;
                return Ok(resp);
            }
            None => {
                if self.search_ms > 0 && path.starts_with("/v1/search") {
                    tokio::time::sleep(Duration::from_millis(self.search_ms)).await;
                }
                json!({"tenant": self.a.tenant, "role": self.a.role, "path": path})
            }
        };
        self.last_progress.store(now_ms(), Ordering::Relaxed);
        Ok(Response::new(Full::new(Bytes::from(body.to_string()))))
    }
}

#[async_trait::async_trait]
impl TenantService for Stub {
    async fn secrets(self: Arc<Self>, _secret: zeroize::Zeroizing<Vec<u8>>) {
        let n = self.received_secrets.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = std::fs::write(self.a.state_dir.join("secret-deliveries"), n.to_string());
    }
    async fn handle_rpc(self: Arc<Self>, _request_id: u64, stream: tokio::net::UnixStream) {
        let me = self.clone();
        let svc = hyper::service::service_fn(move |req| me.clone().serve(req));
        let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(stream), svc).await;
    }

    async fn wake(self: Arc<Self>, reason: WakeReason) {
        if self.a.role == Role::Ingest && reason == WakeReason::DataArrival {
            self.busy.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(50)).await;
            let n = self.parts.fetch_add(1, Ordering::SeqCst);
            let p = self.a.parts_dir.join(format!("part-{n:06}.parquet"));
            if let Err(e) = std::fs::write(&p, format!("part {n} of {}", self.a.tenant)) {
                eprintln!("stub ingest: write {}: {e}", p.display());
            }
            self.last_progress.store(now_ms(), Ordering::SeqCst);
            self.busy.store(false, Ordering::SeqCst);
        }
    }

    async fn shutdown(self: Arc<Self>, _grace: Duration) {
        if let Some(w) = &self.writer {
            w.flush_and_stop().await;
        }
    }

    fn heartbeat(&self) -> Heartbeat {
        Heartbeat {
            busy: self.busy.load(Ordering::SeqCst),
            lag_seconds: 0.0,
            last_progress_unix_ms: self.last_progress.load(Ordering::Relaxed),
            queue_depth: 0,
            detail: None,
            // Ingest start-up (and the cell writer lease, if modelled) is done.
            writer_ready: self.a.role == Role::Ingest
                && self.writer.as_ref().is_none_or(|w| w.pg_lease.as_ref().is_none_or(|pg| pg.epoch.load(Ordering::SeqCst) > 0)),
            ..Heartbeat::default()
        }
    }
}

fn main() -> anyhow::Result<()> {
    let boot = child::bootstrap()?;
    let landlock = boot.jail.landlock.clone();
    tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build()?.block_on(async move {
        let (a, secret, control) = boot.into_async()?;
        let opts = secret_options(&secret);
        // NAN-3004 roll test: a query prewarm held before readiness when asked.
        let warm_ms: u64 = opts.get("warm_ms").and_then(|v| v.parse().ok()).unwrap_or(0);
        let ready_at_ms = if a.query_prewarm_before_ready { now_ms() + warm_ms } else { now_ms() };
        let search_ms: u64 = opts.get("search_ms").and_then(|v| v.parse().ok()).unwrap_or(0);
        let writer = match (a.role, opts.get("store")) {
            (Role::Ingest, Some(store)) => Some(Arc::new(Writer {
                store: store.clone(),
                tenant: a.tenant.to_string(),
                consumer: format!("{}/{}", opts.get("cell").cloned().unwrap_or_default(), std::process::id()),
                state: tokio::sync::Mutex::new(WriterState::default()),
                pg_lease: match (&a.writer_lease, opts.get("pg_lease").map(String::as_str)) {
                    (Some(lease), Some("1")) => Some(PgLease {
                        holder: lease.holder.clone(),
                        ttl_ms: lease.ttl_ms,
                        epoch: AtomicU64::new(0),
                        valid_until: Mutex::new(std::time::Instant::now()),
                    }),
                    _ => None,
                },
            })),
            _ => None,
        };
        let stub = Arc::new(Stub {
            control: control.clone(),
            received_secrets: AtomicU64::new(0),
            secret_sha256: hex::encode(Sha256::digest(&secret[..])),
            a,
            landlock,
            busy: AtomicBool::new(false),
            parts: AtomicU64::new(0),
            last_progress: AtomicU64::new(0),
            hog: Mutex::new(Vec::new()),
            ready_at_ms,
            search_ms,
            writer: writer.clone(),
        });
        drop(secret);
        if let Some(w) = writer {
            tokio::spawn(w.run());
        }
        child::run_service(stub, control).await
    })
}
