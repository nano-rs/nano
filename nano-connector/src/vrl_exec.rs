//! VRL for the connector loop: an allowlisted function set, and isolated
//! worker processes that enforce the execution budget.
//!
//! VRL has no unbounded loops, but string doubling and iteration over large
//! inputs can still burn CPU and memory, and the VRL compiler recurses on
//! nesting (about 700 levels of `[` overflow an 8 MiB stack). An in-process
//! VRL call can neither be interrupted nor survive a stack overflow, so the
//! host never compiles or runs tenant VRL itself. Programs run in a child
//! process (see [`crate::sandbox`]) that holds no credentials, cannot open
//! files or sockets, and is killed when one invocation exceeds its budget.
//!
//! [`VrlPool`] bounds how many workers run at once, globally and per tenant.
//! A worker is single-use: it serves one stream of one run and is killed
//! after it. Workers are never reused across runs, so never across tenants.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::sandbox::{self, CgroupLeaf, CgroupParent, Enforce, Rlimits, SandboxPolicy, SandboxReport};

/// Functions a connector program may call. An allowlist, not a denylist: a VRL
/// upgrade that adds a function adds nothing here until someone reviews it.
pub const ALLOWED_FUNCTIONS: &[&str] = &[
    "abs", "append", "array", "assert", "assert_eq", "bool", "ceil", "chunks", "compact",
    "contains", "contains_all", "decode_base16", "decode_base64", "decode_mime_q", "decode_percent",
    "del", "downcase", "encode_base16", "encode_base64", "encode_json", "encode_key_value",
    "encode_logfmt", "encode_percent", "ends_with", "exists", "filter", "find", "flatten", "float",
    "floor", "for_each", "format_int", "format_number", "format_timestamp", "from_entries",
    "from_unix_timestamp", "get", "includes", "int", "ip_aton", "ip_cidr_contains", "ip_ntoa",
    "ip_subnet", "ip_to_ipv6", "ipv6_to_ipv4", "is_array", "is_boolean", "is_empty", "is_float",
    "is_integer", "is_ipv4", "is_ipv6", "is_json", "is_null", "is_nullish", "is_object", "is_regex",
    "is_string", "is_timestamp", "join", "keys", "length", "map_keys", "map_values", "match",
    "match_any", "match_array", "md5", "merge", "mod", "now", "object", "object_from_array",
    "parse_csv", "parse_duration", "parse_float", "parse_int", "parse_json", "parse_key_value",
    "parse_logfmt", "parse_query_string", "parse_regex", "parse_regex_all", "parse_timestamp",
    "parse_url", "parse_xml", "pop", "push", "redact", "remove", "replace", "round", "set", "sha1",
    "sha2", "slice", "split", "starts_with", "string", "strip_whitespace", "strlen", "tally",
    "tally_value", "timestamp", "to_bool", "to_entries", "to_float", "to_int", "to_string",
    "to_unix_timestamp", "truncate", "unflatten", "unique", "unnest", "upcase", "values", "zip",
];

/// Names the parser side blocks (`nanosiem-core/src/parsers/validator.rs`
/// `BLOCKED_VRL_FUNCTIONS`), plus what this engine additionally refuses.
/// Tested to be disjoint from [`ALLOWED_FUNCTIONS`].
pub const REFUSED_FUNCTIONS: &[&str] = &[
    // parser-side denylist (BLOCKED_VRL_FUNCTIONS)
    "get_env_var", "get_hostname", "http_request", "dns_lookup", "reverse_dns",
    // randomness: nothing in a request loop needs it
    "random_bool", "random_bytes", "random_float", "random_int", "uuid_v4", "uuid_v7",
    // decompression inside VRL would bypass the engine's decompression cap
    "decode_gzip", "decode_zlib", "decode_zstd", "decode_snappy", "decode_lz4",
    // read files from the host
    "validate_json_schema", "parse_proto", "encode_proto",
    // secrets/host state
    "get_secret", "set_secret", "remove_secret", "get_timezone_name", "log",
    // keyed crypto: auth is native, VRL holds no keys
    "hmac", "encrypt", "decrypt", "encrypt_ip", "decrypt_ip",
];

pub fn functions() -> Vec<Box<dyn vrl::compiler::Function>> {
    vrl::stdlib::all()
        .into_iter()
        .filter(|f| ALLOWED_FUNCTIONS.contains(&f.identifier()))
        .collect()
}

pub const MAX_PROGRAM_BYTES: usize = 256 * 1024;

/// Compile with the allowlisted function set. Errors are formatted
/// diagnostics, one per entry. Call only inside a worker: the VRL compiler
/// recurses on nesting and a hostile program overflows the stack.
pub fn compile(source: &str) -> Result<vrl::compiler::Program, Vec<String>> {
    if source.len() > MAX_PROGRAM_BYTES {
        return Err(vec!["program exceeds 256 KiB".into()]);
    }
    vrl::compiler::compile(source, &functions())
        .map(|r| r.program)
        .map_err(|d| {
            d.into_iter()
                .map(|d| vrl::diagnostic::Formatter::new(source, d).to_string())
                .collect()
        })
}

/// Run a compiled program in this process (used by the worker itself).
pub fn resolve(program: &vrl::compiler::Program, input: Value) -> Result<Value, String> {
    use vrl::compiler::TargetValue;
    use vrl::value::{Secrets, Value as V};
    let mut target = TargetValue {
        value: V::from(input),
        metadata: V::Object(BTreeMap::new()),
        secrets: Secrets::default(),
    };
    let mut rt = vrl::compiler::runtime::Runtime::default();
    let out = rt
        .resolve(&mut target, program, &vrl::compiler::TimeZone::parse("UTC").unwrap_or_default())
        .map_err(|e| e.to_string())?;
    let json: Result<Value, _> = out.try_into();
    json.map_err(|e| e.to_string())
}

#[derive(Debug, thiserror::Error)]
pub enum VrlError {
    #[error("VRL program does not compile: {0}")]
    Compile(String),
    #[error("VRL runtime error: {0}")]
    Runtime(String),
    #[error("VRL exceeded its {0} ms budget and was killed")]
    Budget(u64),
    #[error("VRL worker died: {0}")]
    WorkerDied(String),
    #[error("VRL output exceeds {0} bytes")]
    OutputTooLarge(usize),
    #[error("VRL sandbox unavailable: {0}")]
    Sandbox(String),
    #[error("no VRL worker slot free within {0:?} ({1})")]
    PoolExhausted(Duration, &'static str),
}

/// Limits for the worker process.
#[derive(Debug, Clone)]
pub struct WorkerLimits {
    pub address_space_bytes: u64,
    pub cpu_secs: u64,
    pub call_timeout: Duration,
    pub max_output_bytes: usize,
}

/// Main-thread stack for workers: deep-but-legal nesting compiles; absurd
/// nesting overflows inside the worker, never in the host.
const WORKER_STACK_BYTES: u64 = 64 * 1024 * 1024;

/// One isolated worker process.
pub struct VrlWorker {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    limits: WorkerLimits,
    dead: bool,
    leaf: Option<CgroupLeaf>,
    /// What isolation the worker actually got.
    pub report: SandboxReport,
}

impl VrlWorker {
    /// Spawn with the default policy (seccomp preferred, no cgroup).
    pub async fn spawn(exe: &Path, program: &str, limits: WorkerLimits) -> Result<Self, VrlError> {
        Self::spawn_sandboxed(exe, program, limits, Enforce::Prefer, None).await
    }

    /// Spawn, move into `leaf` (if any), install seccomp per `seccomp`, then
    /// send the program. Nothing tenant-controlled reaches the child before
    /// its sandbox is in place.
    pub async fn spawn_sandboxed(
        exe: &Path,
        program: &str,
        limits: WorkerLimits,
        seccomp: Enforce,
        leaf: Option<CgroupLeaf>,
    ) -> Result<Self, VrlError> {
        let mut cmd = Command::new(exe);
        cmd.arg("vrl-worker")
            .arg(format!("--seccomp={}", seccomp.as_str()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        sandbox::harden_command(
            &mut cmd,
            Rlimits { address_space_bytes: limits.address_space_bytes, cpu_secs: limits.cpu_secs, stack_bytes: WORKER_STACK_BYTES },
        );
        let mut child = cmd.spawn().map_err(|e| VrlError::WorkerDied(e.to_string()))?;
        let cgroup = match (&leaf, child.id()) {
            (Some(l), Some(pid)) => match l.add(pid) {
                Ok(()) => "enforced".to_string(),
                Err(e) => {
                    let _ = child.start_kill();
                    return Err(VrlError::Sandbox(format!("cannot move the worker into its cgroup: {e}")));
                }
            },
            (Some(_), None) => return Err(VrlError::WorkerDied("worker exited before it was placed in its cgroup".into())),
            (None, _) => String::new(),
        };
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = BufReader::new(child.stdout.take().expect("piped stdout"));
        let mut w = Self { child, stdin, stdout, limits, dead: false, leaf, report: SandboxReport { rlimits: true, cgroup, ..Default::default() } };
        match w.call_raw(&serde_json::json!({ "program": program })).await? {
            Value::Object(m) if m.get("ok") == Some(&Value::Bool(true)) => {
                w.report.seccomp = m.get("seccomp").and_then(Value::as_str).unwrap_or("unknown").to_string();
                Ok(w)
            }
            Value::Object(m) if m.get("sandbox_error") == Some(&Value::Bool(true)) => {
                Err(VrlError::Sandbox(m.get("error").and_then(Value::as_str).unwrap_or("unknown").to_string()))
            }
            Value::Object(m) => Err(VrlError::Compile(
                m.get("error").and_then(Value::as_str).unwrap_or("unknown").to_string(),
            )),
            other => Err(VrlError::WorkerDied(format!("unexpected handshake {other}"))),
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    async fn call_raw(&mut self, msg: &Value) -> Result<Value, VrlError> {
        if self.dead {
            return Err(VrlError::WorkerDied("worker was killed earlier in this run".into()));
        }
        let mut line = serde_json::to_vec(msg).map_err(|e| VrlError::Runtime(e.to_string()))?;
        line.push(b'\n');
        let max = self.limits.max_output_bytes;
        let fut = async {
            self.stdin.write_all(&line).await.map_err(|e| VrlError::WorkerDied(e.to_string()))?;
            self.stdin.flush().await.map_err(|e| VrlError::WorkerDied(e.to_string()))?;
            let mut buf = Vec::new();
            loop {
                let chunk = self.stdout.fill_buf().await.map_err(|e| VrlError::WorkerDied(e.to_string()))?;
                if chunk.is_empty() {
                    return Err(VrlError::WorkerDied("worker exited".into()));
                }
                if let Some(i) = chunk.iter().position(|b| *b == b'\n') {
                    buf.extend_from_slice(&chunk[..i]);
                    self.stdout.consume(i + 1);
                    break;
                }
                let n = chunk.len();
                buf.extend_from_slice(chunk);
                self.stdout.consume(n);
                if buf.len() > max {
                    return Err(VrlError::OutputTooLarge(max));
                }
            }
            if buf.len() > max {
                return Err(VrlError::OutputTooLarge(max));
            }
            serde_json::from_slice::<Value>(&buf).map_err(|e| VrlError::WorkerDied(e.to_string()))
        };
        match tokio::time::timeout(self.limits.call_timeout, fut).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(VrlError::WorkerDied(msg))) => {
                let status = self.kill().await;
                let oom = self.leaf.as_ref().is_some_and(CgroupLeaf::oom_killed);
                Err(VrlError::WorkerDied(format!("{msg}: {}", sandbox::death_reason(status, oom))))
            }
            Ok(Err(e)) => {
                self.kill().await;
                Err(e)
            }
            Err(_) => {
                self.kill().await;
                Err(VrlError::Budget(self.limits.call_timeout.as_millis() as u64))
            }
        }
    }

    async fn kill(&mut self) -> Option<std::process::ExitStatus> {
        self.dead = true;
        // A worker that already died is reaped as is; one still running is
        // killed. Give a dying worker a moment so its real cause (a signal)
        // is reported rather than our SIGKILL.
        if let Ok(Ok(st)) = tokio::time::timeout(Duration::from_millis(200), self.child.wait()).await {
            return Some(st);
        }
        let _ = self.child.start_kill();
        self.child.wait().await.ok()
    }

    pub async fn call(&mut self, input: &Value) -> Result<Value, VrlError> {
        match self.call_raw(&serde_json::json!({ "input": input })).await? {
            Value::Object(mut m) => {
                if let Some(e) = m.remove("error") {
                    return Err(VrlError::Runtime(e.as_str().unwrap_or("unknown").to_string()));
                }
                Ok(m.remove("output").unwrap_or(Value::Null))
            }
            other => Err(VrlError::WorkerDied(format!("bad reply {other}"))),
        }
    }
}

/// Pool sizing.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Workers alive at once in this process.
    pub max_workers: usize,
    /// Workers alive at once for one tenant (fairness: one tenant's
    /// fan-out cannot starve the others).
    pub max_per_tenant: usize,
    /// How long a run waits for a slot before failing.
    pub acquire_timeout: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self { max_workers: 32, max_per_tenant: 4, acquire_timeout: Duration::from_secs(60) }
    }
}

/// Spawns sandboxed, single-use VRL workers under global and per-tenant
/// concurrency limits.
pub struct VrlPool {
    exe: PathBuf,
    policy: SandboxPolicy,
    cfg: PoolConfig,
    /// The delegated cgroup, or why there is none.
    cgroup: Result<CgroupParent, String>,
    global: Arc<Semaphore>,
    tenants: Mutex<HashMap<String, Arc<Semaphore>>>,
    warned: AtomicBool,
    pub spawned: AtomicU64,
}

impl VrlPool {
    pub fn new(exe: PathBuf, policy: SandboxPolicy, cfg: PoolConfig) -> Self {
        let cgroup = match (&policy.cgroup, &policy.cgroup_parent) {
            (Enforce::Off, _) => Err("off".to_string()),
            (_, None) => Err("unavailable: no delegated cgroup configured (NANO_CONNECTOR_CGROUP_PARENT)".to_string()),
            (_, Some(dir)) => CgroupParent::probe(dir).map_err(|e| format!("unavailable: {e}")),
        };
        Self {
            exe,
            global: Arc::new(Semaphore::new(cfg.max_workers.max(1))),
            policy,
            cfg,
            cgroup,
            tenants: Mutex::new(HashMap::new()),
            warned: AtomicBool::new(false),
            spawned: AtomicU64::new(0),
        }
    }

    pub fn policy(&self) -> &SandboxPolicy {
        &self.policy
    }

    /// The cgroup layer's status as reports will show it.
    pub fn cgroup_status(&self) -> String {
        match &self.cgroup {
            Ok(p) => format!("enforced ({})", p.controllers.join(" ")),
            Err(e) => e.clone(),
        }
    }

    pub fn max_per_tenant(&self) -> usize {
        self.cfg.max_per_tenant.max(1)
    }

    async fn permits(&self, sem: Arc<Semaphore>, n: u32, what: &'static str) -> Result<OwnedSemaphorePermit, VrlError> {
        tokio::time::timeout(self.cfg.acquire_timeout, sem.acquire_many_owned(n))
            .await
            .map_err(|_| VrlError::PoolExhausted(self.cfg.acquire_timeout, what))?
            .map_err(|_| VrlError::PoolExhausted(self.cfg.acquire_timeout, what))
    }

    /// Reserve `n` worker slots for one run, all at once (tokio semaphores
    /// are FIFO, so two runs of one tenant cannot each hold half of what
    /// they need and wait on each other).
    pub async fn reserve(&self, tenant: &str, n: usize) -> Result<Reservation, VrlError> {
        if n > self.max_per_tenant() || n > self.cfg.max_workers.max(1) {
            return Err(VrlError::Sandbox(format!(
                "a run needs {n} VRL workers; at most {} per tenant are allowed",
                self.max_per_tenant()
            )));
        }
        let tsem = self
            .tenants
            .lock()
            .expect("tenants")
            .entry(tenant.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.max_per_tenant())))
            .clone();
        let n = n.max(1) as u32;
        let tenant_permit = self.permits(tsem, n, "per-tenant limit").await?;
        let global_permit = self.permits(self.global.clone(), n, "global limit").await?;
        Ok(Reservation { _tenant: tenant_permit, _global: global_permit })
    }

    /// A fresh single-use worker with its own slot.
    pub async fn spawn(&self, tenant: &str, program: &str, limits: WorkerLimits) -> Result<PooledWorker, VrlError> {
        let r = self.reserve(tenant, 1).await?;
        let worker = self.spawn_reserved(&r, program, limits).await?;
        Ok(PooledWorker { worker, _slots: Some(r) })
    }

    /// A fresh worker inside a reservation (the caller keeps the
    /// reservation alive for as long as its workers run).
    pub async fn spawn_reserved(&self, _slots: &Reservation, program: &str, limits: WorkerLimits) -> Result<VrlWorker, VrlError> {

        let leaf = match (&self.cgroup, self.policy.cgroup) {
            (_, Enforce::Off) => None,
            (Ok(parent), mode) => match parent.leaf(self.policy.memory_max.unwrap_or(limits.address_space_bytes), self.policy.cpu_max) {
                Ok(l) => Some(l),
                Err(e) if mode == Enforce::Require => return Err(VrlError::Sandbox(e)),
                Err(e) => {
                    tracing::warn!(target: "nano_connector::sandbox", error = %e, "VRL worker runs without its cgroup");
                    None
                }
            },
            (Err(e), Enforce::Require) => return Err(VrlError::Sandbox(format!("cgroup is required but {e}"))),
            (Err(_), _) => None,
        };
        let has_leaf = leaf.is_some();
        let mut worker = VrlWorker::spawn_sandboxed(&self.exe, program, limits, self.policy.seccomp, leaf).await?;
        self.spawned.fetch_add(1, Ordering::Relaxed);
        worker.report.cgroup = match (&self.cgroup, has_leaf) {
            (Ok(p), true) => format!("enforced ({})", p.controllers.join(" ")),
            (Ok(_), false) => "unavailable: leaf could not be created".into(),
            (Err(e), _) => e.clone(),
        };
        if worker.report.degraded() && !self.warned.swap(true, Ordering::SeqCst) {
            tracing::warn!(
                target: "nano_connector::sandbox",
                seccomp = %worker.report.seccomp,
                cgroup = %worker.report.cgroup,
                "VRL workers run with DEGRADED isolation (rlimits + no_new_privs + cleared env still apply); see nano-connector/docs/SECURITY.md"
            );
        }
        Ok(worker)
    }
}

/// Worker slots held for one run.
pub struct Reservation {
    _tenant: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

/// A worker, optionally holding its own pool slot. Dropping it kills the
/// process (and removes its cgroup).
pub struct PooledWorker {
    worker: VrlWorker,
    _slots: Option<Reservation>,
}

impl PooledWorker {
    pub fn new(worker: VrlWorker) -> Self {
        Self { worker, _slots: None }
    }
}

impl std::ops::Deref for PooledWorker {
    type Target = VrlWorker;
    fn deref(&self) -> &VrlWorker {
        &self.worker
    }
}

impl std::ops::DerefMut for PooledWorker {
    fn deref_mut(&mut self) -> &mut VrlWorker {
        &mut self.worker
    }
}

/// The worker loop (`nano-connector vrl-worker [--seccomp=MODE]`). The
/// sandbox goes up before the first byte of input is read. Then: first line
/// `{"program"}`, answered `{"ok", "seccomp"}`; then one `{"input"}` per line,
/// answered with `{"output"}` or `{"error"}`.
pub fn worker_main(args: &[String]) -> std::io::Result<()> {
    use std::io::{BufRead, Write};
    // The parent always passes the mode; anything unreadable is Require.
    let mode = args
        .iter()
        .find_map(|a| a.strip_prefix("--seccomp="))
        .and_then(Enforce::parse)
        .unwrap_or(Enforce::Require);
    let sandbox = sandbox::enter_worker_sandbox(mode);
    let stdin = std::io::stdin();
    let mut out = std::io::stdout().lock();
    let mut lines = stdin.lock().lines();
    let seccomp = match sandbox {
        Ok(s) => s,
        Err(e) => {
            // Read (and drop) the program first, so the parent's handshake
            // write cannot fail with EPIPE and hide this reason.
            let _ = lines.next();
            writeln!(out, "{}", serde_json::json!({"ok": false, "sandbox_error": true, "error": e}))?;
            return out.flush();
        }
    };
    let Some(first) = lines.next() else { return Ok(()) };
    let first: Value = serde_json::from_str(&first?).unwrap_or(Value::Null);
    let source = first.get("program").and_then(Value::as_str).unwrap_or_default().to_string();
    let program = match compile(&source) {
        Ok(p) => {
            writeln!(out, "{}", serde_json::json!({"ok": true, "seccomp": seccomp}))?;
            out.flush()?;
            p
        }
        Err(errs) => {
            writeln!(out, "{}", serde_json::json!({"ok": false, "error": errs.join("\n")}))?;
            return out.flush();
        }
    };
    for line in lines {
        let msg: Value = serde_json::from_str(&line?).unwrap_or(Value::Null);
        let input = msg.get("input").cloned().unwrap_or(Value::Null);
        let reply = match resolve(&program, input) {
            Ok(v) => serde_json::json!({ "output": v }),
            Err(e) => serde_json::json!({ "error": e }),
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
    Ok(())
}

/// `nano-connector sandbox-probe <op>`: enter the worker sandbox, then try
/// one thing a compromised interpreter would try, and print what happened.
/// Used by the attack suite; harmless outside it.
pub fn sandbox_probe(args: &[String]) -> std::io::Result<()> {
    use std::io::Write;
    let mode = args.iter().find_map(|a| a.strip_prefix("--seccomp=")).and_then(Enforce::parse).unwrap_or(Enforce::Require);
    let op = args.iter().find(|a| !a.starts_with("--")).cloned().unwrap_or_default();
    // `open_path`: the file to try (taken before the sandbox, like a path an
    // escaped interpreter could learn).
    let path = std::ffi::CString::new(args.iter().find_map(|a| a.strip_prefix("--path=")).unwrap_or("/")).unwrap_or_default();
    // Observed before the sandbox: what the worker inherited.
    let env_count = std::env::vars_os().count();
    // Then the process hardening, observed before seccomp blocks
    // getrlimit/prctl: these are what tenant code runs with.
    let hardened = sandbox::harden_worker_process();
    let mut core = libc::rlimit { rlim_cur: u64::MAX as libc::rlim_t, rlim_max: u64::MAX as libc::rlim_t };
    // SAFETY: getrlimit into a local; prctl GET with no pointers.
    let dumpable = unsafe {
        libc::getrlimit(libc::RLIMIT_CORE, &mut core);
        libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0)
    };
    let status = match hardened {
        Ok(()) => sandbox::install_seccomp(mode),
        Err(e) => Err(e),
    };
    let mut out = std::io::stdout().lock();
    let errno = || std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    // SAFETY: raw syscalls with valid constant arguments; each is expected
    // to fail or to kill the process.
    let (ret, err) = unsafe {
        match op.as_str() {
            "env" => (env_count as i64, 0),
            "open" => {
                let r = libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY);
                (r as i64, errno())
            }
            "open_path" => {
                let r = libc::open(path.as_ptr(), libc::O_RDONLY);
                (r as i64, errno())
            }
            "open_proc_environ" => {
                let r = libc::open(c"/proc/self/environ".as_ptr(), libc::O_RDONLY);
                (r as i64, errno())
            }
            "open_parent_mem" => {
                let path = std::ffi::CString::new(format!("/proc/{}/mem", libc::getppid())).unwrap_or_default();
                let r = libc::open(path.as_ptr(), libc::O_RDONLY);
                (r as i64, errno())
            }
            "socket" => (libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) as i64, errno()),
            "socket_unix" => (libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) as i64, errno()),
            "execve" => {
                let sh = c"/bin/sh";
                let argv = [sh.as_ptr(), std::ptr::null()];
                let envp = [std::ptr::null()];
                (libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr()) as i64, errno())
            }
            "fork" => (libc::syscall(libc::SYS_clone, libc::SIGCHLD as libc::c_ulong, 0, 0, 0, 0), errno()),
            "kill_parent" => (libc::kill(libc::getppid(), 0) as i64, errno()),
            "ptrace" => (libc::ptrace(libc::PTRACE_ATTACH, libc::getppid(), 0, 0) as i64, errno()),
            "mmap_exec" => {
                let p = libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_EXEC, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0);
                (if p == libc::MAP_FAILED { -1 } else { 0 }, errno())
            }
            "read_stdin" => {
                let mut b = [0u8; 1];
                (libc::read(0, b.as_mut_ptr().cast(), 1) as i64, errno())
            }
            "abort" => {
                libc::abort();
            }
            "stack_overflow" => {
                fn deep(n: u64) -> u64 {
                    if n == u64::MAX {
                        return 0;
                    }
                    let pad = std::hint::black_box([n; 64]);
                    deep(n + 1) + pad[0]
                }
                (deep(0) as i64, 0)
            }
            "cpu" => {
                let mut x = 0u64;
                loop {
                    x = std::hint::black_box(x.wrapping_add(1));
                }
            }
            "fds" => {
                // Count open fds above stderr.
                let n = (3..256)
                    .filter(|fd| {
                        let mut st: libc::stat = std::mem::zeroed();
                        libc::fstat(*fd, &mut st) == 0
                    })
                    .count();
                (n as i64, 0)
            }
            _ => (-1, libc::EINVAL),
        }
    };
    let status = match status {
        Ok(s) => s,
        Err(e) => format!("error: {e}"),
    };
    writeln!(
        out,
        "{}",
        serde_json::json!({"op": op, "ret": ret, "errno": err, "seccomp": status, "core_limit": [core.rlim_cur, core.rlim_max], "dumpable": dumpable})
    )?;
    out.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowlist_is_real_and_disjoint_from_refused() {
        let all: Vec<&str> = vrl::stdlib::all().iter().map(|f| f.identifier()).collect();
        for f in ALLOWED_FUNCTIONS {
            assert!(all.contains(f), "allowlisted `{f}` is not a VRL 0.36 stdlib function");
            assert!(!REFUSED_FUNCTIONS.contains(f), "`{f}` is both allowed and refused");
        }
        assert_eq!(functions().len(), ALLOWED_FUNCTIONS.len());
    }

    #[test]
    fn refused_functions_do_not_compile() {
        for f in ["http_request", "get_env_var", "dns_lookup", "decode_gzip", "uuid_v4", "validate_json_schema", "get_hostname"] {
            let src = format!("{f}(\"x\")");
            let err = compile(&src).err().unwrap_or_else(|| panic!("{f} compiled")).join("\n");
            assert!(err.contains("undefined function") || err.contains("call to undefined"), "{f}: {err}");
        }
    }

    /// The parser side's denylist (`BLOCKED_VRL_FUNCTIONS`) must stay a
    /// subset of what this engine refuses. Read from source: the constant is
    /// crate-private to nanosiem-core and this crate does not depend on it.
    #[test]
    fn parser_denylist_is_refused_here_too() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../nanosiem-core/src/parsers/validator.rs");
        let src = std::fs::read_to_string(&path).expect("nanosiem-core validator.rs");
        let start = src.find("BLOCKED_VRL_FUNCTIONS: &[&str] = &[").expect("BLOCKED_VRL_FUNCTIONS");
        let body = &src[start..start + src[start..].find("];").expect("end of list")];
        let names: Vec<&str> = body.split('"').skip(1).step_by(2).collect();
        assert!(names.len() >= 5, "parsed {names:?}");
        for n in names {
            assert!(REFUSED_FUNCTIONS.contains(&n), "`{n}` is blocked for parsers but not refused here");
            assert!(!ALLOWED_FUNCTIONS.contains(&n), "`{n}` is blocked for parsers but allowed here");
        }
    }

    #[test]
    fn resolves_in_process() {
        let p = compile(r#"{"events": [.response.body], "next_request": null, "state": .state}"#).unwrap();
        let out = resolve(&p, serde_json::json!({"state": {"a": 1}, "response": {"body": 2}})).unwrap();
        assert_eq!(out, serde_json::json!({"events": [2], "next_request": null, "state": {"a": 1}}));
    }
}
