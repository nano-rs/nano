//! The VRL worker sandbox, probed from inside: what an interpreter escape
//! could do once it runs code in the worker process.
//!
//! `nano-connector sandbox-probe <op>` is spawned exactly like a worker
//! (same `harden_command`, same hardening and seccomp) and attempts one
//! thing. Seccomp ends the process (SIGSYS, turned into exit 159) or
//! refuses (EPERM) each attempt. No worker death ever goes through the
//! kernel's core-dump path: every fatal signal becomes `_exit(128 + sig)`.

mod common;

use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use nano_connector::engine::{EngineError, RunInput};
use nano_connector::sandbox::{self, Enforce, Rlimits, SandboxPolicy};
use nano_connector::vrl_exec::{PoolConfig, VrlError, VrlPool, WorkerLimits};
use serde_json::{Value, json};

struct Probe {
    signal: Option<i32>,
    code: Option<i32>,
    out: Option<Value>,
}

impl Probe {
    /// The fatal signal behind a hardened worker's `exit(128 + sig)`.
    fn died_of(&self) -> Option<i32> {
        self.code.filter(|c| *c > 128).map(|c| c - 128)
    }
}

async fn probe(op: &str, seccomp: Enforce) -> Probe {
    probe_with(op, seccomp, 10).await
}

async fn probe_with(op: &str, seccomp: Enforce, cpu_secs: u64) -> Probe {
    let mut cmd = tokio::process::Command::new(worker_exe());
    cmd.arg("sandbox-probe").arg(op).arg(format!("--seccomp={}", seccomp.as_str()));
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    sandbox::harden_command(&mut cmd, Rlimits { address_space_bytes: 1 << 30, cpu_secs, stack_bytes: 8 << 20 });
    let out = tokio::time::timeout(Duration::from_secs(20), cmd.output()).await.expect("probe hung").expect("spawn probe");
    Probe {
        signal: out.status.signal(),
        code: out.status.code(),
        out: serde_json::from_slice(out.stdout.split(|b| *b == b'\n').next().unwrap_or_default()).ok(),
    }
}

fn errno(p: &Probe) -> i64 {
    p.out.as_ref().and_then(|v| v["errno"].as_i64()).unwrap_or(-1)
}

#[tokio::test]
async fn worker_sandbox_blocks_escape_attempts() {
    // A canary in the parent's environment and a leaked fd without CLOEXEC.
    // SAFETY: test-only; no concurrent env readers in this test binary.
    unsafe { std::env::set_var("NANO_TEST_CANARY", "platform-secret-value") };
    // SAFETY: plain open of a world-readable file, intentionally not CLOEXEC.
    let leaked = unsafe { libc::open(c"/etc/hostname".as_ptr(), libc::O_RDONLY) };

    // Ended outright: network, exec, new processes, ptrace, signals. The
    // syscall never runs; the SIGSYS trap exits without a core dump.
    for op in ["socket", "socket_unix", "execve", "fork", "kill_parent", "ptrace"] {
        let p = probe(op, Enforce::Require).await;
        assert_eq!(p.signal, None, "{op}: died on a signal (core-dump path): {:?}", p.signal);
        assert_eq!(p.died_of(), Some(libc::SIGSYS), "{op} must be stopped by seccomp, got {:?} {:?}", p.code, p.out);
    }
    // Refused with EPERM: the filesystem (incl. /proc), executable memory.
    for op in ["open", "open_proc_environ", "open_parent_mem", "mmap_exec"] {
        let p = probe(op, Enforce::Require).await;
        let v = p.out.as_ref().unwrap_or_else(|| panic!("{op}: no output, signal {:?}", p.signal));
        assert_eq!(v["ret"], -1, "{op} succeeded: {v}");
        assert_eq!(errno(&p), libc::EPERM as i64, "{op}: {v}");
        assert_eq!(v["seccomp"], "enforced");
    }
    // What the worker inherited: nothing.
    let p = probe("env", Enforce::Require).await;
    assert_eq!(p.out.as_ref().unwrap()["ret"], 0, "environment is not empty");
    let p = probe("fds", Enforce::Require).await;
    assert_eq!(p.out.as_ref().unwrap()["ret"], 0, "inherited fds survived: {:?}", p.out);
    // What it may still do: talk on stdin/stdout.
    let p = probe("read_stdin", Enforce::Require).await;
    assert_eq!(p.out.as_ref().unwrap()["ret"], 0);

    // Control: without seccomp the same probe does open a socket, so the
    // assertions above test the filter, not the environment.
    let p = probe("socket", Enforce::Off).await;
    assert_eq!(p.signal, None);
    assert!(p.out.as_ref().unwrap()["ret"].as_i64().unwrap() >= 0, "{:?}", p.out);
    // ...but rlimits still stop it from forking.
    let p = probe("fork", Enforce::Off).await;
    assert_eq!(p.out.as_ref().unwrap()["ret"], -1, "fork succeeded without seccomp: {:?}", p.out);
    assert_eq!(errno(&p), libc::EAGAIN as i64);

    if leaked >= 0 {
        // SAFETY: closing our own fd.
        unsafe { libc::close(leaked) };
    }
    // SAFETY: as above.
    unsafe { std::env::remove_var("NANO_TEST_CANARY") };
}

#[tokio::test]
async fn workers_never_dump_core() {
    // What tenant code runs with: no core limit, not dumpable.
    let p = probe("core", Enforce::Require).await;
    let v = p.out.expect("probe output");
    assert_eq!(v["core_limit"], json!([0, 0]), "RLIMIT_CORE must be 0 in the worker: {v}");
    assert_eq!(v["dumpable"], 0, "worker must not be dumpable: {v}");
    assert_eq!(v["seccomp"], "enforced");
    // Every way a worker dies on its own ends in a plain exit, never a
    // signal death, so the kernel never runs the core-dump path (which a
    // `|systemd-coredump` core_pattern takes even with RLIMIT_CORE 0).
    for (op, sig, cpu) in [
        ("abort", libc::SIGABRT, 10),
        ("stack_overflow", libc::SIGSEGV, 10),
        ("cpu", libc::SIGXCPU, 1),
        ("execve", libc::SIGSYS, 10),
    ] {
        let p = probe_with(op, Enforce::Require, cpu).await;
        assert_eq!(p.signal, None, "{op}: worker died on signal {:?} (would dump core)", p.signal);
        assert_eq!(p.died_of(), Some(sig), "{op}: exit code {:?}", p.code);
    }
}

/// A delegated cgroup for tests: `NANO_CONNECTOR_TEST_CGROUP_PARENT`, or a
/// fresh directory next to this process's own cgroup when the user owns it
/// (systemd user sessions delegate `user@UID.service`).
fn test_cgroup_parent() -> Option<std::path::PathBuf> {
    if let Some(p) = std::env::var_os("NANO_CONNECTOR_TEST_CGROUP_PARENT") {
        return Some(p.into());
    }
    let own = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let rel = own.lines().find_map(|l| l.strip_prefix("0::"))?.trim().trim_start_matches('/').to_string();
    let parent = std::path::Path::new("/sys/fs/cgroup").join(rel).parent()?.to_path_buf();
    let dir = parent.join(format!("nano-connector-test-{}", std::process::id()));
    match std::fs::create_dir(&dir) {
        Ok(()) => Some(dir),
        Err(e) => {
            eprintln!("no test cgroup at {}: {e}", dir.display());
            None
        }
    }
}

#[tokio::test]
async fn cgroup_limits_apply_where_delegated_and_degrade_loudly_elsewhere() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": [1]}))), false).await;
    let memory_hog = spec(&format!(
        r#"
version: 1
name: cg
kind: collector
allow: [{{ host: api.example.com }}]
limits: {{ vrl_timeout_ms: 10000 }}
streams:
  - id: s
    request: {{ url: "https://api.example.com/x" }}
    program: |
      s = "xxxxxxxxxxxxxxxx"
      {}{{"events": [strlen(s)]}}
"#,
        (0..24).map(|_| "s = s + s\n      ").collect::<String>()
    ));

    let Some(parent) = test_cgroup_parent() else {
        // No delegation here (CI container, k8s pod): Require refuses,
        // Prefer runs and reports the gap.
        let policy = SandboxPolicy { cgroup: Enforce::Require, cgroup_parent: Some("/sys/fs/cgroup/does-not-exist".into()), ..require_seccomp() };
        let pool = VrlPool::new(worker_exe(), policy, PoolConfig::default());
        assert!(pool.cgroup_status().starts_with("unavailable"), "{}", pool.cgroup_status());
        let limits = WorkerLimits { address_space_bytes: 1 << 30, cpu_secs: 10, call_timeout: Duration::from_secs(5), max_output_bytes: 1 << 20 };
        assert!(matches!(pool.spawn("t", "{}", limits).await, Err(VrlError::Sandbox(_))));
        eprintln!("cgroup v2 delegation unavailable here; verified the degrade path only");
        return;
    };

    let policy = SandboxPolicy {
        seccomp: require_seccomp().seccomp,
        cgroup: Enforce::Require,
        cgroup_parent: Some(parent.clone()),
        cpu_max: Some((50_000, 100_000)),
        memory_max: Some(64 * 1024 * 1024),
    };
    let pool = Arc::new(VrlPool::new(worker_exe(), policy, PoolConfig::default()));
    let status = pool.cgroup_status();
    if status.starts_with("unavailable") {
        let _ = std::fs::remove_dir(&parent);
        panic!("a writable test cgroup exists but cannot be used: {status}");
    }
    let mut h = harness(&mock);
    h.cfg.worker_address_space = 8 << 30;
    h.cfg.vrl_pool = pool.clone();

    // 256 MiB string vs a 64 MiB memory.max (the 8 GiB address-space limit
    // would not stop it): the kernel OOM-kills the worker, and the error
    // says so.
    let r = run(&h, &memory_hog, RunInput::default()).await;
    let e = r.out.expect_err("memory hog must die");
    assert!(matches!(&e, EngineError::Vrl(VrlError::WorkerDied(m)) if m.contains("cgroup memory")), "{e}");

    // A normal program runs inside its leaf and reports it.
    let ok = spec("version: 1\nname: cg\nkind: collector\nallow: [{ host: api.example.com }]\nstreams:\n  - id: s\n    request: { url: \"https://api.example.com/x\" }\n    program: '{\"events\": .response.body.items}'\n");
    let out = run(&h, &ok, RunInput::default()).await.out.expect("normal run in cgroup");
    assert!(out.sandbox[0].1.cgroup.starts_with("enforced"), "{:?}", out.sandbox);
    assert_eq!(out.sandbox[0].1.seccomp, "enforced");

    // Leaves are removed after their run.
    drop(h);
    drop(pool);
    std::thread::sleep(Duration::from_millis(500));
    let left: Vec<_> = std::fs::read_dir(&parent).unwrap().filter_map(|e| e.ok()).filter(|e| e.path().is_dir()).map(|e| e.path()).collect();
    assert!(left.is_empty(), "worker cgroups left behind: {left:?}");
    if std::env::var_os("NANO_CONNECTOR_TEST_CGROUP_PARENT").is_none() {
        let _ = std::fs::remove_dir(&parent);
    }
}

/// NAN-3503: the runner holds the lean-assignments file (coordinator
/// endpoints) and per-tenant identity-writer token files. A VRL worker can
/// neither read them nor learn their path from its environment.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn worker_cannot_read_the_identity_assignments_mount() {
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("nan3503-sandbox-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("tokens")).unwrap();
    let assignments = dir.join("assignments.json");
    let token = dir.join("tokens").join("858f3709-a703-4b29-97a6-dd0ea314b84a");
    std::fs::write(&assignments, r#"{"858f3709-a703-4b29-97a6-dd0ea314b84a":{"internal_endpoint":"http://10.0.0.1:8080"}}"#).unwrap();
    std::fs::write(&token, "identity-writer-token-0123456789abcdef").unwrap();
    // SAFETY: test-only; no concurrent env readers in this test.
    unsafe { std::env::set_var("NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE", &assignments) };
    for path in [&assignments, &token] {
        let mut cmd = tokio::process::Command::new(worker_exe());
        cmd.arg("sandbox-probe").arg("open_path").arg(format!("--path={}", path.display())).arg("--seccomp=require");
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
        sandbox::harden_command(&mut cmd, Rlimits { address_space_bytes: 1 << 30, cpu_secs: 10, stack_bytes: 8 << 20 });
        let out = tokio::time::timeout(Duration::from_secs(20), cmd.output()).await.expect("probe hung").expect("spawn probe");
        let v: Value = serde_json::from_slice(out.stdout.split(|b| *b == b'\n').next().unwrap_or_default()).expect("probe output");
        assert_eq!(v["seccomp"], "enforced");
        assert_eq!(v["ret"], -1, "worker opened {}: {v}", path.display());
        assert_eq!(v["errno"], libc::EPERM, "{v}");
        // Control: the same file is readable outside the sandbox.
        assert!(std::fs::read(path).is_ok());
    }
    // The worker's environment is cleared: the assignments path does not leak.
    let p = probe("env", Enforce::Require).await;
    assert_eq!(p.out.as_ref().unwrap()["ret"], 0, "environment is not empty");
    // SAFETY: as above.
    unsafe { std::env::remove_var("NANO_LAKE_LEAN_ENRICHMENT_ASSIGNMENTS_FILE") };
    let _ = std::fs::remove_dir_all(&dir);
}
