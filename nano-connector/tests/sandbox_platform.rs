//! NAN-4914: the VRL sandbox off Linux (the macOS native dev stack).
//!
//! seccomp is a Linux kernel facility, so other targets build a limited
//! sandbox (see `src/sandbox.rs`, "Platforms"). These tests pin the
//! contract that this is never silent: `Require` refuses to run VRL, `Prefer`
//! runs and reports the sandbox as degraded, and the parts that do exist
//! everywhere (cleared env, no inherited fds, no core dumps, no fork) hold.
//! On Linux the full suite in `tests/sandbox.rs` runs instead.
#![cfg(not(target_os = "linux"))]

mod common;

use std::os::unix::process::ExitStatusExt;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use common::*;
use nano_connector::engine::{EngineError, RunInput};
use nano_connector::sandbox::{self, Enforce, Rlimits, SandboxPolicy};
use nano_connector::vrl_exec::{PoolConfig, VrlError, VrlPool};
use serde_json::{Value, json};

async fn probe(op: &str, seccomp: Enforce, cpu_secs: u64) -> (Option<i32>, Option<i32>, Option<Value>) {
    let mut cmd = tokio::process::Command::new(worker_exe());
    cmd.arg("sandbox-probe").arg(op).arg(format!("--seccomp={}", seccomp.as_str()));
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    sandbox::harden_command(&mut cmd, Rlimits { address_space_bytes: 1 << 30, cpu_secs, stack_bytes: 64 << 20 });
    let out = tokio::time::timeout(Duration::from_secs(20), cmd.output()).await.expect("probe hung").expect("spawn probe");
    let v = serde_json::from_slice(out.stdout.split(|b| *b == b'\n').next().unwrap_or_default()).ok();
    (out.status.signal(), out.status.code(), v)
}

#[test]
fn seccomp_is_reported_unavailable_and_require_fails() {
    assert!(sandbox::install_seccomp(Enforce::Require).unwrap_err().contains("Linux-only"));
    assert!(sandbox::install_seccomp(Enforce::Prefer).unwrap().starts_with("unavailable: seccomp is Linux-only"));
    assert_eq!(sandbox::install_seccomp(Enforce::Off).unwrap(), "off");
}

#[tokio::test]
async fn strict_policy_refuses_vrl_and_prefer_runs_degraded() {
    let mock = start_mock(Arc::new(|_r| MockResp::json(json!({"items": [1]}))), false).await;
    let s = spec("version: 1\nname: t\nkind: collector\nallow:\n  - host: api.example.com\nstreams:\n  - id: s\n    request: { url: \"https://api.example.com/v1/x\" }\n    program: '{\"events\": .response.body.items}'\n");

    // Require (what NANO_CONNECTOR_SANDBOX=strict selects): refused before
    // any request.
    let mut strict = harness(&mock);
    let policy = SandboxPolicy { seccomp: Enforce::Require, ..Default::default() };
    strict.cfg.vrl_pool = Arc::new(VrlPool::new(worker_exe(), policy, PoolConfig::default()));
    let r = run(&strict, &s, RunInput::default()).await;
    assert!(matches!(r.out, Err(EngineError::Vrl(VrlError::Sandbox(_)))), "{:?}", r.out.as_ref().err());
    assert!(mock.requests().is_empty(), "the refused run sent nothing");
    assert!(strict.cfg.sandbox_self_test().await.is_err(), "boot self-test must fail under strict");

    // Prefer: runs, and the report says exactly what is missing.
    let mut prefer = harness(&mock);
    let policy = SandboxPolicy { seccomp: Enforce::Prefer, ..Default::default() };
    prefer.cfg.vrl_pool = Arc::new(VrlPool::new(worker_exe(), policy, PoolConfig::default()));
    let out = run(&prefer, &s, RunInput::default()).await.out.expect("prefer runs");
    assert_eq!(out.events, 1);
    let rep = &out.sandbox[0].1;
    assert!(rep.rlimits && rep.degraded(), "{rep:?}");
    assert!(rep.seccomp.starts_with("unavailable: seccomp is Linux-only"), "{rep:?}");
    assert!(rep.cgroup.starts_with("unavailable") || rep.cgroup == "off", "{rep:?}");
}

#[tokio::test]
async fn the_portable_layers_still_hold() {
    // Cleared environment and no inherited fds.
    // SAFETY: test-only; no concurrent env readers in this test binary.
    unsafe { std::env::set_var("NANO_TEST_CANARY", "platform-secret-value") };
    let (_, _, v) = probe("env", Enforce::Prefer, 10).await;
    assert_eq!(v.unwrap()["ret"], 0, "environment is not empty");
    let (_, _, v) = probe("fds", Enforce::Prefer, 10).await;
    assert_eq!(v.unwrap()["ret"], 0, "inherited fds survived");
    // SAFETY: as above.
    unsafe { std::env::remove_var("NANO_TEST_CANARY") };

    // No core dumps: RLIMIT_CORE is 0 in the worker and fatal signals become
    // `_exit(128 + sig)`, never a signal death.
    let (_, _, v) = probe("core", Enforce::Prefer, 10).await;
    let v = v.unwrap();
    assert_eq!(v["core_limit"], json!([0, 0]), "{v}");
    assert!(v["seccomp"].as_str().unwrap().starts_with("unavailable"), "{v}");
    for (op, sig, cpu) in [("abort", libc::SIGABRT, 10), ("cpu", libc::SIGXCPU, 1)] {
        let (signal, code, _) = probe(op, Enforce::Prefer, cpu).await;
        assert_eq!(signal, None, "{op}: worker died on signal {signal:?} (would dump core)");
        assert_eq!(code, Some(sandbox::fatal_exit_code(sig)), "{op}");
    }

    // RLIMIT_NPROC 0: no child processes even without seccomp.
    let (_, _, v) = probe("fork", Enforce::Prefer, 10).await;
    let v = v.unwrap();
    assert_eq!(v["ret"], -1, "fork succeeded: {v}");
    assert_eq!(v["errno"], libc::EAGAIN as i64, "{v}");

    // Require in the worker itself: the sandbox error is reported, the probe
    // never claims seccomp.
    let (_, _, v) = probe("core", Enforce::Require, 10).await;
    assert!(v.unwrap()["seccomp"].as_str().unwrap().starts_with("error: seccomp is required"));
}
