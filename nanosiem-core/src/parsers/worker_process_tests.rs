// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared worker-process bounds (NAN-4919, NAN-5234), driven with stand-in
//! commands. The real workers are exercised end to end by
//! `nanosiem-api/tests/pipe_preview_worker.rs` and
//! `nanosiem-api/tests/parser_test_worker.rs`.
use super::*;

fn limits(wall: Duration, max_output_bytes: usize) -> WorkerLimits {
    WorkerLimits {
        private_memory_bytes: 256 * 1024 * 1024,
        address_space_bytes: 1024 * 1024 * 1024,
        cpu_seconds: 3,
        cpu_ceiling_seconds: 4,
        wall,
        max_output_bytes,
    }
}

#[test]
fn concurrency_is_clamped() {
    assert_eq!(clamp_concurrency(None, 2, 8), 2);
    assert_eq!(clamp_concurrency(Some("0"), 2, 8), 1);
    assert_eq!(clamp_concurrency(Some("99"), 2, 8), 8);
    assert_eq!(clamp_concurrency(Some(" 3 "), 2, 8), 3);
    assert_eq!(clamp_concurrency(Some("x"), 2, 8), 2);
}

#[tokio::test]
async fn a_hung_worker_is_killed_at_the_deadline() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 30"]);
    let started = std::time::Instant::now();
    let result = exchange(command, b"{}", &limits(Duration::from_millis(300), 1024), "test").await;
    assert_eq!(result, Err(WorkerFailure::Deadline));
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn oversized_output_is_refused() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "head -c 4096 /dev/zero"]);
    let result = exchange(command, b"", &limits(Duration::from_secs(5), 1024), "test").await;
    assert_eq!(result, Err(WorkerFailure::OutputLimit));
}

#[tokio::test]
async fn a_failing_worker_is_a_worker_failure() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "exit 3"]);
    let result = exchange(command, b"", &limits(Duration::from_secs(5), 1024), "test").await;
    assert_eq!(result, Err(WorkerFailure::Worker));
}

#[tokio::test]
async fn a_large_request_reaches_the_worker_intact() {
    // Larger than any pipe buffer: the write must not deadlock.
    let input = vec![b'x'; 8 * 1024 * 1024];
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "wc -c"]);
    let output = exchange(command, &input, &limits(Duration::from_secs(10), 1024), "test")
        .await
        .unwrap();
    assert_eq!(String::from_utf8(output).unwrap().trim(), "8388608");
}

#[tokio::test]
async fn the_worker_sees_no_parent_environment() {
    std::env::set_var("NANO_WORKER_SANDBOX_SECRET_PROBE", "leak");
    let command = Command::new("/usr/bin/env");
    let output = exchange(command, b"", &limits(Duration::from_secs(5), 64 * 1024), "test")
        .await
        .unwrap();
    let env = String::from_utf8(output).unwrap();
    assert!(!env.contains("NANO_WORKER_SANDBOX_SECRET_PROBE"), "{env}");
    assert!(env.contains("TZ=UTC"));
}

#[cfg(unix)]
#[tokio::test]
async fn the_cpu_limit_is_installed_before_exec() {
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "ulimit -t; ulimit -c"]);
    let output = exchange(command, b"", &limits(Duration::from_secs(5), 1024), "test")
        .await
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    let mut lines = output.lines();
    assert_eq!(lines.next(), Some("3"), "{output}");
    assert_eq!(lines.next(), Some("0"), "{output}");
}

#[test]
fn read_bounded_refuses_oversized_input() {
    assert_eq!(read_bounded(&b"abcd"[..], 4).as_deref(), Some(&b"abcd"[..]));
    assert_eq!(read_bounded(&b"abcde"[..], 4), None);
}

#[test]
fn one_worker_per_user_then_the_replica_gate() {
    let gate = WorkerGate::new(2);
    let alice = Uuid::new_v4();
    let held = gate.try_admit(Some(alice)).unwrap();
    assert_eq!(gate.try_admit(Some(alice)).err(), Some(AdmissionRefused::UserBusy));
    let bob = gate.try_admit(Some(Uuid::new_v4())).unwrap();
    // Replica full: an anonymous caller and a new user are both refused, and
    // the refused user's claim is released.
    let carol = Uuid::new_v4();
    assert_eq!(gate.try_admit(None).err(), Some(AdmissionRefused::Busy));
    assert_eq!(gate.try_admit(Some(carol)).err(), Some(AdmissionRefused::Busy));
    drop(bob);
    assert!(gate.try_admit(Some(carol)).is_ok());
    drop(held);
    assert!(gate.try_admit(Some(alice)).is_ok());
}

#[tokio::test]
async fn a_bounded_wait_admits_a_freed_slot_or_refuses() {
    let gate = WorkerGate::new(1);
    let held = gate.try_admit(None).unwrap();
    let started = std::time::Instant::now();
    assert_eq!(
        gate.admit_within(None, Duration::from_millis(100)).await.err(),
        Some(AdmissionRefused::Busy)
    );
    assert!(started.elapsed() >= Duration::from_millis(100));
    drop(held);
    assert!(gate.admit_within(None, Duration::from_millis(100)).await.is_ok());
}

#[cfg(unix)]
fn cpu_rlimit() -> libc::rlimit {
    let mut current = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CPU as _, &mut current) }, 0);
    current
}

/// NAN-5396: moving the soft CPU limit between phases counts from the CPU
/// already used and never touches the hard limit. Runs in the test process,
/// so it restores the limit it changed.
#[cfg(unix)]
#[test]
fn extending_the_cpu_soft_limit_counts_from_used_cpu_and_keeps_the_hard_limit() {
    let before = cpu_rlimit();
    if before.rlim_cur < 3600 {
        return; // a constrained test runner: covered by the subprocess probes
    }
    let used = self_cpu_time().unwrap().as_secs();
    let generous = WorkerLimits { cpu_seconds: 3, cpu_ceiling_seconds: 4, ..limits(Duration::from_secs(1), 1) };
    let extended = extend_cpu_soft_limit(&generous, 3600);
    let after = cpu_rlimit();
    // Restore before asserting, so a failure leaves the process as it was.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_CPU as _, &before) }, 0);
    extended.unwrap();
    assert_eq!(after.rlim_max, before.rlim_max);
    let expected = (used + 3600) as libc::rlim_t;
    assert!(
        (expected..=expected + 2).contains(&after.rlim_cur),
        "soft {} for {used} s used",
        after.rlim_cur
    );
    assert_eq!(cpu_rlimit().rlim_cur, before.rlim_cur);
}

/// Child side of the probes below: re-applies the parser-test worker's CPU
/// limit (as `apply_limits` does before exec and on worker entry), moves to
/// the execution phase, prints the result.
/// A no-op unless the parent probe started this process.
#[cfg(unix)]
#[test]
fn cpu_limit_probe_child() {
    if std::env::var_os(PROBE_ENV).is_none() {
        return;
    }
    let limits = crate::parsers::test_sandbox::LIMITS;
    cap(libc::RLIMIT_CPU as _, limits.cpu_seconds, limits.cpu_hard_seconds()).unwrap();
    extend_cpu_soft_limit(&limits, crate::parsers::test_sandbox::WORKER_EXECUTION_CPU_SECONDS).unwrap();
    let after = cpu_rlimit();
    println!("PROBE soft={} hard={}", after.rlim_cur, after.rlim_max);
}

#[cfg(unix)]
const PROBE_ENV: &str = "NANO_CPU_LIMIT_PROBE";

/// Run [`cpu_limit_probe_child`] in a fresh process that inherits
/// `RLIMIT_CPU` soft/hard; return the soft/hard it ends the phase reset with.
#[cfg(unix)]
fn probe(inherited_soft: u64, inherited_hard: u64) -> (u64, u64) {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "parsers::worker_process::tests::cpu_limit_probe_child", "--nocapture", "--test-threads=1"])
        .env(PROBE_ENV, "1");
    // SAFETY: only setrlimit runs between fork and exec.
    unsafe {
        command.pre_exec(move || {
            let value = libc::rlimit {
                rlim_cur: inherited_soft as libc::rlim_t,
                rlim_max: inherited_hard as libc::rlim_t,
            };
            if libc::setrlimit(libc::RLIMIT_CPU as _, &value) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = command.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .find_map(|line| line.split_once("PROBE ").map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("no probe output: {stdout} {}", String::from_utf8_lossy(&output.stderr)));
    let field = |name: &str| -> u64 {
        line.split_whitespace()
            .find_map(|part| part.strip_prefix(name))
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("{line}"))
    };
    (field("soft="), field("hard="))
}

/// NAN-5396 (P3): an operator's stricter inherited soft limit survives the
/// phase reset; otherwise the reset grants the execution allowance, and the
/// hard limit is the stricter of the inherited one and the worker ceiling.
#[cfg(unix)]
#[test]
fn the_phase_reset_honours_inherited_cpu_limits() {
    use crate::parsers::test_sandbox::{WORKER_COMPILE_CPU_SECONDS, WORKER_CPU_CEILING_SECONDS, WORKER_EXECUTION_CPU_SECONDS};
    let execution = WORKER_EXECUTION_CPU_SECONDS;
    // Stricter inherited soft (5 s) with a roomy hard: stays 5, not used+8.
    assert_eq!(probe(5, 30), (5, WORKER_CPU_CEILING_SECONDS));
    // Inherited soft below compile but above used+8: the reset may lower it.
    let (soft, hard) = probe(WORKER_COMPILE_CPU_SECONDS - 1, 60);
    assert!((execution..=execution + 2).contains(&soft), "soft {soft}");
    assert_eq!(hard, WORKER_CPU_CEILING_SECONDS);
    // Roomy inherited soft, stricter inherited hard: soft = used+8, hard kept.
    let (soft, hard) = probe(18, 20);
    assert!((execution..=execution + 2).contains(&soft), "soft {soft}");
    assert_eq!(hard, 20);
    // Unlimited inherited: the configured phases and ceiling.
    let (soft, hard) = probe(libc::RLIM_INFINITY as u64, libc::RLIM_INFINITY as u64);
    assert!((execution..=execution + 2).contains(&soft), "soft {soft}");
    assert_eq!(hard, WORKER_CPU_CEILING_SECONDS);
}

#[test]
fn the_cpu_hard_limit_is_the_ceiling_or_one_past_the_soft_limit() {
    let mut limits = limits(Duration::from_secs(1), 1);
    assert_eq!(limits.cpu_hard_seconds(), 4);
    limits.cpu_ceiling_seconds = 0;
    assert_eq!(limits.cpu_hard_seconds(), 4);
    limits.cpu_ceiling_seconds = 21;
    assert_eq!(limits.cpu_hard_seconds(), 21);
}
