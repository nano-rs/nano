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
