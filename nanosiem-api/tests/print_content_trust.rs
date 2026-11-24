// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5771: `nanosiem-api --print-content-trust` and `nanosiem-jobs
//! --print-content-trust` print the compiled content trust and exit before any
//! configuration, tracing, pool or server exists. The e2e harness probes every
//! binary it starts this way, with an EMPTY environment: a binary that fell
//! through to startup would fail on missing config (or hang) instead of
//! answering, so this runs each with `env_clear()` and a deadline.

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use nanosiem_core::content_bundle::contract;

fn probe(exe: &str) {
    let mut child = Command::new(exe)
        .arg(contract::PRINT_TRUST_ARGUMENT)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("spawn {exe}: {e}"));
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait().expect("wait").is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("{exe} {} did not exit: it reached startup", contract::PRINT_TRUST_ARGUMENT);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = child.wait_with_output().expect("output");
    assert!(out.status.success(), "{exe}: {:?} stderr={}", out.status, String::from_utf8_lossy(&out.stderr));
    assert_eq!(String::from_utf8_lossy(&out.stdout), format!("{}\n", contract::trust_label()), "{exe}");
    // Nothing else ran: no tracing / startup output.
    assert!(out.stderr.is_empty(), "{exe} wrote to stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn api_prints_its_trust_and_exits_before_startup() {
    probe(env!("CARGO_BIN_EXE_nanosiem-api"));
}

#[test]
fn jobs_prints_its_trust_and_exits_before_startup() {
    probe(env!("CARGO_BIN_EXE_nanosiem-jobs"));
}

#[test]
fn trust_label_is_one_of_the_two_compositions() {
    assert!(matches!(contract::trust_label(), "production" | "production+acceptance"));
    assert_eq!(contract::PRINT_TRUST_ARGUMENT, "--print-content-trust");
}
