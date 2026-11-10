// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5234: parser tests execute in the real `nanosiem-api
//! --parser-test-worker` process. A program that allocates without limit, or
//! burns CPU, is stopped by the worker's bounds and this (parent) process
//! carries on serving tests.

use nanosiem_core::parsers::{
    test_sandbox::{
        register_worker_executable, run_with_executable, Outcome, ParserTestJob,
        ParserTestSandboxError, Work, WORKER_ARGUMENT,
    },
    vrl_functions::VrlRegistry,
    VrlValidator,
};
use serde_json::json;
use std::path::Path;

fn worker() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_nanosiem-api"))
}

/// Doubles a string 40 times: a terabyte if nothing stops it, with no
/// budget checkpoint in reach (40 loop iterations).
const MEMORY_HOG: &str = r#"s = "xxxxxxxxxxxxxxxx"
for_each(range(0, 40) ?? []) -> |_i, _v| { s = s + s }
.len = strlen(s)"#;

/// Quadratic work in the sample: stopped by the 5 s execution budget.
const CPU_HOG: &str = r#"parts = split(string!(.message), ",")
n = 0
for_each(parts) -> |_i, _a| { for_each(parts) -> |_j, _b| { n = n + 1 } }
.n = n"#;

fn each(code: &str, inputs: Vec<serde_json::Value>) -> ParserTestJob {
    ParserTestJob {
        registry: VrlRegistry::Parser,
        work: Work::Each {
            code: code.into(),
            inputs,
        },
    }
}

/// The parser-test gate is process-wide: run these serially.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn the_worker_runs_a_normal_parser() {
    let _serial = SERIAL.lock().await;
    let outcome = run_with_executable(
        &each(".parsed = upcase!(.message)", vec![json!({"message": "hi"}), json!({"message": "yo"})]),
        worker(),
        &[WORKER_ARGUMENT],
    )
    .await
    .unwrap();
    let Outcome::Each(Ok(rows)) = outcome else { panic!("{outcome:?}") };
    assert_eq!(rows[0].as_ref().unwrap()["parsed"], "HI");
    assert_eq!(rows[1].as_ref().unwrap()["parsed"], "YO");
}

#[tokio::test]
async fn a_cpu_bound_program_gets_the_budget_error() {
    let _serial = SERIAL.lock().await;
    let started = std::time::Instant::now();
    let outcome = run_with_executable(
        &each(CPU_HOG, vec![json!({"message": ",".repeat(40_000)})]),
        worker(),
        &[WORKER_ARGUMENT],
    )
    .await
    .unwrap();
    let Outcome::Each(Ok(rows)) = outcome else { panic!("{outcome:?}") };
    let error = rows[0].as_ref().unwrap_err();
    assert!(error.contains("time budget"), "{error}");
    assert!(started.elapsed().as_secs() < 12, "{:?}", started.elapsed());
}

/// The finding: on the old in-process path this program allocated until the
/// API was OOM-killed. In the worker, `RLIMIT_DATA` stops it.
#[cfg_attr(
    not(target_os = "linux"),
    ignore = "memory rlimits are enforced on Linux only (macOS: degraded isolation)"
)]
#[tokio::test]
async fn a_memory_hungry_program_is_stopped_and_the_parent_survives() {
    let _serial = SERIAL.lock().await;
    let started = std::time::Instant::now();
    let error = run_with_executable(
        &each(MEMORY_HOG, vec![json!({"message": "x"})]),
        worker(),
        &[WORKER_ARGUMENT],
    )
    .await
    .unwrap_err();
    assert_eq!(error, ParserTestSandboxError::ResourceLimit);
    assert!(started.elapsed().as_secs() < 12, "{:?}", started.elapsed());

    // The same path through the validator (as test-vrl uses it) reports a
    // failed test with a bounded message, and the next test still works.
    register_worker_executable(worker().to_path_buf());
    let validator = VrlValidator::new();
    let failed = validator.test_vrl(MEMORY_HOG, r#"{"message":"x"}"#).await.unwrap();
    assert!(!failed.success);
    let message = failed.error.unwrap();
    assert!(message.contains("memory or CPU bound"), "{message}");
    let ok = validator
        .test_vrl(".parsed = upcase!(.message)", r#"{"message":"x"}"#)
        .await
        .unwrap();
    assert!(ok.success, "{:?}", ok.error);
}

#[tokio::test]
async fn the_validator_executes_through_the_registered_worker() {
    let _serial = SERIAL.lock().await;
    register_worker_executable(worker().to_path_buf());
    let validator = VrlValidator::new();
    let single = validator
        .test_vrl(".parsed = upcase!(.message)", r#"{"message":"hi"}"#)
        .await
        .unwrap();
    assert!(single.success, "{:?}", single.error);
    assert_eq!(single.output.unwrap()["parsed"], "HI");
    let batch = validator
        .test_vrl_batch(
            ".parsed = upcase!(.message)",
            &[r#"{"message":"a"}"#.to_string(), "not json".to_string()],
        )
        .await
        .unwrap();
    assert!(batch[0].success);
    assert!(batch[1].error.as_deref().unwrap().contains("Invalid JSON"));
    let chain = validator
        .test_vrl_chain(&[".a = 1", ".b = to_int(.a) ?? 0\n.b = .b + 1"], "{}")
        .await
        .unwrap();
    assert_eq!(chain.output.unwrap()["b"], 2);
}
