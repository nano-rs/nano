// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded parser-test execution (security review 2026-11-08, NAN-5040).

use super::*;
use crate::parsers::VrlValidator;

/// A nested `for_each` over a split sample: quadratic work in the sample size.
const NESTED_LOOP: &str = r#"
parts = split(string!(.message), ",")
n = 0
for_each(parts) -> |_i, _a| {
  for_each(parts) -> |_j, _b| {
    n = n + 1
  }
}
.n = n
"#;

fn compile(code: &str) -> vrl::compiler::Program {
    VrlValidator::new()
        .compile_program(code)
        .unwrap_or_else(|e| panic!("compile: {e}"))
}

/// Exploit regression: 40k parts is 1.6e9 inner iterations (minutes of CPU).
/// With the budget it stops promptly with a clear error.
#[test]
fn runaway_program_is_interrupted_by_the_budget() {
    let program = compile(NESTED_LOOP);
    let input = serde_json::json!({ "message": ",".repeat(40_000) });
    let mut budget = ExecutionBudget::new(Duration::from_millis(200));
    let started = Instant::now();
    let err = run_program(NESTED_LOOP, &program, &input, &mut budget).unwrap_err();
    assert!(err.contains("time budget"), "{err}");
    assert!(started.elapsed() < Duration::from_secs(3), "{:?}", started.elapsed());
    // Further samples under the same request budget fail fast.
    let started = Instant::now();
    assert!(run_program(NESTED_LOOP, &program, &input, &mut budget).is_err());
    assert!(started.elapsed() < Duration::from_millis(50));
}

/// Legitimate path: a normal parser resolves well inside the budget with the
/// same output as before.
#[test]
fn normal_program_runs_unchanged() {
    let code = ".parsed = upcase!(.message)";
    let program = compile(code);
    let mut budget = ExecutionBudget::new(TEST_EXECUTION_BUDGET);
    let out = run_program(code, &program, &serde_json::json!({"message": "hi"}), &mut budget).unwrap();
    assert_eq!(out["parsed"], "HI");
    // A small nested loop finishes too.
    let program = compile(NESTED_LOOP);
    let out = run_program(
        NESTED_LOOP,
        &program,
        &serde_json::json!({"message": "a,b,c"}),
        &mut budget,
    )
    .unwrap();
    assert_eq!(out["n"], 9);
}

#[test]
fn sample_caps_reject_oversized_requests() {
    let big = "x".repeat(MAX_TEST_SAMPLE_BYTES + 1);
    assert!(matches!(check_samples(&[big]), Err(VrlValidatorError::InvalidInput(_))));
    let many: Vec<String> = (0..=MAX_TEST_SAMPLES).map(|_| "{}".to_string()).collect();
    assert!(matches!(check_samples(&many), Err(VrlValidatorError::InvalidInput(_))));
    let ok: Vec<String> = (0..MAX_TEST_SAMPLES).map(|_| "{}".to_string()).collect();
    assert!(check_samples(&ok).is_ok());
}

/// Execution leaves the tokio worker: the async entry points stay responsive
/// and keep the normal result shape.
#[tokio::test]
async fn test_vrl_batch_legit_path_still_returns_results() {
    let v = VrlValidator::new();
    let ok = v
        .test_vrl_batch(".parsed = upcase!(.message)", &[r#"{"message":"x"}"#.to_string()])
        .await
        .unwrap();
    assert!(ok[0].success, "{:?}", ok[0].error);
}
